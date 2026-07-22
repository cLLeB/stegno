//! Carriers — any cover file as an addressable space of 1-bit slots.
//!
//! The region-based features (decoy slots, multi-recipient regions, splitting a
//! payload across several covers) only ever needed one fact about a cover: how
//! many independent bit-slots it has, and how to read/write slot `i`. They were
//! written directly against RGBA pixels, which is why they used to work on
//! photos and nothing else.
//!
//! A [`Carrier`] is that missing abstraction. Open any cover — photo, WAV, plain
//! text, PDF, video, an arbitrary blob — and you get the same slot space, so
//! every feature composes with every carrier for free.
//!
//! Four backings, chosen by sniffing the cover:
//!
//! * [`ImageCarrier`] — one slot per R/G/B channel LSB. Slot numbering matches
//!   the historical `lsb_common` walk, so stego images made before this module
//!   existed still extract.
//! * [`WavCarrier`]  — one slot per audio sample's low-byte LSB.
//! * [`TextCarrier`] — a run of zero-width characters appended to UTF-8 text.
//! * [`BytesCarrier`] — a trailing region appended past a file's logical end.
//!   Works on literally any bytes, which is what makes video containers, PDFs,
//!   archives and unknown formats usable as covers.
//!
//! The last two are *elastic*: a clean cover has no slots yet, so they publish a
//! budget derived from the cover's size and materialize the region when encoded.
//! Re-opening the resulting stego file recovers the exact same slot count from
//! the trailer, which is what lets extraction replay the embed's region math.

use crate::image_io::{decode_rgba, encode_png, RgbaImage};
use crate::region::Slots;
use crate::StegnoError;

/// What a carrier re-encodes to, so callers can name and type the output file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Image,
    Audio,
    Text,
    Video,
    Bytes,
}

impl CarrierKind {
    /// Extension for a stego file produced by this carrier, without the dot.
    /// Image carriers always re-encode to PNG — lossless is mandatory for LSB
    /// survival. The elastic carriers keep the cover's own extension, so the
    /// caller passes the original name through instead of using this.
    pub fn extension(&self) -> &'static str {
        match self {
            CarrierKind::Image => "png",
            CarrierKind::Audio => "wav",
            CarrierKind::Text => "txt",
            // The video carrier reads and writes raw YUV4MPEG2, not a muxed
            // container — naming it .mkv would mislabel the bytes. Re-encoding
            // to a real container is a separate, lossless step.
            CarrierKind::Video => "y4m",
            CarrierKind::Bytes => "bin",
        }
    }

    pub fn mime(&self) -> &'static str {
        match self {
            CarrierKind::Image => "image/png",
            CarrierKind::Audio => "audio/wav",
            CarrierKind::Text => "text/plain",
            CarrierKind::Video => "video/x-yuv4mpeg",
            CarrierKind::Bytes => "application/octet-stream",
        }
    }

    /// Whether the carrier rewrites the cover in place (image/audio) or appends
    /// a region to it (text/bytes). Callers use this to decide whether the
    /// original filename and extension should be preserved.
    pub fn preserves_container(&self) -> bool {
        matches!(self, CarrierKind::Text | CarrierKind::Bytes)
    }
}

/// A cover exposed as `slot_count()` independently addressable bits.
///
/// Implementations must guarantee that writing slot `i` never disturbs slot `j`,
/// which is what makes disjoint regions safe to hand to different passphrases.
pub trait Carrier: Send {
    fn kind(&self) -> CarrierKind;

    /// Number of addressable 1-bit slots.
    fn slot_count(&self) -> usize;

    /// Read slot `slot`. Out-of-range reads yield 0 rather than panicking, so a
    /// truncated or mismatched carrier degrades to "no hidden data".
    fn get_bit(&self, slot: u32) -> u8;

    /// Write slot `slot`. Out-of-range writes are ignored.
    fn set_bit(&mut self, slot: u32, bit: u8);

    /// Re-encode to a shareable file that preserves every slot exactly.
    fn encode(&self) -> Result<Vec<u8>, StegnoError>;
}

/// Bytes a carrier can hold across all its slots, before frame/crypto overhead.
pub fn raw_capacity_bytes(c: &dyn Carrier) -> usize {
    c.slot_count() / 8
}

/// Read `count` whole bytes from the front of `order`, MSB-first within each
/// byte — the same bit order every method in the engine uses.
///
/// Takes a count rather than reading everything `order` offers: a region can
/// span an entire cover, and callers almost always want only a frame's worth.
pub fn read_bytes_n(c: &dyn Carrier, order: &dyn Slots, count: usize) -> Vec<u8> {
    let count = count.min(order.len() / 8);
    let mut out = Vec::with_capacity(count);
    for byte_idx in 0..count {
        let mut b = 0u8;
        for shift in (0..8).rev() {
            let bit = byte_idx * 8 + (7 - shift);
            b |= (c.get_bit(order.at(bit)) & 1) << shift;
        }
        out.push(b);
    }
    out
}

/// Read every whole byte `order` covers.
pub fn read_bytes(c: &dyn Carrier, order: &dyn Slots) -> Vec<u8> {
    read_bytes_n(c, order, order.len() / 8)
}

/// Write `payload` along `order`, MSB-first, starting `skip` bytes in.
///
/// `skip` lets one region be filled in pieces — the composite scheme spreads a
/// single frame across several covers — without building a sub-slice of the
/// slot order first.
pub fn write_bytes_at(
    c: &mut dyn Carrier,
    payload: &[u8],
    order: &dyn Slots,
    skip: usize,
) -> Result<(), StegnoError> {
    if (skip + payload.len()) * 8 > order.len() {
        return Err(StegnoError::CoverTooSmall);
    }
    let mut bit = skip * 8;
    for &byte in payload {
        for shift in (0..8).rev() {
            c.set_bit(order.at(bit), (byte >> shift) & 1);
            bit += 1;
        }
    }
    Ok(())
}

/// Write `payload` from the start of `order`.
pub fn write_bytes(
    c: &mut dyn Carrier,
    payload: &[u8],
    order: &dyn Slots,
) -> Result<(), StegnoError> {
    write_bytes_at(c, payload, order, 0)
}

/* ------------------------------- image ------------------------------- */

/// Photo cover: one slot per R/G/B channel LSB, alpha untouched.
pub struct ImageCarrier {
    pub img: RgbaImage,
}

/// Colour channels used as carriers: R, G, B.
const CHANNELS_PER_PIXEL: usize = 3;

/// Slot `c` → pixel `c / 3`, channel `c % 3`, in the RGBA8 buffer. Identical to
/// the pre-carrier `lsb_common::slot_to_offset`, so old stego files still read.
#[inline]
fn image_offset(slot: u32) -> usize {
    let c = slot as usize;
    (c / CHANNELS_PER_PIXEL) * 4 + (c % CHANNELS_PER_PIXEL)
}

impl Carrier for ImageCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Image
    }
    fn slot_count(&self) -> usize {
        (self.img.width as usize) * (self.img.height as usize) * CHANNELS_PER_PIXEL
    }
    fn get_bit(&self, slot: u32) -> u8 {
        let off = image_offset(slot);
        self.img.pixels.get(off).map_or(0, |v| v & 1)
    }
    fn set_bit(&mut self, slot: u32, bit: u8) {
        let off = image_offset(slot);
        if let Some(v) = self.img.pixels.get_mut(off) {
            *v = (*v & 0xFE) | (bit & 1);
        }
    }
    fn encode(&self) -> Result<Vec<u8>, StegnoError> {
        encode_png(&self.img)
    }
}

/* -------------------------------- wav -------------------------------- */

/// Audio cover: one slot per sample's low-byte LSB. Headers and non-sample
/// chunks are carried through untouched, so the file stays a valid WAV.
pub struct WavCarrier {
    bytes: Vec<u8>,
    data_off: usize,
    bytes_per_sample: usize,
    units: usize,
}

impl WavCarrier {
    fn parse(bytes: &[u8]) -> Result<Self, StegnoError> {
        if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Err(StegnoError::UnsupportedFormat);
        }
        let mut pos = 12;
        let mut bytes_per_sample = 0usize;
        let mut data: Option<(usize, usize)> = None;
        while pos + 8 <= bytes.len() {
            let id = &bytes[pos..pos + 4];
            let sz =
                u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]])
                    as usize;
            let body = pos + 8;
            if body + sz > bytes.len() {
                return Err(StegnoError::UnsupportedFormat);
            }
            if id == b"fmt " && sz >= 16 {
                bytes_per_sample =
                    u16::from_le_bytes([bytes[body + 14], bytes[body + 15]]) as usize / 8;
            } else if id == b"data" {
                data = Some((body, sz));
            }
            pos = body + sz + (sz & 1);
        }
        let (data_off, data_len) = data.ok_or(StegnoError::UnsupportedFormat)?;
        if !(1..=4).contains(&bytes_per_sample) {
            return Err(StegnoError::UnsupportedFormat);
        }
        Ok(WavCarrier {
            units: data_len / bytes_per_sample,
            bytes: bytes.to_vec(),
            data_off,
            bytes_per_sample,
        })
    }

    #[inline]
    fn offset(&self, slot: u32) -> usize {
        self.data_off + (slot as usize) * self.bytes_per_sample
    }
}

impl Carrier for WavCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Audio
    }
    fn slot_count(&self) -> usize {
        self.units
    }
    fn get_bit(&self, slot: u32) -> u8 {
        if slot as usize >= self.units {
            return 0;
        }
        self.bytes.get(self.offset(slot)).map_or(0, |v| v & 1)
    }
    fn set_bit(&mut self, slot: u32, bit: u8) {
        if slot as usize >= self.units {
            return;
        }
        let off = self.offset(slot);
        if let Some(v) = self.bytes.get_mut(off) {
            *v = (*v & 0xFE) | (bit & 1);
        }
    }
    fn encode(&self) -> Result<Vec<u8>, StegnoError> {
        Ok(self.bytes.clone())
    }
}

/* ------------------------ elastic region carriers ----------------------- */

/// Trailer magic marking an appended slot region: `... | region | N | "SCAR"`.
const REGION_MAGIC: &[u8; 4] = b"SCAR";
const REGION_TRAILER: usize = 8 + 4;

/// Smallest and largest slot region an elastic carrier will offer, in bytes.
///
/// The floor keeps tiny covers usable at all. The ceiling used to be 1 MiB
/// because the position permutations were materialized `Vec<u32>`s, so a large
/// region cost proportional memory before a single byte was hidden. [`crate::prp`]
/// computes those positions instead, so that reason is gone — and the old cap
/// was badly limiting in practice: a 25 MB document offered the same 1 MiB as a
/// 4 MB one, and two secrets sharing two such covers got about a megabyte each.
///
/// What remains is the region itself, which is allocated whether or not it is
/// filled. 64 MiB bounds that while being far above anything the proportional
/// budget below reaches for ordinary files — it only binds past a ~256 MB cover.
const ELASTIC_MIN_BYTES: usize = 4 * 1024;
const ELASTIC_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Slot budget for a clean cover of `len` bytes.
///
/// The region is materialized whether or not it is filled, so the budget is
/// what the stego file grows by. A quarter of the cover keeps that growth
/// unremarkable — a file that suddenly doubles invites exactly the attention
/// steganography is meant to avoid — while still leaving far more room than a
/// typical secret needs. Small covers get the floor instead, since a proportion
/// of very little is useless.
fn elastic_budget_bits(len: usize) -> usize {
    (len / 4).clamp(ELASTIC_MIN_BYTES, ELASTIC_MAX_BYTES) * 8
}

/// UTF-8 bytes each zero-width character costs. Both U+200B and U+200C encode
/// as three bytes.
const ZW_BYTES_PER_BIT: usize = 3;

/// Slot budget for a text cover.
///
/// A zero-width run costs [`ZW_BYTES_PER_BIT`] bytes for every *bit*, so
/// budgeting it like the byte carrier — which reasons in bytes of capacity —
/// inflates the file twenty-four fold, turning a short note into a megabyte of
/// invisible padding. Budget by the real encoded cost instead: `len / 9` bits
/// costs `len / 3` bytes, about a third of the cover.
///
/// This is why a text cover holds so much less than its size suggests. It is
/// the honest ceiling for zero-width embedding — the alternative is a file that
/// visibly doubles, which defeats the point.
fn text_budget_bits(len: usize) -> usize {
    let growth_third = len / (ZW_BYTES_PER_BIT * 3);
    growth_third.clamp(4 * 1024, ELASTIC_MAX_BYTES * 8 / ZW_BYTES_PER_BIT)
}

/// A packed run of bits plus the untouched cover it will be appended to.
struct BitRegion {
    bits: Vec<u8>,
    count: usize,
}

impl BitRegion {
    fn empty(count: usize) -> Self {
        BitRegion {
            bits: vec![0u8; count.div_ceil(8)],
            count,
        }
    }
    fn from_packed(bits: Vec<u8>, count: usize) -> Self {
        BitRegion { bits, count }
    }
    #[inline]
    fn get(&self, slot: u32) -> u8 {
        let i = slot as usize;
        if i >= self.count {
            return 0;
        }
        (self.bits[i / 8] >> (7 - (i % 8))) & 1
    }
    #[inline]
    fn set(&mut self, slot: u32, bit: u8) {
        let i = slot as usize;
        if i >= self.count {
            return;
        }
        let mask = 1u8 << (7 - (i % 8));
        if bit & 1 == 1 {
            self.bits[i / 8] |= mask;
        } else {
            self.bits[i / 8] &= !mask;
        }
    }
}

/// Any file as a cover: the payload lives in a region appended past the file's
/// logical end, where container formats stop parsing. The cover bytes are an
/// untouched prefix, so the file still opens exactly as before — which is what
/// lets PDFs, archives, executables and video containers act as covers.
pub struct BytesCarrier {
    cover: Vec<u8>,
    region: BitRegion,
}

impl BytesCarrier {
    /// Open `bytes`, reusing an existing appended region if one is present.
    fn open(bytes: &[u8]) -> Self {
        if let Some((cover, region)) = split_region(bytes) {
            return BytesCarrier { cover, region };
        }
        BytesCarrier {
            cover: bytes.to_vec(),
            region: BitRegion::empty(elastic_budget_bits(bytes.len())),
        }
    }
}

/// Peel an appended slot region off the end of `bytes`, if one is there.
fn split_region(bytes: &[u8]) -> Option<(Vec<u8>, BitRegion)> {
    let n = bytes.len();
    if n < REGION_TRAILER || &bytes[n - 4..] != REGION_MAGIC {
        return None;
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[n - REGION_TRAILER..n - 4]);
    let count = u64::from_be_bytes(len_bytes) as usize;
    let packed = count.div_ceil(8);
    // A bogus length means this trailer isn't ours; treat it as a clean cover.
    if packed > n - REGION_TRAILER {
        return None;
    }
    let start = n - REGION_TRAILER - packed;
    Some((
        bytes[..start].to_vec(),
        BitRegion::from_packed(bytes[start..n - REGION_TRAILER].to_vec(), count),
    ))
}

/// Append `region` to `cover` with the trailer that lets it be found again.
fn join_region(cover: &[u8], region: &BitRegion) -> Vec<u8> {
    let mut out = Vec::with_capacity(cover.len() + region.bits.len() + REGION_TRAILER);
    out.extend_from_slice(cover);
    out.extend_from_slice(&region.bits);
    out.extend_from_slice(&(region.count as u64).to_be_bytes());
    out.extend_from_slice(REGION_MAGIC);
    out
}

impl Carrier for BytesCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Bytes
    }
    fn slot_count(&self) -> usize {
        self.region.count
    }
    fn get_bit(&self, slot: u32) -> u8 {
        self.region.get(slot)
    }
    fn set_bit(&mut self, slot: u32, bit: u8) {
        self.region.set(slot, bit)
    }
    fn encode(&self) -> Result<Vec<u8>, StegnoError> {
        Ok(join_region(&self.cover, &self.region))
    }
}

/// Zero-width characters carrying one bit each: ZWSP = 0, ZWNJ = 1. Both are
/// invisible in every renderer and survive copy/paste through most chat apps.
const ZW_ZERO: char = '\u{200B}';
const ZW_ONE: char = '\u{200C}';

/// UTF-8 text as a cover: the payload is a run of zero-width characters
/// appended to the text. The visible content is byte-identical to the original.
pub struct TextCarrier {
    text: String,
    region: BitRegion,
}

impl TextCarrier {
    /// `None` if `bytes` isn't text we can safely round-trip.
    fn open(bytes: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(bytes).ok()?;
        if s.is_empty() || s.contains('\0') {
            return None;
        }
        // Refuse binary-ish blobs that merely happen to decode as UTF-8.
        let printable = s
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            .count();
        if printable * 10 < s.chars().count() * 9 {
            return None;
        }
        let trailing: String = s
            .chars()
            .rev()
            .take_while(|&c| c == ZW_ZERO || c == ZW_ONE)
            .collect();
        if trailing.is_empty() {
            return Some(TextCarrier {
                region: BitRegion::empty(text_budget_bits(bytes.len())),
                text: s.to_string(),
            });
        }
        // `trailing` was collected in reverse; walk it back to source order.
        let count = trailing.chars().count();
        let mut region = BitRegion::empty(count);
        for (i, c) in trailing.chars().rev().enumerate() {
            region.set(i as u32, if c == ZW_ONE { 1 } else { 0 });
        }
        let visible: String = s.chars().take(s.chars().count() - count).collect();
        Some(TextCarrier {
            text: visible,
            region,
        })
    }
}

impl Carrier for TextCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Text
    }
    fn slot_count(&self) -> usize {
        self.region.count
    }
    fn get_bit(&self, slot: u32) -> u8 {
        self.region.get(slot)
    }
    fn set_bit(&mut self, slot: u32, bit: u8) {
        self.region.set(slot, bit)
    }
    fn encode(&self) -> Result<Vec<u8>, StegnoError> {
        let mut out = String::with_capacity(self.text.len() + self.region.count * 3);
        out.push_str(&self.text);
        for i in 0..self.region.count {
            out.push(if self.region.get(i as u32) == 1 {
                ZW_ONE
            } else {
                ZW_ZERO
            });
        }
        Ok(out.into_bytes())
    }
}

/* -------------------------------- open -------------------------------- */

/// Open any cover as a slot space, picking the richest carrier that fits.
///
/// Order matters: a PNG is an image before it is bytes, a WAV is audio before it
/// is bytes, and anything that decodes as neither falls back to text (if it
/// reads as UTF-8) or to the universal appended-region carrier. Because the last
/// two accept everything, this never fails on a non-empty cover.
pub fn open(cover: &[u8]) -> Result<Box<dyn Carrier>, StegnoError> {
    if cover.is_empty() {
        return Err(StegnoError::UnsupportedFormat);
    }
    if let Ok(img) = decode_rgba(cover) {
        return Ok(Box::new(ImageCarrier { img }));
    }
    if let Ok(w) = WavCarrier::parse(cover) {
        return Ok(Box::new(w));
    }
    if let Some(v) = crate::video::Y4mCarrier::parse(cover) {
        return Ok(Box::new(v));
    }
    if let Some(t) = TextCarrier::open(cover) {
        return Ok(Box::new(t));
    }
    Ok(Box::new(BytesCarrier::open(cover)))
}

/// Open a cover as a slot space, forcing the universal appended-region carrier.
/// Used when a caller needs a carrier that never re-encodes the container — e.g.
/// hiding inside a JPEG or a video without transcoding it to PNG.
pub fn open_bytes(cover: &[u8]) -> Result<Box<dyn Carrier>, StegnoError> {
    if cover.is_empty() {
        return Err(StegnoError::UnsupportedFormat);
    }
    Ok(Box::new(BytesCarrier::open(cover)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        encode_png(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![128u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    fn wav(n: usize) -> Vec<u8> {
        let data_len = n * 2;
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
        v.extend_from_slice(b"WAVE");
        v.extend_from_slice(b"fmt ");
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&44100u32.to_le_bytes());
        v.extend_from_slice(&88200u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&16u16.to_le_bytes());
        v.extend_from_slice(b"data");
        v.extend_from_slice(&(data_len as u32).to_le_bytes());
        for i in 0..n {
            v.extend_from_slice(&((i as i16).wrapping_mul(7)).to_le_bytes());
        }
        v
    }

    /// Every carrier must round-trip bytes written along an arbitrary order.
    fn roundtrip(cover: &[u8], expect: CarrierKind) {
        let mut c = open(cover).unwrap();
        assert_eq!(c.kind(), expect, "carrier choice for {expect:?}");
        let payload: Vec<u8> = (0..64u16).map(|i| (i * 7) as u8).collect();
        let order: Vec<u32> = (0..(payload.len() * 8) as u32).rev().collect();
        write_bytes(c.as_mut(), &payload, &order).unwrap();
        let encoded = c.encode().unwrap();

        let back = open(&encoded).unwrap();
        assert_eq!(back.kind(), expect, "kind survives a re-open");
        assert_eq!(read_bytes(back.as_ref(), &order), payload);
    }

    #[test]
    fn image_cover_roundtrips() {
        roundtrip(&png(40, 40), CarrierKind::Image);
    }

    #[test]
    fn audio_cover_roundtrips() {
        roundtrip(&wav(8000), CarrierKind::Audio);
    }

    #[test]
    fn text_cover_roundtrips() {
        roundtrip(
            "the quick brown fox jumps over the lazy dog\n".repeat(40).as_bytes(),
            CarrierKind::Text,
        );
    }

    #[test]
    fn arbitrary_file_cover_roundtrips() {
        // A PDF header followed by binary noise: not an image, not a WAV, not text.
        let mut blob = b"%PDF-1.7\n".to_vec();
        blob.extend((0..9000u32).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8));
        roundtrip(&blob, CarrierKind::Bytes);
    }

    #[test]
    fn text_carrier_leaves_visible_text_untouched() {
        let src = "meet me at noon";
        let mut c = open(src.as_bytes()).unwrap();
        write_bytes(c.as_mut(), b"hi", &(0..16u32).collect::<Vec<_>>()).unwrap();
        let out = String::from_utf8(c.encode().unwrap()).unwrap();
        let visible: String = out.chars().filter(|&c| c != ZW_ZERO && c != ZW_ONE).collect();
        assert_eq!(visible, src);
    }

    #[test]
    fn bytes_carrier_leaves_cover_prefix_untouched() {
        let mut blob = b"%PDF-1.7\n".to_vec();
        blob.extend((0..9000u32).map(|i| (i % 251) as u8));
        let mut c = open_bytes(&blob).unwrap();
        write_bytes(c.as_mut(), b"secret", &(0..48u32).collect::<Vec<_>>()).unwrap();
        let out = c.encode().unwrap();
        assert_eq!(&out[..blob.len()], &blob[..], "cover must be an exact prefix");
    }

    #[test]
    fn image_slot_numbering_matches_the_legacy_lsb_walk() {
        // Slot n must still address pixel n/3, channel n%3 — otherwise every
        // stego file made before carriers existed would stop extracting.
        let mut c = open(&png(8, 8)).unwrap();
        c.set_bit(0, 1);
        c.set_bit(4, 1); // pixel 1, channel G → byte offset 5
        let out = c.encode().unwrap();
        let img = decode_rgba(&out).unwrap();
        assert_eq!(img.pixels[0] & 1, 1);
        assert_eq!(img.pixels[5] & 1, 1);
        assert_eq!(img.pixels[1] & 1, 0);
    }

    #[test]
    fn slots_are_independent() {
        // Writing one slot must never disturb another — the property that makes
        // disjoint regions safe to hand to different passphrases.
        for cover in [png(20, 20), wav(2000)] {
            let mut c = open(&cover).unwrap();
            let n = c.slot_count().min(500);
            for i in 0..n {
                c.set_bit(i as u32, (i % 2) as u8);
            }
            for i in 0..n {
                assert_eq!(c.get_bit(i as u32), (i % 2) as u8, "slot {i}");
            }
        }
    }

    #[test]
    fn out_of_range_access_is_inert() {
        let mut c = open(&png(4, 4)).unwrap();
        let past_end = c.slot_count() as u32 + 100;
        c.set_bit(past_end, 1);
        assert_eq!(c.get_bit(past_end), 0);
    }

    #[test]
    fn empty_cover_is_rejected() {
        assert!(matches!(open(&[]), Err(StegnoError::UnsupportedFormat)));
    }

    /// A carrier must never balloon the cover. Text is the trap here: every bit
    /// costs three UTF-8 bytes, so budgeting it in bytes of capacity inflated
    /// files 24-fold — a 2.4 KB note became 100 KB of invisible padding.
    /// Capacity must track the cover's size, not flatten at a fixed ceiling.
    ///
    /// A 25 MB document used to offer the same 1 MiB as a 4 MB one, so a real
    /// pair of large PDF covers carried about a megabyte per secret when they
    /// could hold several.
    #[test]
    fn a_large_cover_offers_proportionally_more_room() {
        let cap = |mb: usize| -> usize {
            let blob: Vec<u8> = (0..mb * 1024 * 1024).map(|i| (i % 251) as u8).collect();
            raw_capacity_bytes(open_bytes(&blob).unwrap().as_ref())
        };
        let four = cap(4);
        let twenty_five = cap(25);
        assert!(
            twenty_five > four * 5,
            "25 MB cover gave {twenty_five} bytes against {four} for 4 MB — still capped"
        );
        // And it is genuinely a quarter of the cover, not an arbitrary number.
        let expected = 25 * 1024 * 1024 / 4;
        assert!(
            twenty_five.abs_diff(expected) < expected / 20,
            "expected about {expected} bytes, got {twenty_five}"
        );
    }

    #[test]
    fn stego_output_stays_close_to_the_cover_size() {
        let text = "The garden is lovely this year, and the roses have taken.\n"
            .repeat(400)
            .into_bytes();
        let blob: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for (label, cover) in [("text", text), ("bytes", blob)] {
            let c = open(&cover).unwrap();
            let out = c.encode().unwrap();
            assert!(
                out.len() <= cover.len() * 2,
                "{label}: {} -> {} is more than double",
                cover.len(),
                out.len()
            );
        }
    }

    #[test]
    fn text_covers_still_hold_a_useful_payload() {
        // The budget must not shrink so far that text stops being a carrier.
        let cover = "a short memo about nothing in particular.\n".repeat(200);
        let c = open(cover.as_bytes()).unwrap();
        assert!(
            raw_capacity_bytes(c.as_ref()) >= 512,
            "text capacity fell to {}",
            raw_capacity_bytes(c.as_ref())
        );
    }

    #[test]
    fn elastic_slot_count_survives_reopen() {
        let blob: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
        let c = open_bytes(&blob).unwrap();
        let before = c.slot_count();
        let encoded = c.encode().unwrap();
        assert_eq!(open_bytes(&encoded).unwrap().slot_count(), before);
    }
}
