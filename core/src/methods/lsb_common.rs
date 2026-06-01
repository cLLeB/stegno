//! Shared mechanics for the LSB family (`lsb_image`, `lsb_seeded`,
//! `lsb_matching`).
//!
//! All of them encode each payload bit in the least-significant bit of one
//! colour channel; they differ only in (a) the *order* in which channel slots
//! are visited and (b) how a channel value is nudged to carry the bit
//! (overwrite vs. ±1 matching). This module owns the parts they share: the
//! channel-slot ↔ pixel mapping, capacity math, the generic write loop, and the
//! frame reader (identical for every variant, since they all store the bit in
//! the LSB).

use crate::image_io::{decode_rgba, encode_png, RgbaImage};
use crate::payload;
use crate::seed::{self, Slot};
use crate::StegnoError;

/// Fixed, non-secret seed defining the decoy "master ranking". Splitting this
/// public permutation in half yields two disjoint position sets — one per slot
/// — so the real and decoy payloads can never collide. It is a constant (not
/// key-derived) precisely so the extractor can reconstruct the regions with
/// only the passphrase.
const DECOY_MASTER_SEED: [u8; 32] = *b"stegno/decoy/master-ranking/v1!!";

/// Colour channels used as carriers: R, G, B (alpha is left untouched).
pub const CHANNELS_PER_PIXEL: usize = 3;

/// Number of usable LSB slots in an image: one per R/G/B channel of every pixel.
pub fn total_slots(width: u32, height: u32) -> usize {
    (width as usize) * (height as usize) * CHANNELS_PER_PIXEL
}

/// Raw capacity in bytes (before frame/crypto overhead).
pub fn raw_capacity_bytes(width: u32, height: u32) -> usize {
    total_slots(width, height) / 8
}

/// Usable capacity after subtracting frame + crypto overhead.
pub fn usable_capacity_bytes(width: u32, height: u32) -> u64 {
    (raw_capacity_bytes(width, height) as u64).saturating_sub(payload::overhead() as u64)
}

/// Map a channel-slot index to the byte offset of that channel in the RGBA8
/// buffer. Slot `c` → pixel `c / 3`, channel `c % 3`.
#[inline]
fn slot_to_offset(slot: u32) -> usize {
    let c = slot as usize;
    (c / CHANNELS_PER_PIXEL) * 4 + (c % CHANNELS_PER_PIXEL)
}

/// The visiting order of channel slots for a given seed.
///
/// `None` → sequential (identity) order, byte-for-byte the Phase-0 walk.
/// `Some(seed)` → a key-seeded permutation of every slot.
pub fn slot_order(width: u32, height: u32, seed: Option<&[u8; 32]>) -> Vec<u32> {
    let n = total_slots(width, height);
    match seed {
        None => (0..n as u32).collect(),
        Some(s) => seed::permutation(n, s),
    }
}

/// Decode the cover and produce both the image and its slot visiting order.
pub fn prepare(cover: &[u8], seed: Option<&[u8; 32]>) -> Result<(RgbaImage, Vec<u32>), StegnoError> {
    let img = decode_rgba(cover)?;
    let order = slot_order(img.width, img.height, seed);
    Ok((img, order))
}

/// Embed `payload` into an already-decoded image following `order` and a
/// per-channel `write` strategy. Does not encode — lets callers (e.g. the decoy
/// scheme) embed several frames into one image before encoding once.
///
/// Fails with `CoverTooSmall` if the payload needs more slots than `order` has.
pub fn embed_into<F>(
    img: &mut RgbaImage,
    payload: &[u8],
    order: &[u32],
    mut write: F,
) -> Result<(), StegnoError>
where
    F: FnMut(u8, u8) -> u8,
{
    let need_bits = payload.len() * 8;
    if need_bits > order.len() {
        return Err(StegnoError::CoverTooSmall);
    }
    let mut bit = 0usize;
    for &byte in payload {
        for shift in (0..8).rev() {
            let b = (byte >> shift) & 1;
            let off = slot_to_offset(order[bit]);
            img.pixels[off] = write(img.pixels[off], b);
            bit += 1;
        }
    }
    Ok(())
}

/// Embed `payload` and encode to PNG. Convenience wrapper over [`embed_into`].
pub fn embed_with<F>(
    mut img: RgbaImage,
    payload: &[u8],
    order: &[u32],
    write: F,
) -> Result<Vec<u8>, StegnoError>
where
    F: FnMut(u8, u8) -> u8,
{
    embed_into(&mut img, payload, order, write)?;
    encode_png(&img)
}

/// Capacity (bytes) of one decoy slot's region — roughly half the image, minus
/// frame/crypto overhead.
pub fn decoy_slot_capacity_bytes(width: u32, height: u32) -> u64 {
    let region = total_slots(width, height) / 2; // bits in one half
    ((region / 8) as u64).saturating_sub(payload::overhead() as u64)
}

/// Channel-slot visiting order for one decoy slot.
///
/// The fixed [`DECOY_MASTER_SEED`] permutation is split in half — `Primary`
/// takes the first half, `Decoy` the second — guaranteeing the two slots use
/// disjoint positions. Within the half, the visiting order is the
/// passphrase-keyed permutation, so the payload is still scattered and only the
/// holder of the right passphrase reconstructs it.
pub fn decoy_region_order(
    width: u32,
    height: u32,
    slot: Slot,
    key_seed: &[u8; 32],
) -> Vec<u32> {
    let n = total_slots(width, height);
    if n == 0 {
        return Vec::new();
    }
    let master = seed::permutation(n, &DECOY_MASTER_SEED);
    let half = n / 2;
    let region: &[u32] = match slot {
        Slot::Primary => &master[..half],
        Slot::Decoy => &master[half..],
    };
    seed::permutation(region.len(), key_seed)
        .into_iter()
        .map(|i| region[i as usize])
        .collect()
}

/// Overwrite the LSB of `value` with `bit` (classic LSB replacement).
#[inline]
pub fn replace_lsb(value: u8, bit: u8) -> u8 {
    (value & 0xFE) | (bit & 1)
}

/// Read the framed payload back out of `stego` following `order`. The bit is
/// always the channel LSB, so this is shared by every LSB-family variant.
///
/// `Ok(None)` if the magic header is absent at the seeded positions (no hidden
/// data, or wrong key — both indistinguishable, which aids deniability).
pub fn read_frame(stego: &[u8], seed: Option<&[u8; 32]>) -> Result<Option<Vec<u8>>, StegnoError> {
    let img = decode_rgba(stego)?;
    let order = slot_order(img.width, img.height, seed);
    read_frame_with(&img, &order)
}

/// As [`read_frame`] but on an already-decoded image and explicit order — used
/// by the decoy scheme, which reads several orders from one decode.
pub fn read_frame_with(img: &RgbaImage, order: &[u32]) -> Result<Option<Vec<u8>>, StegnoError> {
    let total_slot_bits = order.len();
    let read_byte = |byte_idx: usize| -> u8 {
        let mut out = 0u8;
        for shift in (0..8).rev() {
            let bit = byte_idx * 8 + (7 - shift);
            let off = slot_to_offset(order[bit]);
            out |= (img.pixels[off] & 1) << shift;
        }
        out
    };

    let hdr = payload::header_len();
    if total_slot_bits < hdr * 8 {
        return Ok(None);
    }
    let mut head = Vec::with_capacity(hdr);
    for i in 0..hdr {
        head.push(read_byte(i));
    }
    if head[..4] != *b"STG0" {
        return Ok(None);
    }
    let len = u32::from_be_bytes([head[7], head[8], head[9], head[10]]) as usize;
    let need = hdr + len;
    if need * 8 > total_slot_bits {
        return Err(StegnoError::CorruptPayload);
    }
    let mut buf = Vec::with_capacity(need);
    for i in 0..need {
        buf.push(read_byte(i));
    }
    Ok(Some(buf))
}
