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
use crate::seed;
use crate::StegnoError;

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

/// Embed `payload` using `order` and a per-channel `write` strategy, then encode
/// to PNG. `write(channel_value, bit) -> new_channel_value`.
///
/// Fails with `CoverTooSmall` if the payload needs more slots than `order` has.
pub fn embed_with<F>(
    mut img: RgbaImage,
    payload: &[u8],
    order: &[u32],
    mut write: F,
) -> Result<Vec<u8>, StegnoError>
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
    encode_png(&img)
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
