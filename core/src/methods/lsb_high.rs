//! `lsb_high` — high-capacity 2-bit LSB embedding in PNG.
//!
//! The rest of the LSB family carries one bit per colour channel. `lsb_high`
//! uses the **two** least-significant bits of each R/G/B channel, doubling
//! capacity (≈ 6 bits/pixel) at the cost of a larger per-channel perturbation
//! (up to ±3) and therefore easier detection — a deliberate capacity/stealth
//! trade the planner and `risk` command surface. Positions are key-seeded like
//! [`super::lsb_seeded`], and both bits are recovered directly, so it stays
//! bit-exact and carries the AES-GCM frame reliably.

use super::lsb_common;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct LsbHigh;

const BITS_PER_SLOT: usize = 2;

/// Byte offset in the RGBA buffer of the `idx`-th slot in `order`.
#[inline]
fn slot_offset(order: &[u32], idx: usize) -> usize {
    let c = order[idx] as usize;
    (c / lsb_common::CHANNELS_PER_PIXEL) * 4 + (c % lsb_common::CHANNELS_PER_PIXEL)
}

#[inline]
fn payload_bit(payload: &[u8], j: usize) -> u8 {
    (payload[j / 8] >> (7 - (j % 8))) & 1
}

impl Method for LsbHigh {
    fn id(&self) -> &'static str {
        "lsb_high"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — high capacity (2-bit)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = crate::image_io::decode_rgba(cover)?;
        let raw = lsb_common::total_slots(img.width, img.height) * BITS_PER_SLOT / 8;
        Ok(Capacity {
            usable_bytes: (raw as u64).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (mut img, order) = lsb_common::prepare(cover, opts.seed.as_ref())?;
        let need_bits = payload.len() * 8;
        if need_bits > order.len() * BITS_PER_SLOT {
            return Err(StegnoError::CoverTooSmall);
        }
        let mut j = 0usize;
        while j < need_bits {
            let slot = j / BITS_PER_SLOT;
            let off = slot_offset(&order, slot);
            let hi = payload_bit(payload, j); // high of the two carried bits
            let lo = if j + 1 < need_bits {
                payload_bit(payload, j + 1)
            } else {
                0
            };
            img.pixels[off] = (img.pixels[off] & 0xFC) | (hi << 1) | lo;
            j += BITS_PER_SLOT;
        }
        crate::image_io::encode_png(&img)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = crate::image_io::decode_rgba(stego)?;
        let order = lsb_common::slot_order(img.width, img.height, opts.seed.as_ref());
        let total_bits = order.len() * BITS_PER_SLOT;

        let read_bit = |j: usize| -> u8 {
            let slot = j / BITS_PER_SLOT;
            let v = img.pixels[slot_offset(&order, slot)];
            if j % BITS_PER_SLOT == 0 {
                (v >> 1) & 1
            } else {
                v & 1
            }
        };
        let read_byte = |k: usize| -> u8 {
            let mut out = 0u8;
            for shift in (0..8).rev() {
                out |= read_bit(k * 8 + (7 - shift)) << shift;
            }
            out
        };

        let hdr = payload::header_len();
        if total_bits < hdr * 8 {
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
        if need * 8 > total_bits {
            return Err(StegnoError::CorruptPayload);
        }
        let mut buf = Vec::with_capacity(need);
        for i in 0..need {
            buf.push(read_byte(i));
        }
        Ok(Some(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{decode_rgba, encode_png as enc, RgbaImage};
    use crate::seed::{derive_seed, Slot};

    fn cover(w: u32, h: u32, fill: u8) -> Vec<u8> {
        enc(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![fill; (w * h * 4) as usize],
        })
        .unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn roundtrip() {
        let c = cover(64, 64, 100);
        let body = payload::frame(b"twice the capacity of one-bit lsb");
        let (eo, xo) = opts("key");
        let stego = LsbHigh.embed(&c, &body, &eo).unwrap();
        assert_eq!(LsbHigh.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn capacity_is_about_double_single_bit() {
        let c = cover(100, 100, 128);
        let high = LsbHigh.capacity(&c).unwrap().usable_bytes;
        let one = crate::methods::lsb_seeded::LsbSeeded.capacity(&c).unwrap().usable_bytes;
        // ~2x minus the shared fixed overhead.
        assert!(high > one + (one / 2), "high={high} one={one}");
    }

    #[test]
    fn per_channel_change_is_bounded_by_three() {
        let c = cover(64, 64, 100);
        let body = payload::frame(&vec![0xFFu8; 200]);
        let (eo, _) = opts("k");
        let stego = LsbHigh.embed(&c, &body, &eo).unwrap();
        let before = decode_rgba(&c).unwrap();
        let after = decode_rgba(&stego).unwrap();
        for (x, y) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!((*x as i16 - *y as i16).abs() <= 3);
        }
    }

    #[test]
    fn wrong_seed_finds_no_frame() {
        let c = cover(64, 64, 80);
        let body = payload::frame(b"hidden");
        let (eo, _) = opts("right");
        let stego = LsbHigh.embed(&c, &body, &eo).unwrap();
        let (_, xo) = opts("wrong");
        assert_eq!(LsbHigh.extract(&stego, &xo).unwrap(), None);
    }

    #[test]
    fn boundary_fills_roundtrip() {
        for fill in [0u8, 255u8] {
            let c = cover(48, 48, fill);
            let body = payload::frame(b"edges 2-bit");
            let (eo, xo) = opts("k");
            let stego = LsbHigh.embed(&c, &body, &eo).unwrap();
            assert_eq!(LsbHigh.extract(&stego, &xo).unwrap().unwrap(), body);
        }
    }
}
