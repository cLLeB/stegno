//! `lsbmr` — LSB Matching Revisited (Mielikäinen, 2006).
//!
//! Plain LSB matching ([`super::lsb_matching`]) treats each channel value
//! independently: whenever a bit must change it does a ±1, so on average it
//! perturbs one value per bit. LSBMR carries **two** message bits per **pair**
//! of channel values (a, b) using the relation
//!
//! ```text
//!   m1 = LSB(a)
//!   m2 = LSB( floor(a / 2) + b )
//! ```
//!
//! Because `f(a−1, b)` and `f(a+1, b)` always differ, the second bit can usually
//! be fixed by choosing the *direction* of a's ±1 rather than by touching `b` —
//! so it changes at most one of the two values (expected 0.375 changes per bit
//! vs. 0.5 for matching), a smaller statistical footprint at the same capacity.
//!
//! Reading needs no side information: both bits are recomputed from the stego
//! values, so recovery is bit-exact and carries the AES-GCM frame reliably.
//! Positions are key-seeded exactly like the rest of the LSB family.

use super::lsb_common;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct Lsbmr;

/// The second-bit function `f(a, b) = LSB(floor(a/2) + b)`.
#[inline]
fn f(a: u8, b: u8) -> u8 {
    (((a as u16) / 2 + b as u16) & 1) as u8
}

/// Encode two message bits into a pair of channel values, changing each value by
/// at most ±1. Returns the adjusted `(a', b')` such that `LSB(a') == m1` and
/// `f(a', b') == m2`.
fn embed_pair(a: u8, b: u8, m1: u8, m2: u8) -> (u8, u8) {
    let m1 = m1 & 1;
    let m2 = m2 & 1;
    if a & 1 == m1 {
        // First bit already correct; fix the second by nudging b if needed.
        if f(a, b) == m2 {
            (a, b)
        } else {
            let b2 = if b == 0 { b + 1 } else { b - 1 };
            (a, b2)
        }
    } else {
        // First bit must flip parity of a. The direction of the ±1 sets the
        // second bit for free (interior values); only boundaries need b.
        if a != 0 && f(a - 1, b) == m2 {
            (a - 1, b)
        } else if a != 255 && f(a + 1, b) == m2 {
            (a + 1, b)
        } else {
            let a2 = if a == 0 { a + 1 } else { a - 1 };
            let b2 = if f(a2, b) == m2 {
                b
            } else if b == 0 {
                b + 1
            } else {
                b - 1
            };
            (a2, b2)
        }
    }
}

/// The j-th bit (MSB-first within each byte) of the framed payload.
#[inline]
fn payload_bit(payload: &[u8], j: usize) -> u8 {
    let byte = payload[j / 8];
    (byte >> (7 - (j % 8))) & 1
}

impl Method for Lsbmr {
    fn id(&self) -> &'static str {
        "lsbmr"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — low-footprint (LSBMR)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = crate::image_io::decode_rgba(cover)?;
        Ok(Capacity {
            usable_bytes: lsb_common::usable_capacity_bytes(img.width, img.height),
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
        let pair_bits = (order.len() / 2) * 2; // usable bits (pairs only)
        if need_bits > pair_bits {
            return Err(StegnoError::CoverTooSmall);
        }

        let mut j = 0usize;
        while j < need_bits {
            let pair = j / 2;
            let off_a = slot_offset(&order, 2 * pair);
            let off_b = slot_offset(&order, 2 * pair + 1);
            let m1 = payload_bit(payload, 2 * pair);
            // The pair always carries two bits; if the payload ends on an odd
            // bit, the second message bit is 0 (harmless padding — the length in
            // the frame header bounds what the reader consumes).
            let m2 = if 2 * pair + 1 < need_bits {
                payload_bit(payload, 2 * pair + 1)
            } else {
                0
            };
            let (a2, b2) = embed_pair(img.pixels[off_a], img.pixels[off_b], m1, m2);
            img.pixels[off_a] = a2;
            img.pixels[off_b] = b2;
            j += 2;
        }
        crate::image_io::encode_png(&img)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = crate::image_io::decode_rgba(stego)?;
        let order = lsb_common::slot_order(img.width, img.height, opts.seed.as_ref());
        let pair_bits = (order.len() / 2) * 2;

        let read_bit = |j: usize| -> u8 {
            let pair = j / 2;
            let a = img.pixels[slot_offset(&order, 2 * pair)];
            if j % 2 == 0 {
                a & 1
            } else {
                let b = img.pixels[slot_offset(&order, 2 * pair + 1)];
                f(a, b)
            }
        };
        let read_byte = |k: usize| -> u8 {
            let mut out = 0u8;
            for shift in (0..8).rev() {
                let j = k * 8 + (7 - shift);
                out |= read_bit(j) << shift;
            }
            out
        };

        let hdr = payload::header_len();
        if pair_bits < hdr * 8 {
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
        if need * 8 > pair_bits {
            return Err(StegnoError::CorruptPayload);
        }
        let mut buf = Vec::with_capacity(need);
        for i in 0..need {
            buf.push(read_byte(i));
        }
        Ok(Some(buf))
    }
}

/// Byte offset in the RGBA buffer of the `idx`-th slot in `order`.
#[inline]
fn slot_offset(order: &[u32], idx: usize) -> usize {
    let c = order[idx] as usize;
    (c / lsb_common::CHANNELS_PER_PIXEL) * 4 + (c % lsb_common::CHANNELS_PER_PIXEL)
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
    fn embed_pair_is_correct_for_all_inputs() {
        // Exhaustively verify recovery and the ±1 bound over every (a,b,m1,m2).
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                for m1 in 0u8..2 {
                    for m2 in 0u8..2 {
                        let (a2, b2) = embed_pair(a, b, m1, m2);
                        assert_eq!(a2 & 1, m1, "m1 mismatch a={a} b={b}");
                        assert_eq!(f(a2, b2), m2, "m2 mismatch a={a} b={b}");
                        assert!((a as i16 - a2 as i16).abs() <= 1);
                        assert!((b as i16 - b2 as i16).abs() <= 1);
                    }
                }
            }
        }
    }

    #[test]
    fn roundtrip() {
        let c = cover(64, 64, 100);
        let body = payload::frame(b"lsb matching revisited carries this");
        let (eo, xo) = opts("key");
        let stego = Lsbmr.embed(&c, &body, &eo).unwrap();
        assert_eq!(Lsbmr.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn changes_are_at_most_one_per_channel() {
        let c = cover(64, 64, 100);
        let body = payload::frame(b"bounded perturbation check");
        let (eo, _) = opts("key");
        let stego = Lsbmr.embed(&c, &body, &eo).unwrap();
        let before = decode_rgba(&c).unwrap();
        let after = decode_rgba(&stego).unwrap();
        for (x, y) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!((*x as i16 - *y as i16).abs() <= 1);
        }
    }

    #[test]
    fn fewer_changes_than_plain_matching() {
        // LSBMR should modify strictly fewer channel values than replacement LSB
        // for the same payload, on average.
        let c = cover(96, 96, 120);
        let body = payload::frame(&vec![0xB7u8; 300]);
        let (eo, _) = opts("bench");
        let before = decode_rgba(&c).unwrap();

        let mr = Lsbmr.embed(&c, &body, &eo).unwrap();
        let mr_changed = decode_rgba(&mr)
            .unwrap()
            .pixels
            .iter()
            .zip(before.pixels.iter())
            .filter(|(x, y)| x != y)
            .count();

        let plain = crate::methods::lsb_seeded::LsbSeeded.embed(&c, &body, &eo).unwrap();
        let plain_changed = decode_rgba(&plain)
            .unwrap()
            .pixels
            .iter()
            .zip(before.pixels.iter())
            .filter(|(x, y)| x != y)
            .count();

        assert!(
            mr_changed < plain_changed,
            "LSBMR changed {mr_changed}, replacement changed {plain_changed}"
        );
    }

    #[test]
    fn boundary_covers_roundtrip() {
        for fill in [0u8, 255u8] {
            let c = cover(48, 48, fill);
            let body = payload::frame(b"edges");
            let (eo, xo) = opts("k");
            let stego = Lsbmr.embed(&c, &body, &eo).unwrap();
            assert_eq!(Lsbmr.extract(&stego, &xo).unwrap().unwrap(), body);
        }
    }

    #[test]
    fn wrong_seed_finds_no_frame() {
        let c = cover(64, 64, 80);
        let body = payload::frame(b"hidden");
        let (eo, _) = opts("right");
        let stego = Lsbmr.embed(&c, &body, &eo).unwrap();
        let (_, xo) = opts("wrong");
        assert_eq!(Lsbmr.extract(&stego, &xo).unwrap(), None);
    }
}
