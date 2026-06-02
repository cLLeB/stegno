//! `jpeg_f5` — F5-style hiding in quantized JPEG DCT coefficients.
//!
//! Like `jpeg_jsteg` it works on quantized AC coefficients of a baseline JPEG we
//! build ourselves, but it fixes JSteg's tell-tale histogram artefact. JSteg
//! *overwrites* the LSB, which pairs values `2k ↔ 2k+1` and flattens their
//! histogram bins — the classic chi-square signature. F5 instead **decrements the
//! magnitude toward zero** to flip the parity, so coefficient magnitudes only ever
//! shrink and the histogram keeps its natural monotone shape.
//!
//! Two consequences, both handled for bit-exact blind recovery:
//!
//! * **Shrinkage.** Decrementing a `±1` coefficient yields `0`, which is no longer
//!   a usable carrier. F5's rule: when that happens the message bit is *not*
//!   consumed and is re-embedded in the next coefficient. The decoder reads a bit
//!   from every *non-zero* coefficient, so a shrunk-to-zero coefficient is simply
//!   skipped on both sides — encoder and decoder stay in lock-step with no side
//!   information.
//! * **Permutative straddling.** When a passphrase-derived `seed` is present the
//!   coefficient visiting order is a keyed permutation of the AC slot space, so the
//!   payload is scattered across the whole image instead of front-loaded.
//!
//! The represented bit of a non-zero coefficient `c` is `c & 1` (equivalently the
//! LSB of `|c|`). Decrementing toward zero (`c - signum(c)`) flips exactly that
//! bit. DC coefficients are never touched.

use super::codec::{decode_scan, encode_scan};
use super::container::{parse_jpeg, write_jpeg};
use super::pipeline::{ac_slot_count, cover_to_blocks, slot_to_coord, Blocks};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct JpegF5;

/// The traversal order over AC slots: a keyed permutation when seeded, else the
/// canonical sequential order. Shared by capacity, embed, and extract.
fn slot_order(total: usize, seed: Option<&[u8; 32]>) -> Vec<usize> {
    match seed {
        Some(s) => seed::permutation(total, s)
            .into_iter()
            .map(|x| x as usize)
            .collect(),
        None => (0..total).collect(),
    }
}

impl Method for JpegF5 {
    fn id(&self) -> &'static str {
        "jpeg_f5"
    }
    fn display_name(&self) -> &'static str {
        "Photo (JPEG) — harder to detect"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let (_, _, blocks) = cover_to_blocks(cover)?;
        let total = ac_slot_count(blocks.len());
        // Conservative guaranteed capacity: every non-zero AC coefficient carries
        // a bit, minus the worst case where every ±1 coefficient shrinks away.
        let mut nonzero = 0u64;
        let mut ones = 0u64;
        for slot in 0..total {
            let (b, comp, k) = slot_to_coord(slot);
            let c = blocks.at(b, comp, k);
            if c != 0 {
                nonzero += 1;
                if c.abs() == 1 {
                    ones += 1;
                }
            }
        }
        let guaranteed_bits = nonzero.saturating_sub(ones);
        Ok(Capacity {
            usable_bytes: (guaranteed_bits / 8).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload_bytes: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (w, h, mut blocks) = cover_to_blocks(cover)?;
        let total = ac_slot_count(blocks.len());
        let order = slot_order(total, opts.seed.as_ref());
        let payload_bits = payload_bytes.len() * 8;
        let read = |i: usize| -> u8 { (payload_bytes[i / 8] >> (7 - (i % 8))) & 1 };

        let mut written = 0usize;
        for &slot in &order {
            if written >= payload_bits {
                break;
            }
            let (b, comp, k) = slot_to_coord(slot);
            let c = blocks.at(b, comp, k);
            if c == 0 {
                continue; // zeros are not carriers
            }
            let desired = read(written);
            if (c & 1) as u8 == desired {
                written += 1; // already carries the bit, unchanged
                continue;
            }
            let nc = c - c.signum(); // decrement magnitude toward zero
            *blocks.at_mut(b, comp, k) = nc;
            if nc != 0 {
                written += 1;
            }
            // else: shrinkage — bit not consumed, re-embedded in the next slot.
        }
        if written < payload_bits {
            return Err(StegnoError::CoverTooSmall);
        }
        let entropy = encode_scan(&blocks.y, &blocks.cb, &blocks.cr);
        Ok(write_jpeg(w, h, &entropy))
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let (geo, entropy) = match parse_jpeg(stego) {
            Some(v) => v,
            None => return Ok(None),
        };
        let (y, cb, cr) = match decode_scan(entropy, geo.num_blocks()) {
            Some(v) => v,
            None => return Ok(None),
        };
        let blocks = Blocks { y, cb, cr };
        let total = ac_slot_count(blocks.len());
        let order = slot_order(total, opts.seed.as_ref());

        let hdr = payload::header_len();
        let mut bytes: Vec<u8> = Vec::new();
        let mut acc = 0u32;
        let mut acc_bits = 0u32;
        let mut target: Option<usize> = None;

        for &slot in &order {
            let (b, comp, k) = slot_to_coord(slot);
            let c = blocks.at(b, comp, k);
            if c == 0 {
                continue;
            }
            acc = (acc << 1) | (c & 1) as u32;
            acc_bits += 1;
            if acc_bits == 8 {
                bytes.push(acc as u8);
                acc = 0;
                acc_bits = 0;
                if target.is_none() && bytes.len() == hdr {
                    if bytes[..4] != *b"STG0" {
                        return Ok(None);
                    }
                    let len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
                    target = Some(hdr + len);
                }
                if let Some(t) = target {
                    if bytes.len() >= t {
                        bytes.truncate(t);
                        return Ok(Some(bytes));
                    }
                }
            }
        }
        match target {
            Some(_) => Err(StegnoError::CorruptPayload),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{decode_rgba, encode_png, RgbaImage};
    use crate::seed::{derive_seed, Slot};

    fn textured(w: u32, h: u32) -> Vec<u8> {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
            let x = (i as u32) % w;
            let y = (i as u32) / w;
            px[0] = ((x * 13) ^ (y * 7)) as u8;
            px[1] = ((x * 5).wrapping_add(y * 11)) as u8;
            px[2] = ((x ^ y).wrapping_mul(3)) as u8;
            px[3] = 255;
        }
        encode_png(&RgbaImage {
            width: w,
            height: h,
            pixels,
        })
        .unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn f5_roundtrip_seeded() {
        let cover = textured(96, 96);
        let body = payload::frame(b"hidden by F5 decrement embedding");
        let (eo, xo) = opts("passphrase");
        let stego = JpegF5.embed(&cover, &body, &eo).unwrap();
        assert_eq!(&stego[..2], &[0xFF, 0xD8]); // real JPEG
        assert_eq!(JpegF5.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn f5_roundtrip_sequential() {
        let cover = textured(96, 96);
        let body = payload::frame(b"unseeded sequential F5");
        let stego = JpegF5.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            JpegF5.extract(&stego, &ExtractOpts::default()).unwrap().unwrap(),
            body
        );
    }

    #[test]
    fn output_decodes_as_a_real_jpeg() {
        let cover = textured(64, 64);
        let body = payload::frame(b"valid jfif");
        let (eo, _) = opts("k");
        let stego = JpegF5.embed(&cover, &body, &eo).unwrap();
        let decoded = decode_rgba(&stego).expect("stego must be a decodable JPEG");
        assert_eq!((decoded.width, decoded.height), (64, 64));
    }

    #[test]
    fn never_increases_coefficient_magnitude() {
        // The defining F5 property: magnitudes only shrink toward zero.
        let cover = textured(64, 64);
        let body = payload::frame(b"monotone");
        let (eo, _) = opts("k");
        let stego = JpegF5.embed(&cover, &body, &eo).unwrap();

        let (geo, entropy) = parse_jpeg(&stego).unwrap();
        let (sy, scb, scr) = decode_scan(entropy, geo.num_blocks()).unwrap();
        let (_, _, before) = cover_to_blocks(&cover).unwrap();
        let after = Blocks { y: sy, cb: scb, cr: scr };
        for slot in 0..ac_slot_count(before.len()) {
            let (b, comp, k) = slot_to_coord(slot);
            let bc = before.at(b, comp, k);
            let ac = after.at(b, comp, k);
            assert!(ac.abs() <= bc.abs(), "magnitude grew: {bc} -> {ac}");
            assert!((bc - ac).abs() <= 1, "changed by more than 1: {bc} -> {ac}");
        }
    }

    #[test]
    fn clean_image_returns_none() {
        let cover = textured(48, 48);
        let entropy = {
            let (_, _, b) = cover_to_blocks(&cover).unwrap();
            encode_scan(&b.y, &b.cb, &b.cr)
        };
        let jpeg = write_jpeg(48, 48, &entropy);
        let (_, xo) = opts("k");
        assert_eq!(JpegF5.extract(&jpeg, &xo).unwrap(), None);
    }

    #[test]
    fn non_jpeg_returns_none() {
        let (_, xo) = opts("k");
        assert_eq!(JpegF5.extract(&[0u8, 1, 2, 3, 4], &xo).unwrap(), None);
    }

    #[test]
    fn too_small_cover_errors() {
        let cover = textured(8, 8);
        let big = payload::frame(&vec![0xABu8; 4096]);
        let (eo, _) = opts("k");
        assert!(matches!(
            JpegF5.embed(&cover, &big, &eo),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn capacity_matches_what_embeds() {
        let cover = textured(80, 80);
        let (eo, xo) = opts("k");
        let cap = JpegF5.capacity(&cover).unwrap().usable_bytes as usize;
        assert!(cap > 0);
        let secret = vec![0x5Au8; cap];
        let body = payload::frame(&secret);
        let stego = JpegF5.embed(&cover, &body, &eo).unwrap();
        assert_eq!(JpegF5.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn wrong_seed_does_not_recover() {
        let cover = textured(96, 96);
        let body = payload::frame(b"keyed scatter");
        let (eo, _) = opts("right");
        let (_, wrong) = opts("wrong");
        let stego = JpegF5.embed(&cover, &body, &eo).unwrap();
        // A different permutation must not reproduce the exact framed payload.
        let got = JpegF5.extract(&stego, &wrong).unwrap();
        assert_ne!(got, Some(body));
    }
}
