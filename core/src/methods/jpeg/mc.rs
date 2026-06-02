//! `jpeg_mc` — matrix-coded JPEG DCT hiding.
//!
//! Combines the JSteg-style usable-coefficient model (overwrite the LSB of AC
//! coefficients whose value isn't `0`/`1`, which keeps the usable set invariant)
//! with Hamming `(1, 2ᵏ−1, k)` [matrix coding](super::hamming): every group of
//! `n = 2ᵏ−1` coefficients carries `k` payload bits while changing **at most one**
//! coefficient. For `k = 3` that's 3 bits per 7 coefficients with ≤1 change, versus
//! ~3 changes for plain bit-by-bit embedding — far fewer modifications for the same
//! payload, so the statistical footprint shrinks.
//!
//! Coefficients are visited along a passphrase-keyed permutation (so the payload
//! is scattered), grouped into consecutive runs of `n`. Because an LSB flip on a
//! usable coefficient keeps it usable, the decoder re-derives the identical groups
//! straight from the stego image with no side information — recovery is bit-exact
//! and carries the AES-GCM payload. The trade-off is capacity: only `k/(2ᵏ−1)` of
//! the usable coefficients' worth of bits (3/7 at `k = 3`).

use super::codec::{decode_scan, encode_scan};
use super::container::{parse_jpeg, write_jpeg};
use super::hamming::{decode_group, flip_index, K, N};
use super::pipeline::{
    ac_slot_count, cover_to_blocks, lsb_usable, read_lsb, set_lsb, slot_to_coord, Blocks,
};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct JpegMc;

/// Keyed permutation of the AC slot space when seeded, else sequential.
fn slot_order(total: usize, seed: Option<&[u8; 32]>) -> Vec<usize> {
    match seed {
        Some(s) => seed::permutation(total, s)
            .into_iter()
            .map(|x| x as usize)
            .collect(),
        None => (0..total).collect(),
    }
}

/// The usable AC coefficient slots in keyed-walk order — the carrier sequence
/// both embed and extract group into runs of `N`.
fn usable_walk(blocks: &Blocks, seed: Option<&[u8; 32]>) -> Vec<usize> {
    let total = ac_slot_count(blocks.len());
    slot_order(total, seed)
        .into_iter()
        .filter(|&slot| {
            let (b, comp, k) = slot_to_coord(slot);
            lsb_usable(blocks.at(b, comp, k))
        })
        .collect()
}

impl Method for JpegMc {
    fn id(&self) -> &'static str {
        "jpeg_mc"
    }
    fn display_name(&self) -> &'static str {
        "Photo (JPEG) — fewest changes"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let (_, _, blocks) = cover_to_blocks(cover)?;
        let usable = usable_walk(&blocks, None).len();
        let groups = usable / N;
        let bits = groups as u64 * K as u64;
        Ok(Capacity {
            usable_bytes: (bits / 8).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload_bytes: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (w, h, mut blocks) = cover_to_blocks(cover)?;
        let walk = usable_walk(&blocks, opts.seed.as_ref());
        let payload_bits = payload_bytes.len() * 8;
        let read = |i: usize| -> u8 { (payload_bytes[i / 8] >> (7 - (i % 8))) & 1 };

        let num_groups = (payload_bits + K as usize - 1) / K as usize; // ceil
        if num_groups * N > walk.len() {
            return Err(StegnoError::CoverTooSmall);
        }

        for g in 0..num_groups {
            // The k message bits for this group (MSB-first), zero-padded past the
            // payload end — the frame's length field makes padding harmless.
            let mut message = 0u32;
            for j in 0..K as usize {
                let bit_idx = g * K as usize + j;
                let bit = if bit_idx < payload_bits { read(bit_idx) } else { 0 };
                message = (message << 1) | bit as u32;
            }
            let group = &walk[g * N..g * N + N];
            let lsbs: Vec<u8> = group
                .iter()
                .map(|&slot| {
                    let (b, comp, k) = slot_to_coord(slot);
                    read_lsb(blocks.at(b, comp, k))
                })
                .collect();
            if let Some(fi) = flip_index(&lsbs, message) {
                let (b, comp, k) = slot_to_coord(group[fi]);
                let c = blocks.at(b, comp, k);
                *blocks.at_mut(b, comp, k) = set_lsb(c, read_lsb(c) ^ 1);
            }
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
        let walk = usable_walk(&blocks, opts.seed.as_ref());
        let num_groups = walk.len() / N;

        let hdr = payload::header_len();
        let mut bytes: Vec<u8> = Vec::new();
        let mut acc = 0u32;
        let mut acc_bits = 0u32;
        let mut target: Option<usize> = None;

        for g in 0..num_groups {
            let group = &walk[g * N..g * N + N];
            let lsbs: Vec<u8> = group
                .iter()
                .map(|&slot| {
                    let (b, comp, k) = slot_to_coord(slot);
                    read_lsb(blocks.at(b, comp, k))
                })
                .collect();
            let message = decode_group(&lsbs);
            // Emit the k bits MSB-first, same order embed packed them.
            for j in (0..K).rev() {
                acc = (acc << 1) | ((message >> j) & 1);
                acc_bits += 1;
                if acc_bits == 8 {
                    bytes.push(acc as u8);
                    acc = 0;
                    acc_bits = 0;
                    if target.is_none() && bytes.len() == hdr {
                        if bytes[..4] != *b"STG0" {
                            return Ok(None);
                        }
                        let len =
                            u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
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
    fn mc_roundtrip_seeded() {
        let cover = textured(96, 96);
        let body = payload::frame(b"hidden by matrix coding (<=1 change / 7 coeffs)");
        let (eo, xo) = opts("passphrase");
        let stego = JpegMc.embed(&cover, &body, &eo).unwrap();
        assert_eq!(&stego[..2], &[0xFF, 0xD8]);
        assert_eq!(JpegMc.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn mc_roundtrip_sequential() {
        let cover = textured(96, 96);
        let body = payload::frame(b"unseeded matrix coding");
        let stego = JpegMc.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            JpegMc.extract(&stego, &ExtractOpts::default()).unwrap().unwrap(),
            body
        );
    }

    #[test]
    fn output_decodes_as_a_real_jpeg() {
        let cover = textured(64, 64);
        let body = payload::frame(b"valid jfif");
        let (eo, _) = opts("k");
        let stego = JpegMc.embed(&cover, &body, &eo).unwrap();
        let decoded = decode_rgba(&stego).expect("stego must be a decodable JPEG");
        assert_eq!((decoded.width, decoded.height), (64, 64));
    }

    #[test]
    fn fewer_changes_than_plain_lsb() {
        // Matrix coding must change strictly fewer coefficients than overwriting
        // one coefficient per bit would for the same payload.
        let cover = textured(96, 96);
        let body = payload::frame(b"count the coefficient changes please");
        let (eo, _) = opts("k");
        let stego = JpegMc.embed(&cover, &body, &eo).unwrap();

        let (_, _, before) = cover_to_blocks(&cover).unwrap();
        let (geo, entropy) = parse_jpeg(&stego).unwrap();
        let (sy, scb, scr) = decode_scan(entropy, geo.num_blocks()).unwrap();
        let after = Blocks { y: sy, cb: scb, cr: scr };

        let mut changed = 0usize;
        for slot in 0..ac_slot_count(before.len()) {
            let (b, comp, k) = slot_to_coord(slot);
            if before.at(b, comp, k) != after.at(b, comp, k) {
                changed += 1;
            }
        }
        let payload_bits = body.len() * 8;
        // Plain LSB embedding changes ~half the carried bits; matrix coding caps
        // changes at one per group of N. Assert the hard upper bound.
        let num_groups = (payload_bits + K as usize - 1) / K as usize;
        assert!(
            changed <= num_groups,
            "changed {changed} should be ≤ {num_groups} groups"
        );
        assert!(changed < payload_bits, "should change fewer coeffs than bits");
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
        assert_eq!(JpegMc.extract(&jpeg, &xo).unwrap(), None);
    }

    #[test]
    fn non_jpeg_returns_none() {
        let (_, xo) = opts("k");
        assert_eq!(JpegMc.extract(&[0u8, 1, 2, 3], &xo).unwrap(), None);
    }

    #[test]
    fn too_small_cover_errors() {
        let cover = textured(8, 8);
        let big = payload::frame(&vec![0xABu8; 4096]);
        let (eo, _) = opts("k");
        assert!(matches!(
            JpegMc.embed(&cover, &big, &eo),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn capacity_matches_what_embeds() {
        let cover = textured(96, 96);
        let (eo, xo) = opts("k");
        let cap = JpegMc.capacity(&cover).unwrap().usable_bytes as usize;
        assert!(cap > 0);
        let secret = vec![0x5Au8; cap];
        let body = payload::frame(&secret);
        let stego = JpegMc.embed(&cover, &body, &eo).unwrap();
        assert_eq!(JpegMc.extract(&stego, &xo).unwrap().unwrap(), body);
    }
}
