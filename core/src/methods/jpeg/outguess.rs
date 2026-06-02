//! `jpeg_outguess` — OutGuess-style hiding in quantized JPEG DCT coefficients
//! with a histogram-preserving correction pass.
//!
//! Embedding is JSteg-like — overwrite the LSB of usable AC coefficients (value
//! not `0`/`1`) — but two things distinguish OutGuess:
//!
//! * **Keyed walk.** Coefficients are visited in a passphrase-keyed permutation,
//!   so the payload is scattered and its position is secret.
//! * **Correction pass.** Overwriting LSBs perturbs the global coefficient
//!   histogram (the basis of the chi-square attack). After the message is placed
//!   in the first stretch of the keyed walk, OutGuess spends the *remaining*
//!   coefficients restoring that histogram: a leftover coefficient whose value is
//!   over-represented and whose LSB-partner is under-represented is flipped to its
//!   partner, monotonically driving the stego histogram back toward the cover's.
//!
//! The correction only ever touches coefficients **after** the message region of
//! the walk, so the message LSBs are untouched and the extractor — which reads the
//! keyed walk only until the framed payload is complete — recovers the AES-GCM
//! payload bit-exactly with no side information. The usable set stays invariant
//! under both overwrite and correction (neither can create or consume a `0`/`1`),
//! so encoder and decoder select identical coefficients.

use std::collections::HashMap;

use super::codec::{decode_scan, encode_scan};
use super::container::{parse_jpeg, write_jpeg};
use super::pipeline::{
    ac_slot_count, cover_to_blocks, lsb_usable, read_lsb, set_lsb, slot_to_coord, Blocks,
};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct JpegOutguess;

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

/// Histogram of usable-coefficient values across all AC slots.
fn histogram(blocks: &Blocks) -> HashMap<i32, i64> {
    let mut h: HashMap<i32, i64> = HashMap::new();
    let total = ac_slot_count(blocks.len());
    for slot in 0..total {
        let (b, comp, k) = slot_to_coord(slot);
        let c = blocks.at(b, comp, k);
        if lsb_usable(c) {
            *h.entry(c).or_insert(0) += 1;
        }
    }
    h
}

impl Method for JpegOutguess {
    fn id(&self) -> &'static str {
        "jpeg_outguess"
    }
    fn display_name(&self) -> &'static str {
        "Photo (JPEG) — extra stealthy"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let (_, _, blocks) = cover_to_blocks(cover)?;
        let total = ac_slot_count(blocks.len());
        let mut usable = 0u64;
        for slot in 0..total {
            let (b, comp, k) = slot_to_coord(slot);
            if lsb_usable(blocks.at(b, comp, k)) {
                usable += 1;
            }
        }
        Ok(Capacity {
            usable_bytes: (usable / 8).saturating_sub(payload::overhead() as u64),
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

        // Histogram we want to restore (the cover's usable-coefficient histogram).
        let orig = histogram(&blocks);

        // Embed into the first `payload_bits` usable coefficients of the walk;
        // remember the rest as the correction pool (in walk order).
        let mut written = 0usize;
        let mut pool: Vec<usize> = Vec::new();
        for &slot in &order {
            let (b, comp, k) = slot_to_coord(slot);
            let c = blocks.at(b, comp, k);
            if !lsb_usable(c) {
                continue;
            }
            if written < payload_bits {
                *blocks.at_mut(b, comp, k) = set_lsb(c, read(written));
                written += 1;
            } else {
                pool.push(slot);
            }
        }
        if written < payload_bits {
            return Err(StegnoError::CoverTooSmall);
        }

        // Correction pass: greedily flip pool coefficients toward the original
        // histogram. Each flip moves one count from an over- to an
        // under-represented partner, so total deviation never increases.
        let mut cur = histogram(&blocks);
        let count = |m: &HashMap<i32, i64>, v: i32| m.get(&v).copied().unwrap_or(0);
        for &slot in &pool {
            let (b, comp, k) = slot_to_coord(slot);
            let v = blocks.at(b, comp, k);
            let partner = set_lsb(v, read_lsb(v) ^ 1);
            if count(&cur, v) > count(&orig, v) && count(&cur, partner) < count(&orig, partner) {
                *blocks.at_mut(b, comp, k) = partner;
                *cur.entry(v).or_insert(0) -= 1;
                *cur.entry(partner).or_insert(0) += 1;
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
            if !lsb_usable(c) {
                continue;
            }
            acc = (acc << 1) | read_lsb(c) as u32;
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
    use crate::methods::jpeg::JpegJsteg;
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

    /// Total absolute deviation between two usable-coefficient histograms.
    fn hist_distance(a: &HashMap<i32, i64>, b: &HashMap<i32, i64>) -> i64 {
        let mut keys: Vec<i32> = a.keys().chain(b.keys()).copied().collect();
        keys.sort_unstable();
        keys.dedup();
        keys.iter()
            .map(|k| (a.get(k).copied().unwrap_or(0) - b.get(k).copied().unwrap_or(0)).abs())
            .sum()
    }

    fn usable_hist(jpeg_or_png: &[u8], from_jpeg: bool) -> HashMap<i32, i64> {
        if from_jpeg {
            let (geo, entropy) = parse_jpeg(jpeg_or_png).unwrap();
            let (y, cb, cr) = decode_scan(entropy, geo.num_blocks()).unwrap();
            histogram(&Blocks { y, cb, cr })
        } else {
            let (_, _, blocks) = cover_to_blocks(jpeg_or_png).unwrap();
            histogram(&blocks)
        }
    }

    #[test]
    fn outguess_roundtrip_seeded() {
        let cover = textured(96, 96);
        let body = payload::frame(b"hidden by OutGuess keyed embedding");
        let (eo, xo) = opts("passphrase");
        let stego = JpegOutguess.embed(&cover, &body, &eo).unwrap();
        assert_eq!(&stego[..2], &[0xFF, 0xD8]);
        assert_eq!(JpegOutguess.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn output_decodes_as_a_real_jpeg() {
        let cover = textured(64, 64);
        let body = payload::frame(b"valid jfif");
        let (eo, _) = opts("k");
        let stego = JpegOutguess.embed(&cover, &body, &eo).unwrap();
        let decoded = decode_rgba(&stego).expect("stego must be a decodable JPEG");
        assert_eq!((decoded.width, decoded.height), (64, 64));
    }

    #[test]
    fn correction_preserves_histogram_better_than_jsteg() {
        // The whole point of OutGuess: with a small message and a large cover,
        // the correction pass restores the coefficient histogram far better than
        // plain JSteg overwriting.
        let cover = textured(128, 128);
        let body = payload::frame(b"small secret");
        let cover_hist = usable_hist(&cover, false);

        let (eo, _) = opts("k");
        let og = JpegOutguess.embed(&cover, &body, &eo).unwrap();
        let js = JpegJsteg.embed(&cover, &body, &EmbedOpts::default()).unwrap();

        let dev_og = hist_distance(&cover_hist, &usable_hist(&og, true));
        let dev_js = hist_distance(&cover_hist, &usable_hist(&js, true));
        assert!(
            dev_og <= dev_js,
            "OutGuess deviation {dev_og} should be ≤ JSteg deviation {dev_js}"
        );
        // For a small message the pool is ample → histogram fully restored.
        assert_eq!(dev_og, 0, "OutGuess should fully restore the histogram here");
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
        assert_eq!(JpegOutguess.extract(&jpeg, &xo).unwrap(), None);
    }

    #[test]
    fn non_jpeg_returns_none() {
        let (_, xo) = opts("k");
        assert_eq!(JpegOutguess.extract(&[0u8, 1, 2, 3], &xo).unwrap(), None);
    }

    #[test]
    fn too_small_cover_errors() {
        let cover = textured(8, 8);
        let big = payload::frame(&vec![0xABu8; 4096]);
        let (eo, _) = opts("k");
        assert!(matches!(
            JpegOutguess.embed(&cover, &big, &eo),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn capacity_matches_what_embeds() {
        let cover = textured(80, 80);
        let (eo, xo) = opts("k");
        let cap = JpegOutguess.capacity(&cover).unwrap().usable_bytes as usize;
        assert!(cap > 0);
        let secret = vec![0x5Au8; cap];
        let body = payload::frame(&secret);
        let stego = JpegOutguess.embed(&cover, &body, &eo).unwrap();
        assert_eq!(JpegOutguess.extract(&stego, &xo).unwrap().unwrap(), body);
    }
}
