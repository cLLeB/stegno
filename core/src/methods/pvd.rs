//! `pvd` — Pixel-Value Differencing (Wu–Tsai style, variable capacity).
//!
//! Consecutive carrier samples (R/G/B, alpha skipped) are taken in pairs. The
//! absolute difference of a pair selects a range from a table; a wider range
//! (smoother→edgy transition) carries more bits. So flat areas carry ~3 bits
//! per pair while busy areas carry up to 7 — capacity adapts to content and the
//! perturbation tracks local activity, which is harder to detect than flat LSB.
//!
//! ## Reversibility (the hard part of PVD), guaranteed here
//!
//! For a pair with difference `d`, range `[l, u]` and `t = log2(width)` bits, we
//! embed value `v ∈ [0, 2^t)` by setting the new |difference| to `l + v`, which
//! stays inside `[l, u]` — the **same range**. The extractor therefore derives
//! the identical `(l, u, t)` from the stego difference and reads `v = |d*| − l`.
//!
//! The classic "fall-off-boundary" problem (the modified pixels leaving
//! `[0,255]`) is handled without side information: we realise the target
//! difference `nd` by the balanced split when it fits, and otherwise **shift the
//! whole pair** to stay in range while keeping `b' − a' = nd` exactly. Since the
//! difference is preserved in every case, extraction never needs to know a pair
//! was shifted — no pairs are ever skipped.

use super::lsb_common::CHANNELS_PER_PIXEL;
use crate::image_io::{decode_rgba, encode_png, RgbaImage};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct Pvd;

/// Range table: each entry `(lower, upper)` over |difference|, covering 0..=255.
/// Widths are powers of two (8,8,16,32,64,128) so every range uses all its
/// codes (`l + 2^t − 1 == u`).
const RANGES: [(i32, i32); 6] = [
    (0, 7),
    (8, 15),
    (16, 31),
    (32, 63),
    (64, 127),
    (128, 255),
];

/// `(lower, upper, bits)` for an absolute difference `m`.
fn range_of(m: i32) -> (i32, i32, u32) {
    for &(l, u) in &RANGES {
        if m >= l && m <= u {
            let width = (u - l + 1) as u32;
            return (l, u, width.trailing_zeros()); // log2 of a power of two
        }
    }
    // m is always within 0..=255 for u8 differences; unreachable in practice.
    let (l, u) = RANGES[RANGES.len() - 1];
    (l, u, ((u - l + 1) as u32).trailing_zeros())
}

/// Carrier sample byte-offsets (R,G,B of every pixel; alpha skipped).
fn carrier_offsets(width: u32, height: u32) -> Vec<usize> {
    let n = (width as usize) * (height as usize);
    let mut v = Vec::with_capacity(n * CHANNELS_PER_PIXEL);
    for p in 0..n {
        v.push(p * 4);
        v.push(p * 4 + 1);
        v.push(p * 4 + 2);
    }
    v
}

/// Non-overlapping pairs of carrier offsets, in (optionally key-seeded) order.
fn pair_order(offsets: &[usize], seed: Option<&[u8; 32]>) -> Vec<usize> {
    let num_pairs = offsets.len() / 2;
    match seed {
        Some(s) => seed::permutation(num_pairs, s)
            .into_iter()
            .map(|x| x as usize)
            .collect(),
        None => (0..num_pairs).collect(),
    }
}

/// Realise a pair `(a, b)` whose new difference is exactly `nd`, staying within
/// `[0, 255]`. Balanced split when it fits, otherwise shift the pair.
fn place(a: i32, b: i32, nd: i32) -> (u8, u8) {
    let d = b - a;
    let delta = nd - d;
    let q = delta / 2; // truncated toward zero
    let mut a2 = a - q;
    let mut b2 = b + (delta - q); // b2 - a2 == nd
    if !(0..=255).contains(&a2) || !(0..=255).contains(&b2) {
        // Shift while preserving the difference nd.
        let lo = 0.max(-nd);
        let hi = 255.min(255 - nd);
        a2 = (a - q).clamp(lo, hi);
        b2 = a2 + nd;
    }
    debug_assert!((0..=255).contains(&a2) && (0..=255).contains(&b2));
    debug_assert_eq!(b2 - a2, nd);
    (a2 as u8, b2 as u8)
}

/// Total embeddable bits across all pairs (used for capacity).
fn total_bits(img: &RgbaImage) -> u64 {
    let offsets = carrier_offsets(img.width, img.height);
    let mut bits = 0u64;
    for pair in offsets.chunks_exact(2) {
        let a = img.pixels[pair[0]] as i32;
        let b = img.pixels[pair[1]] as i32;
        let (_, _, t) = range_of((b - a).abs());
        bits += t as u64;
    }
    bits
}

impl Method for Pvd {
    fn id(&self) -> &'static str {
        "pvd"
    }
    fn display_name(&self) -> &'static str {
        "Pixel-Value Differencing (PNG)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = decode_rgba(cover)?;
        let bytes = total_bits(&img) / 8;
        Ok(Capacity {
            usable_bytes: bytes.saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload_bytes: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let mut img = decode_rgba(cover)?;
        let offsets = carrier_offsets(img.width, img.height);
        let order = pair_order(&offsets, opts.seed.as_ref());

        let payload_bits = payload_bytes.len() * 8;
        if payload_bits as u64 > total_bits(&img) {
            return Err(StegnoError::CoverTooSmall);
        }

        // MSB-first bit reader over the payload; reads past the end yield 0 (pad).
        let read_bit = |i: usize| -> u32 {
            if i >= payload_bits {
                0
            } else {
                ((payload_bytes[i / 8] >> (7 - (i % 8))) & 1) as u32
            }
        };

        let mut written = 0usize;
        for &pi in &order {
            if written >= payload_bits {
                break;
            }
            let oa = offsets[pi * 2];
            let ob = offsets[pi * 2 + 1];
            let a = img.pixels[oa] as i32;
            let b = img.pixels[ob] as i32;
            let d = b - a;
            let (l, _u, t) = range_of(d.abs());

            let mut v = 0i32;
            for _ in 0..t {
                v = (v << 1) | read_bit(written) as i32;
                written += 1;
            }
            let m2 = l + v;
            let nd = if d >= 0 { m2 } else { -m2 };
            let (a2, b2) = place(a, b, nd);
            img.pixels[oa] = a2;
            img.pixels[ob] = b2;
        }

        encode_png(&img)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let offsets = carrier_offsets(img.width, img.height);
        let order = pair_order(&offsets, opts.seed.as_ref());

        let hdr = payload::header_len();
        let mut bytes: Vec<u8> = Vec::new();
        let mut acc = 0u32;
        let mut acc_bits = 0u32;
        let mut target: Option<usize> = None; // total frame bytes once known

        for &pi in &order {
            let oa = offsets[pi * 2];
            let ob = offsets[pi * 2 + 1];
            let a = img.pixels[oa] as i32;
            let b = img.pixels[ob] as i32;
            let d = b - a;
            let (l, _u, t) = range_of(d.abs());
            let v = (d.abs() - l) as u32; // value carried by this pair

            for shift in (0..t).rev() {
                acc = (acc << 1) | ((v >> shift) & 1);
                acc_bits += 1;
                if acc_bits == 8 {
                    bytes.push(acc as u8);
                    acc = 0;
                    acc_bits = 0;

                    // Validate magic as soon as the header is complete.
                    if target.is_none() && bytes.len() == hdr {
                        if bytes[..4] != *b"STG0" {
                            return Ok(None);
                        }
                        let len =
                            u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
                        target = Some(hdr + len);
                    }
                    if let Some(tgt) = target {
                        if bytes.len() >= tgt {
                            bytes.truncate(tgt);
                            return Ok(Some(bytes));
                        }
                    }
                }
            }
        }

        // Ran out of pairs.
        match target {
            Some(_) => Err(StegnoError::CorruptPayload), // header said more than we could read
            None => Ok(None),                            // never even got a full, valid header
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{derive_seed, Slot};

    fn textured(w: u32, h: u32) -> RgbaImage {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let p = ((y * w + x) * 4) as usize;
                let v = (((x * 13 + y * 7) ^ x.wrapping_mul(3)) % 256) as u8;
                pixels[p] = v;
                pixels[p + 1] = v.wrapping_add(90);
                pixels[p + 2] = v.wrapping_mul(5);
                pixels[p + 3] = 255;
            }
        }
        RgbaImage {
            width: w,
            height: h,
            pixels,
        }
    }

    fn cover_textured(w: u32, h: u32) -> Vec<u8> {
        encode_png(&textured(w, h)).unwrap()
    }

    fn cover_solid(w: u32, h: u32, fill: u8) -> Vec<u8> {
        encode_png(&RgbaImage {
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
    fn pvd_roundtrip_textured() {
        let c = cover_textured(80, 80);
        let body = payload::frame(b"differencing carries variable bits");
        let (eo, xo) = opts("key");
        let stego = Pvd.embed(&c, &body, &eo).unwrap();
        assert_eq!(Pvd.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn pvd_roundtrip_flat() {
        // Flat → every pair is range 0 (3 bits). Still must roundtrip.
        let c = cover_solid(64, 64, 130);
        let body = payload::frame(b"flat cover, three bits per pair");
        let (eo, xo) = opts("k");
        let stego = Pvd.embed(&c, &body, &eo).unwrap();
        assert_eq!(Pvd.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn pvd_boundary_covers_roundtrip() {
        for fill in [0u8, 255u8, 1u8, 254u8] {
            let c = cover_solid(48, 48, fill);
            let body = payload::frame(b"boundary safe");
            let (eo, xo) = opts("k");
            let stego = Pvd.embed(&c, &body, &eo).unwrap();
            assert_eq!(
                Pvd.extract(&stego, &xo).unwrap().unwrap(),
                body,
                "fill={fill}"
            );
        }
    }

    #[test]
    fn pvd_no_data_returns_none() {
        let c = cover_textured(32, 32);
        let (_, xo) = opts("k");
        assert_eq!(Pvd.extract(&c, &xo).unwrap(), None);
    }

    #[test]
    fn pvd_capacity_positive() {
        let c = cover_textured(64, 64);
        assert!(Pvd.capacity(&c).unwrap().usable_bytes > 0);
    }

    #[test]
    fn place_preserves_difference_everywhere() {
        // Exhaustive-ish: for representative pairs and targets, difference holds
        // and values stay in range.
        for a in [0i32, 1, 100, 200, 254, 255] {
            for b in [0i32, 1, 100, 200, 254, 255] {
                for nd in [-255i32, -128, -1, 0, 1, 128, 255] {
                    let (a2, b2) = place(a, b, nd);
                    assert_eq!(b2 as i32 - a2 as i32, nd, "a={a} b={b} nd={nd}");
                }
            }
        }
    }
}
