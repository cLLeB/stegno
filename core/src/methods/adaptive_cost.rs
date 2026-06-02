//! `adaptive_cost` — content-adaptive embedding (simplified UNIWARD-style).
//!
//! Assigns each pixel an embedding *cost* from directional second-order
//! residuals: smooth, predictable regions cost a lot (changes there are
//! conspicuous), textured regions cost little. The payload fills the
//! lowest-cost positions first, concentrating changes where they hide best —
//! the same principle as WOW / S-UNIWARD. Hamming `(1,2ᵏ−1,k)` matrix coding —
//! which lowers the *number* of changes per payload bit — is implemented for the
//! JPEG domain as `jpeg_mc`; this spatial method embeds one bit per cost-ordered
//! position.
//!
//! Like [`super::edge_adaptive`], the cost is computed from LSB-stripped values
//! so the ordering is invariant under LSB replacement and the extractor
//! reconstructs it exactly. The richer second-order, multi-directional residual
//! (vs. edge-adaptive's first-order gradient) tracks texture more like UNIWARD.

use super::lsb_common::{self, CHANNELS_PER_PIXEL};
use crate::image_io::{decode_rgba, RgbaImage};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::seed;
use crate::StegnoError;

pub struct AdaptiveCost;

/// LSB-stripped luminance proxy.
#[inline]
fn luma_hi(px: &[u8], p: usize) -> i32 {
    let o = p * 4;
    ((px[o] >> 1) as i32) + ((px[o + 1] >> 1) as i32) + ((px[o + 2] >> 1) as i32)
}

/// Texture energy from second-order residuals in H, V and both diagonals.
/// Higher = more textured = cheaper to embed. Invariant under LSB replacement.
fn residual_energy(img: &RgbaImage) -> Vec<u32> {
    let w = img.width as usize;
    let h = img.height as usize;
    let mut e = vec![0u32; w * h];
    let at = |x: usize, y: usize| luma_hi(&img.pixels, y * w + x);
    for y in 0..h {
        for x in 0..w {
            let c = at(x, y);
            let mut r = 0i32;
            if x >= 1 && x + 1 < w {
                r += (2 * c - at(x - 1, y) - at(x + 1, y)).abs();
            }
            if y >= 1 && y + 1 < h {
                r += (2 * c - at(x, y - 1) - at(x, y + 1)).abs();
            }
            if x >= 1 && y >= 1 && x + 1 < w && y + 1 < h {
                r += (2 * c - at(x - 1, y - 1) - at(x + 1, y + 1)).abs();
                r += (2 * c - at(x + 1, y - 1) - at(x - 1, y + 1)).abs();
            }
            e[y * w + x] = r as u32;
        }
    }
    e
}

/// Channel-slot order: highest residual energy (lowest cost) first, ties broken
/// by a passphrase-keyed rank.
fn cost_order(img: &RgbaImage, seed: Option<&[u8; 32]>) -> Vec<u32> {
    let n = lsb_common::total_slots(img.width, img.height);
    if n == 0 {
        return Vec::new();
    }
    let energy = residual_energy(img);
    let mut tiebreak = vec![0u32; n];
    match seed {
        Some(s) => {
            for (rank, &slot) in seed::permutation(n, s).iter().enumerate() {
                tiebreak[slot as usize] = rank as u32;
            }
        }
        None => {
            for (i, t) in tiebreak.iter_mut().enumerate() {
                *t = i as u32;
            }
        }
    }
    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_by(|&a, &b| {
        let pa = a as usize / CHANNELS_PER_PIXEL;
        let pb = b as usize / CHANNELS_PER_PIXEL;
        energy[pb]
            .cmp(&energy[pa])
            .then_with(|| tiebreak[a as usize].cmp(&tiebreak[b as usize]))
    });
    order
}

impl Method for AdaptiveCost {
    fn id(&self) -> &'static str {
        "adaptive_cost"
    }
    fn display_name(&self) -> &'static str {
        "Content-Adaptive Cost (PNG)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = decode_rgba(cover)?;
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
        let img = decode_rgba(cover)?;
        let order = cost_order(&img, opts.seed.as_ref());
        lsb_common::embed_with(img, payload, &order, lsb_common::replace_lsb)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let order = cost_order(&img, opts.seed.as_ref());
        lsb_common::read_frame_with(&img, &order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::encode_png;
    use crate::payload;
    use crate::seed::{derive_seed, Slot};

    fn textured(w: u32, h: u32) -> RgbaImage {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
            let v = (((i * 53) ^ (i >> 3)) % 256) as u8;
            px[0] = v;
            px[1] = v.wrapping_add(80);
            px[2] = v.wrapping_mul(11);
            px[3] = 255;
        }
        RgbaImage {
            width: w,
            height: h,
            pixels,
        }
    }

    fn cover(w: u32, h: u32) -> Vec<u8> {
        encode_png(&textured(w, h)).unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn adaptive_roundtrip() {
        let c = cover(96, 96);
        let body = payload::frame(b"into the busiest pixels");
        let (eo, xo) = opts("key");
        let stego = AdaptiveCost.embed(&c, &body, &eo).unwrap();
        assert_eq!(AdaptiveCost.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn order_invariant_under_embedding() {
        let c = cover(64, 64);
        let body = payload::frame(b"invariance");
        let (eo, _) = opts("k");
        let stego = AdaptiveCost.embed(&c, &body, &eo).unwrap();
        let seed = derive_seed("k", Slot::Primary);
        let o1 = cost_order(&decode_rgba(&c).unwrap(), Some(&seed));
        let o2 = cost_order(&decode_rgba(&stego).unwrap(), Some(&seed));
        assert_eq!(o1, o2);
    }

    #[test]
    fn prefers_textured_pixels() {
        let img = textured(48, 48);
        let order = cost_order(&img, None);
        let energy = residual_energy(&img);
        let first = energy[order[0] as usize / CHANNELS_PER_PIXEL];
        let last = energy[order[order.len() - 1] as usize / CHANNELS_PER_PIXEL];
        assert!(first >= last);
    }

    #[test]
    fn clean_image_returns_none() {
        let (_, xo) = opts("k");
        assert_eq!(AdaptiveCost.extract(&cover(48, 48), &xo).unwrap(), None);
    }
}
