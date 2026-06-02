//! `edge_adaptive` — embed in busy/edge regions first.
//!
//! Flat regions are where LSB changes stick out (both perceptually and
//! statistically); textured/edge regions hide changes far better. This method
//! ranks every pixel by a local edge score and fills the highest-energy
//! positions first, so a small payload lands entirely in texture.
//!
//! **The reproducibility trick.** The extractor must rebuild the *exact* same
//! ordering from the stego image. We therefore compute the edge score from
//! `value >> 1` (the LSB stripped off). LSB *replacement* never touches those
//! high bits, so the score — and hence the order — is identical before and
//! after embedding. Among equal scores the order is broken by a passphrase-keyed
//! rank, making the walk key-dependent too.

use super::lsb_common::{self, CHANNELS_PER_PIXEL};
use crate::image_io::{decode_rgba, RgbaImage};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::seed;
use crate::StegnoError;

pub struct EdgeAdaptive;

/// LSB-stripped luminance proxy for one pixel (sum of high 7 bits of R,G,B).
#[inline]
fn luma_hi(pixels: &[u8], pixel: usize) -> i32 {
    let o = pixel * 4;
    ((pixels[o] >> 1) as i32) + ((pixels[o + 1] >> 1) as i32) + ((pixels[o + 2] >> 1) as i32)
}

/// Per-pixel edge score: sum of |Δluma| to the 4-connected neighbours, computed
/// from LSB-stripped values so it is invariant under LSB replacement.
fn edge_scores(img: &RgbaImage) -> Vec<u32> {
    let w = img.width as usize;
    let h = img.height as usize;
    let mut scores = vec![0u32; w * h];
    for y in 0..h {
        for x in 0..w {
            let p = y * w + x;
            let l = luma_hi(&img.pixels, p);
            let mut s = 0i32;
            if x + 1 < w {
                s += (l - luma_hi(&img.pixels, p + 1)).abs();
            }
            if x > 0 {
                s += (l - luma_hi(&img.pixels, p - 1)).abs();
            }
            if y + 1 < h {
                s += (l - luma_hi(&img.pixels, p + w)).abs();
            }
            if y > 0 {
                s += (l - luma_hi(&img.pixels, p - w)).abs();
            }
            scores[p] = s as u32;
        }
    }
    scores
}

/// The channel-slot visiting order: highest edge score first, ties broken by a
/// passphrase-keyed rank (or slot index when unseeded). Deterministic and
/// invariant under LSB replacement, so embed and extract agree.
fn edge_order(img: &RgbaImage, seed: Option<&[u8; 32]>) -> Vec<u32> {
    let n = lsb_common::total_slots(img.width, img.height);
    if n == 0 {
        return Vec::new();
    }
    let scores = edge_scores(img);

    // Keyed tiebreak rank per slot: position of the slot in the key permutation
    // (its inverse). Unseeded → identity (slot index).
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
        // Higher score first; then keyed tiebreak ascending.
        scores[pb]
            .cmp(&scores[pa])
            .then_with(|| tiebreak[a as usize].cmp(&tiebreak[b as usize]))
    });
    order
}

impl Method for EdgeAdaptive {
    fn id(&self) -> &'static str {
        "edge_adaptive"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — hides in busy areas"
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
        let order = edge_order(&img, opts.seed.as_ref());
        lsb_common::embed_with(img, payload, &order, lsb_common::replace_lsb)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let order = edge_order(&img, opts.seed.as_ref());
        lsb_common::read_frame_with(&img, &order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::encode_png as enc;
    use crate::payload;
    use crate::seed::{derive_seed, Slot};

    /// A textured cover (checkerboard-ish gradient) so edge scores vary.
    fn textured(w: u32, h: u32) -> RgbaImage {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let p = ((y * w + x) * 4) as usize;
                let v = (((x * 17 + y * 29) ^ (x.wrapping_mul(y))) % 256) as u8;
                pixels[p] = v;
                pixels[p + 1] = v.wrapping_add(40);
                pixels[p + 2] = v.wrapping_mul(3);
                pixels[p + 3] = 255;
            }
        }
        RgbaImage {
            width: w,
            height: h,
            pixels,
        }
    }

    fn cover(w: u32, h: u32) -> Vec<u8> {
        enc(&textured(w, h)).unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn edge_roundtrip() {
        let c = cover(80, 80);
        let body = payload::frame(b"hidden in the texture");
        let (eo, xo) = opts("key");
        let stego = EdgeAdaptive.embed(&c, &body, &eo).unwrap();
        assert_eq!(EdgeAdaptive.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn order_is_invariant_under_embedding() {
        // The whole method hinges on this: the order computed from the stego
        // must equal the order computed from the cover.
        let c = cover(64, 64);
        let body = payload::frame(b"invariance is everything");
        let (eo, _) = opts("k");
        let stego = EdgeAdaptive.embed(&c, &body, &eo).unwrap();
        let seed = derive_seed("k", Slot::Primary);
        let cover_order = edge_order(&decode_rgba(&c).unwrap(), Some(&seed));
        let stego_order = edge_order(&decode_rgba(&stego).unwrap(), Some(&seed));
        assert_eq!(cover_order, stego_order);
    }

    #[test]
    fn prefers_high_edge_pixels() {
        // First slots in the order must have edge scores >= later slots
        // (descending by construction).
        let img = textured(40, 40);
        let order = edge_order(&img, None);
        let scores = edge_scores(&img);
        let s_first = scores[order[0] as usize / CHANNELS_PER_PIXEL];
        let s_last = scores[order[order.len() - 1] as usize / CHANNELS_PER_PIXEL];
        assert!(s_first >= s_last);
    }

    #[test]
    fn seed_changes_tiebreak_order() {
        // The seed only breaks ties among equal-score pixels, so two seeds
        // produce different orders only where scores collide. A flat (all-equal
        // score) cover makes every tie a seed decision — orders must differ.
        let flat = RgbaImage {
            width: 32,
            height: 32,
            pixels: vec![120u8; 32 * 32 * 4],
        };
        let a = edge_order(&flat, Some(&derive_seed("alpha", Slot::Primary)));
        let b = edge_order(&flat, Some(&derive_seed("bravo", Slot::Primary)));
        assert_ne!(a, b);
    }

    // NOTE: unlike the LSB-family methods, edge-adaptive positions are
    // determined mostly by the (key-independent) edge map, so a wrong seed can
    // still locate the frame. Rejecting a wrong passphrase is the crypto
    // layer's job (AES-GCM auth), exercised end-to-end via the public API.
}
