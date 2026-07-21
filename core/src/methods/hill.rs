//! `hill` — HILL content-adaptive embedding (High-pass, Low-pass, Low-pass).
//!
//! A second, differently-characterized adaptive spatial method alongside
//! [`super::adaptive_cost`]. HILL (Li et al., 2014) is one of the strongest
//! hand-designed spatial cost functions: it takes the KB high-pass residual of
//! the image, then smooths its magnitude with two successive low-pass filters.
//! The result is a *suitability* map that is high in busy, hard-to-model regions
//! and — crucially — spreads embedding into clustered textured areas rather than
//! isolated edges, which is what makes HILL resist modern detectors well.
//!
//! The payload fills the highest-suitability positions first. Like the other
//! adaptive methods the map is computed from LSB-stripped values, so it is
//! invariant under LSB replacement and the extractor rebuilds the identical
//! ordering with no side information.

use super::lsb_common::{self, CHANNELS_PER_PIXEL};
use crate::image_io::{decode_rgba, RgbaImage};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::seed;
use crate::StegnoError;

pub struct Hill;

#[inline]
fn luma_hi(px: &[u8], p: usize) -> i64 {
    let o = p * 4;
    ((px[o] >> 1) as i64) + ((px[o + 1] >> 1) as i64) + ((px[o + 2] >> 1) as i64)
}

/// Clamp a coordinate to the image (edge replication for borders).
#[inline]
fn clamp(v: i64, max: usize) -> usize {
    v.clamp(0, max as i64 - 1) as usize
}

/// Magnitude of the KB high-pass residual on LSB-stripped luma.
fn kb_residual(img: &RgbaImage) -> Vec<i64> {
    let w = img.width as usize;
    let h = img.height as usize;
    let l = |x: i64, y: i64| luma_hi(&img.pixels, clamp(y, h) * w + clamp(x, w));
    let mut r = vec![0i64; w * h];
    for y in 0..h as i64 {
        for x in 0..w as i64 {
            // KB kernel: [[-1,2,-1],[2,-4,2],[-1,2,-1]]
            let v = -l(x - 1, y - 1) + 2 * l(x, y - 1) - l(x + 1, y - 1)
                + 2 * l(x - 1, y) - 4 * l(x, y) + 2 * l(x + 1, y)
                - l(x - 1, y + 1) + 2 * l(x, y + 1) - l(x + 1, y + 1);
            r[y as usize * w + x as usize] = v.abs();
        }
    }
    r
}

/// Box blur (integer mean over a (2·radius+1)² window, edge-clamped).
fn box_blur(src: &[i64], w: usize, h: usize, radius: usize) -> Vec<i64> {
    let mut out = vec![0i64; w * h];
    let r = radius as i64;
    for y in 0..h as i64 {
        for x in 0..w as i64 {
            let mut sum = 0i64;
            let mut count = 0i64;
            for dy in -r..=r {
                for dx in -r..=r {
                    let sx = clamp(x + dx, w);
                    let sy = clamp(y + dy, h);
                    sum += src[sy * w + sx];
                    count += 1;
                }
            }
            out[y as usize * w + x as usize] = sum / count.max(1);
        }
    }
    out
}

/// HILL suitability per pixel: high-pass residual, smoothed twice.
fn suitability(img: &RgbaImage) -> Vec<i64> {
    let w = img.width as usize;
    let h = img.height as usize;
    if w == 0 || h == 0 {
        return Vec::new();
    }
    let residual = kb_residual(img);
    let l1 = box_blur(&residual, w, h, 1); // 3×3 low-pass
    box_blur(&l1, w, h, 3) // 7×7 low-pass
}

/// Channel-slot order: highest suitability first, ties broken by a keyed rank.
fn hill_order(img: &RgbaImage, seed: Option<&[u8; 32]>) -> Vec<u32> {
    let n = lsb_common::total_slots(img.width, img.height);
    if n == 0 {
        return Vec::new();
    }
    let s = suitability(img);
    let mut tiebreak = vec![0u32; n];
    match seed {
        Some(sd) => {
            for (rank, &slot) in seed::permutation(n, sd).iter().enumerate() {
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
        s[pb]
            .cmp(&s[pa])
            .then_with(|| tiebreak[a as usize].cmp(&tiebreak[b as usize]))
    });
    order
}

impl Method for Hill {
    fn id(&self) -> &'static str {
        "hill"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — HILL adaptive stealth"
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
        let order = hill_order(&img, opts.seed.as_ref());
        lsb_common::embed_with(img, payload, &order, lsb_common::replace_lsb)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let order = hill_order(&img, opts.seed.as_ref());
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
        RgbaImage { width: w, height: h, pixels }
    }

    fn cover(w: u32, h: u32) -> Vec<u8> {
        encode_png(&textured(w, h)).unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn hill_roundtrip() {
        let c = cover(96, 96);
        let body = payload::frame(b"high-pass low-pass low-pass");
        let (eo, xo) = opts("key");
        let stego = Hill.embed(&c, &body, &eo).unwrap();
        assert_eq!(Hill.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn order_invariant_under_embedding() {
        let c = cover(64, 64);
        let body = payload::frame(b"invariance");
        let (eo, _) = opts("k");
        let stego = Hill.embed(&c, &body, &eo).unwrap();
        let seed = derive_seed("k", Slot::Primary);
        let o1 = hill_order(&decode_rgba(&c).unwrap(), Some(&seed));
        let o2 = hill_order(&decode_rgba(&stego).unwrap(), Some(&seed));
        assert_eq!(o1, o2);
    }

    #[test]
    fn clean_image_returns_none() {
        let (_, xo) = opts("k");
        assert_eq!(Hill.extract(&cover(48, 48), &xo).unwrap(), None);
    }

    #[test]
    fn boundary_covers_roundtrip() {
        // Flat cover (residual ~0 everywhere) must still round-trip.
        let flat = encode_png(&RgbaImage {
            width: 48,
            height: 48,
            pixels: vec![130u8; 48 * 48 * 4],
        })
        .unwrap();
        let body = payload::frame(b"flat");
        let (eo, xo) = opts("k");
        let stego = Hill.embed(&flat, &body, &eo).unwrap();
        assert_eq!(Hill.extract(&stego, &xo).unwrap().unwrap(), body);
    }
}
