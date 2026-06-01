//! Steganalysis and image-quality metrics (Phase 5).
//!
//! Two families:
//!   * **Quality** — how much a stego image differs from its cover: MSE, PSNR,
//!     and (windowed) SSIM.
//!   * **Detection** — how *suspicious* a single image looks for LSB embedding:
//!     the Westfeld–Pfitzmann chi-square attack (with a real p-value) and an
//!     RS-style regularity diagnostic.
//!
//! These are measurement tools — they never modify images and have no crypto.

use crate::image_io::RgbaImage;

const L: f64 = 255.0;

// ---------------------------------------------------------------------------
// Quality metrics
// ---------------------------------------------------------------------------

/// Mean squared error over the R, G, B channels of two equal-sized images.
pub fn mse(a: &RgbaImage, b: &RgbaImage) -> f64 {
    let mut sum = 0f64;
    let mut count = 0u64;
    for (pa, pb) in a.pixels.chunks_exact(4).zip(b.pixels.chunks_exact(4)) {
        for c in 0..3 {
            let d = pa[c] as f64 - pb[c] as f64;
            sum += d * d;
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f64
    }
}

/// Peak signal-to-noise ratio in dB. Identical images → +∞.
pub fn psnr(a: &RgbaImage, b: &RgbaImage) -> f64 {
    let e = mse(a, b);
    if e == 0.0 {
        f64::INFINITY
    } else {
        10.0 * (L * L / e).log10()
    }
}

/// Luminance (Rec. 601) of a pixel offset.
#[inline]
fn luma(px: &[u8], o: usize) -> f64 {
    0.299 * px[o] as f64 + 0.587 * px[o + 1] as f64 + 0.114 * px[o + 2] as f64
}

/// Mean SSIM over 8×8 non-overlapping luminance windows. Identical → 1.0.
pub fn ssim(a: &RgbaImage, b: &RgbaImage) -> f64 {
    if a.width != b.width || a.height != b.height {
        return 0.0;
    }
    let w = a.width as usize;
    let h = a.height as usize;
    let c1 = (0.01 * L) * (0.01 * L);
    let c2 = (0.03 * L) * (0.03 * L);
    let win = 8usize;
    let mut total = 0f64;
    let mut windows = 0u64;
    let mut by = 0;
    while by + win <= h {
        let mut bx = 0;
        while bx + win <= w {
            let (mut ma, mut mb) = (0f64, 0f64);
            let n = (win * win) as f64;
            for y in by..by + win {
                for x in bx..bx + win {
                    let o = (y * w + x) * 4;
                    ma += luma(&a.pixels, o);
                    mb += luma(&b.pixels, o);
                }
            }
            ma /= n;
            mb /= n;
            let (mut va, mut vb, mut cov) = (0f64, 0f64, 0f64);
            for y in by..by + win {
                for x in bx..bx + win {
                    let o = (y * w + x) * 4;
                    let da = luma(&a.pixels, o) - ma;
                    let db = luma(&b.pixels, o) - mb;
                    va += da * da;
                    vb += db * db;
                    cov += da * db;
                }
            }
            va /= n - 1.0;
            vb /= n - 1.0;
            cov /= n - 1.0;
            let s = ((2.0 * ma * mb + c1) * (2.0 * cov + c2))
                / ((ma * ma + mb * mb + c1) * (va + vb + c2));
            total += s;
            windows += 1;
            bx += win;
        }
        by += win;
    }
    if windows == 0 {
        1.0
    } else {
        total / windows as f64
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Combined R/G/B value histogram (alpha ignored).
fn histogram(img: &RgbaImage) -> [u64; 256] {
    let mut h = [0u64; 256];
    for px in img.pixels.chunks_exact(4) {
        for c in 0..3 {
            h[px[c] as usize] += 1;
        }
    }
    h
}

/// Westfeld–Pfitzmann chi-square attack. Returns the probability that the image
/// carries an LSB-replacement payload, in `[0, 1]` (higher = more suspicious).
///
/// LSB replacement drives each pair-of-values `(2k, 2k+1)` toward equal counts;
/// a small chi-square against that "embedded" hypothesis ⇒ high probability.
pub fn chi_square_lsb(img: &RgbaImage) -> f64 {
    let h = histogram(img);
    let mut chi2 = 0f64;
    let mut df = 0i32;
    for k in 0..128 {
        let n0 = h[2 * k] as f64;
        let n1 = h[2 * k + 1] as f64;
        let expected = (n0 + n1) / 2.0;
        if expected < 1.0 {
            continue; // too few samples for a valid term
        }
        let d = n0 - expected;
        chi2 += d * d / expected;
        df += 1;
    }
    df -= 1;
    if df <= 0 {
        return 0.0;
    }
    // p(embedded) = 1 − chi-square CDF(chi2; df) = 1 − P(df/2, chi2/2).
    1.0 - gammp(df as f64 / 2.0, chi2 / 2.0)
}

/// RS regularity gap `(R − S)/(R + S)` for the positive mask. Clean images show
/// a clear positive gap (regular ≫ singular); LSB embedding pushes it toward 0,
/// so a **smaller** gap is more suspicious. Diagnostic, not a calibrated rate.
pub fn rs_regularity_gap(img: &RgbaImage) -> f64 {
    // Flatten R,G,B samples row-major.
    let mut s: Vec<i32> = Vec::with_capacity(img.pixels.len() / 4 * 3);
    for px in img.pixels.chunks_exact(4) {
        s.push(px[0] as i32);
        s.push(px[1] as i32);
        s.push(px[2] as i32);
    }
    const MASK: [bool; 4] = [false, true, true, false];
    let var = |g: &[i32]| (g[1] - g[0]).abs() + (g[2] - g[1]).abs() + (g[3] - g[2]).abs();
    let (mut regular, mut singular) = (0u64, 0u64);
    for g in s.chunks_exact(4) {
        let orig = var(g);
        let mut f = [g[0], g[1], g[2], g[3]];
        for i in 0..4 {
            if MASK[i] {
                f[i] ^= 1; // F1 flip
            }
        }
        let flipped = var(&f);
        if flipped > orig {
            regular += 1;
        } else if flipped < orig {
            singular += 1;
        }
    }
    let denom = (regular + singular) as f64;
    if denom == 0.0 {
        0.0
    } else {
        (regular as f64 - singular as f64) / denom
    }
}

// ---------------------------------------------------------------------------
// Regularized lower incomplete gamma P(a, x) — for the chi-square CDF.
// Numerical Recipes style: series for x < a+1, continued fraction otherwise.
// ---------------------------------------------------------------------------

fn gammln(x: f64) -> f64 {
    const COF: [f64; 6] = [
        76.180_091_729_471_46,
        -86.505_320_329_416_77,
        24.014_098_240_830_91,
        -1.231_739_572_450_155,
        0.001_208_650_973_866_179,
        -0.000_005_395_239_384_953,
    ];
    let mut y = x;
    let tmp = x + 5.5 - (x + 0.5) * (x + 5.5).ln();
    let mut ser = 1.000_000_000_190_015;
    for c in COF {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.506_628_274_631_000_5 * ser / x).ln()
}

fn gammp(a: f64, x: f64) -> f64 {
    if x <= 0.0 || a <= 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        // Series representation.
        let mut ap = a;
        let mut sum = 1.0 / a;
        let mut del = sum;
        for _ in 0..200 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-12 {
                break;
            }
        }
        sum * (-x + a * x.ln() - gammln(a)).exp()
    } else {
        // Continued fraction for Q = 1 − P.
        let mut b = x + 1.0 - a;
        let mut c = 1e30;
        let mut d = 1.0 / b;
        let mut hh = d;
        for i in 1..200 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < 1e-30 {
                d = 1e-30;
            }
            c = b + an / c;
            if c.abs() < 1e-30 {
                c = 1e-30;
            }
            d = 1.0 / d;
            let del = d * c;
            hh *= del;
            if (del - 1.0).abs() < 1e-12 {
                break;
            }
        }
        let q = (-x + a * x.ln() - gammln(a)).exp() * hh;
        1.0 - q
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};
    use crate::method::{EmbedOpts, ExtractOpts, Method};
    use crate::methods::lsb_image::LsbImage;
    use crate::payload;

    /// Smooth gradient — natural-looking LSBs (low chi-square when clean).
    fn gradient(w: u32, h: u32) -> RgbaImage {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let o = ((y * w + x) * 4) as usize;
                let v = ((x * 255 / w.max(1)) as u8).wrapping_add((y * 255 / h.max(1)) as u8);
                pixels[o] = v;
                pixels[o + 1] = v;
                pixels[o + 2] = v;
                pixels[o + 3] = 255;
            }
        }
        RgbaImage {
            width: w,
            height: h,
            pixels,
        }
    }

    #[test]
    fn psnr_identical_is_infinite() {
        let g = gradient(32, 32);
        assert!(psnr(&g, &g).is_infinite());
        assert_eq!(mse(&g, &g), 0.0);
    }

    #[test]
    fn ssim_identical_is_one() {
        let g = gradient(32, 32);
        assert!((ssim(&g, &g) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn psnr_decreases_with_distortion() {
        let g = gradient(32, 32);
        let mut noisy = g.clone();
        for p in noisy.pixels.chunks_exact_mut(4) {
            p[0] = p[0].wrapping_add(10);
        }
        let clean_psnr = psnr(&g, &g);
        let noisy_psnr = psnr(&g, &noisy);
        assert!(noisy_psnr < clean_psnr);
        assert!(noisy_psnr > 0.0);
    }

    #[test]
    fn chi_square_separates_clean_from_embedded() {
        // Clean cover has all-even sample values → strong pair-of-values
        // imbalance (n_odd ≈ 0) → chi-square attack reads "not embedded" (p≈0).
        let mut clean = gradient(96, 96);
        for b in clean.pixels.iter_mut() {
            *b &= 0xFE;
        }
        clean.pixels.chunks_exact_mut(4).for_each(|p| p[3] = 255); // keep alpha opaque
        let cover_png = encode_png(&clean).unwrap();

        // Fill the full capacity with pseudo-random bytes → LSBs randomised →
        // pairs equalise → chi-square reads "embedded" (p≈1).
        let cap = LsbImage.capacity(&cover_png).unwrap().usable_bytes as usize;
        let mut data = vec![0u8; cap];
        let mut s = 0x1234_5678u32;
        for b in data.iter_mut() {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            *b = s as u8;
        }
        let framed = payload::frame(&data);
        let stego_png = LsbImage
            .embed(&cover_png, &framed, &EmbedOpts::default())
            .unwrap();
        let stego = crate::image_io::decode_rgba(&stego_png).unwrap();

        let p_clean = chi_square_lsb(&clean);
        let p_stego = chi_square_lsb(&stego);
        assert!(
            p_clean < 0.5 && p_stego > 0.5 && p_stego > p_clean,
            "expected clean≈0, embedded≈1: clean={p_clean} stego={p_stego}"
        );
        // sanity: extraction confirms we really embedded
        assert!(LsbImage
            .extract(&stego_png, &ExtractOpts::default())
            .unwrap()
            .is_some());
    }

    #[test]
    fn rs_gap_shrinks_after_embedding() {
        let clean = gradient(96, 96);
        let cover_png = encode_png(&clean).unwrap();
        let cap = LsbImage.capacity(&cover_png).unwrap().usable_bytes as usize;
        let data = vec![0xACu8; cap.min(2500)];
        let framed = payload::frame(&data);
        let stego_png = LsbImage
            .embed(&cover_png, &framed, &EmbedOpts::default())
            .unwrap();
        let stego = crate::image_io::decode_rgba(&stego_png).unwrap();

        let gap_clean = rs_regularity_gap(&clean);
        let gap_stego = rs_regularity_gap(&stego);
        assert!(
            gap_stego < gap_clean,
            "expected smaller gap after embedding: clean={gap_clean} stego={gap_stego}"
        );
    }

    #[test]
    fn gammp_matches_known_values() {
        // P(1, x) = 1 − e^−x (exponential CDF).
        assert!((gammp(1.0, 1.0) - (1.0 - (-1.0f64).exp())).abs() < 1e-6);
        assert!((gammp(1.0, 2.0) - (1.0 - (-2.0f64).exp())).abs() < 1e-6);
        // Boundaries.
        assert_eq!(gammp(2.0, 0.0), 0.0);
        assert!(gammp(2.0, 1000.0) > 0.999);
    }
}
