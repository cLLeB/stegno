//! Colour transform, forward 8×8 DCT-II, and quantization for the encoder.
//! (Decoding for extraction needs no IDCT — we read quantized coefficients
//! straight from the entropy stream.)

use std::f64::consts::PI;

/// JFIF full-range RGB → YCbCr.
#[inline]
pub fn rgb_to_ycbcr(r: f64, g: f64, b: f64) -> (f64, f64, f64) {
    let y = 0.299 * r + 0.587 * g + 0.114 * b;
    let cb = 128.0 - 0.168_736 * r - 0.331_264 * g + 0.5 * b;
    let cr = 128.0 + 0.5 * r - 0.418_688 * g - 0.081_312 * b;
    (y, cb, cr)
}

/// Precomputed cosine basis: COS[x][u] = cos((2x+1)·u·π/16).
fn cos_table() -> [[f64; 8]; 8] {
    let mut t = [[0.0; 8]; 8];
    for x in 0..8 {
        for u in 0..8 {
            t[x][u] = (((2 * x + 1) as f64) * (u as f64) * PI / 16.0).cos();
        }
    }
    t
}

/// Forward DCT-II of a level-shifted 8×8 block (natural order in and out).
pub fn fdct_8x8(block: &[f64; 64]) -> [f64; 64] {
    let cos = cos_table();
    let alpha = |k: usize| if k == 0 { 1.0 / 2f64.sqrt() } else { 1.0 };
    let mut out = [0.0f64; 64];
    for v in 0..8 {
        for u in 0..8 {
            let mut sum = 0.0;
            for y in 0..8 {
                for x in 0..8 {
                    sum += block[y * 8 + x] * cos[x][u] * cos[y][v];
                }
            }
            out[v * 8 + u] = 0.25 * alpha(u) * alpha(v) * sum;
        }
    }
    out
}

/// Quantize a coefficient block by a quant table (natural order), rounding to
/// the nearest integer.
pub fn quantize(coef: &[f64; 64], q: &[u16; 64]) -> [i32; 64] {
    let mut out = [0i32; 64];
    for i in 0..64 {
        out[i] = (coef[i] / q[i] as f64).round() as i32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc_only_for_flat_block() {
        // A constant (level-shifted) block has energy only in the DC term.
        let block = [10.0f64; 64];
        let c = fdct_8x8(&block);
        assert!((c[0] - 10.0 * 8.0).abs() < 1e-6); // DC = mean * 8
        for &v in &c[1..] {
            assert!(v.abs() < 1e-6);
        }
    }

    #[test]
    fn ycbcr_grey_is_neutral_chroma() {
        let (y, cb, cr) = rgb_to_ycbcr(100.0, 100.0, 100.0);
        assert!((y - 100.0).abs() < 1e-6);
        assert!((cb - 128.0).abs() < 1e-6);
        assert!((cr - 128.0).abs() < 1e-6);
    }
}
