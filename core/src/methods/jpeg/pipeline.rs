//! Shared forward JPEG pipeline for the coefficient-domain methods
//! (`jpeg_jsteg`, `jpeg_f5`): decode a cover image and produce quantized,
//! zig-zag-ordered DCT coefficient blocks at 4:4:4, plus a fixed enumeration of
//! the AC coefficient slots that the methods agree to traverse.

use super::dct::{fdct_8x8, quantize, rgb_to_ycbcr};
use super::tables::{CHROMA_QUANT, LUMA_QUANT, ZIGZAG};
use crate::image_io::decode_rgba;
use crate::StegnoError;

/// Quantized, zig-zag-ordered coefficient blocks for the three components.
pub struct Blocks {
    pub y: Vec<[i32; 64]>,
    pub cb: Vec<[i32; 64]>,
    pub cr: Vec<[i32; 64]>,
}

impl Blocks {
    pub fn len(&self) -> usize {
        self.y.len()
    }

    /// Mutable reference to coefficient `k` of component `comp` (0=Y,1=Cb,2=Cr)
    /// in block `i`.
    #[inline]
    pub fn at_mut(&mut self, i: usize, comp: usize, k: usize) -> &mut i32 {
        let block = match comp {
            0 => &mut self.y[i],
            1 => &mut self.cb[i],
            _ => &mut self.cr[i],
        };
        &mut block[k]
    }

    #[inline]
    pub fn at(&self, i: usize, comp: usize, k: usize) -> i32 {
        match comp {
            0 => self.y[i][k],
            1 => self.cb[i][k],
            _ => self.cr[i][k],
        }
    }
}

/// The number of AC coefficient slots (excludes DC, all three components).
pub fn ac_slot_count(num_blocks: usize) -> usize {
    num_blocks * 3 * 63
}

/// A coefficient usable for LSB-overwrite hiding (JSteg / OutGuess): skips `0`
/// and `1` so the usable set is invariant under an LSB overwrite — a usable
/// coefficient can never become `0`/`1`, and `0`/`1` are never touched. This lets
/// the extractor re-derive the identical selection with no side information.
#[inline]
pub fn lsb_usable(c: i32) -> bool {
    c != 0 && c != 1
}

/// Overwrite the two's-complement LSB of `c` with `bit`.
#[inline]
pub fn set_lsb(c: i32, bit: u8) -> i32 {
    (c & !1) | bit as i32
}

/// The bit carried by a coefficient's LSB.
#[inline]
pub fn read_lsb(c: i32) -> u8 {
    (c & 1) as u8
}

/// Decompose a flat AC slot index into `(block, component, coefficient)` with the
/// coefficient in `1..64`. Inverse of the implicit ordering used by both methods.
#[inline]
pub fn slot_to_coord(slot: usize) -> (usize, usize, usize) {
    let k = 1 + slot % 63;
    let rest = slot / 63;
    let comp = rest % 3;
    let block = rest / 3;
    (block, comp, k)
}

/// Natural-order block → zig-zag order.
fn to_zigzag(nat: &[i32; 64]) -> [i32; 64] {
    let mut zz = [0i32; 64];
    for k in 0..64 {
        zz[k] = nat[ZIGZAG[k]];
    }
    zz
}

/// Forward path: decode the cover and produce quantized zig-zag blocks at 4:4:4,
/// replicating edge pixels to fill partial 8×8 blocks.
pub fn cover_to_blocks(cover: &[u8]) -> Result<(u32, u32, Blocks), StegnoError> {
    let img = decode_rgba(cover)?;
    let (w, h) = (img.width, img.height);
    if w == 0 || h == 0 {
        return Err(StegnoError::UnsupportedFormat);
    }
    let bw = (w as usize + 7) / 8;
    let bh = (h as usize + 7) / 8;
    let mut blocks = Blocks {
        y: Vec::with_capacity(bw * bh),
        cb: Vec::with_capacity(bw * bh),
        cr: Vec::with_capacity(bw * bh),
    };
    let px = |x: usize, y: usize| -> (f64, f64, f64) {
        let cx = x.min(w as usize - 1);
        let cy = y.min(h as usize - 1);
        let i = (cy * w as usize + cx) * 4;
        (
            img.pixels[i] as f64,
            img.pixels[i + 1] as f64,
            img.pixels[i + 2] as f64,
        )
    };
    for by in 0..bh {
        for bx in 0..bw {
            let mut yb = [0f64; 64];
            let mut cbb = [0f64; 64];
            let mut crb = [0f64; 64];
            for r in 0..8 {
                for c in 0..8 {
                    let (rr, gg, bb) = px(bx * 8 + c, by * 8 + r);
                    let (y, cb, cr) = rgb_to_ycbcr(rr, gg, bb);
                    let idx = r * 8 + c;
                    yb[idx] = y - 128.0; // level shift
                    cbb[idx] = cb - 128.0;
                    crb[idx] = cr - 128.0;
                }
            }
            blocks
                .y
                .push(to_zigzag(&quantize(&fdct_8x8(&yb), &LUMA_QUANT)));
            blocks
                .cb
                .push(to_zigzag(&quantize(&fdct_8x8(&cbb), &CHROMA_QUANT)));
            blocks
                .cr
                .push(to_zigzag(&quantize(&fdct_8x8(&crb), &CHROMA_QUANT)));
        }
    }
    Ok((w, h, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_coord_roundtrips_in_canonical_order() {
        // Canonical order: block, then component, then k in 1..64.
        let mut slot = 0;
        for block in 0..2 {
            for comp in 0..3 {
                for k in 1..64 {
                    assert_eq!(slot_to_coord(slot), (block, comp, k));
                    slot += 1;
                }
            }
        }
        assert_eq!(ac_slot_count(2), slot);
    }
}
