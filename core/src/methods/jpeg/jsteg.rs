//! `jpeg_jsteg` — transform-domain hiding in quantized JPEG DCT coefficients.
//!
//! The cover is taken into the JPEG domain ourselves: RGB → YCbCr (4:4:4),
//! per-block forward DCT, quantization with the standard Annex-K tables, zig-zag
//! ordering. We then apply the classic **JSteg** rule — overwrite the LSB of every
//! AC coefficient whose value is not `0` and not `1` — and re-emit a real baseline
//! JPEG via our own entropy coder and container.
//!
//! **Bit-exact, no side information.** The usable set `{c : c ≠ 0 ∧ c ≠ 1}` is
//! invariant under an LSB overwrite (a usable coefficient can never become `0` or
//! `1`, and we never touch `0`/`1`), so the extractor re-derives the identical
//! coefficient selection straight from the stego entropy stream — it never needs
//! the cover or an inverse DCT. Because our encoder/decoder share fixed tables,
//! the quantized coefficients survive the JPEG round-trip exactly, so the
//! AES-GCM-sealed payload recovers without a single bit error.
//!
//! The DC term is skipped (index 0 of each zig-zag block) to keep block
//! brightness stable; only AC coefficients carry payload.

use super::codec::{decode_scan, encode_scan};
use super::container::{parse_jpeg, write_jpeg};
use super::dct::{fdct_8x8, quantize, rgb_to_ycbcr};
use super::tables::{CHROMA_QUANT, LUMA_QUANT, ZIGZAG};
use crate::image_io::decode_rgba;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct JpegJsteg;

/// Quantized, zig-zag-ordered coefficient blocks for the three components.
struct Blocks {
    y: Vec<[i32; 64]>,
    cb: Vec<[i32; 64]>,
    cr: Vec<[i32; 64]>,
}

/// A JSteg-usable coefficient (skips 0 and 1 so the usable set is LSB-invariant).
#[inline]
fn usable(c: i32) -> bool {
    c != 0 && c != 1
}

/// Overwrite the two's-complement LSB of `c` with `bit`.
#[inline]
fn set_lsb(c: i32, bit: u8) -> i32 {
    (c & !1) | bit as i32
}

#[inline]
fn read_lsb(c: i32) -> u8 {
    (c & 1) as u8
}

/// Natural-order block → zig-zag order.
fn to_zigzag(nat: &[i32; 64]) -> [i32; 64] {
    let mut zz = [0i32; 64];
    for k in 0..64 {
        zz[k] = nat[ZIGZAG[k]];
    }
    zz
}

/// Forward path: decode the cover image and produce quantized zig-zag blocks at
/// 4:4:4 with edge pixels replicated to fill partial 8×8 blocks.
fn cover_to_blocks(cover: &[u8]) -> Result<(u32, u32, Blocks), StegnoError> {
    let img = decode_rgba(cover)?;
    let (w, h) = (img.width, img.height);
    let bw = (w as usize + 7) / 8;
    let bh = (h as usize + 7) / 8;
    let mut blocks = Blocks {
        y: Vec::with_capacity(bw * bh),
        cb: Vec::with_capacity(bw * bh),
        cr: Vec::with_capacity(bw * bh),
    };
    let px = |x: usize, y: usize| -> (f64, f64, f64) {
        // Clamp to the image edge so partial blocks replicate the border.
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
                    // Level shift by -128 before the DCT.
                    yb[idx] = y - 128.0;
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

/// Visit every component's AC coefficients in a fixed MCU order (Y, Cb, Cr; AC
/// indices 1..64), calling `f` with a mutable reference to each. The order is
/// shared by capacity, embed, and extract.
fn for_each_ac<F: FnMut(&mut i32)>(blocks: &mut Blocks, mut f: F) {
    let n = blocks.y.len();
    for i in 0..n {
        for comp in [&mut blocks.y, &mut blocks.cb, &mut blocks.cr] {
            for k in 1..64 {
                f(&mut comp[i][k]);
            }
        }
    }
}

fn count_usable(blocks: &Blocks) -> u64 {
    let mut n = 0u64;
    for i in 0..blocks.y.len() {
        for comp in [&blocks.y, &blocks.cb, &blocks.cr] {
            for k in 1..64 {
                if usable(comp[i][k]) {
                    n += 1;
                }
            }
        }
    }
    n
}

impl Method for JpegJsteg {
    fn id(&self) -> &'static str {
        "jpeg_jsteg"
    }
    fn display_name(&self) -> &'static str {
        "JPEG DCT (JSteg)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let (_, _, blocks) = cover_to_blocks(cover)?;
        let bits = count_usable(&blocks);
        Ok(Capacity {
            usable_bytes: (bits / 8).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload_bytes: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (w, h, mut blocks) = cover_to_blocks(cover)?;
        let payload_bits = payload_bytes.len() * 8;
        let read = |i: usize| -> u8 { (payload_bytes[i / 8] >> (7 - (i % 8))) & 1 };

        let mut written = 0usize;
        for_each_ac(&mut blocks, |c| {
            if written < payload_bits && usable(*c) {
                *c = set_lsb(*c, read(written));
                written += 1;
            }
        });
        if written < payload_bits {
            return Err(StegnoError::CoverTooSmall);
        }
        let entropy = encode_scan(&blocks.y, &blocks.cb, &blocks.cr);
        Ok(write_jpeg(w, h, &entropy))
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let (geo, entropy) = match parse_jpeg(stego) {
            Some(v) => v,
            None => return Ok(None),
        };
        let (y, cb, cr) = match decode_scan(entropy, geo.num_blocks()) {
            Some(v) => v,
            None => return Ok(None),
        };
        let mut blocks = Blocks { y, cb, cr };

        let hdr = payload::header_len();
        let mut bytes: Vec<u8> = Vec::new();
        let mut acc = 0u32;
        let mut acc_bits = 0u32;
        let mut target: Option<usize> = None;
        let mut done: Option<Result<Option<Vec<u8>>, ()>> = None;

        for_each_ac(&mut blocks, |c| {
            if done.is_some() {
                return;
            }
            if !usable(*c) {
                return;
            }
            acc = (acc << 1) | read_lsb(*c) as u32;
            acc_bits += 1;
            if acc_bits == 8 {
                bytes.push(acc as u8);
                acc = 0;
                acc_bits = 0;
                if target.is_none() && bytes.len() == hdr {
                    if bytes[..4] != *b"STG0" {
                        done = Some(Ok(None));
                        return;
                    }
                    let len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
                    target = Some(hdr + len);
                }
                if let Some(t) = target {
                    if bytes.len() >= t {
                        bytes.truncate(t);
                        done = Some(Err(())); // sentinel: full payload captured
                    }
                }
            }
        });

        match done {
            Some(Ok(none)) => Ok(none),
            Some(Err(())) => Ok(Some(bytes)),
            None => match target {
                Some(_) => Err(StegnoError::CorruptPayload),
                None => Ok(None),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};

    /// A textured cover with plenty of high-frequency content (→ many usable
    /// AC coefficients) so JSteg has capacity.
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

    #[test]
    fn jsteg_roundtrip() {
        let cover = textured(96, 96);
        let body = payload::frame(b"hidden in quantized DCT coefficients");
        let stego = JpegJsteg
            .embed(&cover, &body, &EmbedOpts::default())
            .unwrap();
        // Output is a real JPEG.
        assert_eq!(&stego[..2], &[0xFF, 0xD8]);
        let got = JpegJsteg
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn output_decodes_as_a_real_jpeg() {
        // The `image` crate must accept our container as a valid JPEG.
        let cover = textured(64, 64);
        let body = payload::frame(b"valid jfif");
        let stego = JpegJsteg
            .embed(&cover, &body, &EmbedOpts::default())
            .unwrap();
        let decoded = decode_rgba(&stego).expect("stego must be a decodable JPEG");
        assert_eq!((decoded.width, decoded.height), (64, 64));
    }

    #[test]
    fn clean_image_returns_none() {
        let cover = textured(48, 48);
        // A freshly encoded JPEG of the cover has no STG0 frame.
        let entropy = {
            let (_, _, b) = cover_to_blocks(&cover).unwrap();
            encode_scan(&b.y, &b.cb, &b.cr)
        };
        let jpeg = write_jpeg(48, 48, &entropy);
        assert_eq!(
            JpegJsteg.extract(&jpeg, &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn non_jpeg_returns_none() {
        assert_eq!(
            JpegJsteg
                .extract(&[0u8, 1, 2, 3, 4], &ExtractOpts::default())
                .unwrap(),
            None
        );
    }

    #[test]
    fn too_small_cover_errors() {
        let cover = textured(8, 8); // very little capacity
        let big = payload::frame(&vec![0xABu8; 4096]);
        assert!(matches!(
            JpegJsteg.embed(&cover, &big, &EmbedOpts::default()),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn capacity_matches_what_embeds() {
        let cover = textured(80, 80);
        let cap = JpegJsteg.capacity(&cover).unwrap().usable_bytes as usize;
        assert!(cap > 0);
        // A payload that exactly fills capacity must embed and extract.
        let secret = vec![0x5Au8; cap];
        let body = payload::frame(&secret);
        let stego = JpegJsteg
            .embed(&cover, &body, &EmbedOpts::default())
            .unwrap();
        assert_eq!(
            JpegJsteg
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }
}
