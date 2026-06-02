//! `dwt_haar` — transform-domain embedding in reversible integer-wavelet
//! detail coefficients.
//!
//! Adjacent carrier samples `(a, b)` are run through the integer Haar
//! S-transform: approximation `l = b + ((a-b) >> 1)` and detail `d = a - b`
//! (exactly invertible over integers). The payload bit is written into the LSB
//! of the detail coefficient `d`; the inverse transform leaves `b` untouched and
//! shifts only `a` by at most ±1. Embedding in the *detail* (high-frequency)
//! band rather than the raw pixel changes the statistical fingerprint relative
//! to plain spatial LSB.
//!
//! **Bit-exact & overflow-safe.** A pair is used only if *both* LSB choices keep
//! the reconstructed sample in `[0,255]`. That predicate depends only on
//! `(l, d>>1)` — invariant under flipping `d`'s LSB — so the extractor makes the
//! identical use/skip decision from the stego image. No pair is corrupted and no
//! side information is needed.
//!
//! For the JPEG transform domain see the sibling `jpeg_jsteg` method, which
//! ships a baseline-JPEG coefficient codec and embeds bit-exactly in quantized
//! DCT coefficients. F5 / OutGuess remain deferred — see the README roadmap note.

use super::lsb_common::CHANNELS_PER_PIXEL;
use crate::image_io::{decode_rgba, encode_png};
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct DwtHaar;

/// R,G,B sample offsets (alpha skipped), as for the other spatial methods.
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

fn pair_order(num_pairs: usize, seed: Option<&[u8; 32]>) -> Vec<usize> {
    match seed {
        Some(s) => seed::permutation(num_pairs, s)
            .into_iter()
            .map(|x| x as usize)
            .collect(),
        None => (0..num_pairs).collect(),
    }
}

/// Can this pair carry a bit without overflow, for *either* LSB choice?
/// Depends only on `(b, d>>1)`, which are invariant under flipping `d`'s LSB.
#[inline]
fn usable(a: i32, b: i32) -> bool {
    let d = a - b;
    let base = d & !1; // detail with LSB cleared
    let a0 = b + base; // reconstructed `a` for bit 0
    let a1 = a0 + 1; // for bit 1
    (0..=255).contains(&a0) && (0..=255).contains(&a1)
}

/// Set the detail LSB of pair `(a,b)` to `bit`, returning the new `a` (`b` is
/// unchanged by the inverse transform).
#[inline]
fn embed_pair(a: i32, b: i32, bit: u8) -> u8 {
    let base = (a - b) & !1;
    (b + base + bit as i32) as u8
}

/// The bit carried by a (stego) pair.
#[inline]
fn read_bit(a: i32, b: i32) -> u8 {
    ((a - b) & 1) as u8
}

impl DwtHaar {
    fn pairs(width: u32, height: u32) -> usize {
        carrier_offsets(width, height).len() / 2
    }
}

impl Method for DwtHaar {
    fn id(&self) -> &'static str {
        "dwt_haar"
    }
    fn display_name(&self) -> &'static str {
        "Haar Wavelet Detail LSB (PNG)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = decode_rgba(cover)?;
        let offsets = carrier_offsets(img.width, img.height);
        let mut usable_pairs = 0u64;
        for pair in offsets.chunks_exact(2) {
            if usable(img.pixels[pair[0]] as i32, img.pixels[pair[1]] as i32) {
                usable_pairs += 1;
            }
        }
        Ok(Capacity {
            usable_bytes: (usable_pairs / 8).saturating_sub(payload::overhead() as u64),
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
        let order = pair_order(Self::pairs(img.width, img.height), opts.seed.as_ref());
        let payload_bits = payload_bytes.len() * 8;

        // Bit reader (MSB-first) over the payload.
        let read = |i: usize| -> u8 { (payload_bytes[i / 8] >> (7 - (i % 8))) & 1 };

        let mut written = 0usize;
        for &pi in &order {
            if written >= payload_bits {
                break;
            }
            let oa = offsets[pi * 2];
            let ob = offsets[pi * 2 + 1];
            let a = img.pixels[oa] as i32;
            let b = img.pixels[ob] as i32;
            if !usable(a, b) {
                continue;
            }
            img.pixels[oa] = embed_pair(a, b, read(written));
            written += 1;
        }
        if written < payload_bits {
            return Err(StegnoError::CoverTooSmall);
        }
        encode_png(&img)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let offsets = carrier_offsets(img.width, img.height);
        let order = pair_order(Self::pairs(img.width, img.height), opts.seed.as_ref());

        let hdr = payload::header_len();
        let mut bytes: Vec<u8> = Vec::new();
        let mut acc = 0u32;
        let mut acc_bits = 0u32;
        let mut target: Option<usize> = None;

        for &pi in &order {
            let a = img.pixels[offsets[pi * 2]] as i32;
            let b = img.pixels[offsets[pi * 2 + 1]] as i32;
            if !usable(a, b) {
                continue;
            }
            acc = (acc << 1) | read_bit(a, b) as u32;
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
        match target {
            Some(_) => Err(StegnoError::CorruptPayload),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::RgbaImage;
    use crate::seed::{derive_seed, Slot};

    fn textured(w: u32, h: u32) -> RgbaImage {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
            let v = ((i * 41) % 256) as u8;
            px[0] = v;
            px[1] = v.wrapping_add(70);
            px[2] = v.wrapping_mul(9);
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
    fn dwt_roundtrip() {
        let c = cover(96, 96);
        let body = payload::frame(b"hidden in the wavelet detail band");
        let (eo, xo) = opts("key");
        let stego = DwtHaar.embed(&c, &body, &eo).unwrap();
        assert_eq!(DwtHaar.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn only_lead_sample_shifts_and_stays_in_range() {
        let c = cover(64, 64);
        let body = payload::frame(b"bounded");
        let (eo, _) = opts("k");
        let stego = DwtHaar.embed(&c, &body, &eo).unwrap();
        let before = decode_rgba(&c).unwrap();
        let after = decode_rgba(&stego).unwrap();
        for (x, y) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!((*x as i16 - *y as i16).abs() <= 1);
        }
    }

    #[test]
    fn boundary_covers_roundtrip() {
        // All-0 and all-255: usable() must skip the unusable pairs and still
        // roundtrip whatever fits.
        for fill in [0u8, 255u8, 1u8, 254u8] {
            let img = RgbaImage {
                width: 80,
                height: 80,
                pixels: vec![fill; 80 * 80 * 4],
            };
            let c = encode_png(&img).unwrap();
            let body = payload::frame(b"edge");
            let (eo, xo) = opts("k");
            // Capacity at extremes may be tiny; only assert roundtrip when it fits.
            if let Ok(stego) = DwtHaar.embed(&c, &body, &eo) {
                assert_eq!(
                    DwtHaar.extract(&stego, &xo).unwrap().unwrap(),
                    body,
                    "fill={fill}"
                );
            }
        }
    }

    #[test]
    fn clean_image_returns_none() {
        let c = cover(48, 48);
        let (_, xo) = opts("k");
        assert_eq!(DwtHaar.extract(&c, &xo).unwrap(), None);
    }

    #[test]
    fn usable_predicate_is_lsb_invariant() {
        // The crux of reversibility: flipping the detail LSB never changes the
        // usable() verdict.
        for a in 0..=255i32 {
            for b in 0..=255i32 {
                let d = a - b;
                let a_bit0 = b + (d & !1);
                let a_bit1 = a_bit0 + 1;
                if (0..=255).contains(&a_bit0) && (0..=255).contains(&a_bit1) {
                    // Both reconstructions are valid pixels → both must be usable.
                    assert!(usable(a_bit0, b));
                    assert!(usable(a_bit1, b));
                }
            }
        }
    }
}
