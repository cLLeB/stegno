//! `lsb_image` — sequential least-significant-bit embedding in PNG.
//!
//! Writes the framed payload bit-by-bit into the LSB of the R, G, B channels in
//! pixel order (3 bits/pixel). Alpha is left untouched. Phase 1 will swap the
//! sequential walk for a key-seeded permutation without changing the format.

use crate::image_io::{decode_rgba, encode_png};
use crate::method::{Capacity, EmbedOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct LsbImage;

const BITS_PER_PIXEL: usize = 3; // R, G, B LSBs

fn write_bit(byte: &mut u8, bit: u8) {
    *byte = (*byte & 0xFE) | (bit & 1);
}

impl Method for LsbImage {
    fn id(&self) -> &'static str {
        "lsb_image"
    }
    fn display_name(&self) -> &'static str {
        "LSB Image (PNG)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = decode_rgba(cover)?;
        let total_bits = (img.width as u64) * (img.height as u64) * BITS_PER_PIXEL as u64;
        let total_bytes = total_bits / 8;
        let overhead = payload::overhead() as u64;
        Ok(Capacity {
            usable_bytes: total_bytes.saturating_sub(overhead),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload_bytes: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let mut img = decode_rgba(cover)?;
        let capacity_bytes =
            ((img.width as usize) * (img.height as usize) * BITS_PER_PIXEL) / 8;
        if payload_bytes.len() > capacity_bytes {
            return Err(StegnoError::CoverTooSmall);
        }
        let mut bit_index = 0usize;
        for &byte in payload_bytes {
            for b in (0..8).rev() {
                let bit = (byte >> b) & 1;
                let pixel = bit_index / BITS_PER_PIXEL;
                let chan = bit_index % BITS_PER_PIXEL; // 0=R,1=G,2=B
                let idx = pixel * 4 + chan;
                write_bit(&mut img.pixels[idx], bit);
                bit_index += 1;
            }
        }
        encode_png(&img)
    }

    fn extract(&self, stego: &[u8]) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let total_bytes = ((img.width as usize) * (img.height as usize) * BITS_PER_PIXEL) / 8;
        let read_byte = |byte_idx: usize| -> u8 {
            let mut out = 0u8;
            for b in (0..8).rev() {
                let bit_index = byte_idx * 8 + (7 - b);
                let pixel = bit_index / BITS_PER_PIXEL;
                let chan = bit_index % BITS_PER_PIXEL;
                let idx = pixel * 4 + chan;
                out |= (img.pixels[idx] & 1) << b;
            }
            out
        };

        let hdr = payload::header_len();
        if total_bytes < hdr {
            return Ok(None);
        }
        let mut head = Vec::with_capacity(hdr);
        for i in 0..hdr {
            head.push(read_byte(i));
        }
        if head[..4] != *b"STG0" {
            return Ok(None);
        }
        let len = u32::from_be_bytes([head[7], head[8], head[9], head[10]]) as usize;
        let need = hdr + len;
        if need > total_bytes {
            return Err(StegnoError::CorruptPayload);
        }
        let mut buf = Vec::with_capacity(need);
        for i in 0..need {
            buf.push(read_byte(i));
        }
        Ok(Some(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png as enc, RgbaImage};

    fn solid(w: u32, h: u32) -> Vec<u8> {
        enc(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![128u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    #[test]
    fn embed_extract_identity() {
        let cover = solid(64, 64);
        let body = payload::frame(b"the quick brown fox");
        let stego = LsbImage.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        let got = LsbImage.extract(&stego).unwrap().unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn no_data_returns_none() {
        let cover = solid(16, 16);
        assert_eq!(LsbImage.extract(&cover).unwrap(), None);
    }

    #[test]
    fn too_small_errors() {
        let cover = solid(4, 4); // 48 bits = 6 bytes raw capacity
        let body = vec![0u8; 100];
        assert!(matches!(
            LsbImage.embed(&cover, &body, &EmbedOpts::default()),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn capacity_subtracts_overhead() {
        let cover = solid(100, 100); // 30000 bits = 3750 bytes raw
        let cap = LsbImage.capacity(&cover).unwrap();
        assert_eq!(cap.usable_bytes, 3750 - payload::overhead() as u64);
    }
}
