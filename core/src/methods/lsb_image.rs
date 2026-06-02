//! `lsb_image` — sequential least-significant-bit replacement in PNG.
//!
//! The Phase-0 baseline: writes the framed payload bit-by-bit into the LSB of
//! the R, G, B channels in raster (pixel) order, 3 bits/pixel, alpha untouched.
//! Simple and maximal-capacity, but the changed samples are the first N in
//! order — trivially detectable. For detection resistance use the key-seeded
//! variants ([`super::lsb_seeded`], [`super::lsb_matching`]).
//!
//! Kept byte-for-byte compatible with Phase 0 (sequential order) so existing
//! stego images and golden vectors still extract.

use super::lsb_common;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::StegnoError;

pub struct LsbImage;

impl Method for LsbImage {
    fn id(&self) -> &'static str {
        "lsb_image"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — most hiding space"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = crate::image_io::decode_rgba(cover)?;
        Ok(Capacity {
            usable_bytes: lsb_common::usable_capacity_bytes(img.width, img.height),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        // Sequential: ignore any seed.
        let (img, order) = lsb_common::prepare(cover, None)?;
        lsb_common::embed_with(img, payload, &order, lsb_common::replace_lsb)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        lsb_common::read_frame(stego, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png as enc, RgbaImage};
    use crate::payload;

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
        let got = LsbImage
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn no_data_returns_none() {
        let cover = solid(16, 16);
        assert_eq!(
            LsbImage.extract(&cover, &ExtractOpts::default()).unwrap(),
            None
        );
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
