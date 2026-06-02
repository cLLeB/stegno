//! `lsb_seeded` — key-seeded LSB replacement in PNG.
//!
//! Same per-channel mechanic as [`super::lsb_image`] (overwrite the LSB), but
//! the payload bits are scattered across a passphrase-keyed pseudo-random
//! permutation of every channel slot instead of the first N in raster order.
//! This removes the "first N samples changed" structure that sequential LSB
//! leaks, raising the bar for steganalysis. Same capacity as `lsb_image`.

use super::lsb_common;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::StegnoError;

pub struct LsbSeeded;

impl Method for LsbSeeded {
    fn id(&self) -> &'static str {
        "lsb_seeded"
    }
    fn display_name(&self) -> &'static str {
        "Photo (PNG) — password-scrambled"
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
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (img, order) = lsb_common::prepare(cover, opts.seed.as_ref())?;
        lsb_common::embed_with(img, payload, &order, lsb_common::replace_lsb)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        lsb_common::read_frame(stego, opts.seed.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png as enc, RgbaImage};
    use crate::payload;
    use crate::seed::{derive_seed, Slot};

    fn solid(w: u32, h: u32) -> Vec<u8> {
        enc(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![100u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (
            EmbedOpts { seed: Some(s) },
            ExtractOpts { seed: Some(s) },
        )
    }

    #[test]
    fn seeded_roundtrip() {
        let cover = solid(64, 64);
        let body = payload::frame(b"scattered across the image");
        let (eo, xo) = opts("hunter2");
        let stego = LsbSeeded.embed(&cover, &body, &eo).unwrap();
        let got = LsbSeeded.extract(&stego, &xo).unwrap().unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn wrong_seed_finds_no_frame() {
        let cover = solid(64, 64);
        let body = payload::frame(b"secret");
        let (eo, _) = opts("right-key");
        let stego = LsbSeeded.embed(&cover, &body, &eo).unwrap();
        let (_, xo_wrong) = opts("wrong-key");
        // Different permutation → magic almost certainly absent → None.
        assert_eq!(LsbSeeded.extract(&stego, &xo_wrong).unwrap(), None);
    }

    #[test]
    fn is_not_sequential() {
        // A seeded embed must differ from the sequential (lsb_image) output for
        // the same payload, proving positions were actually permuted.
        let cover = solid(64, 64);
        let body = payload::frame(b"xyzzy");
        let (eo, _) = opts("k");
        let seeded = LsbSeeded.embed(&cover, &body, &eo).unwrap();
        let sequential = super::super::lsb_image::LsbImage
            .embed(&cover, &body, &EmbedOpts::default())
            .unwrap();
        assert_ne!(seeded, sequential);
    }

    #[test]
    fn no_data_returns_none() {
        let cover = solid(32, 32);
        let (_, xo) = opts("any");
        assert_eq!(LsbSeeded.extract(&cover, &xo).unwrap(), None);
    }
}
