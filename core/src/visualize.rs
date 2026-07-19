//! Steganalysis visualization: render hidden-data planes and change-maps.
//!
//! Two classic "see the secret" tools, returned as ordinary PNGs the apps can
//! display directly:
//!
//! * [`bit_plane`] extracts a single bit-plane of one colour channel as a
//!   black/white image. In a clean photo the low planes look like smooth natural
//!   texture; after LSB embedding the least-significant plane becomes visible
//!   random noise — the payload, made visible.
//! * [`change_map`] compares a cover with its stego version and paints every
//!   modified pixel white, showing exactly where (and how densely) a method
//!   embedded.

use crate::image_io::{decode_rgba, encode_png, RgbaImage};
use crate::StegnoError;

fn mono(width: u32, height: u32, on: impl Fn(usize) -> bool) -> RgbaImage {
    let n = (width * height) as usize;
    let mut pixels = vec![0u8; n * 4];
    for i in 0..n {
        let v = if on(i) { 255 } else { 0 };
        pixels[i * 4] = v;
        pixels[i * 4 + 1] = v;
        pixels[i * 4 + 2] = v;
        pixels[i * 4 + 3] = 255;
    }
    RgbaImage { width, height, pixels }
}

/// Render bit-plane `plane` (0 = least-significant … 7) of colour `channel`
/// (0 = R, 1 = G, 2 = B) as a black/white PNG the size of the source image.
#[uniffi::export]
pub fn bit_plane(image: Vec<u8>, channel: u8, plane: u8) -> Result<Vec<u8>, StegnoError> {
    if channel > 2 {
        return Err(StegnoError::Internal("channel must be 0..=2".into()));
    }
    if plane > 7 {
        return Err(StegnoError::Internal("plane must be 0..=7".into()));
    }
    let img = decode_rgba(&image)?;
    let ch = channel as usize;
    let plane = plane;
    let out = mono(img.width, img.height, |i| {
        (img.pixels[i * 4 + ch] >> plane) & 1 == 1
    });
    encode_png(&out)
}

/// Paint every pixel that differs between `cover` and `stego` white, the rest
/// black — a map of where an embed touched. Both must share dimensions.
#[uniffi::export]
pub fn change_map(cover: Vec<u8>, stego: Vec<u8>) -> Result<Vec<u8>, StegnoError> {
    let a = decode_rgba(&cover)?;
    let b = decode_rgba(&stego)?;
    if a.width != b.width || a.height != b.height {
        return Err(StegnoError::Internal("images differ in size".into()));
    }
    let out = mono(a.width, a.height, |i| {
        let base = i * 4;
        a.pixels[base] != b.pixels[base]
            || a.pixels[base + 1] != b.pixels[base + 1]
            || a.pixels[base + 2] != b.pixels[base + 2]
    });
    encode_png(&out)
}

/// Fraction of pixels changed between `cover` and `stego`, in [0,1]. A quick
/// numeric companion to [`change_map`].
#[uniffi::export]
pub fn change_rate(cover: Vec<u8>, stego: Vec<u8>) -> Result<f64, StegnoError> {
    let a = decode_rgba(&cover)?;
    let b = decode_rgba(&stego)?;
    if a.width != b.width || a.height != b.height {
        return Err(StegnoError::Internal("images differ in size".into()));
    }
    let n = (a.width * a.height) as usize;
    if n == 0 {
        return Ok(0.0);
    }
    let mut changed = 0usize;
    for i in 0..n {
        let base = i * 4;
        if a.pixels[base] != b.pixels[base]
            || a.pixels[base + 1] != b.pixels[base + 1]
            || a.pixels[base + 2] != b.pixels[base + 2]
        {
            changed += 1;
        }
    }
    Ok(changed as f64 / n as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::Secret;
    use crate::{embed, image_io::RgbaImage};

    fn flat(w: u32, h: u32, fill: u8) -> Vec<u8> {
        encode_png(&RgbaImage { width: w, height: h, pixels: vec![fill; (w * h * 4) as usize] })
            .unwrap()
    }

    #[test]
    fn bit_plane_of_flat_cover_is_uniform() {
        // 120 = 0b0111_1000 → plane 0 is all 0 (black), plane 3 is all 1 (white).
        let cover = flat(32, 32, 120);
        let p0 = decode_rgba(&bit_plane(cover.clone(), 0, 0).unwrap()).unwrap();
        assert!(p0.pixels.chunks(4).all(|px| px[0] == 0));
        let p3 = decode_rgba(&bit_plane(cover, 0, 3).unwrap()).unwrap();
        assert!(p3.pixels.chunks(4).all(|px| px[0] == 255));
    }

    #[test]
    fn bit_plane_rejects_bad_args() {
        let cover = flat(8, 8, 0);
        assert!(bit_plane(cover.clone(), 3, 0).is_err());
        assert!(bit_plane(cover, 0, 8).is_err());
    }

    #[test]
    fn change_map_marks_embedded_pixels() {
        let cover = flat(64, 64, 100);
        let stego = embed(
            "lsb_image".into(),
            cover.clone(),
            Secret::Text { text: "leaves a trail".into() },
            "pw".into(),
        )
        .unwrap();
        let map = decode_rgba(&change_map(cover.clone(), stego.clone()).unwrap()).unwrap();
        let white = map.pixels.chunks(4).filter(|px| px[0] == 255).count();
        assert!(white > 0, "no changed pixels shown");

        // change_rate agrees and is between 0 and 1.
        let rate = change_rate(cover, stego).unwrap();
        assert!(rate > 0.0 && rate < 1.0);
    }

    #[test]
    fn change_map_of_identical_is_black() {
        let cover = flat(16, 16, 50);
        let map = decode_rgba(&change_map(cover.clone(), cover.clone()).unwrap()).unwrap();
        assert!(map.pixels.chunks(4).all(|px| px[0] == 0));
        assert_eq!(change_rate(cover.clone(), cover).unwrap(), 0.0);
    }
}
