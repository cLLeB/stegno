//! Image decode/encode helpers.
//!
//! Any supported input (PNG/JPEG/BMP/WebP/GIF) is normalized to RGBA8. Output
//! is always PNG — lossless is mandatory for LSB survival.

use crate::StegnoError;
use image::{ExtendedColorType, ImageEncoder, ImageReader};
use std::io::Cursor;

/// A decoded RGBA8 image, row-major.
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

/// Decode arbitrary image bytes into RGBA8.
pub fn decode_rgba(bytes: &[u8]) -> Result<RgbaImage, StegnoError> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| StegnoError::UnsupportedFormat)?;
    let img = reader.decode().map_err(|_| StegnoError::UnsupportedFormat)?;
    let rgba = img.to_rgba8();
    Ok(RgbaImage {
        width: rgba.width(),
        height: rgba.height(),
        pixels: rgba.into_raw(),
    })
}

/// Encode an RGBA8 image to PNG bytes.
pub fn encode_png(img: &RgbaImage) -> Result<Vec<u8>, StegnoError> {
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(&img.pixels, img.width, img.height, ExtendedColorType::Rgba8)
        .map_err(|_| StegnoError::Internal("png encode failed".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_roundtrips_dimensions() {
        let rgba = RgbaImage {
            width: 4,
            height: 3,
            pixels: vec![255u8; 4 * 3 * 4],
        };
        let png = encode_png(&rgba).unwrap();
        let back = decode_rgba(&png).unwrap();
        assert_eq!((back.width, back.height), (4, 3));
        assert_eq!(back.pixels.len(), 4 * 3 * 4);
    }

    #[test]
    fn garbage_is_unsupported() {
        assert!(matches!(
            decode_rgba(&[0xde, 0xad, 0xbe, 0xef]),
            Err(StegnoError::UnsupportedFormat)
        ));
    }
}
