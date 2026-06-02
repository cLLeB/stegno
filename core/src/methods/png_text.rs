//! `png_text` — hide the payload in a private PNG metadata chunk.
//!
//! PNG files are a signature followed by typed chunks. Decoders ignore chunks
//! they don't recognise, so we tuck the frame into a private ancillary chunk
//! (`stEg`) inserted just before `IEND`. The image renders identically and the
//! pixels are untouched — unlike LSB, this survives lossless re-saving by tools
//! that preserve ancillary chunks, but is also easy to spot/strip if someone
//! lists the chunks.
//!
//! Chunk name `stEg`: lower-`s` = ancillary (safe to ignore), lower-`t` =
//! private, upper-`E` = reserved bit clear (valid), lower-`g` = safe to copy.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct PngText;

const SIG: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const CHUNK: &[u8; 4] = b"stEg";
const IEND: &[u8; 4] = b"IEND";
const SOFT_CAPACITY: u64 = 1 << 24;

use super::crc32::crc32;

fn write_chunk(out: &mut Vec<u8>, ctype: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(ctype);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(ctype);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Parse a PNG into `(type, data)` chunks (CRC not re-validated — lenient read).
fn parse_chunks(png: &[u8]) -> Result<Vec<([u8; 4], Vec<u8>)>, StegnoError> {
    if png.len() < 8 || png[..8] != SIG {
        return Err(StegnoError::UnsupportedFormat);
    }
    let mut pos = 8;
    let mut chunks = Vec::new();
    while pos + 8 <= png.len() {
        let dlen = u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
        let mut ctype = [0u8; 4];
        ctype.copy_from_slice(&png[pos + 4..pos + 8]);
        let dstart = pos + 8;
        let dend = dstart + dlen;
        if dend + 4 > png.len() {
            return Err(StegnoError::UnsupportedFormat); // truncated
        }
        let data = png[dstart..dend].to_vec();
        let is_iend = &ctype == IEND;
        chunks.push((ctype, data));
        pos = dend + 4; // skip CRC
        if is_iend {
            break;
        }
    }
    Ok(chunks)
}

impl Method for PngText {
    fn id(&self) -> &'static str {
        "png_text"
    }
    fn display_name(&self) -> &'static str {
        "PNG Metadata Chunk"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        parse_chunks(cover)?; // validates it's a PNG
        Ok(Capacity {
            usable_bytes: SOFT_CAPACITY.saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let chunks = parse_chunks(cover)?;
        let mut out = SIG.to_vec();
        let mut inserted = false;
        for (ctype, data) in &chunks {
            if ctype == CHUNK {
                continue; // drop any previous hidden chunk (idempotent re-embed)
            }
            if ctype == IEND && !inserted {
                write_chunk(&mut out, CHUNK, payload);
                inserted = true;
            }
            write_chunk(&mut out, ctype, data);
        }
        if !inserted {
            // No IEND seen (unusual) — append our chunk and a terminator.
            write_chunk(&mut out, CHUNK, payload);
            write_chunk(&mut out, IEND, &[]);
        }
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        for (ctype, data) in parse_chunks(stego)? {
            if &ctype == CHUNK {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{decode_rgba, encode_png, RgbaImage};

    fn png(w: u32, h: u32) -> Vec<u8> {
        encode_png(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![123u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    #[test]
    fn png_text_roundtrip() {
        let cover = png(16, 16);
        let body = payload::frame(b"in the metadata");
        let stego = PngText.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            PngText
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }

    #[test]
    fn stego_is_still_a_valid_png() {
        let cover = png(20, 12);
        let body = payload::frame(b"valid");
        let stego = PngText.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        let img = decode_rgba(&stego).unwrap();
        assert_eq!((img.width, img.height), (20, 12));
    }

    #[test]
    fn re_embed_replaces_previous() {
        let cover = png(16, 16);
        let first = PngText
            .embed(&cover, &payload::frame(b"one"), &EmbedOpts::default())
            .unwrap();
        let second = PngText
            .embed(&first, &payload::frame(b"two"), &EmbedOpts::default())
            .unwrap();
        assert_eq!(
            PngText
                .extract(&second, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            payload::frame(b"two")
        );
    }

    #[test]
    fn clean_png_returns_none() {
        assert_eq!(
            PngText.extract(&png(8, 8), &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn non_png_is_unsupported() {
        assert!(matches!(
            PngText.embed(b"not a png", b"x", &EmbedOpts::default()),
            Err(StegnoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn crc32_matches_known_value() {
        // CRC-32 of "IEND" is a fixed PNG constant.
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }
}
