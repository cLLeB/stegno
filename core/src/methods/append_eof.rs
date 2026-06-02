//! `append_eof` — append the payload after a file's logical end.
//!
//! Most container formats (PNG after `IEND`, JPEG after `EOI`, ZIP, …) stop
//! parsing at their end marker and ignore trailing bytes, so data appended to
//! the file is invisible to viewers yet trivially recoverable. Works on **any**
//! cover; the file still opens normally.
//!
//! Layout: `cover | frame | frame_len(u64 BE) | "SEOF"`. The 12-byte trailer
//! lets the extractor locate the frame from the end without scanning.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct AppendEof;

const FOOTER_MAGIC: &[u8; 4] = b"SEOF";
const FOOTER_LEN: usize = 8 + 4; // u64 length + magic
const SOFT_CAPACITY: u64 = 1 << 24; // 16 MiB soft limit (truly unbounded)

impl Method for AppendEof {
    fn id(&self) -> &'static str {
        "append_eof"
    }
    fn display_name(&self) -> &'static str {
        "Add onto any file"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, _cover: &[u8]) -> Result<Capacity, StegnoError> {
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
        let mut out = Vec::with_capacity(cover.len() + payload.len() + FOOTER_LEN);
        out.extend_from_slice(cover);
        out.extend_from_slice(payload);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(FOOTER_MAGIC);
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let n = stego.len();
        if n < FOOTER_LEN {
            return Ok(None);
        }
        if &stego[n - 4..] != FOOTER_MAGIC {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&stego[n - FOOTER_LEN..n - 4]);
        let frame_len = u64::from_be_bytes(len_bytes) as usize;
        // n >= FOOTER_LEN is guaranteed above; compare without risking overflow.
        if frame_len > n - FOOTER_LEN {
            return Err(StegnoError::CorruptPayload);
        }
        let start = n - FOOTER_LEN - frame_len;
        Ok(Some(stego[start..n - FOOTER_LEN].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};

    fn png_cover() -> Vec<u8> {
        encode_png(&RgbaImage {
            width: 8,
            height: 8,
            pixels: vec![200u8; 8 * 8 * 4],
        })
        .unwrap()
    }

    #[test]
    fn append_roundtrip_png() {
        let cover = png_cover();
        let body = payload::frame(b"after the end");
        let stego = AppendEof.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        // The original file is an untouched prefix → still a valid PNG.
        assert_eq!(&stego[..cover.len()], &cover[..]);
        let got = AppendEof
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn append_roundtrip_arbitrary_bytes() {
        let cover = b"any old bytes, not even a real format".to_vec();
        let body = payload::frame(&[0u8, 1, 2, 250, 255]);
        let stego = AppendEof.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            AppendEof
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }

    #[test]
    fn clean_file_returns_none() {
        let cover = png_cover();
        assert_eq!(
            AppendEof.extract(&cover, &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn truncated_footer_returns_none() {
        assert_eq!(
            AppendEof.extract(b"SEOF", &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn bogus_length_is_corrupt() {
        // Ends in SEOF but claims a frame far larger than the file.
        let mut data = vec![0u8; 8]; // stand-in for a tiny "frame" area
        data.extend_from_slice(&u64::MAX.to_be_bytes());
        data.extend_from_slice(FOOTER_MAGIC);
        assert!(matches!(
            AppendEof.extract(&data, &ExtractOpts::default()),
            Err(StegnoError::CorruptPayload)
        ));
    }
}
