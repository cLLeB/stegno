//! `whitespace` — hide bits in trailing whitespace (SNOW-style).
//!
//! After the (trailing-whitespace-trimmed) cover text and a newline, append one
//! whitespace character per payload bit: SPACE = 0, TAB = 1. The run is
//! invisible in most renderings and editors, though more fragile than
//! [`super::zero_width`] since some tools strip trailing whitespace.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::methods::bitvec::{bits_to_bytes, bytes_to_bits};
use crate::payload;
use crate::StegnoError;

pub struct Whitespace;

const SOFT_CAPACITY: u64 = 1 << 20;

#[inline]
fn is_trailing_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

impl Method for Whitespace {
    fn id(&self) -> &'static str {
        "whitespace"
    }
    fn display_name(&self) -> &'static str {
        "Hidden spaces in text"
    }
    fn media(&self) -> Media {
        Media::Text
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
        // Trim any existing trailing whitespace so our run is the only one.
        let mut end = cover.len();
        while end > 0 && is_trailing_ws(cover[end - 1]) {
            end -= 1;
        }
        let mut out = cover[..end].to_vec();
        out.push(b'\n');
        for bit in bytes_to_bits(payload) {
            out.push(if bit == 0 { b' ' } else { b'\t' });
        }
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        // The encoded run is the maximal trailing block of spaces/tabs.
        let mut start = stego.len();
        while start > 0 && matches!(stego[start - 1], b' ' | b'\t') {
            start -= 1;
        }
        let run = &stego[start..];
        if run.is_empty() {
            return Ok(None);
        }
        let bits: Vec<u8> = run.iter().map(|&b| if b == b'\t' { 1 } else { 0 }).collect();
        Ok(Some(bits_to_bytes(&bits)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_roundtrip() {
        let cover = b"A line of perfectly ordinary text.";
        let body = payload::frame(b"snow");
        let stego = Whitespace.embed(cover, &body, &EmbedOpts::default()).unwrap();
        let got = Whitespace
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn visible_content_preserved() {
        let cover = b"Keep me intact";
        let body = payload::frame(b"z");
        let stego = Whitespace.embed(cover, &body, &EmbedOpts::default()).unwrap();
        // Strip trailing whitespace/newlines from the stego → original cover.
        let mut end = stego.len();
        while end > 0 && is_trailing_ws(stego[end - 1]) {
            end -= 1;
        }
        assert_eq!(&stego[..end], cover);
    }

    #[test]
    fn clean_text_returns_none() {
        assert_eq!(
            Whitespace
                .extract(b"no trailing run", &ExtractOpts::default())
                .unwrap(),
            None
        );
    }

    #[test]
    fn pre_existing_trailing_ws_does_not_corrupt() {
        let cover = b"text with trailing spaces        \n\n";
        let body = payload::frame(b"ok");
        let stego = Whitespace.embed(cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            Whitespace
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }
}
