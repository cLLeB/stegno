//! `zero_width` — hide bits in invisible zero-width Unicode characters.
//!
//! Each payload bit becomes a zero-width code point inserted into the cover
//! text: ZERO WIDTH SPACE (U+200B) = 0, ZERO WIDTH NON-JOINER (U+200C) = 1.
//! These render as nothing, so the visible text is unchanged while the bytes
//! ride along invisibly — ideal for pasting a "normal" message that secretly
//! carries data.
//!
//! Capacity is effectively bounded only by how much text you're willing to
//! carry, so a generous soft limit is reported.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::methods::bitvec::{bits_to_bytes, bytes_to_bits};
use crate::payload;
use crate::StegnoError;

pub struct ZeroWidth;

const ZWSP: char = '\u{200B}'; // bit 0
const ZWNJ: char = '\u{200C}'; // bit 1
const SOFT_CAPACITY: u64 = 1 << 20; // 1 MiB — text carriers are ~unbounded

fn is_marker(c: char) -> bool {
    c == ZWSP || c == ZWNJ
}

impl Method for ZeroWidth {
    fn id(&self) -> &'static str {
        "zero_width"
    }
    fn display_name(&self) -> &'static str {
        "Zero-Width Unicode (text)"
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
        let text = std::str::from_utf8(cover).map_err(|_| StegnoError::UnsupportedFormat)?;
        // Strip any pre-existing markers so extraction is unambiguous.
        let cleaned: String = text.chars().filter(|c| !is_marker(*c)).collect();

        let run: String = bytes_to_bits(payload)
            .into_iter()
            .map(|b| if b == 0 { ZWSP } else { ZWNJ })
            .collect();

        // Tuck the invisible run in after the first visible character so it sits
        // inside the text rather than as a trailing blob.
        let mut out = String::with_capacity(cleaned.len() + run.len());
        let mut chars = cleaned.chars();
        match chars.next() {
            Some(first) => {
                out.push(first);
                out.push_str(&run);
                out.extend(chars);
            }
            None => out.push_str(&run),
        }
        Ok(out.into_bytes())
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let text = std::str::from_utf8(stego).map_err(|_| StegnoError::UnsupportedFormat)?;
        let bits: Vec<u8> = text
            .chars()
            .filter_map(|c| match c {
                ZWSP => Some(0),
                ZWNJ => Some(1),
                _ => None,
            })
            .collect();
        if bits.is_empty() {
            return Ok(None);
        }
        Ok(Some(bits_to_bytes(&bits)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_width_roundtrip() {
        let cover = "The quick brown fox jumps over the lazy dog.".as_bytes();
        let body = payload::frame(b"invisible ink");
        let stego = ZeroWidth.embed(cover, &body, &EmbedOpts::default()).unwrap();
        let got = ZeroWidth
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn visible_text_is_preserved() {
        let cover = "Hello, world!";
        let body = payload::frame(b"x");
        let stego = ZeroWidth
            .embed(cover.as_bytes(), &body, &EmbedOpts::default())
            .unwrap();
        let stego_text = String::from_utf8(stego).unwrap();
        let visible: String = stego_text.chars().filter(|c| !is_marker(*c)).collect();
        assert_eq!(visible, cover);
    }

    #[test]
    fn clean_text_returns_none() {
        let cover = "No hidden data here".as_bytes();
        assert_eq!(
            ZeroWidth.extract(cover, &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn empty_cover_still_works() {
        let body = payload::frame(b"data");
        let stego = ZeroWidth.embed(b"", &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            ZeroWidth
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }

    #[test]
    fn invalid_utf8_is_unsupported() {
        assert!(matches!(
            ZeroWidth.embed(&[0xff, 0xfe], b"x", &EmbedOpts::default()),
            Err(StegnoError::UnsupportedFormat)
        ));
    }
}
