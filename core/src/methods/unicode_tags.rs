//! `unicode_tags` — hide bytes in invisible Unicode Tag characters.
//!
//! The Unicode Tags block (U+E0000–U+E007F) is rendered as nothing by
//! conforming software, which is exactly why it has become the vehicle for
//! "invisible text" smuggling (e.g. hiding instructions inside a prompt or a
//! copied string). This method weaponizes it for legitimate covert messaging:
//! each payload byte is encoded as two invisible tag characters (one per nibble)
//! and appended to an ordinary-looking cover string. The visible text is
//! untouched; the payload rides along unseen.
//!
//! Distinct from [`super::zero_width`] (which uses the ZERO-WIDTH space/non-
//! joiner): this uses the Tags block, so it survives some filters that only
//! strip the classic zero-width set — and is caught by the engine's own scanner
//! and `sanitize`.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct UnicodeTags;

/// 16 consecutive invisible tag code points (TAG DIGIT ZERO … TAG QUESTION
/// MARK) used to represent a nibble each.
const NIBBLE_BASE: u32 = 0xE0030;

const SOFT_CAPACITY: u64 = 1 << 20; // text carriers are ~unbounded

fn nibble_to_char(n: u8) -> char {
    char::from_u32(NIBBLE_BASE + (n & 0x0F) as u32).expect("valid tag code point")
}

fn char_to_nibble(c: char) -> Option<u8> {
    let v = c as u32;
    if (NIBBLE_BASE..NIBBLE_BASE + 16).contains(&v) {
        Some((v - NIBBLE_BASE) as u8)
    } else {
        None
    }
}

fn is_tag_nibble(c: char) -> bool {
    char_to_nibble(c).is_some()
}

impl Method for UnicodeTags {
    fn id(&self) -> &'static str {
        "unicode_tags"
    }
    fn display_name(&self) -> &'static str {
        "Invisible Unicode tag characters in text"
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
        // Strip any pre-existing tag-nibble chars so extraction is unambiguous.
        let cleaned: String = text.chars().filter(|c| !is_tag_nibble(*c)).collect();

        let mut run = String::with_capacity(payload.len() * 2);
        for &byte in payload {
            run.push(nibble_to_char(byte >> 4));
            run.push(nibble_to_char(byte & 0x0F));
        }

        let mut out = String::with_capacity(cleaned.len() + run.len());
        out.push_str(&cleaned);
        out.push_str(&run);
        Ok(out.into_bytes())
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let text = std::str::from_utf8(stego).map_err(|_| StegnoError::UnsupportedFormat)?;
        let nibbles: Vec<u8> = text.chars().filter_map(char_to_nibble).collect();
        if nibbles.is_empty() {
            return Ok(None);
        }
        // Pair nibbles into bytes; a dangling odd nibble is ignored.
        let mut bytes = Vec::with_capacity(nibbles.len() / 2);
        for pair in nibbles.chunks_exact(2) {
            bytes.push((pair[0] << 4) | pair[1]);
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cover = "This looks like a perfectly normal sentence.".as_bytes();
        let body = payload::frame(b"smuggled through tag characters");
        let stego = UnicodeTags.embed(cover, &body, &EmbedOpts::default()).unwrap();
        let got = UnicodeTags
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn visible_text_is_preserved() {
        let cover = "Hello, world!";
        let body = payload::frame(b"x");
        let stego = UnicodeTags
            .embed(cover.as_bytes(), &body, &EmbedOpts::default())
            .unwrap();
        let stego_text = String::from_utf8(stego).unwrap();
        let visible: String = stego_text.chars().filter(|c| !is_tag_nibble(*c)).collect();
        assert_eq!(visible, cover);
    }

    #[test]
    fn all_byte_values_roundtrip() {
        let body: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let stego = UnicodeTags.embed(b"cover", &body, &EmbedOpts::default()).unwrap();
        let got = UnicodeTags
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn clean_text_returns_none() {
        assert_eq!(
            UnicodeTags
                .extract("nothing hidden".as_bytes(), &ExtractOpts::default())
                .unwrap(),
            None
        );
    }

    #[test]
    fn invalid_utf8_is_unsupported() {
        assert!(matches!(
            UnicodeTags.embed(&[0xff, 0xfe], b"x", &EmbedOpts::default()),
            Err(StegnoError::UnsupportedFormat)
        ));
    }
}
