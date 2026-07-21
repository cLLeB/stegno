//! `mimic_words` — generative linguistic stego via wordlist mimicry.
//!
//! Rather than hiding data *in* a cover, this **generates** innocuous-looking
//! word salad that encodes the payload. Each byte maps to two words drawn from a
//! fixed 16-word table (high nibble, then low nibble), so the output reads like
//! (clumsy) English and decodes unambiguously by splitting on whitespace.
//!
//! This is the classic, model-free mimicry approach — the right fit for an
//! offline, dependency-light crate (LLM-driven fluent text would need a bundled
//! language model, which is out of scope for this toolkit).
//!
//! The `cover` argument is ignored (the text is generated from scratch).

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct MimicWords;

/// 16 common words — index = nibble value. Distinct, lowercase, whitespace-split.
const WORDS: [&str; 16] = [
    "the", "a", "and", "of", "to", "in", "is", "it", "that", "for", "on", "with", "as", "by", "at",
    "be",
];

const SOFT_CAPACITY: u64 = 1 << 20;

fn word_to_nibble(w: &str) -> Option<u8> {
    WORDS.iter().position(|&x| x == w).map(|i| i as u8)
}

impl Method for MimicWords {
    fn id(&self) -> &'static str {
        "mimic_words"
    }
    fn display_name(&self) -> &'static str {
        "Disguised as random words"
    }
    fn media(&self) -> Media {
        Media::Text
    }

    /// This method *generates* a carrier and ignores the cover completely, so
    /// the output is word-salad rather than the file you supplied. Legitimate
    /// when you want innocuous text from nothing; never what you want when you
    /// asked to hide something inside a particular document.
    fn preserves_cover(&self) -> bool {
        false
    }

    fn capacity(&self, _cover: &[u8]) -> Result<Capacity, StegnoError> {
        Ok(Capacity {
            usable_bytes: SOFT_CAPACITY.saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        _cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        // Two words per byte: high nibble then low nibble.
        let mut words = Vec::with_capacity(payload.len() * 2);
        for &b in payload {
            words.push(WORDS[(b >> 4) as usize]);
            words.push(WORDS[(b & 0x0F) as usize]);
        }
        Ok(words.join(" ").into_bytes())
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let text = std::str::from_utf8(stego).map_err(|_| StegnoError::UnsupportedFormat)?;
        // Collect known words → nibbles; ignore anything not in the table.
        let nibbles: Vec<u8> = text.split_whitespace().filter_map(word_to_nibble).collect();
        if nibbles.len() < 2 {
            return Ok(None);
        }
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
    fn mimic_roundtrip() {
        let body = payload::frame(b"generated cover");
        let stego = MimicWords.embed(b"", &body, &EmbedOpts::default()).unwrap();
        let got = MimicWords
            .extract(&stego, &ExtractOpts::default())
            .unwrap()
            .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn output_is_only_known_words() {
        let body = payload::frame(b"\x00\xFF\xA5");
        let stego = MimicWords.embed(b"", &body, &EmbedOpts::default()).unwrap();
        let text = String::from_utf8(stego).unwrap();
        for w in text.split_whitespace() {
            assert!(WORDS.contains(&w), "unexpected word {w}");
        }
    }

    #[test]
    fn all_byte_values_roundtrip() {
        let body = payload::frame(&(0u8..=255).collect::<Vec<u8>>());
        let stego = MimicWords.embed(b"", &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            MimicWords
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }

    #[test]
    fn unrelated_prose_returns_garbage_or_none() {
        // Ordinary prose has known words ("the", "a", ...) so it decodes to
        // *some* bytes, but they won't carry the STG0 frame — the public
        // extract's unframe rejects it. Here we only assert it doesn't panic and
        // returns a value or None.
        let _ = MimicWords
            .extract(b"hello world", &ExtractOpts::default())
            .unwrap();
    }

    #[test]
    fn cover_is_ignored() {
        let body = payload::frame(b"x");
        let a = MimicWords.embed(b"cover one", &body, &EmbedOpts::default()).unwrap();
        let b = MimicWords
            .embed(b"a totally different cover", &body, &EmbedOpts::default())
            .unwrap();
        assert_eq!(a, b);
    }
}
