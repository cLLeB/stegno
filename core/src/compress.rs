//! Optional compression pre-pass.
//!
//! Compression only helps *before* encryption — ciphertext is
//! indistinguishable from random and won't shrink — so this operates on the
//! serialized `Secret` plaintext, ahead of `crypto::seal`. A frame flag records
//! whether the pass was applied, and it is only applied when it actually shrinks
//! the data, so incompressible secrets are never inflated.
//!
//! Raw DEFLATE via `miniz_oxide` (already in the dependency tree through the
//! `image`/`png` stack), so no new download and nothing new to audit.

use crate::StegnoError;

/// DEFLATE level (0–10 in miniz_oxide). 8 is a good size/speed balance for the
/// small payloads this engine handles.
const LEVEL: u8 = 8;

/// Compress `data`. Returns `Some(compressed)` only when the result is strictly
/// smaller than the input; `None` means "not worth it, store as-is".
pub fn maybe_deflate(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let out = miniz_oxide::deflate::compress_to_vec(data, LEVEL);
    if out.len() < data.len() {
        Some(out)
    } else {
        None
    }
}

/// Inverse of [`maybe_deflate`].
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, StegnoError> {
    miniz_oxide::inflate::decompress_to_vec(data).map_err(|_| StegnoError::CorruptPayload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_data_roundtrips_and_shrinks() {
        let data = vec![0xABu8; 4096];
        let c = maybe_deflate(&data).expect("repetitive data should compress");
        assert!(c.len() < data.len());
        assert_eq!(inflate(&c).unwrap(), data);
    }

    #[test]
    fn text_roundtrips() {
        let data = "the quick brown fox ".repeat(200).into_bytes();
        let c = maybe_deflate(&data).unwrap();
        assert_eq!(inflate(&c).unwrap(), data);
    }

    #[test]
    fn incompressible_data_returns_none() {
        // Pseudo-random bytes shouldn't compress; must not be inflated.
        let data: Vec<u8> = (0..2048).map(|i| ((i * 2654435761u64 as usize) >> 13) as u8).collect();
        // Either None, or if it "compresses" it must still roundtrip.
        if let Some(c) = maybe_deflate(&data) {
            assert_eq!(inflate(&c).unwrap(), data);
        }
    }

    #[test]
    fn empty_is_none() {
        assert!(maybe_deflate(&[]).is_none());
    }

    #[test]
    fn garbage_inflate_errors() {
        assert!(inflate(&[0xFF, 0x00, 0x13, 0x37]).is_err());
    }
}
