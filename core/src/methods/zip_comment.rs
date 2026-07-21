//! `zip_comment` — hide inside a ZIP archive's end-of-central-directory comment.
//!
//! Every ZIP ends with an End Of Central Directory record carrying an optional
//! free-text comment and its 16-bit length. The comment is part of the format:
//! archivers preserve it, extraction ignores it, and the archive stays valid and
//! fully openable. Nothing is appended past the end of the file and no offset
//! inside the archive moves, so the entries themselves are untouched.
//!
//! This covers far more than `.zip`. **DOCX, XLSX, PPTX, ODT, JAR, APK and EPUB
//! are all ZIP containers**, so an Office document or an Android package carries
//! a payload here with its structure intact — where the generic
//! [`crate::methods::append_eof`] would simply staple bytes past the end.
//!
//! Capacity is the comment field's own limit: 64 KiB minus framing.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct ZipComment;

/// End of central directory record signature.
const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
/// Fixed part of the EOCD, up to and including the 2-byte comment length.
const EOCD_FIXED: usize = 22;
/// The comment length field is a `u16`.
const MAX_COMMENT: usize = u16::MAX as usize;

/// Offset of the last EOCD record, which is the authoritative one.
///
/// The record is at most `EOCD_FIXED + 65535` bytes from the end, so the scan is
/// bounded rather than walking the whole archive.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_FIXED {
        return None;
    }
    let horizon = data.len().saturating_sub(EOCD_FIXED + MAX_COMMENT);
    let mut i = data.len() - EOCD_FIXED;
    loop {
        if &data[i..i + 4] == EOCD_SIG {
            // Trust it only if the declared comment length matches what's left.
            let declared = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            if i + EOCD_FIXED + declared == data.len() {
                return Some(i);
            }
        }
        if i == horizon {
            return None;
        }
        i -= 1;
    }
}

impl Method for ZipComment {
    fn id(&self) -> &'static str {
        "zip_comment"
    }
    fn display_name(&self) -> &'static str {
        "Archive or Office document (ZIP comment)"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        find_eocd(cover).ok_or(StegnoError::UnsupportedFormat)?;
        Ok(Capacity {
            usable_bytes: (MAX_COMMENT as u64).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let eocd = find_eocd(cover).ok_or(StegnoError::UnsupportedFormat)?;
        if payload.len() > MAX_COMMENT {
            return Err(StegnoError::CoverTooSmall);
        }
        // Keep everything up to the comment-length field, then write our own
        // comment. Any pre-existing comment is replaced, which is why the
        // length is rewritten rather than extended.
        let mut out = Vec::with_capacity(eocd + EOCD_FIXED + payload.len());
        out.extend_from_slice(&cover[..eocd + EOCD_FIXED - 2]);
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let Some(eocd) = find_eocd(stego) else {
            return Ok(None);
        };
        let len = u16::from_le_bytes([stego[eocd + 20], stego[eocd + 21]]) as usize;
        if len == 0 {
            return Ok(None);
        }
        let start = eocd + EOCD_FIXED;
        Ok(Some(stego[start..start + len].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally valid empty ZIP: just an EOCD.
    fn empty_zip(comment: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(EOCD_SIG);
        v.extend_from_slice(&0u16.to_le_bytes()); // disk number
        v.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        v.extend_from_slice(&0u16.to_le_bytes()); // entries on this disk
        v.extend_from_slice(&0u16.to_le_bytes()); // total entries
        v.extend_from_slice(&0u32.to_le_bytes()); // CD size
        v.extend_from_slice(&0u32.to_le_bytes()); // CD offset
        v.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        v.extend_from_slice(comment);
        v
    }

    #[test]
    fn roundtrips_through_the_comment_field() {
        let cover = empty_zip(b"");
        let body = payload::frame(b"inside an archive");
        let stego = ZipComment.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            ZipComment.extract(&stego, &ExtractOpts::default()).unwrap(),
            Some(body)
        );
    }

    #[test]
    fn the_archive_structure_is_untouched() {
        // Everything before the comment length must survive byte for byte, so
        // entries and their offsets still resolve.
        let cover = empty_zip(b"");
        let body = payload::frame(b"x");
        let stego = ZipComment.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(&stego[..EOCD_FIXED - 2], &cover[..EOCD_FIXED - 2]);
        assert!(find_eocd(&stego).is_some(), "still a locatable ZIP");
    }

    #[test]
    fn an_existing_comment_is_replaced_not_appended() {
        let cover = empty_zip(b"original comment");
        let body = payload::frame(b"y");
        let stego = ZipComment.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            ZipComment.extract(&stego, &ExtractOpts::default()).unwrap(),
            Some(body)
        );
        assert!(!stego.windows(8).any(|w| w == b"original"));
    }

    #[test]
    fn a_clean_archive_yields_nothing() {
        assert_eq!(
            ZipComment.extract(&empty_zip(b""), &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn non_zip_covers_are_declined() {
        assert!(matches!(
            ZipComment.capacity(b"%PDF-1.7 not an archive at all"),
            Err(StegnoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn oversized_payload_is_refused() {
        let cover = empty_zip(b"");
        let body = vec![0u8; MAX_COMMENT + 1];
        assert!(matches!(
            ZipComment.embed(&cover, &body, &EmbedOpts::default()),
            Err(StegnoError::CoverTooSmall)
        ));
    }
}
