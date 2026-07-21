//! `pdf_object` — hide inside a PDF incremental update.
//!
//! A PDF records byte offsets for every object in its cross-reference table, so
//! inserting bytes anywhere in the body invalidates them and leaves a file that
//! viewers either repair or reject. The format's own answer is the **incremental
//! update**: append new objects, a new xref pointing at them, and a trailer
//! whose `/Prev` links to the previous xref. Everything already in the file
//! keeps its offset, and the result is a fully valid PDF — this is the same
//! mechanism used when a document is signed or annotated.
//!
//! The payload becomes a stream object that nothing references, so no page
//! renders it and no text extractor sees it, while every existing byte is
//! untouched.
//!
//! Unlike [`crate::methods::append_eof`], which leaves bytes dangling past the
//! end marker, the appended region here *is* PDF structure: a parser walking the
//! file finds a well-formed revision rather than trailing garbage.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct PdfObject;

const SOFT_CAPACITY: u64 = 1 << 24;
/// Marks our object so extraction reads only what we wrote.
const TAG: &[u8] = b"/StegnoData true";

fn is_pdf(data: &[u8]) -> bool {
    data.starts_with(b"%PDF-")
}

/// Byte offset of the last `startxref` value, i.e. the current xref location.
fn last_startxref(data: &[u8]) -> Option<usize> {
    let at = rfind(data, b"startxref")?;
    let tail = &data[at + 9..];
    let digits: String = tail
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|b| *b as char)
        .collect();
    digits.parse().ok()
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Highest object number currently in use, so the new object doesn't collide.
fn highest_object_number(data: &[u8]) -> usize {
    let mut best = 0usize;
    let mut i = 0usize;
    // Scan for "<n> 0 obj" declarations.
    while let Some(at) = find_from(data, b" 0 obj", i) {
        let mut start = at;
        while start > 0 && data[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start < at {
            if let Ok(n) = std::str::from_utf8(&data[start..at]).unwrap_or("").parse::<usize>() {
                best = best.max(n);
            }
        }
        i = at + 6;
    }
    best
}

/// Copy the `/Root` reference out of the previous trailer, which the new
/// trailer must repeat for the document to remain openable.
fn root_ref(data: &[u8]) -> Option<String> {
    let at = rfind(data, b"/Root")?;
    let tail = &data[at + 5..(at + 64).min(data.len())];
    let text = String::from_utf8_lossy(tail);
    let trimmed = text.trim_start();
    // Expect "<num> <gen> R".
    let mut it = trimmed.split_whitespace();
    let num = it.next()?;
    let gen = it.next()?;
    let r = it.next()?;
    if r.starts_with('R') && num.chars().all(|c| c.is_ascii_digit()) && gen.chars().all(|c| c.is_ascii_digit())
    {
        Some(format!("{num} {gen} R"))
    } else {
        None
    }
}

impl Method for PdfObject {
    fn id(&self) -> &'static str {
        "pdf_object"
    }
    fn display_name(&self) -> &'static str {
        "PDF document (incremental update)"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        if !is_pdf(cover) || last_startxref(cover).is_none() || root_ref(cover).is_none() {
            return Err(StegnoError::UnsupportedFormat);
        }
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
        if !is_pdf(cover) {
            return Err(StegnoError::UnsupportedFormat);
        }
        let prev = last_startxref(cover).ok_or(StegnoError::UnsupportedFormat)?;
        let root = root_ref(cover).ok_or(StegnoError::UnsupportedFormat)?;
        let obj_num = highest_object_number(cover) + 1;

        let mut out = cover.to_vec();
        // PDF revisions must begin on a fresh line.
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        let obj_offset = out.len();

        out.extend_from_slice(
            format!(
                "{obj_num} 0 obj\n<< /Length {} {} >>\nstream\n",
                payload.len(),
                String::from_utf8_lossy(TAG)
            )
            .as_bytes(),
        );
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\nendstream\nendobj\n");

        let xref_offset = out.len();
        out.extend_from_slice(
            format!(
                "xref\n{obj_num} 1\n{obj_offset:010} 00000 n \n\
                 trailer\n<< /Size {} /Root {root} /Prev {prev} >>\nstartxref\n{xref_offset}\n%%EOF\n",
                obj_num + 1
            )
            .as_bytes(),
        );
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let Some(tag_at) = rfind(stego, TAG) else {
            return Ok(None);
        };
        // Read the declared /Length from the same dictionary.
        let dict_start = stego[..tag_at]
            .iter()
            .rposition(|&b| b == b'<')
            .unwrap_or(0);
        let dict = String::from_utf8_lossy(&stego[dict_start..tag_at]);
        let len: usize = match dict.split("/Length").nth(1) {
            Some(rest) => match rest.trim_start().split_whitespace().next() {
                Some(n) => match n.parse() {
                    Ok(v) => v,
                    Err(_) => return Ok(None),
                },
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        let Some(stream_at) = find_from(stego, b"stream\n", tag_at) else {
            return Ok(None);
        };
        let start = stream_at + 7;
        if start + len > stego.len() {
            return Err(StegnoError::CorruptPayload);
        }
        Ok(Some(stego[start..start + len].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdf() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        v.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        let xref = v.len();
        v.extend_from_slice(b"xref\n0 3\n0000000000 65535 f \n");
        v.extend_from_slice(
            format!("trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        v
    }

    #[test]
    fn roundtrips_through_an_incremental_update() {
        let cover = pdf();
        let body = payload::frame(b"hidden in a document");
        let stego = PdfObject.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            PdfObject.extract(&stego, &ExtractOpts::default()).unwrap(),
            Some(body)
        );
    }

    /// The reason this method exists: existing bytes and offsets must not move.
    #[test]
    fn the_original_revision_is_an_exact_prefix() {
        let cover = pdf();
        let body = payload::frame(&vec![3u8; 400]);
        let stego = PdfObject.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(&stego[..cover.len()], &cover[..], "original bytes shifted");
        assert!(stego.starts_with(b"%PDF-"));
    }

    #[test]
    fn the_new_revision_is_well_formed() {
        let stego = PdfObject
            .embed(&pdf(), &payload::frame(b"x"), &EmbedOpts::default())
            .unwrap();
        let text = String::from_utf8_lossy(&stego);
        // A second xref, a /Prev link back to the first, and a final %%EOF.
        assert_eq!(text.matches("xref").count() >= 2, true);
        assert!(text.contains("/Prev "), "no link to the previous revision");
        assert!(text.contains("/Root 1 0 R"), "catalog reference not carried over");
        assert!(text.trim_end().ends_with("%%EOF"));
        // startxref must point at our new xref.
        let at = last_startxref(&stego).unwrap();
        assert_eq!(&stego[at..at + 4], b"xref");
    }

    #[test]
    fn a_clean_pdf_yields_nothing() {
        assert_eq!(
            PdfObject.extract(&pdf(), &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn non_pdf_covers_are_declined() {
        assert!(matches!(
            PdfObject.capacity(b"PK\x03\x04 an archive"),
            Err(StegnoError::UnsupportedFormat)
        ));
    }
}
