//! Counter-steganography: sanitize a file so no hidden payload survives.
//!
//! The offensive side of this engine hides data in pixel low-bits, in structural
//! slack (after a format's end marker, private chunks, polyglots), and in
//! invisible text characters. `sanitize` is the defensive inverse: pass it any
//! incoming file and it returns a cleaned copy with those channels destroyed —
//! useful for a gateway that must strip covert payloads from user uploads.
//!
//! Images are decoded and re-encoded as a fresh PNG with the two least-
//! significant bits of every R/G/B channel zeroed. That single step defeats the
//! entire spatial family (1- and 2-bit LSB, matching, LSBMR, edge-adaptive, PVD,
//! wavelet/adaptive-cost — all of which live in or derive from those bits) and,
//! because it is a clean re-encode, simultaneously discards any appended data,
//! polyglot ZIP, or private metadata chunk. Text has its zero-width carriers and
//! trailing whitespace removed.

use crate::image_io::{decode_rgba, encode_png};

/// The result of sanitizing a file.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SanitizeReport {
    /// The cleaned bytes (a PNG for images, cleaned text for text, else the
    /// input unchanged).
    pub cleaned: Vec<u8>,
    /// The detected input format.
    pub format: String,
    /// Human-readable list of what was neutralized.
    pub actions: Vec<String>,
    /// Whether anything was changed.
    pub changed: bool,
}

fn is_image(data: &[u8]) -> bool {
    data.starts_with(&[0x89, b'P', b'N', b'G'])
        || data.starts_with(&[0xFF, 0xD8, 0xFF])
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || data.starts_with(b"BM")
        || data.starts_with(b"RIFF")
}

/// Number of least-significant bits cleared per channel. Two covers both the
/// 1-bit and 2-bit LSB methods.
const CLEARED_BITS: u8 = 2;

fn sanitize_image(data: &[u8]) -> Option<SanitizeReport> {
    let mut img = decode_rgba(data).ok()?;
    let mask = 0xFFu8 << CLEARED_BITS; // e.g. 0b1111_1100
    let mut touched = false;
    for (i, byte) in img.pixels.iter_mut().enumerate() {
        if i % 4 == 3 {
            continue; // leave alpha
        }
        let cleared = *byte & mask;
        if cleared != *byte {
            touched = true;
        }
        *byte = cleared;
    }
    let cleaned = encode_png(&img).ok()?;
    let mut actions = vec![format!(
        "zeroed the {CLEARED_BITS} low bits of every R/G/B channel (destroys LSB-family payloads)"
    )];
    // A fresh re-encode always drops trailing/append/polyglot/metadata.
    if cleaned.len() != data.len() || !touched {
        actions.push("re-encoded as a clean PNG (drops appended data, polyglots, private chunks)".into());
    }
    Some(SanitizeReport {
        cleaned,
        format: "image".into(),
        actions,
        changed: true,
    })
}

fn sanitize_text(data: &[u8]) -> Option<SanitizeReport> {
    let text = std::str::from_utf8(data).ok()?;
    let mut removed_zw = 0usize;
    let no_zw: String = text
        .chars()
        .filter(|&c| {
            let zw = matches!(
                c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{180E}'
            ) || (0xE0000..=0xE007F).contains(&(c as u32)); // Unicode Tags block
            if zw {
                removed_zw += 1;
            }
            !zw
        })
        .collect();
    // Strip trailing whitespace on each line (SNOW channel).
    let cleaned: String = no_zw
        .split_inclusive('\n')
        .map(|line| {
            let end = line.trim_end_matches(['\n']);
            let trimmed = end.trim_end_matches([' ', '\t']);
            let nl = &line[end.len()..];
            format!("{trimmed}{nl}")
        })
        .collect();

    let changed = cleaned.as_bytes() != data;
    let mut actions = Vec::new();
    if removed_zw > 0 {
        actions.push(format!("removed {removed_zw} zero-width / invisible characters"));
    }
    if cleaned.len() != no_zw.len() {
        actions.push("stripped trailing whitespace".into());
    }
    Some(SanitizeReport {
        cleaned: cleaned.into_bytes(),
        format: "text".into(),
        actions,
        changed,
    })
}

/// Sanitize `data`, returning cleaned bytes and a record of what was removed.
/// Unknown formats are returned unchanged (with `changed = false`).
#[uniffi::export]
pub fn sanitize(data: Vec<u8>) -> SanitizeReport {
    if is_image(&data) {
        if let Some(r) = sanitize_image(&data) {
            return r;
        }
    }
    if let Some(r) = sanitize_text(&data) {
        return r;
    }
    SanitizeReport {
        cleaned: data,
        format: "unknown".into(),
        actions: vec!["unrecognized format — left unchanged".into()],
        changed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};
    use crate::payload::{Revealed, Secret};
    use crate::structural::scan_structure;
    use crate::{embed, extract, list_methods};

    fn cover(w: u32, h: u32) -> Vec<u8> {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
            let v = ((i * 37) % 256) as u8;
            px[0] = v;
            px[1] = v.wrapping_add(50);
            px[2] = v.wrapping_mul(3);
            px[3] = 255;
        }
        encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
    }

    fn has(id: &str) -> bool {
        list_methods().into_iter().any(|m| m.id == id)
    }

    #[test]
    fn destroys_lsb_family_payloads() {
        for method in ["lsb_image", "lsb_seeded", "lsb_matching", "lsb_high"] {
            if !has(method) {
                continue;
            }
            let stego = embed(
                method.into(),
                cover(96, 96),
                Secret::Text { text: "you cannot read this after sanitize".into() },
                "pw".into(),
            )
            .unwrap();
            let clean = sanitize(stego).cleaned;
            let revealed = extract(method.into(), clean, "pw".into()).unwrap();
            assert!(
                matches!(revealed, Revealed::None),
                "{method} payload survived sanitize"
            );
        }
    }

    #[test]
    fn destroys_appended_data() {
        if !has("append_eof") {
            return;
        }
        let stego = embed(
            "append_eof".into(),
            cover(64, 64),
            Secret::Text { text: "trailing secret".into() },
            "pw".into(),
        )
        .unwrap();
        let clean = sanitize(stego).cleaned;
        let report = scan_structure(clean);
        assert!(!report.suspicious, "structural payload survived: {:?}", report.findings);
    }

    #[test]
    fn strips_zero_width_text() {
        let dirty = "hello\u{200B}\u{200C} world\u{200B}".to_string();
        let r = sanitize(dirty.into_bytes());
        assert_eq!(r.format, "text");
        assert!(r.changed);
        assert_eq!(String::from_utf8(r.cleaned).unwrap(), "hello world");
    }

    #[test]
    fn clean_text_is_unchanged() {
        let text = "nothing to see here\n".to_string();
        let r = sanitize(text.clone().into_bytes());
        assert!(!r.changed);
        assert_eq!(String::from_utf8(r.cleaned).unwrap(), text);
    }

    #[test]
    fn sanitized_image_still_decodes() {
        let clean = sanitize(cover(48, 48)).cleaned;
        assert!(decode_rgba(&clean).is_ok());
    }
}
