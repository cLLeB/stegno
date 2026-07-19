//! Structural / container steganalysis.
//!
//! Where `analysis.rs` looks at *pixel statistics* (LSB embedding), this module
//! looks at *file structure*: data appended after a format's end marker, format
//! polyglots (a file that is simultaneously a PNG and a ZIP), suspicious
//! metadata chunks, and zero-width characters in text. These are exactly the
//! signatures produced by the engine's own `append_eof`, `polyglot`, `png_text`,
//! and `zero_width` methods, so this doubles as a self-test and a red/blue-team
//! scanner for third-party files.
//!
//! Pure structural parsing — no decompression, no allocation of the payload,
//! and no dependency beyond the standard library.

/// One structural signal found in a file.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StructuralFinding {
    /// Machine-readable category, e.g. `trailing_data`, `polyglot_zip`.
    pub kind: String,
    /// Human-readable explanation with offsets/sizes.
    pub detail: String,
    /// 0 = informational, 1 = noteworthy, 2 = strong indicator of hidden data.
    pub severity: u8,
}

/// The result of scanning a file's structure.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StructuralReport {
    /// The detected container format (`png`, `jpeg`, `gif`, `text`, `unknown`).
    pub format: String,
    /// Everything noteworthy the scan turned up, most-severe first.
    pub findings: Vec<StructuralFinding>,
    /// True if any finding reaches severity 2.
    pub suspicious: bool,
}

const PNG_SIG: &[u8] = &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
const ZIP_EOCD: &[u8] = &[b'P', b'K', 0x05, 0x06];
const ZIP_CDH: &[u8] = &[b'P', b'K', 0x01, 0x02]; // central-directory file header

/// Last offset at which `needle` occurs in `haystack`.
fn rfind_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
}

fn detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(PNG_SIG) {
        "png"
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "jpeg"
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "gif"
    } else if std::str::from_utf8(data).is_ok() {
        "text"
    } else {
        "unknown"
    }
}

/// Walk PNG chunks, returning the offset just past the IEND chunk and the list
/// of chunk type tags seen. Returns `None` if the stream isn't a parseable PNG.
fn png_scan(data: &[u8]) -> Option<(usize, Vec<[u8; 4]>)> {
    let mut off = PNG_SIG.len();
    let mut tags = Vec::new();
    while off + 8 <= data.len() {
        let len = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            as usize;
        let tag = [data[off + 4], data[off + 5], data[off + 6], data[off + 7]];
        tags.push(tag);
        let next = off.checked_add(12)?.checked_add(len)?; // len + type(4) + data + crc(4)
        if next > data.len() {
            return None; // truncated chunk
        }
        off = next;
        if &tag == b"IEND" {
            return Some((off, tags));
        }
    }
    None
}

fn scan_png(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    let Some((iend_end, tags)) = png_scan(data) else {
        findings.push(StructuralFinding {
            kind: "malformed_png".into(),
            detail: "PNG chunk structure could not be parsed to IEND.".into(),
            severity: 1,
        });
        return;
    };

    // Trailing bytes after IEND — the classic append-after-EOF channel.
    if iend_end < data.len() {
        let extra = data.len() - iend_end;
        findings.push(StructuralFinding {
            kind: "trailing_data".into(),
            detail: format!("{extra} bytes present after the PNG IEND marker (offset {iend_end})."),
            severity: 2,
        });
    }

    // Text/metadata chunks that can carry a payload.
    for tag in &tags {
        match tag {
            b"tEXt" | b"iTXt" | b"zTXt" => findings.push(StructuralFinding {
                kind: "metadata_chunk".into(),
                detail: format!("PNG contains a {} metadata chunk.", tag_str(tag)),
                severity: 1,
            }),
            // Private/ancillary chunk with a lowercase-first tag that isn't standard.
            _ if tag[0].is_ascii_lowercase() && !is_standard_ancillary(tag) => {
                findings.push(StructuralFinding {
                    kind: "private_chunk".into(),
                    detail: format!(
                        "PNG contains a private/non-standard chunk `{}`.",
                        tag_str(tag)
                    ),
                    severity: 2,
                });
            }
            _ => {}
        }
    }
}

fn is_standard_ancillary(tag: &[u8; 4]) -> bool {
    matches!(
        tag,
        b"bKGD" | b"cHRM" | b"dSIG" | b"eXIf" | b"gAMA" | b"hIST" | b"iCCP" | b"pHYs"
            | b"sBIT" | b"sPLT" | b"sRGB" | b"sTER" | b"tIME" | b"tRNS" | b"tEXt"
            | b"iTXt" | b"zTXt"
    )
}

fn tag_str(tag: &[u8; 4]) -> String {
    tag.iter().map(|&b| b as char).collect()
}

fn scan_jpeg(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    // Find the End-Of-Image marker 0xFFD9, scanning from the end for the last one.
    let mut eoi = None;
    let mut i = 2;
    while i + 1 < data.len() {
        if data[i] == 0xFF && data[i + 1] == 0xD9 {
            eoi = Some(i + 2);
        }
        i += 1;
    }
    if let Some(end) = eoi {
        if end < data.len() {
            let extra = data.len() - end;
            findings.push(StructuralFinding {
                kind: "trailing_data".into(),
                detail: format!("{extra} bytes present after the JPEG EOI marker (offset {end})."),
                severity: 2,
            });
        }
    } else {
        findings.push(StructuralFinding {
            kind: "malformed_jpeg".into(),
            detail: "No JPEG EOI (FFD9) marker found.".into(),
            severity: 1,
        });
    }
}

fn scan_gif(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    // GIF ends at the trailer byte 0x3B. Anything after it is trailing data.
    if let Some(pos) = data.iter().rposition(|&b| b == 0x3B) {
        if pos + 1 < data.len() {
            let extra = data.len() - (pos + 1);
            findings.push(StructuralFinding {
                kind: "trailing_data".into(),
                detail: format!("{extra} bytes after the GIF trailer (offset {}).", pos + 1),
                severity: 2,
            });
        }
    }
}

/// Detect a genuine ZIP-in-image polyglot by *validating* the archive's
/// End-Of-Central-Directory record rather than merely spotting a `PK` byte
/// pair — the EOCD's central-directory offset must point at a real central
/// directory header, which random compressed bytes essentially never satisfy.
fn scan_zip_polyglot(data: &[u8], format: &str, findings: &mut Vec<StructuralFinding>) {
    if format == "unknown" || format == "text" {
        return;
    }
    let Some(eocd) = rfind_subsequence(data, ZIP_EOCD) else {
        return;
    };
    // The fixed EOCD record is 22 bytes: sig(4) .. cd_offset(4 @ +16) .. comment_len(2).
    if eocd + 22 > data.len() {
        return;
    }
    let cd_offset = u32::from_le_bytes([
        data[eocd + 16],
        data[eocd + 17],
        data[eocd + 18],
        data[eocd + 19],
    ]) as usize;
    // The central directory it points to must actually start with a CDH signature.
    if cd_offset + 4 <= data.len() && data[cd_offset..cd_offset + 4] == *ZIP_CDH {
        findings.push(StructuralFinding {
            kind: "polyglot_zip".into(),
            detail: format!(
                "File is a valid {} but also contains a structurally valid ZIP archive.",
                format.to_uppercase()
            ),
            severity: 2,
        });
    }
}

fn scan_text(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Zero-width / invisible carriers used by the zero_width method.
    let zw = text
        .chars()
        .filter(|&c| {
            matches!(
                c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{180E}'
            )
        })
        .count();
    if zw > 0 {
        findings.push(StructuralFinding {
            kind: "zero_width".into(),
            detail: format!("{zw} zero-width / invisible characters found in text."),
            severity: 2,
        });
    }

    // Unicode Tags block (U+E0000–U+E007F): invisible "smuggling" characters.
    let tags = text
        .chars()
        .filter(|&c| (0xE0000..=0xE007F).contains(&(c as u32)))
        .count();
    if tags > 0 {
        findings.push(StructuralFinding {
            kind: "unicode_tags".into(),
            detail: format!("{tags} invisible Unicode tag characters found in text."),
            severity: 2,
        });
    }

    // Trailing-whitespace (SNOW-style) channel: runs of space/tab at line ends.
    let trailing: usize = text
        .lines()
        .map(|line| line.len() - line.trim_end_matches([' ', '\t']).len())
        .sum();
    if trailing >= 8 {
        findings.push(StructuralFinding {
            kind: "trailing_whitespace".into(),
            detail: format!("{trailing} trailing-whitespace characters (possible SNOW channel)."),
            severity: 1,
        });
    }
}

/// Scan a file's structure for signs of hidden data. Fully offline, no payload
/// is decoded or decrypted — only container structure is inspected.
#[uniffi::export]
pub fn scan_structure(data: Vec<u8>) -> StructuralReport {
    let format = detect_format(&data);
    let mut findings = Vec::new();

    match format {
        "png" => scan_png(&data, &mut findings),
        "jpeg" => scan_jpeg(&data, &mut findings),
        "gif" => scan_gif(&data, &mut findings),
        "text" => scan_text(&data, &mut findings),
        _ => {}
    }
    scan_zip_polyglot(&data, format, &mut findings);

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let suspicious = findings.iter().any(|f| f.severity >= 2);

    StructuralReport {
        format: format.to_string(),
        findings,
        suspicious,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_png() -> Vec<u8> {
        // Signature + a bare IHDR + IEND (CRCs are not validated by the scanner).
        let mut v = PNG_SIG.to_vec();
        // IHDR chunk: len=13
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&[0u8; 13]);
        v.extend_from_slice(&[0u8; 4]); // crc
                                        // IEND chunk: len=0
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0u8; 4]); // crc
        v
    }

    #[test]
    fn clean_png_is_not_suspicious() {
        let r = scan_structure(minimal_png());
        assert_eq!(r.format, "png");
        assert!(!r.suspicious, "unexpected findings: {:?}", r.findings);
    }

    #[test]
    fn appended_data_after_iend_is_flagged() {
        let mut png = minimal_png();
        png.extend_from_slice(b"THIS IS A HIDDEN SECRET PAYLOAD");
        let r = scan_structure(png);
        assert!(r.suspicious);
        assert!(r.findings.iter().any(|f| f.kind == "trailing_data"));
    }

    #[test]
    fn private_chunk_is_flagged() {
        // Insert a private `stEg` chunk before IEND.
        let mut v = PNG_SIG.to_vec();
        v.extend_from_slice(&4u32.to_be_bytes());
        v.extend_from_slice(b"stEg");
        v.extend_from_slice(b"data");
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0u8; 4]);
        let r = scan_structure(v);
        assert!(r.findings.iter().any(|f| f.kind == "private_chunk"));
        assert!(r.suspicious);
    }

    #[test]
    fn png_zip_polyglot_is_flagged() {
        let mut png = minimal_png();
        // Append a structurally valid (minimal) ZIP: a central-directory header
        // followed by an EOCD whose cd_offset points at that header.
        let cd_offset = png.len() as u32;
        png.extend_from_slice(ZIP_CDH); // central directory header signature
        png.extend_from_slice(&[0u8; 42]); // rest of a (zeroed) CDH
        // EOCD: sig(4) disk(2) disk_cd(2) n_this(2) n_total(2) cd_size(4) cd_offset(4) comment_len(2)
        png.extend_from_slice(ZIP_EOCD);
        png.extend_from_slice(&[0u8; 12]); // through cd_size (offsets +4..+16)
        png.extend_from_slice(&cd_offset.to_le_bytes()); // cd_offset @ +16
        png.extend_from_slice(&[0u8; 2]); // comment_len
        let r = scan_structure(png);
        assert!(r.findings.iter().any(|f| f.kind == "polyglot_zip"));
    }

    #[test]
    fn stray_pk_bytes_do_not_false_positive() {
        // A PNG whose data merely contains PK signatures (no valid EOCD/CDH
        // structure) must NOT be reported as a polyglot.
        let mut png = minimal_png();
        png.extend_from_slice(&[b'P', b'K', 0x03, 0x04]); // local header sig only
        png.extend_from_slice(&[b'P', b'K', 0x05, 0x06]); // EOCD sig but no valid record
        let r = scan_structure(png);
        assert!(
            !r.findings.iter().any(|f| f.kind == "polyglot_zip"),
            "stray PK bytes falsely flagged as polyglot"
        );
    }

    #[test]
    fn zero_width_text_is_flagged() {
        let text = "Hello\u{200B}\u{200C} world\u{200B} this looks normal".to_string();
        let r = scan_structure(text.into_bytes());
        assert_eq!(r.format, "text");
        assert!(r.findings.iter().any(|f| f.kind == "zero_width"));
        assert!(r.suspicious);
    }

    #[test]
    fn jpeg_trailing_data_is_flagged() {
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpg.extend_from_slice(&[0u8; 10]);
        jpg.extend_from_slice(&[0xFF, 0xD9]); // EOI
        jpg.extend_from_slice(b"appended");
        let r = scan_structure(jpg);
        assert_eq!(r.format, "jpeg");
        assert!(r.findings.iter().any(|f| f.kind == "trailing_data"));
    }
}
