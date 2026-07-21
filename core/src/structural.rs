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

/// The container `data` actually is. Public so callers can name output files
/// after what they hold rather than what a carrier would have produced.
pub fn detect_container(data: &[u8]) -> &'static str {
    detect_format(data)
}

fn detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(PNG_SIG) {
        "png"
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "jpeg"
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "gif"
    } else if data.starts_with(b"%PDF-") {
        "pdf"
    } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WAVE" {
        "wav"
    } else if data.starts_with(b"YUV4MPEG2") {
        "y4m"
    } else if std::str::from_utf8(data).is_ok() {
        "text"
    } else {
        "unknown"
    }
}

/// Markers this engine itself writes. Finding one is not a statistical hint —
/// it is proof the file was produced by Stegno.
const FRAME_MAGIC: &[u8] = b"STG0"; // payload frame header (payload.rs)
const EOF_FOOTER: &[u8] = b"SEOF"; // append_eof trailer
const CARRIER_FOOTER: &[u8] = b"SCAR"; // appended-region carrier trailer

/// Scan for the engine's own signatures, whatever the container.
///
/// This runs for **every** format, including ones nothing else here understands.
/// Previously an unrecognised container got no structural scan at all, so a
/// payload appended to a PDF — magic bytes and all, sitting in plain sight at
/// the end of the file — was reported as "clean". A scanner that misses the
/// tool's own output is worse than no scanner, because it reassures.
fn scan_engine_markers(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    let n = data.len();

    // append_eof: `... | frame | len(u64 BE) | "SEOF"`.
    if n >= 12 && &data[n - 4..] == EOF_FOOTER {
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&data[n - 12..n - 4]);
        let claimed = u64::from_be_bytes(len_bytes);
        findings.push(StructuralFinding {
            kind: "stegno_append_eof".into(),
            detail: format!(
                "Stegno `append_eof` trailer at the end of the file, declaring a {claimed}-byte payload."
            ),
            severity: 2,
        });
    }

    // Appended-region carrier: `... | region | count(u64 BE) | "SCAR"`.
    if n >= 12 && &data[n - 4..] == CARRIER_FOOTER {
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&data[n - 12..n - 4]);
        let slots = u64::from_be_bytes(len_bytes);
        findings.push(StructuralFinding {
            kind: "stegno_carrier_region".into(),
            detail: format!(
                "Stegno appended-region trailer declaring {slots} payload slots ({} bytes).",
                slots / 8
            ),
            severity: 2,
        });
    }

    // Format-native carriers park the payload in a field the format defines as
    // ignorable. Each leaves its own fingerprint, so name the method rather than
    // reporting a generic frame and leaving the user to guess.
    scan_native_carriers(data, findings);

    // The framed payload itself. Methods that append leave it in the clear; LSB
    // methods scatter it through the carrier, so absence here proves nothing.
    // Only report it when nothing more specific already explained the file.
    if findings.is_empty() {
        if let Some(at) = rfind_subsequence(data, FRAME_MAGIC) {
            findings.push(StructuralFinding {
                kind: "stegno_frame".into(),
                detail: format!("Stegno payload frame header `STG0` at offset {at}."),
                severity: 2,
            });
        }
    }
}

/// Signatures of the format-native carriers, each keyed to the field it uses.
fn scan_native_carriers(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    let n = data.len();

    // zip_comment: a non-empty end-of-central-directory comment holding a frame.
    if n >= 22 {
        let horizon = n.saturating_sub(22 + u16::MAX as usize);
        let mut i = n - 22;
        loop {
            if &data[i..i + 4] == b"PK\x05\x06" {
                let len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
                if i + 22 + len == n && len > 0 && data[i + 22..].starts_with(FRAME_MAGIC) {
                    findings.push(StructuralFinding {
                        kind: "stegno_zip_comment".into(),
                        detail: format!(
                            "{len} bytes in the archive's end-of-central-directory comment."
                        ),
                        severity: 2,
                    });
                }
                break;
            }
            if i == horizon {
                break;
            }
            i -= 1;
        }
    }

    // pdf_object: our marked stream object in an incremental update.
    if data.starts_with(b"%PDF-") && rfind_subsequence(data, b"/StegnoData true").is_some() {
        findings.push(StructuralFinding {
            kind: "stegno_pdf_object".into(),
            detail: "An appended PDF revision contains a marked, unreferenced stream object."
                .into(),
            severity: 2,
        });
    }

    // stl_attrib: our marker replaces the start of the 80-byte STL header.
    if n > 84 && data.starts_with(b"STGL") {
        let tris = u32::from_le_bytes([data[80], data[81], data[82], data[83]]) as usize;
        if 84 + tris * 50 == n {
            findings.push(StructuralFinding {
                kind: "stegno_stl_attrib".into(),
                detail: format!(
                    "STL header carries a Stegno marker; payload rides {tris} attribute words."
                ),
                severity: 2,
            });
        }
    }

    // mp4_free: our marker inside a top-level free/skip box.
    if n > 16 && rfind_subsequence(data, b"freeSTG4").is_some() {
        findings.push(StructuralFinding {
            kind: "stegno_mp4_free".into(),
            detail: "A top-level ISO-BMFF `free` box carries a Stegno payload.".into(),
            severity: 2,
        });
    }

    // mp3_id3: a PRIV frame owned by us inside the ID3 tag.
    if data.starts_with(b"ID3") && rfind_subsequence(data, b"PRIV").is_some() {
        if let Some(at) = rfind_subsequence(data, b"stegno\0") {
            findings.push(StructuralFinding {
                kind: "stegno_mp3_id3".into(),
                detail: format!("An ID3 PRIV frame owned by `stegno` at offset {at}."),
                severity: 2,
            });
        }
    }
}

/// Data appended after a PDF's final `%%EOF` marker.
fn scan_pdf(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    let Some(eof) = rfind_subsequence(data, b"%%EOF") else {
        findings.push(StructuralFinding {
            kind: "malformed_pdf".into(),
            detail: "No %%EOF marker found; the file may be truncated or disguised.".into(),
            severity: 1,
        });
        return;
    };
    // A trailing newline or two after %%EOF is normal.
    let after = data.len().saturating_sub(eof + 5);
    if after > 4 {
        findings.push(StructuralFinding {
            kind: "trailing_data".into(),
            detail: format!("{after} bytes follow the final %%EOF marker."),
            severity: 2,
        });
    }
}

/// Sample bytes past the end of a WAV's declared RIFF size.
fn scan_wav(data: &[u8], findings: &mut Vec<StructuralFinding>) {
    if data.len() < 12 {
        return;
    }
    let riff_size =
        u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let declared_end = riff_size + 8;
    if data.len() > declared_end + 4 {
        findings.push(StructuralFinding {
            kind: "trailing_data".into(),
            detail: format!(
                "{} bytes follow the end declared by the RIFF header.",
                data.len() - declared_end
            ),
            severity: 2,
        });
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
        "pdf" => scan_pdf(&data, &mut findings),
        "wav" => scan_wav(&data, &mut findings),
        _ => {}
    }
    scan_zip_polyglot(&data, format, &mut findings);
    // Format-independent, so it also covers containers nothing above parses.
    scan_engine_markers(&data, &mut findings);

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let suspicious = findings.iter().any(|f| f.severity >= 2);

    StructuralReport {
        format: format.to_string(),
        findings,
        suspicious,
    }
}

#[cfg(test)]
mod round_trip_tests {
    //! The scanner must catch what this engine itself produces.
    //!
    //! It previously did not. Any container it could not parse — a PDF, a video,
    //! an arbitrary blob — skipped structural scanning entirely, so a payload
    //! appended in plain sight with its own magic bytes came back "clean". These
    //! tests hide real data with real methods and demand it be found.

    use crate::payload::Secret;
    use crate::structural::scan_structure;

    fn pdf() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend((0..20_000u32).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8));
        v.extend_from_slice(b"\n%%EOF\n");
        v
    }

    fn hide(method: &str, cover: Vec<u8>) -> Vec<u8> {
        crate::embed(
            method.into(),
            cover,
            Secret::Text { text: "x".repeat(500) },
            "pw".into(),
        )
        .unwrap_or_else(|e| panic!("{method} failed to embed: {e}"))
    }

    #[test]
    fn appended_payload_in_a_pdf_is_detected() {
        let clean = scan_structure(pdf());
        assert!(!clean.suspicious, "a clean PDF must not be flagged");
        assert_eq!(clean.format, "pdf", "PDFs must be recognised, not 'unknown'");

        let stego = scan_structure(hide("append_eof", pdf()));
        assert!(
            stego.suspicious,
            "appended payload in a PDF reported as clean: {:?}",
            stego.findings
        );
    }

    #[test]
    fn the_carrier_appended_region_is_detected() {
        // The composite/decoy path on a non-image cover.
        let stego = crate::embed_composite(
            vec![crate::ByteChunk { bytes: pdf() }],
            vec![crate::Recipient {
                secret: Secret::Text { text: "real".into() },
                passphrase: "a".into(),
            }],
            0,
            false,
        )
        .unwrap();
        let report = scan_structure(stego[0].bytes.clone());
        assert!(
            report.suspicious,
            "carrier region reported as clean: {:?}",
            report.findings
        );
        assert!(report.findings.iter().any(|f| f.kind == "stegno_carrier_region"));
    }

    #[test]
    fn appended_payload_is_detected_in_any_container() {
        // Containers the scanner has no parser for must still be covered.
        let blobs: Vec<(&str, Vec<u8>)> = vec![
            ("mkv-ish", {
                let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
                v.extend((0..9000u32).map(|i| (i % 251) as u8));
                v
            }),
            ("random", (0..9000u32).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()),
        ];
        for (label, cover) in blobs {
            let report = scan_structure(hide("append_eof", cover));
            assert!(
                report.suspicious,
                "{label}: appended payload reported as clean: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn a_clean_file_of_an_unparsed_format_is_not_flagged() {
        // Catching everything by crying wolf would be just as useless.
        let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
        v.extend((0..9000u32).map(|i| (i % 251) as u8));
        let report = scan_structure(v);
        assert!(!report.suspicious, "false positive: {:?}", report.findings);
    }

    #[test]
    fn trailing_data_after_a_wav_is_detected() {
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&(36u32 + 800).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44100u32.to_le_bytes());
        wav.extend_from_slice(&88200u32.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&800u32.to_le_bytes());
        wav.extend(std::iter::repeat_n(7u8, 800));

        assert!(!scan_structure(wav.clone()).suspicious, "clean WAV flagged");
        wav.extend_from_slice(b"appended secret payload here");
        let report = scan_structure(wav);
        assert!(report.suspicious, "trailing data after WAV missed: {:?}", report.findings);
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
