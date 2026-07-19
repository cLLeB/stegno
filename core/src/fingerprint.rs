//! Method fingerprinting.
//!
//! Given a suspect file, rank *which* steganography technique most likely
//! produced it — a blue-team triage tool and a satisfying demo. It fuses two
//! existing detectors: the structural scanner ([`crate::structural`]), which
//! nails the container-level methods (append-after-EOF, polyglot, metadata,
//! zero-width text), and the pixel-statistics detector ([`crate::detect_lsb`]),
//! which flags the spatial LSB family. Each signal maps to the method(s) that
//! produce it, with a confidence, and the guesses are returned best-first.
//!
//! This is a heuristic ranker, not a proof: a top guess means "these methods
//! best explain what I see", and an empty/low result means "nothing obvious".

use crate::structural::scan_structure;

/// One ranked hypothesis about how a file was made.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MethodGuess {
    /// The method id or family this signal points to.
    pub label: String,
    /// Confidence in [0,1].
    pub confidence: f64,
    /// Why this guess was made.
    pub reason: String,
}

fn push(guesses: &mut Vec<MethodGuess>, label: &str, confidence: f64, reason: &str) {
    guesses.push(MethodGuess {
        label: label.to_string(),
        confidence,
        reason: reason.to_string(),
    });
}

/// Rank likely embedding methods for `data`, most-likely first. Fully offline.
#[uniffi::export]
pub fn fingerprint(data: Vec<u8>) -> Vec<MethodGuess> {
    let mut guesses: Vec<MethodGuess> = Vec::new();

    // 1) Structural signals map directly to container-level methods.
    let s = scan_structure(data.clone());
    for f in &s.findings {
        match f.kind.as_str() {
            "trailing_data" => push(
                &mut guesses,
                "append_eof",
                0.9,
                "data appended after the format's end marker",
            ),
            "polyglot_zip" => push(
                &mut guesses,
                "polyglot",
                0.9,
                "file is simultaneously an image and a ZIP archive",
            ),
            "private_chunk" => push(
                &mut guesses,
                "png_text",
                0.85,
                "private/non-standard PNG chunk carries the payload",
            ),
            "metadata_chunk" => push(
                &mut guesses,
                "png_text",
                0.5,
                "PNG text metadata chunk present",
            ),
            "zero_width" => push(
                &mut guesses,
                "zero_width",
                0.9,
                "zero-width / invisible characters in the text",
            ),
            "unicode_tags" => push(
                &mut guesses,
                "unicode_tags",
                0.9,
                "invisible Unicode tag characters in the text",
            ),
            "trailing_whitespace" => push(
                &mut guesses,
                "whitespace",
                0.7,
                "SNOW-style trailing whitespace present",
            ),
            _ => {}
        }
    }

    // 2) Pixel statistics point to the spatial LSB family (image formats only).
    if matches!(s.format.as_str(), "png" | "jpeg" | "gif") {
        if let Ok(d) = crate::detect_lsb(data) {
            // A blend of the strongest LSB indicators.
            let lsb_score = (d.sample_pair_rate * 0.6
                + (1.0 - d.rs_regularity_gap.clamp(0.0, 1.0)) * 0.2
                + d.chi_square_p * 0.2)
                .clamp(0.0, 1.0);
            if lsb_score > 0.15 {
                push(
                    &mut guesses,
                    "lsb-family (lsb_image / lsb_seeded / lsb_matching / edge_adaptive / pvd)",
                    lsb_score,
                    "elevated LSB-plane statistics (sample-pair / chi-square)",
                );
            }
            if s.format == "jpeg" {
                push(
                    &mut guesses,
                    "jpeg-dct (jpeg_jsteg / jpeg_f5 / jpeg_outguess / jpeg_mc)",
                    0.3,
                    "JPEG cover — DCT-domain methods are possible",
                );
            }
        }
    }

    if guesses.is_empty() {
        push(
            &mut guesses,
            "none",
            0.05,
            "no structural or statistical signature detected",
        );
    }

    guesses.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    guesses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};
    use crate::payload::Secret;
    use crate::{embed, list_methods};

    fn png_cover(w: u32, h: u32) -> Vec<u8> {
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
            let v = ((i * 53) % 256) as u8;
            px[0] = v;
            px[1] = v.wrapping_add(30);
            px[2] = v.wrapping_mul(9);
            px[3] = 255;
        }
        encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
    }

    /// A flat cover is statistically benign for the LSB detector, so structural
    /// signals dominate and there are no synthetic-pattern false positives.
    fn flat_cover(w: u32, h: u32) -> Vec<u8> {
        encode_png(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![120u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    fn has(id: &str) -> bool {
        list_methods().into_iter().any(|m| m.id == id)
    }

    #[test]
    fn top_guess_for_append_eof() {
        if !has("append_eof") {
            return;
        }
        let stego = embed(
            "append_eof".into(),
            flat_cover(64, 64),
            Secret::Text { text: "x".into() },
            "pw".into(),
        )
        .unwrap();
        let g = fingerprint(stego);
        assert_eq!(g[0].label, "append_eof");
        assert!(g[0].confidence > 0.8);
    }

    #[test]
    fn top_guess_for_zero_width() {
        if !has("zero_width") {
            return;
        }
        let carrier = "ordinary looking sentence. ".repeat(30);
        let stego = embed(
            "zero_width".into(),
            carrier.into_bytes(),
            Secret::Text { text: "hi".into() },
            "pw".into(),
        )
        .unwrap();
        let g = fingerprint(stego);
        assert_eq!(g[0].label, "zero_width");
    }

    #[test]
    fn lsb_family_flagged_on_heavy_embed() {
        // Fill much of the LSB plane so statistics stand out.
        let cover = png_cover(96, 96);
        let payload = vec![0x5Au8; 2500];
        let stego = embed(
            "lsb_image".into(),
            cover,
            Secret::File { name: "b".into(), bytes: payload },
            "pw".into(),
        )
        .unwrap();
        let g = fingerprint(stego);
        assert!(
            g.iter().any(|x| x.label.starts_with("lsb-family")),
            "guesses: {:?}",
            g.iter().map(|x| &x.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn clean_cover_has_no_container_false_positive() {
        // Statistical LSB scores are unreliable on synthetic covers (a known
        // property of steganalysis), so we assert the robust guarantee: a clean
        // file must never be flagged as a *container-level* method, which have
        // definitive structural signatures rather than fuzzy statistics.
        for cover in [flat_cover(64, 64), png_cover(80, 80)] {
            let g = fingerprint(cover);
            assert!(
                !g.iter().any(|x| matches!(
                    x.label.as_str(),
                    "append_eof" | "polyglot" | "png_text" | "zero_width" | "whitespace"
                )),
                "clean cover falsely flagged a container method: {:?}",
                g.iter().map(|x| &x.label).collect::<Vec<_>>()
            );
        }
    }
}
