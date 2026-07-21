//! Capacity & method planner.
//!
//! Given a cover and how many bytes you want to hide, rank the methods that can
//! carry it — filtering out those that don't fit and ordering the rest by how
//! hard they are to detect, then by how much spare room is left (more headroom
//! ⇒ a lower, less-detectable embedding rate). It turns "which method should I
//! use?" — a real usability wall for a toolkit with 18 methods — into a sorted
//! answer.
//!
//! Uses only the public per-method `capacity`, so it automatically covers any
//! method the registry gains later.

use crate::method::Media;
use crate::registry;

/// A ranked recommendation for one method against a specific cover + payload.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MethodRecommendation {
    pub method_id: String,
    pub display_name: String,
    pub media: String,
    /// Usable payload bytes this method offers for the cover.
    pub usable_bytes: u64,
    /// Whether the requested payload fits.
    pub fits: bool,
    /// payload / capacity in [0,1] when it fits (lower ⇒ stealthier). 1.0 if it
    /// doesn't fit.
    pub fill_ratio: f64,
    /// 0 = statistically detectable, 1 = randomized/spatial, 2 = adaptive or
    /// transform-domain (hardest to detect).
    pub stealth_tier: u8,
    /// Whether the output is still the cover you supplied. `false` means the
    /// method synthesizes a new carrier and discards your file.
    pub preserves_cover: bool,
    /// A one-line rationale for the ranking.
    pub note: String,
}

/// Static detection-resistance tier per method id, from the engine's own
/// security notes. Unknown ids default to tier 1.
fn stealth_tier(id: &str) -> u8 {
    match id {
        // Format-native carriers: the file stays valid and its real content is
        // untouched, but the payload sits in a named field a scanner can read
        // straight out. Quiet to a person, obvious to a tool.
        "zip_comment" | "pdf_object" | "stl_attrib" | "mp4_free" | "mp3_id3" => 1,
        // Sequential LSB and 2-bit LSB have clear statistical signatures.
        "lsb_image" | "lsb_high" | "append_eof" | "png_text" | "polyglot" | "whitespace" => 0,
        // Randomized / spatial / basic text channels.
        "lsb_seeded" | "lsb_matching" | "edge_adaptive" | "pvd" | "wav_lsb" | "zero_width"
        | "unicode_tags" => 1,
        // Transform-domain, adaptive-cost, matrix-coding, generative.
        "dwt_haar" | "jpeg_jsteg" | "jpeg_f5" | "jpeg_outguess" | "jpeg_mc" | "adaptive_cost"
        | "hill" | "mimic_words" => 2,
        _ => 1,
    }
}

fn tier_label(tier: u8) -> &'static str {
    match tier {
        0 => "detectable",
        1 => "randomized",
        _ => "adaptive/transform",
    }
}

/// Rank every method for hiding `payload_len` bytes in `cover`.
///
/// Methods that can't read the cover at all (wrong media) are omitted. The
/// result is sorted best-first: methods that fit come before those that don't;
/// among fitting methods, higher stealth tier wins, then lower fill ratio.
#[uniffi::export]
pub fn plan_embedding(cover: Vec<u8>, payload_len: u64) -> Vec<MethodRecommendation> {
    let mut recs: Vec<MethodRecommendation> = Vec::new();

    for m in registry::registry() {
        // A method whose media can't parse this cover simply doesn't apply.
        let usable = match m.capacity(&cover) {
            Ok(c) => c.usable_bytes,
            Err(_) => continue,
        };
        let fits = payload_len <= usable;
        let fill_ratio = if fits && usable > 0 {
            payload_len as f64 / usable as f64
        } else if fits {
            0.0
        } else {
            1.0
        };
        let tier = stealth_tier(m.id());
        let preserves = m.preserves_cover();
        let note = if !fits {
            format!("too small — needs {payload_len} bytes, holds {usable}")
        } else if !preserves {
            format!(
                "{}; replaces your cover with generated text",
                tier_label(tier)
            )
        } else {
            format!("{}; {:.0}% full", tier_label(tier), fill_ratio * 100.0)
        };

        recs.push(MethodRecommendation {
            method_id: m.id().to_string(),
            display_name: m.display_name().to_string(),
            media: format!("{:?}", media_of(&m)),
            usable_bytes: usable,
            fits,
            fill_ratio,
            stealth_tier: tier,
            preserves_cover: preserves,
            note,
        });
    }

    recs.sort_by(|a, b| {
        // Fitting methods first.
        b.fits
            .cmp(&a.fits)
            // Then methods that actually keep your cover. A generative method
            // can score top marks for stealth while handing back word-salad
            // instead of your document — never the right default.
            .then(b.preserves_cover.cmp(&a.preserves_cover))
            // Then higher stealth tier.
            .then(b.stealth_tier.cmp(&a.stealth_tier))
            // Then lower fill ratio (stealthier embedding rate).
            .then(
                a.fill_ratio
                    .partial_cmp(&b.fill_ratio)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    recs
}

fn media_of(m: &Box<dyn crate::method::Method>) -> Media {
    m.media()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};

    fn png(w: u32, h: u32) -> Vec<u8> {
        encode_png(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![128u8; (w * h * 4) as usize],
        })
        .unwrap()
    }

    #[test]
    fn ranks_fitting_methods_first() {
        let recs = plan_embedding(png(128, 128), 100);
        assert!(!recs.is_empty());
        // The very first recommendation must fit.
        assert!(recs[0].fits, "top recommendation should fit");
        // Fitting ones precede non-fitting ones.
        let first_nonfit = recs.iter().position(|r| !r.fits);
        if let Some(idx) = first_nonfit {
            assert!(recs[..idx].iter().all(|r| r.fits));
        }
    }

    #[test]
    fn prefers_stealthier_methods_among_fitting() {
        let recs = plan_embedding(png(256, 256), 50);
        // Stealth only orders methods that keep your cover; a generative method
        // is ranked below all of them however stealthy it scores, so the tier
        // ordering is checked within that group rather than across everything.
        let fitting: Vec<_> = recs
            .iter()
            .filter(|r| r.fits && r.preserves_cover)
            .collect();
        assert!(fitting.len() >= 2);
        for w in fitting.windows(2) {
            assert!(
                w[0].stealth_tier >= w[1].stealth_tier,
                "{} (tier {}) ranked above {} (tier {})",
                w[0].method_id,
                w[0].stealth_tier,
                w[1].method_id,
                w[1].stealth_tier
            );
        }
        // lsb_image (detectable, tier 0) must not be the top pick when better fit.
        assert_ne!(recs[0].method_id, "lsb_image");
    }

    #[test]
    fn cover_preserving_methods_outrank_generative_ones() {
        let recs = plan_embedding(png(256, 256), 50);
        let mimic = recs.iter().position(|r| r.method_id == "mimic_words");
        let seeded = recs.iter().position(|r| r.method_id == "lsb_seeded");
        if let (Some(m), Some(s)) = (mimic, seeded) {
            assert!(s < m, "a real hide must outrank generated word-salad");
        }
    }

    #[test]
    fn huge_payload_marks_pixel_methods_as_not_fitting() {
        // A 32×32 cover holds only a few hundred LSB bytes. Pixel-based methods
        // must be marked "too small"; container methods that append/store data
        // (append_eof, png_text, polyglot) can still fit and are exempt.
        let recs = plan_embedding(png(32, 32), 1_000_000);
        for pixel_method in ["lsb_image", "lsb_seeded", "lsb_matching", "edge_adaptive", "pvd"] {
            let rec = recs
                .iter()
                .find(|r| r.method_id == pixel_method)
                .unwrap_or_else(|| panic!("{pixel_method} missing from plan"));
            assert!(!rec.fits, "{pixel_method} should not fit a 1MB payload in 32x32");
            assert!(rec.note.contains("too small"));
        }
    }

    #[test]
    fn incompatible_media_methods_are_omitted() {
        // A PNG cover: audio (wav_lsb) can't parse it, so it shouldn't appear.
        let recs = plan_embedding(png(64, 64), 10);
        assert!(recs.iter().all(|r| r.method_id != "wav_lsb"));
    }

    /// A PDF-shaped binary blob — a cover with no image, audio or text reading.
    fn pdf() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        v.extend((0..20_000u32).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8));
        v.extend_from_slice(b"\n%%EOF\n");
        v
    }

    /// The regression that mattered: every method the planner ranks must survive
    /// a real embed and extract against the very cover it was ranked for.
    ///
    /// The planner used to trust `Method::capacity` alone, and several methods
    /// returned a fixed capacity while ignoring the cover — so a PDF was told
    /// that text and generative methods applied to it. The top suggestion was
    /// `mimic_words`, which discards the cover and emits word-salad.
    #[test]
    fn every_recommendation_actually_round_trips() {
        use crate::payload::{Revealed, Secret};

        let covers: Vec<(&str, Vec<u8>)> = vec![
            ("png", png(160, 160)),
            ("pdf", pdf()),
            ("text", "a memo about nothing at all.\n".repeat(400).into_bytes()),
        ];

        for (label, cover) in covers {
            let recs = plan_embedding(cover.clone(), 200);
            let fitting: Vec<_> = recs.iter().filter(|r| r.fits).collect();
            assert!(!fitting.is_empty(), "{label}: nothing recommended at all");

            for r in fitting {
                let secret = Secret::Text { text: "x".repeat(200) };
                let stego = crate::embed(
                    r.method_id.clone(),
                    cover.clone(),
                    secret,
                    "pw".into(),
                )
                .unwrap_or_else(|e| {
                    panic!("{label}: recommended `{}` but embedding failed: {e}", r.method_id)
                });

                match crate::extract(r.method_id.clone(), stego, "pw".into()) {
                    Ok(Revealed::Text { text }) => assert_eq!(text.len(), 200),
                    other => panic!(
                        "{label}: recommended `{}` but it did not round-trip: {other:?}",
                        r.method_id
                    ),
                }
            }
        }
    }

    #[test]
    fn the_top_pick_for_a_binary_cover_keeps_the_cover() {
        // Hiding in a PDF must hand back a PDF, not generated prose.
        let cover = pdf();
        let recs = plan_embedding(cover.clone(), 3000);
        let top = &recs[0];
        assert!(top.fits, "top pick must fit");
        assert!(
            top.preserves_cover,
            "top pick `{}` throws the cover away",
            top.method_id
        );
        assert_ne!(top.method_id, "mimic_words");

        // ...and the file it returns still starts with the original bytes.
        let stego = crate::embed(
            top.method_id.clone(),
            cover.clone(),
            crate::payload::Secret::Text { text: "hi".into() },
            "pw".into(),
        )
        .unwrap();
        assert!(
            stego.starts_with(b"%PDF-1.7"),
            "`{}` did not return a PDF",
            top.method_id
        );
    }

    #[test]
    fn text_methods_decline_binary_covers() {
        // These promise capacity only where `embed` can honour it.
        let recs = plan_embedding(pdf(), 100);
        for text_only in ["zero_width", "unicode_tags", "whitespace"] {
            assert!(
                recs.iter().all(|r| r.method_id != text_only),
                "{text_only} should not be offered for a binary cover"
            );
        }
    }
}
