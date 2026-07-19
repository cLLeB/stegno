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
    /// A one-line rationale for the ranking.
    pub note: String,
}

/// Static detection-resistance tier per method id, from the engine's own
/// security notes. Unknown ids default to tier 1.
fn stealth_tier(id: &str) -> u8 {
    match id {
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
        let note = if !fits {
            format!("too small — needs {payload_len} bytes, holds {usable}")
        } else {
            format!(
                "{}; {:.0}% full",
                tier_label(tier),
                fill_ratio * 100.0
            )
        };

        recs.push(MethodRecommendation {
            method_id: m.id().to_string(),
            display_name: m.display_name().to_string(),
            media: format!("{:?}", media_of(&m)),
            usable_bytes: usable,
            fits,
            fill_ratio,
            stealth_tier: tier,
            note,
        });
    }

    recs.sort_by(|a, b| {
        // Fitting methods first.
        b.fits
            .cmp(&a.fits)
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
        let fitting: Vec<_> = recs.iter().filter(|r| r.fits).collect();
        assert!(fitting.len() >= 2);
        // Stealth tier is non-increasing across the fitting prefix.
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
}
