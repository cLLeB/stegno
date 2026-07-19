//! Detectability benchmarking.
//!
//! "How risky is *this* method on *this* image?" — answered empirically. It
//! performs a real dry-run embed of random data with the chosen method, then
//! measures two things the sender actually cares about:
//!
//! * the rise in the LSB detector's confidence (clean cover vs. stego), and
//! * the image-quality cost (PSNR).
//!
//! Because it embeds *random* bytes under a throwaway key, it never touches the
//! user's real secret, and it works for any image method the registry has.

use crate::method::{EmbedOpts, Media};
use crate::payload::Secret;
use crate::seed::{derive_seed, Slot};
use crate::{analysis, image_io, registry, StegnoError};

/// The outcome of a detectability dry-run.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DetectabilityReport {
    pub method_id: String,
    /// Detector ML-confidence on the clean cover, [0,1].
    pub clean_confidence: f64,
    /// Detector ML-confidence after embedding, [0,1].
    pub stego_confidence: f64,
    /// stego − clean (higher ⇒ this embed stands out more).
    pub delta: f64,
    /// Peak signal-to-noise ratio of the stego vs. cover, dB (higher ⇒ subtler).
    pub psnr_db: f64,
    /// "low" / "moderate" / "high" overall detectability verdict.
    pub verdict: String,
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("OS RNG unavailable");
    v
}

fn verdict_for(delta: f64, stego_conf: f64) -> &'static str {
    // Blend absolute detector confidence with how much the embed moved it.
    let score = stego_conf.max(delta.max(0.0));
    if score < 0.25 {
        "low"
    } else if score < 0.55 {
        "moderate"
    } else {
        "high"
    }
}

/// Estimate how detectable embedding `payload_len` random bytes with `method_id`
/// would be on `cover`. Image methods only.
#[uniffi::export]
pub fn detectability(
    method_id: String,
    cover: Vec<u8>,
    payload_len: u64,
) -> Result<DetectabilityReport, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;
    if m.media() != Media::Image {
        return Err(StegnoError::Internal(
            "detectability is defined for image methods only".into(),
        ));
    }

    // Detector baseline on the clean cover.
    let cover_img = image_io::decode_rgba(&cover)?;
    let clean = crate::detect_lsb(cover.clone())?.ml_confidence;

    // Dry-run embed of random bytes under a throwaway passphrase.
    let pass = "benchmark-throwaway-key";
    let secret = Secret::File {
        name: "b".into(),
        bytes: rand_bytes(payload_len as usize),
    };
    let inner = crate::payload::serialize_secret(&secret);
    let sealed =
        crate::crypto::seal(&inner, pass).map_err(|_| StegnoError::Internal("seal".into()))?;
    let framed = crate::payload::frame(&sealed);
    let opts = EmbedOpts {
        seed: Some(derive_seed(pass, Slot::Primary)),
    };
    let stego = m.embed(&cover, &framed, &opts)?;

    // Detector after embedding, plus the quality cost.
    let stego_conf = crate::detect_lsb(stego.clone())?.ml_confidence;
    let stego_img = image_io::decode_rgba(&stego)?;
    let psnr_db = if stego_img.width == cover_img.width && stego_img.height == cover_img.height {
        analysis::psnr(&cover_img, &stego_img)
    } else {
        f64::INFINITY
    };

    let delta = stego_conf - clean;
    Ok(DetectabilityReport {
        method_id,
        clean_confidence: clean,
        stego_confidence: stego_conf,
        delta,
        psnr_db,
        verdict: verdict_for(delta, stego_conf).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{encode_png, RgbaImage};

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

    #[test]
    fn produces_a_report_for_image_methods() {
        let r = detectability("lsb_seeded".into(), cover(96, 96), 200).unwrap();
        assert_eq!(r.method_id, "lsb_seeded");
        assert!((0.0..=1.0).contains(&r.clean_confidence));
        assert!((0.0..=1.0).contains(&r.stego_confidence));
        assert!(r.psnr_db > 20.0, "psnr unexpectedly low: {}", r.psnr_db);
        assert!(["low", "moderate", "high"].contains(&r.verdict.as_str()));
    }

    #[test]
    fn larger_payload_lowers_psnr() {
        // More embedded bytes = more pixel changes = lower PSNR (deterministic).
        let small = detectability("lsb_image".into(), cover(128, 128), 100).unwrap();
        let large = detectability("lsb_image".into(), cover(128, 128), 3000).unwrap();
        assert!(
            large.psnr_db < small.psnr_db,
            "large={} small={}",
            large.psnr_db,
            small.psnr_db
        );
    }

    #[test]
    fn rejects_non_image_methods() {
        assert!(detectability("zero_width".into(), cover(64, 64), 10).is_err());
    }

    #[test]
    fn rejects_over_capacity() {
        assert!(detectability("lsb_image".into(), cover(32, 32), 1_000_000).is_err());
    }
}
