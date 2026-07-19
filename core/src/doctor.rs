//! Engine self-test ("doctor").
//!
//! Runs a real hide→reveal round-trip of a known secret through *every*
//! registered method, choosing a cover that matches each method's medium, and
//! reports pass/fail plus capacity. It's a one-call health check for a build
//! (does the shipped `.so` / binary actually work end-to-end?) and doubles as a
//! broad integration test.

use crate::image_io::{encode_png, RgbaImage};
use crate::method::Media;
use crate::payload::{Revealed, Secret};
use crate::{capacity, embed, extract, registry};

/// Health of one method after a round-trip attempt.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SelfTestResult {
    pub method_id: String,
    pub media: String,
    /// True if the secret was hidden and recovered identically.
    pub ok: bool,
    /// Usable capacity of the test cover (0 if it couldn't be computed).
    pub usable_bytes: u64,
    /// "ok", or a short reason for failure/skip.
    pub detail: String,
}

/// A textured 256×256 RGBA cover (varied local content for edge/PVD methods).
fn image_cover() -> Vec<u8> {
    let (w, h) = (256u32, 256u32);
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

fn text_cover() -> Vec<u8> {
    "The quick brown fox jumps over the lazy dog. "
        .repeat(20)
        .into_bytes()
}

/// A minimal valid 16-bit mono PCM WAV with a short ramp, for audio methods.
fn wav_cover() -> Vec<u8> {
    let samples: u32 = 4096;
    let data_len = samples * 2;
    let mut v = Vec::with_capacity((44 + data_len) as usize);
    v.extend_from_slice(b"RIFF");
    v.extend_from_slice(&(36 + data_len).to_le_bytes());
    v.extend_from_slice(b"WAVE");
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    v.extend_from_slice(&1u16.to_le_bytes()); // PCM
    v.extend_from_slice(&1u16.to_le_bytes()); // mono
    v.extend_from_slice(&44100u32.to_le_bytes()); // sample rate
    v.extend_from_slice(&(44100u32 * 2).to_le_bytes()); // byte rate
    v.extend_from_slice(&2u16.to_le_bytes()); // block align
    v.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    v.extend_from_slice(b"data");
    v.extend_from_slice(&data_len.to_le_bytes());
    for i in 0..samples {
        v.extend_from_slice(&((i as i16).wrapping_mul(7)).to_le_bytes());
    }
    v
}

fn cover_for(media: Media) -> Vec<u8> {
    match media {
        Media::Image => image_cover(),
        Media::Text => text_cover(),
        Media::Audio => wav_cover(),
        Media::File => image_cover(),
    }
}

/// Round-trip a known secret through every method and report the results.
#[uniffi::export]
pub fn run_self_test() -> Vec<SelfTestResult> {
    const PASS: &str = "self-test-passphrase";
    let secret_text = "stegno self-test payload";

    let mut results = Vec::new();
    for m in registry::registry() {
        let id = m.id().to_string();
        let media = format!("{:?}", m.media());
        let cover = cover_for(m.media());

        let usable = capacity(id.clone(), cover.clone()).unwrap_or(0);

        let (ok, detail) = match embed(
            id.clone(),
            cover.clone(),
            Secret::Text { text: secret_text.into() },
            PASS.into(),
        ) {
            Ok(stego) => match extract(id.clone(), stego, PASS.into()) {
                Ok(Revealed::Text { text }) if text == secret_text => (true, "ok".to_string()),
                Ok(other) => (false, format!("mismatch: {other:?}")),
                Err(e) => (false, format!("extract: {e}")),
            },
            Err(e) => (false, format!("embed: {e}")),
        };

        results.push(SelfTestResult {
            method_id: id,
            media,
            ok,
            usable_bytes: usable,
            detail,
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_passes_self_test() {
        let results = run_self_test();
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.ok, "method {} failed self-test: {}", r.method_id, r.detail);
        }
    }

    #[test]
    fn covers_are_all_media_kinds() {
        // Sanity: every synthesized cover is non-trivially sized and decodes/parses
        // for its intended method family (covered indirectly by the roundtrip).
        assert!(image_cover().len() > 100);
        assert!(text_cover().len() > 100);
        assert!(wav_cover().len() > 100);
    }
}
