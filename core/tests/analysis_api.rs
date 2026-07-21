//! Steganalysis / quality metrics via the public API (Phase 5).

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::Secret;
use stegno_core::{detect_lsb, embed, quality};

fn gradient_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        for x in 0..w {
            let o = ((y * w + x) * 4) as usize;
            let v = ((x * 255 / w) as u8).wrapping_add((y * 255 / h) as u8) & 0xFE;
            pixels[o] = v;
            pixels[o + 1] = v;
            pixels[o + 2] = v;
            pixels[o + 3] = 255;
        }
    }
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels,
    })
    .unwrap()
}

#[test]
fn quality_of_lsb_stego_is_high_psnr() {
    let cover = gradient_png(96, 96);
    let stego = embed(
        "lsb_image".into(),
        cover.clone(),
        Secret::Text {
            text: "tiny".into(),
        },
        "pw".into(),
    )
    .unwrap();
    let q = quality(cover, stego).unwrap();
    // A few changed LSBs → tiny error, very high PSNR, SSIM ~1.
    assert!(q.psnr_db > 40.0, "psnr {}", q.psnr_db);
    assert!(q.ssim > 0.99, "ssim {}", q.ssim);
    assert!(q.mse >= 0.0);
}

#[test]
fn quality_identical_is_perfect() {
    let img = gradient_png(48, 48);
    let q = quality(img.clone(), img).unwrap();
    assert_eq!(q.mse, 0.0);
    assert!(q.psnr_db.is_infinite());
    assert!((q.ssim - 1.0).abs() < 1e-9);
}

#[test]
fn quality_rejects_size_mismatch() {
    assert!(quality(gradient_png(32, 32), gradient_png(48, 48)).is_err());
}

/// A gradient with sensor-like noise, so the LSB plane looks like a real photo's.
///
/// [`gradient_png`] masks every LSB to zero, which is fine for PSNR/SSIM but
/// invalid input for LSB steganalysis: RS analysis reasons about natural image
/// statistics, and no natural image has a uniformly zero LSB plane. Measured on
/// that fixture the RS gap moves the *wrong way* (0.021 clean → 0.191 embedded),
/// while on any noisy image it separates cleanly (0.06–1.00 → ≈0).
fn noisy_png(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    let mut s = 0x1234_5678u32;
    for y in 0..h {
        for x in 0..w {
            let o = ((y * w + x) * 4) as usize;
            let base = (x * 255 / w) as i32;
            for c in 0..3 {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                let noise = (s % 9) as i32 - 4;
                pixels[o + c] = (base + (y * 255 / h) as i32 + noise).clamp(0, 255) as u8;
            }
            pixels[o + 3] = 255;
        }
    }
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels,
    })
    .unwrap()
}

#[test]
fn detect_lsb_flags_full_embedding() {
    let cover = noisy_png(96, 96);
    let cap = stegno_core::capacity("lsb_image".into(), cover.clone()).unwrap() as usize;
    // Fill most of the capacity with random bytes (leave margin for the file
    // name's framing overhead) to maximise LSB randomisation.
    let mut data = vec![0u8; cap.saturating_sub(32)];
    let mut s = 0x9E37_79B9u32;
    for b in data.iter_mut() {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        *b = s as u8;
    }
    let stego = embed(
        "lsb_image".into(),
        cover.clone(),
        Secret::File {
            name: "f".into(),
            bytes: data,
        },
        "pw".into(),
    )
    .unwrap();

    let clean = detect_lsb(cover).unwrap();
    let dirty = detect_lsb(stego).unwrap();
    assert!(
        dirty.chi_square_p > clean.chi_square_p,
        "clean={} dirty={}",
        clean.chi_square_p,
        dirty.chi_square_p
    );
    assert!(
        dirty.rs_regularity_gap < clean.rs_regularity_gap,
        "RS gap should collapse when the LSB plane is randomised: clean={} dirty={}",
        clean.rs_regularity_gap,
        dirty.rs_regularity_gap
    );
    // The headline verdict must move too, and a clean image must not be accused.
    assert!(
        clean.ml_confidence < 0.2,
        "clean image reported as {:.3} suspicious",
        clean.ml_confidence
    );
    assert!(
        dirty.ml_confidence > 0.7,
        "fully embedded image only reported as {:.3} suspicious",
        dirty.ml_confidence
    );
}

/// Sample-pair analysis is currently **wrong** and is excluded from the verdict.
///
/// SPA should estimate the LSB embedding rate: ≈0 for a clean image, rising
/// toward 1 as the plane is randomised. It does the opposite — on a noisy cover
/// it reads ≈0.78 clean and ≈0.14 when fully embedded, and it sits around 0.80
/// for ordinary untouched photos. At weight 0.4 that single number used to put
/// every clean image above 60% "suspicious".
///
/// It is excluded from [`stegno_core::DetectionReport::ml_confidence`] and from
/// the fingerprint ranking, and reported only as a raw diagnostic. This test
/// pins the defect so it cannot be quietly reintroduced: when the SPA solver is
/// reworked and validated, this test should start failing and be replaced with
/// the correct directional assertion.
#[test]
fn sample_pair_analysis_is_known_broken_and_unused() {
    let cover = noisy_png(96, 96);
    let stego = fully_embed(&cover);
    let clean = detect_lsb(cover).unwrap();
    let dirty = detect_lsb(stego).unwrap();

    assert!(
        clean.sample_pair_rate > 0.5,
        "SPA now reads {:.3} on a clean image — if it has been fixed, restore \
         the directional assertion and fold it back into ml_confidence",
        clean.sample_pair_rate
    );
    assert!(
        dirty.sample_pair_rate < clean.sample_pair_rate,
        "SPA direction changed (clean {:.3}, embedded {:.3}) — recheck whether \
         it is now trustworthy",
        clean.sample_pair_rate,
        dirty.sample_pair_rate
    );

    // Whatever SPA says, the verdict must not depend on it.
    assert!(clean.ml_confidence < 0.2, "a broken SPA leaked into the verdict");
}

/// Fill nearly all of a cover's LSB capacity with pseudo-random bytes.
fn fully_embed(cover: &[u8]) -> Vec<u8> {
    let cap = stegno_core::capacity("lsb_image".into(), cover.to_vec()).unwrap() as usize;
    let mut data = vec![0u8; cap.saturating_sub(32)];
    let mut s = 0x9E37_79B9u32;
    for b in data.iter_mut() {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        *b = s as u8;
    }
    embed(
        "lsb_image".into(),
        cover.to_vec(),
        Secret::File {
            name: "f".into(),
            bytes: data,
        },
        "pw".into(),
    )
    .unwrap()
}
