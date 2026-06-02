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

#[test]
fn detect_lsb_flags_full_embedding() {
    let cover = gradient_png(96, 96);
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
    assert!(dirty.rs_regularity_gap < clean.rs_regularity_gap);
    assert!(
        dirty.sample_pair_rate > clean.sample_pair_rate,
        "SPA clean={} dirty={}",
        clean.sample_pair_rate,
        dirty.sample_pair_rate
    );
}
