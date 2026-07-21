//! End-to-end test for the Reed–Solomon robustness layer (`embed_robust`).
//!
//! Proves the headline property: a stego image whose pixel LSBs are partly
//! corrupted after embedding still yields the exact hidden message, whereas the
//! same corruption defeats a non-FEC embed.

use stegno_core::image_io::{decode_rgba, encode_png};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed, embed_robust, extract};

fn cover(w: u32, h: u32) -> Vec<u8> {
    // Mildly textured so the LSB plane isn't pathologically uniform.
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 29) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(90);
        px[2] = v.wrapping_mul(5);
        px[3] = 255;
    }
    encode_png(&stegno_core::image_io::RgbaImage {
        width: w,
        height: h,
        pixels,
    })
    .unwrap()
}

/// Flip the LSB of `count` R-channel bytes, starting at pixel `start`, in a
/// decoded-then-reencoded copy of `stego`. This models real carrier corruption
/// at the sample level (a re-encode / light edit), not random file-byte noise.
fn corrupt_pixel_lsbs(stego: &[u8], start: usize, count: usize) -> Vec<u8> {
    let mut img = decode_rgba(stego).unwrap();
    for k in 0..count {
        let pixel = start + k;
        let idx = pixel * 4; // R channel
        if idx < img.pixels.len() {
            img.pixels[idx] ^= 1;
        }
    }
    encode_png(&img).unwrap()
}

#[test]
fn fec_survives_pixel_corruption_that_breaks_plain_embed() {
    let msg = "meet at the old pier, 23:00 — bring the blue folder";
    let pass = "correct-horse-battery-staple";

    // Corrupt a run of LSBs well past the 11-byte frame header (~30 pixels in),
    // sized within the level-3 budget (t = 32 byte-errors per 255-block).
    let corrupt_start = 60;
    let corrupt_count = 20;

    // --- Robust embed recovers exactly ---
    let robust_stego = embed_robust(
        "lsb_image".into(),
        cover(200, 200),
        Secret::Text { text: msg.into() },
        pass.into(),
        3,
    )
    .unwrap();
    let damaged = corrupt_pixel_lsbs(&robust_stego, corrupt_start, corrupt_count);
    let revealed = extract("lsb_image".into(), damaged, pass.into()).unwrap();
    match revealed {
        Revealed::Text { text } => assert_eq!(text, msg),
        other => panic!("FEC embed failed to recover: {other:?}"),
    }

    // --- Plain embed, same corruption, must NOT silently return the message ---
    let plain_stego = embed(
        "lsb_image".into(),
        cover(200, 200),
        Secret::Text { text: msg.into() },
        pass.into(),
    )
    .unwrap();
    let damaged_plain = corrupt_pixel_lsbs(&plain_stego, corrupt_start, corrupt_count);
    let plain_result = extract("lsb_image".into(), damaged_plain, pass.into());
    match plain_result {
        Ok(Revealed::Text { text }) => {
            assert_ne!(text, msg, "corruption should have damaged the plain payload")
        }
        Ok(Revealed::None) | Err(_) => { /* expected: auth fails or no data */ }
        Ok(other) => panic!("unexpected plain result: {other:?}"),
    }
}

#[test]
fn fec_clean_roundtrip_matches_plain() {
    let msg = "no corruption here";
    let pass = "pw12345";
    for level in 1u8..=3 {
        let stego = embed_robust(
            "lsb_image".into(),
            cover(160, 160),
            Secret::Text { text: msg.into() },
            pass.into(),
            level,
        )
        .unwrap();
        let revealed = extract("lsb_image".into(), stego, pass.into()).unwrap();
        assert!(
            matches!(revealed, Revealed::Text { text } if text == msg),
            "level {level} clean roundtrip failed"
        );
    }
}

#[test]
fn fec_wrong_passphrase_still_fails() {
    let stego = embed_robust(
        "lsb_image".into(),
        cover(160, 160),
        Secret::Text { text: "x".into() },
        "right".into(),
        2,
    )
    .unwrap();
    // FEC repairs bytes, but the AES-GCM tag must still reject a wrong key.
    assert!(matches!(
        extract("lsb_image".into(), stego, "wrong".into()),
        Err(stegno_core::StegnoError::AuthFailed)
    ));
}
