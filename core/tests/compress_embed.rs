//! End-to-end tests for the compression pre-pass and the combined
//! compression + FEC pipeline exposed via `embed_advanced`.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{capacity, embed_advanced, extract};

fn cover(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 31) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(40);
        px[2] = v.wrapping_mul(7);
        px[3] = 255;
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

#[test]
fn compressed_payload_roundtrips() {
    // Highly compressible text.
    let msg = "PAYLOAD ".repeat(400);
    let stego = embed_advanced(
        "lsb_seeded".into(),
        cover(128, 128),
        Secret::Text { text: msg.clone() },
        "pw".into(),
        0,
        true,
    )
    .unwrap();
    let revealed = extract("lsb_seeded".into(), stego, "pw".into()).unwrap();
    assert!(matches!(revealed, Revealed::Text { text } if text == msg));
}

#[test]
fn compression_lets_a_larger_secret_fit() {
    // A cover just big enough that the *compressed* secret fits but the raw one
    // would not.
    let c = cover(64, 64);
    let usable = capacity("lsb_seeded".into(), c.clone()).unwrap() as usize;

    // Build a very compressible secret larger than raw capacity.
    let msg = "A".repeat(usable + 500);
    // Without compression: must fail (too big).
    let raw = embed_advanced(
        "lsb_seeded".into(),
        c.clone(),
        Secret::Text { text: msg.clone() },
        "pw".into(),
        0,
        false,
    );
    assert!(raw.is_err(), "raw secret unexpectedly fit");

    // With compression: fits and roundtrips.
    let stego = embed_advanced(
        "lsb_seeded".into(),
        c,
        Secret::Text { text: msg.clone() },
        "pw".into(),
        0,
        true,
    )
    .unwrap();
    let revealed = extract("lsb_seeded".into(), stego, "pw".into()).unwrap();
    assert!(matches!(revealed, Revealed::Text { text } if text == msg));
}

#[test]
fn compression_and_fec_together_roundtrip() {
    let msg = "log line 42: everything nominal. ".repeat(60);
    let stego = embed_advanced(
        "lsb_seeded".into(),
        cover(200, 200),
        Secret::Text { text: msg.clone() },
        "pw".into(),
        2, // FEC level 2
        true, // + compression
    )
    .unwrap();
    let revealed = extract("lsb_seeded".into(), stego, "pw".into()).unwrap();
    assert!(matches!(revealed, Revealed::Text { text } if text == msg));
}

#[test]
fn incompressible_secret_still_roundtrips_with_compress_flag() {
    // Random-ish bytes won't shrink; the engine must store them uncompressed and
    // still recover them.
    let bytes: Vec<u8> = (0..1024).map(|i| ((i * 2654435761u64) >> 16) as u8).collect();
    let stego = embed_advanced(
        "lsb_seeded".into(),
        cover(160, 160),
        Secret::File { name: "rand.bin".into(), bytes: bytes.clone() },
        "pw".into(),
        0,
        true,
    )
    .unwrap();
    let revealed = extract("lsb_seeded".into(), stego, "pw".into()).unwrap();
    assert!(matches!(revealed, Revealed::File { bytes: b, .. } if b == bytes));
}
