//! How the region machinery scales with cover size.
//!
//! Run with `cargo run --release -p stegno-core --example scale_probe`.
//!
//! Slot positions used to be a materialized Fisher–Yates shuffle — one `u32`
//! per slot, built once per cover and again for every layout a reveal probed.
//! That is invisible on a thumbnail and crippling on a real photo. This probe
//! exists so the claim is checkable rather than asserted: it embeds a real
//! decoy pair and reveals it at three ordinary camera resolutions, printing what
//! the shuffle *would* have cost alongside the measured time.
//!
//! With [`stegno_core::prp`] computing positions instead, a 12-megapixel photo
//! went from 9.2 s embed / 18.9 s reveal to well under a second, and the 137 MB
//! allocation disappeared entirely.

use std::time::Instant;
use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed_composite, extract_composite, ByteChunk, Recipient};

fn photo(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = (i % 251) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(70);
        px[2] = v.wrapping_mul(3);
        px[3] = 255;
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

fn entry(text: &str, pass: &str) -> Recipient {
    Recipient {
        secret: Secret::Text { text: text.into() },
        passphrase: pass.into(),
    }
}

fn main() {
    for (label, w, h) in [("2 MP", 1600u32, 1200u32), ("6 MP", 3000, 2000), ("12 MP", 4000, 3000)] {
        let slots = (w as u64) * (h as u64) * 3;
        // What a materialized Vec<u32> permutation would have cost, for scale.
        let was_mb = slots * 4 / 1_048_576;

        let t = Instant::now();
        let stego = embed_composite(
            vec![ByteChunk { bytes: photo(w, h) }],
            vec![entry("real", "a"), entry("decoy", "b")],
            0,
            false,
        )
        .unwrap();
        let embed_s = t.elapsed().as_secs_f64();

        let t = Instant::now();
        let revealed = extract_composite(stego, "b".into()).unwrap();
        let reveal_s = t.elapsed().as_secs_f64();
        assert!(matches!(revealed, Revealed::Text { .. }), "{label} lost the payload");

        println!(
            "{label:6} {slots:>10} slots  (a stored shuffle would be {was_mb:>4} MB)  \
             embed {embed_s:6.2}s  reveal {reveal_s:6.2}s"
        );
    }
}
