//! Does the RS regularity gap separate clean from embedded, and on what images?
//!
//! Run: `cargo run --release -p stegno-core --example rs_probe`

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::Secret;
use stegno_core::{capacity, detect_lsb, embed};

/// A perfectly smooth synthetic gradient — no sensor noise anywhere.
fn gradient(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            pixels[i] = (x * 255 / w.max(1)) as u8;
            pixels[i + 1] = (y * 255 / h.max(1)) as u8;
            pixels[i + 2] = ((x + y) * 255 / (w + h).max(1)) as u8;
            pixels[i + 3] = 255;
        }
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

/// The old test fixture: a grey gradient with every LSB forced to zero. No
/// natural image looks like this, and RS analysis assumes natural statistics.
fn zero_lsb_gradient(w: u32, h: u32) -> Vec<u8> {
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
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

/// The same gradient with a few levels of pseudo-random noise, as any real
/// camera sensor produces.
fn noisy(w: u32, h: u32, amp: i32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    let mut s = 0x1234_5678u32;
    let mut rnd = || {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        (s % (2 * amp as u32 + 1)) as i32 - amp
    };
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            let base = [
                (x * 255 / w.max(1)) as i32,
                (y * 255 / h.max(1)) as i32,
                ((x + y) * 255 / (w + h).max(1)) as i32,
            ];
            for c in 0..3 {
                pixels[i + c] = (base[c] + rnd()).clamp(0, 255) as u8;
            }
            pixels[i + 3] = 255;
        }
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

fn fill(cover: &[u8]) -> Vec<u8> {
    let cap = capacity("lsb_image".into(), cover.to_vec()).unwrap() as usize;
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
        Secret::File { name: "f".into(), bytes: data },
        "pw".into(),
    )
    .unwrap()
}

fn main() {
    for (label, cover) in [
        ("zeroed LSB plane ", zero_lsb_gradient(96, 96)),
        ("smooth gradient  ", gradient(96, 96)),
        ("noise amp 1      ", noisy(96, 96, 1)),
        ("noise amp 4      ", noisy(96, 96, 4)),
        ("noise amp 12     ", noisy(256, 256, 12)),
    ] {
        let clean = detect_lsb(cover.clone()).unwrap();
        let dirty = detect_lsb(fill(&cover)).unwrap();
        let ok = if dirty.rs_regularity_gap < clean.rs_regularity_gap { "separates" } else { "NO SEPARATION" };
        println!(
            "{label} RS clean {:>7.4} -> embedded {:>7.4}   chi {:>5.3} -> {:>5.3}   conf {:>5.3} -> {:>5.3}   {ok}",
            clean.rs_regularity_gap,
            dirty.rs_regularity_gap,
            clean.chi_square_p,
            dirty.chi_square_p,
            clean.ml_confidence,
            dirty.ml_confidence,
        );
    }
}
