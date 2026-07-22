//! Do "Toughness" (Reed–Solomon FEC) and "Squeeze" (compression) actually work?
//!
//! Run: `cargo run --release -p stegno-core --example toughness_probe`
//!
//! Toughness claims the payload survives a bounded amount of carrier damage.
//! The only way to know is to damage a carrier and try to read it back, so this
//! embeds at each level, corrupts a measured fraction of the bytes, and reports
//! what still decodes. Squeeze claims it raises effective capacity for
//! compressible payloads and steps aside when it would not help — likewise
//! checked by measuring, not by reading the flag.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed_advanced, extract};

/// Deterministic pseudo-random stream, so runs are comparable.
struct Rng(u32);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

fn photo(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    let mut r = Rng(0x1234_5678);
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            let base = (x * 200 / w.max(1)) as i32 + (y * 40 / h.max(1)) as i32;
            for c in 0..3 {
                let noise = (r.next() % 9) as i32 - 4;
                pixels[i + c] = (base + noise).clamp(0, 255) as u8;
            }
            pixels[i + 3] = 255;
        }
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

/// Flip `pct`% of the trailing region's bytes — where append_eof puts the frame.
fn corrupt_tail(data: &[u8], region: usize, pct: usize, seed: u32) -> Vec<u8> {
    let mut out = data.to_vec();
    let n = out.len();
    let start = n.saturating_sub(region);
    let hits = region * pct / 100;
    let mut r = Rng(seed);
    for _ in 0..hits {
        let at = start + (r.next() as usize % region.max(1));
        if at < n {
            out[at] ^= 0xFF;
        }
    }
    out
}

fn recovers(method: &str, stego: &[u8], want: &str) -> bool {
    matches!(
        extract(method.into(), stego.to_vec(), "pw".into()),
        Ok(Revealed::Text { ref text }) if text == want
    )
}

fn main() {
    let secret = "the payload that has to survive".repeat(20);
    let cover = photo(256, 256);

    // ---- Toughness: contiguous carrier (append_eof) so damage is measurable.
    println!("TOUGHNESS — bytes of the hidden frame corrupted, does it still read?\n");
    println!("{:<10} {:>9} {:>7} {:>7} {:>7} {:>7} {:>7}", "level", "size", "0%", "1%", "3%", "6%", "12%");
    for level in 0u8..=3 {
        let stego = embed_advanced(
            "append_eof".into(),
            cover.clone(),
            Secret::Text { text: secret.clone() },
            "pw".into(),
            level,
            false,
        )
        .unwrap();
        let region = stego.len() - cover.len();
        let mut row = format!("{:<10} {:>9}", level, region);
        for pct in [0usize, 1, 3, 6, 12] {
            let damaged = corrupt_tail(&stego, region, pct, 0xABCD + pct as u32);
            row.push_str(&format!("{:>7}", if recovers("append_eof", &damaged, &secret) { "ok" } else { "--" }));
        }
        println!("{row}");
    }

    // ---- Toughness on a real LSB carrier: flip random pixel LSBs.
    println!("\nTOUGHNESS on image LSB — % of pixel LSBs flipped\n");
    println!("{:<10} {:>7} {:>7} {:>7} {:>7}", "level", "0%", "0.5%", "1%", "3%");
    for level in [0u8, 3] {
        let stego = embed_advanced(
            "lsb_seeded".into(),
            cover.clone(),
            Secret::Text { text: secret.clone() },
            "pw".into(),
            level,
            false,
        )
        .unwrap();
        let mut row = format!("{:<10}", level);
        for pct in [0.0f64, 0.5, 1.0, 3.0] {
            let mut img = stegno_core::image_io::decode_rgba(&stego).unwrap();
            let total = img.pixels.len();
            let hits = (total as f64 * pct / 100.0) as usize;
            let mut r = Rng(0x9999);
            for _ in 0..hits {
                let at = r.next() as usize % total;
                img.pixels[at] ^= 1;
            }
            let damaged = encode_png(&img).unwrap();
            row.push_str(&format!("{:>7}", if recovers("lsb_seeded", &damaged, &secret) { "ok" } else { "--" }));
        }
        println!("{row}");
    }

    // ---- Squeeze: does it actually buy capacity, and is it skipped when useless?
    println!("\nSQUEEZE — embedded frame size with compression off vs on\n");
    println!("{:<22} {:>10} {:>10} {:>10}", "payload", "off", "on", "change");
    let cases: Vec<(&str, String)> = vec![
        ("highly compressible", "A".repeat(4000)),
        ("natural text", "the quick brown fox jumps over the lazy dog. ".repeat(90)),
        // Random *letters* are only ~4.7 bits each, so DEFLATE still shrinks
        // them by a third — genuinely incompressible input needs full-range
        // bytes, tested separately below.
        ("random letters", {
            let mut r = Rng(0x2222);
            (0..4000).map(|_| char::from(b'a' + (r.next() % 26) as u8)).collect()
        }),
    ];
    for (label, text) in &cases {
        let mut sizes = [0usize; 2];
        for (i, comp) in [false, true].iter().enumerate() {
            let stego = embed_advanced(
                "append_eof".into(),
                cover.clone(),
                Secret::Text { text: text.clone() },
                "pw".into(),
                0,
                *comp,
            )
            .unwrap();
            sizes[i] = stego.len() - cover.len();
            // Must still round-trip whichever way.
            assert!(recovers("append_eof", &stego, text), "{label} (compress={comp}) failed to recover");
        }
        let delta = sizes[1] as f64 / sizes[0] as f64 * 100.0 - 100.0;
        println!("{label:<22} {:>10} {:>10} {:>9.1}%", sizes[0], sizes[1], delta);
    }

    // Truly incompressible input: full-range random bytes, which DEFLATE cannot
    // shrink. The claim is that compression is *skipped* rather than applied at
    // a loss, so the frame must not grow.
    let mut r = Rng(0x7777);
    let noise: Vec<u8> = (0..4000).map(|_| (r.next() % 256) as u8).collect();
    let mut sizes = [0usize; 2];
    for (i, comp) in [false, true].iter().enumerate() {
        let stego = embed_advanced(
            "append_eof".into(),
            cover.clone(),
            Secret::File { name: "noise.bin".into(), bytes: noise.clone() },
            "pw".into(),
            0,
            *comp,
        )
        .unwrap();
        sizes[i] = stego.len() - cover.len();
        match extract("append_eof".into(), stego, "pw".into()) {
            Ok(Revealed::File { bytes, .. }) if bytes == noise => {}
            other => panic!("incompressible payload did not round-trip: {other:?}"),
        }
    }
    let delta = sizes[1] as i64 - sizes[0] as i64;
    println!(
        "{:<22} {:>10} {:>10} {:>+9} bytes  {}",
        "random bytes",
        sizes[0],
        sizes[1],
        delta,
        if delta <= 0 { "skipped correctly" } else { "GREW — compression applied at a loss" }
    );
}
