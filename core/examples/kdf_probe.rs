//! Cost of candidate Argon2id profiles on this machine.
//!
//! Run: `cargo run --release -p stegno-core --example kdf_probe`
//!
//! The engine ships one fixed profile, so it has to serve both a desktop and a
//! mid-range phone. Phones land roughly 3–4x slower than a desktop, so a profile
//! is only viable if `desktop x 4` is still a tolerable wait.

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

fn time_profile(memory_kib: u32, iterations: u32) -> f64 {
    let params = Params::new(memory_kib, iterations, 1, Some(32)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    let start = Instant::now();
    argon
        .hash_password_into(b"benchmark passphrase", &[0x5A; 16], &mut key)
        .unwrap();
    start.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    println!("{:>9} {:>5}  {:>9}  {:>12}  {:>9}", "memory", "iter", "desktop", "phone (x3.5)", "guesses/s");
    for (m, t) in [
        (19_456u32, 2u32), // the old shipped profile — OWASP interactive minimum
        (32_768, 2),
        (32_768, 3),
        (47_104, 2),
        (47_104, 3),
        (65_536, 3),
    ] {
        // Two runs, keep the faster: first touch pays for page allocation.
        let ms = time_profile(m, t).min(time_profile(m, t));
        println!(
            "{:>6} KiB {:>5}  {:>7.0} ms  {:>10.0} ms  {:>9.0}",
            m,
            t,
            ms,
            ms * 3.5,
            1000.0 / ms
        );
    }
}
