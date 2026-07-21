//! Authenticated encryption: Argon2id key derivation + AES-256-GCM.
//!
//! Wire format of a sealed blob:
//! `kdf_id(1) | salt(16) | nonce(12) | ciphertext+tag`.
//!
//! The one-byte `kdf_id` names the Argon2id cost profile used, so the work
//! factor can be raised later without orphaning anything sealed today: a blob
//! carries the recipe for opening itself. Before it existed the parameters were
//! hardcoded at both ends, which meant strengthening them would silently break
//! every existing file — the reason they had been left at the bare minimum.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KDF_ID_LEN: usize = 1;

/// Overhead added by `seal` on top of the plaintext length.
pub const CRYPTO_OVERHEAD: usize = KDF_ID_LEN + SALT_LEN + NONCE_LEN + TAG_LEN;

/// An Argon2id cost profile, identified by the byte stored in every blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfProfile {
    pub id: u8,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (passes).
    pub iterations: u32,
}

/// OWASP's *minimum* interactive profile. Retained only so older blobs open.
const KDF_MINIMAL: KdfProfile = KdfProfile { id: 1, memory_kib: 19_456, iterations: 2 };

/// The profile new secrets are sealed with: 46 MiB, three passes.
///
/// The previous 19 MiB / 2 passes is the floor OWASP publishes for interactive
/// use. On a current desktop it finishes in ~35–50 ms — roughly 21 guesses per
/// second per core for anyone brute-forcing a passphrase offline, which is why
/// the built-in benchmark called it weak. That warning was accurate and
/// unactionable, because the cost was fixed in the binary.
///
/// One profile has to serve both a desktop and a phone, and phones run these
/// about 3–4x slower. Measured here (`cargo run --release --example kdf_probe`):
///
/// | profile        | desktop | phone (est.) | guesses/s |
/// |----------------|---------|--------------|-----------|
/// | 19 MiB, t=2    |   49 ms |       170 ms |        21 |
/// | 46 MiB, t=3    |  188 ms |       660 ms |         5 |
/// | 64 MiB, t=3    |  444 ms |      1550 ms |         2 |
///
/// 64 MiB is stronger still, but a reveal that stalls for over a second on a
/// phone is a cost paid on every single use. 46 MiB / t=3 quarters an attacker's
/// throughput while staying under a second on mobile.
const KDF_STRONG: KdfProfile = KdfProfile { id: 2, memory_kib: 47_104, iterations: 3 };

/// The profile used for new material.
pub const KDF_CURRENT: KdfProfile = KDF_STRONG;

fn profile_by_id(id: u8) -> Option<KdfProfile> {
    match id {
        1 => Some(KDF_MINIMAL),
        2 => Some(KDF_STRONG),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("crypto input too short")]
    TooShort,
    #[error("key derivation failed")]
    Kdf,
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    profile: KdfProfile,
) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(profile.memory_kib, profile.iterations, 1, Some(32))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("OS RNG unavailable");
    v
}

/// Encrypt `plaintext` under a key derived from `passphrase`.
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let salt = rand_bytes(SALT_LEN);
    let nonce_bytes = rand_bytes(NONCE_LEN);
    let key = derive_key(passphrase, &salt, KDF_CURRENT)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CryptoError::AuthFailed)?;
    let mut out = Vec::with_capacity(CRYPTO_OVERHEAD - TAG_LEN + ct.len());
    out.push(KDF_CURRENT.id);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Measured cost of the Argon2id key-derivation on this device, plus a verdict
/// on whether it hits a sane interactive target.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KdfBenchmark {
    /// Wall-clock milliseconds for one key derivation.
    pub millis: f64,
    /// Argon2id memory cost in KiB (the shipped parameter).
    pub memory_kib: u32,
    /// Argon2id time cost / iterations (the shipped parameter).
    pub iterations: u32,
    /// How long each attacker guess costs on this device: "weak" (<50 ms),
    /// "ok" (50–1000 ms), or "slow" (>1000 ms, painful to use).
    pub verdict: String,
    /// Plain-language reading of the number, since the verdict alone gives no
    /// sense of what it means or what to do about it.
    pub explanation: String,
}

/// Time one Argon2id derivation with the shipped parameters.
///
/// The figure is how long *one* passphrase guess costs an attacker with
/// comparable hardware, so slower is stronger. It says nothing about the
/// strength of any particular passphrase — that is what
/// [`crate::passphrase`] estimates.
#[uniffi::export]
pub fn benchmark_kdf() -> KdfBenchmark {
    let salt = [0x5Au8; SALT_LEN];
    let start = std::time::Instant::now();
    let _ = derive_key("benchmark passphrase", &salt, KDF_CURRENT);
    let millis = start.elapsed().as_secs_f64() * 1000.0;
    let rate = if millis > 0.0 { 1000.0 / millis } else { f64::INFINITY };
    // Below ten a whole number rounds away the distinction between 1.4 and 9.4.
    let guesses_per_sec = if rate < 10.0 {
        format!("{rate:.1}")
    } else {
        format!("{rate:.0}")
    };

    let (verdict, explanation) = if millis < 50.0 {
        (
            "weak",
            format!(
                "This device derives a key in {millis:.0} ms, so an attacker with similar \
                 hardware could try about {guesses_per_sec} passphrases per second per core. \
                 Use a long passphrase."
            ),
        )
    } else if millis <= 1000.0 {
        (
            "ok",
            format!(
                "A key takes {millis:.0} ms here, holding an attacker to roughly \
                 {guesses_per_sec} guesses per second per core."
            ),
        )
    } else {
        (
            "slow",
            format!(
                "A key takes {millis:.0} ms here — very costly to attack, but hiding and \
                 revealing will feel sluggish on this device."
            ),
        )
    };

    KdfBenchmark {
        millis,
        memory_kib: KDF_CURRENT.memory_kib,
        iterations: KDF_CURRENT.iterations,
        verdict: verdict.to_string(),
        explanation,
    }
}

/// Decrypt a blob produced by `seal`. Wrong passphrase or tampering -> AuthFailed.
pub fn open(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < CRYPTO_OVERHEAD {
        return Err(CryptoError::TooShort);
    }
    // The leading byte names the cost profile this blob was sealed with, so a
    // stronger default never orphans anything sealed earlier.
    let profile = profile_by_id(blob[0]).ok_or(CryptoError::AuthFailed)?;
    let body = &blob[KDF_ID_LEN..];
    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &body[SALT_LEN + NONCE_LEN..];
    let key = derive_key(passphrase, salt, profile)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob must carry the recipe for opening itself, so the work factor can
    /// be raised later without orphaning anything sealed today. Without this,
    /// strengthening the KDF silently breaks every existing file — which is why
    /// it had been left at OWASP's bare minimum.
    #[test]
    fn a_blob_records_the_profile_that_sealed_it() {
        let blob = seal(b"secret", "pw").unwrap();
        assert_eq!(blob[0], KDF_CURRENT.id, "profile id must lead the blob");

        // A blob sealed under the older, weaker profile still opens.
        let salt = rand_bytes(SALT_LEN);
        let nonce = rand_bytes(NONCE_LEN);
        let key = derive_key("pw", &salt, KDF_MINIMAL).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), b"older secret".as_ref()).unwrap();
        let mut legacy = vec![KDF_MINIMAL.id];
        legacy.extend_from_slice(&salt);
        legacy.extend_from_slice(&nonce);
        legacy.extend_from_slice(&ct);
        assert_eq!(open(&legacy, "pw").unwrap(), b"older secret");
    }

    #[test]
    fn an_unknown_profile_is_rejected_rather_than_guessed() {
        let mut blob = seal(b"secret", "pw").unwrap();
        blob[0] = 0xFE;
        assert_eq!(open(&blob, "pw"), Err(CryptoError::AuthFailed));
    }

    #[test]
    fn the_shipped_profile_is_stronger_than_the_owasp_floor() {
        assert!(
            KDF_CURRENT.memory_kib > KDF_MINIMAL.memory_kib
                || KDF_CURRENT.iterations > KDF_MINIMAL.iterations,
            "the default must not regress to the interactive minimum"
        );
    }

    #[test]
    fn the_benchmark_explains_itself() {
        let b = benchmark_kdf();
        assert_eq!(b.memory_kib, KDF_CURRENT.memory_kib);
        assert!(!b.explanation.is_empty(), "a bare verdict is not actionable");
        // Every branch must state the measured cost, whichever verdict it gives
        // — a debug build lands on "slow", a release build on "ok" or "weak".
        assert!(
            b.explanation.contains(" ms"),
            "explanation should quote the measured time: {}",
            b.explanation
        );
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let blob = seal(b"hello world", "correct horse").unwrap();
        let out = open(&blob, "correct horse").unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"secret", "right").unwrap();
        assert_eq!(open(&blob, "wrong"), Err(CryptoError::AuthFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = seal(b"secret", "pw").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert_eq!(open(&blob, "pw"), Err(CryptoError::AuthFailed));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let blob = seal(b"", "pw").unwrap();
        assert_eq!(open(&blob, "pw").unwrap(), b"");
    }

    #[test]
    fn kdf_benchmark_reports_positive_time() {
        let b = benchmark_kdf();
        assert!(b.millis > 0.0 && b.millis.is_finite());
        assert!(["weak", "ok", "slow"].contains(&b.verdict.as_str()));
        // Report the profile actually in use, not a number frozen in the test.
        assert_eq!(b.memory_kib, KDF_CURRENT.memory_kib);
        assert_eq!(b.iterations, KDF_CURRENT.iterations);
    }
}
