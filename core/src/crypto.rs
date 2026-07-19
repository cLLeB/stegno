//! Authenticated encryption: Argon2id key derivation + AES-256-GCM.
//!
//! Wire format of a sealed blob: `salt(16) | nonce(12) | ciphertext+tag`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Overhead added by `seal` on top of the plaintext length.
pub const CRYPTO_OVERHEAD: usize = SALT_LEN + NONCE_LEN + TAG_LEN;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("crypto input too short")]
    TooShort,
    #[error("key derivation failed")]
    Kdf,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    // Interactive target (~250ms on a mid-range phone): m=19456 KiB, t=2, p=1.
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|_| CryptoError::Kdf)?;
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
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CryptoError::AuthFailed)?;
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
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
    /// "weak" (<50 ms), "ok" (50–1000 ms), or "slow" (>1000 ms).
    pub verdict: String,
}

/// Time one Argon2id derivation with the shipped parameters. Lets an app warn
/// when the device makes key-stretching too cheap (brute force is easier) or too
/// slow (bad UX) — without changing the on-disk format.
#[uniffi::export]
pub fn benchmark_kdf() -> KdfBenchmark {
    let salt = [0x5Au8; SALT_LEN];
    let start = std::time::Instant::now();
    let _ = derive_key("benchmark passphrase", &salt);
    let millis = start.elapsed().as_secs_f64() * 1000.0;
    let verdict = if millis < 50.0 {
        "weak"
    } else if millis <= 1000.0 {
        "ok"
    } else {
        "slow"
    };
    KdfBenchmark {
        millis,
        memory_kib: 19456,
        iterations: 2,
        verdict: verdict.to_string(),
    }
}

/// Decrypt a blob produced by `seal`. Wrong passphrase or tampering -> AuthFailed.
pub fn open(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::TooShort);
    }
    let salt = &blob[..SALT_LEN];
    let nonce_bytes = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &blob[SALT_LEN + NONCE_LEN..];
    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(b.memory_kib, 19456);
    }
}
