//! Key-seeded embedding positions.
//!
//! Sequential LSB embedding is trivially detectable: the changed samples are the
//! first N in raster order. Spreading the payload across a *key-dependent*
//! pseudo-random permutation of the carrier removes that structure. The key is
//! derived from the user's passphrase, so extraction needs no extra secret.
//!
//! Secrecy of the data still rests on AES-256-GCM (see [`crate::crypto`]); the
//! permutation only governs *where* the already-encrypted bits land.

use crate::prng::Xoshiro256pp;
use sha2::{Digest, Sha256};

const SEED_DOMAIN: &[u8] = b"stegno/seed/v1";

/// Slot identifiers for the plausible-deniability scheme. The same passphrase
/// produces a different permutation per slot, so the real and decoy payloads
/// never derive identical positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Primary payload — the real secret.
    Primary = 0,
    /// Decoy payload — the message revealed under coercion.
    Decoy = 1,
}

/// Derive a 32-byte permutation seed from the passphrase and slot.
///
/// A single SHA-256 (fast, unlike the Argon2id used for the encryption key):
/// brute-force resistance is the cipher's job, this only needs to be a stable,
/// key-dependent value.
pub fn derive_seed(passphrase: &str, slot: Slot) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SEED_DOMAIN);
    h.update([slot as u8]);
    h.update(passphrase.as_bytes());
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// A key-seeded permutation of `0..n` (Fisher–Yates over the seeded PRNG).
/// Deterministic across platforms, so a stego image embedded on one platform
/// extracts identically on another.
pub fn permutation(n: usize, seed: &[u8; 32]) -> Vec<u32> {
    let mut rng = Xoshiro256pp::from_bytes(seed);
    let mut v: Vec<u32> = (0..n as u32).collect();
    for i in (1..n).rev() {
        let j = rng.below((i as u64) + 1) as usize;
        v.swap(i, j);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn permutation_is_a_bijection() {
        let seed = derive_seed("hunter2", Slot::Primary);
        let p = permutation(1000, &seed);
        assert_eq!(p.len(), 1000);
        let set: HashSet<u32> = p.iter().copied().collect();
        assert_eq!(set.len(), 1000); // no duplicates
        assert!(p.iter().all(|&x| (x as usize) < 1000)); // in range
    }

    #[test]
    fn permutation_is_deterministic_for_same_key() {
        let s = derive_seed("pw", Slot::Primary);
        assert_eq!(permutation(500, &s), permutation(500, &s));
    }

    #[test]
    fn different_passphrases_differ() {
        let a = permutation(500, &derive_seed("alpha", Slot::Primary));
        let b = permutation(500, &derive_seed("bravo", Slot::Primary));
        assert_ne!(a, b);
    }

    #[test]
    fn different_slots_differ() {
        let a = permutation(500, &derive_seed("same", Slot::Primary));
        let b = permutation(500, &derive_seed("same", Slot::Decoy));
        assert_ne!(a, b);
    }

    #[test]
    fn is_not_the_identity() {
        let p = permutation(256, &derive_seed("key", Slot::Primary));
        let identity: Vec<u32> = (0..256).collect();
        assert_ne!(p, identity);
    }

    #[test]
    fn handles_trivial_sizes() {
        assert_eq!(permutation(0, &derive_seed("k", Slot::Primary)).len(), 0);
        assert_eq!(permutation(1, &derive_seed("k", Slot::Primary)), vec![0]);
    }
}
