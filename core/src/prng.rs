//! Deterministic, cross-platform PRNG for key-seeded embedding.
//!
//! **Security note.** Payload secrecy comes entirely from AES-256-GCM. This PRNG
//! only needs to produce a key-dependent, uniform-ish ordering of carrier
//! positions so that embedding is not a trivially detectable sequential walk.
//! We hand-roll xoshiro256++ (seeded via SplitMix64) so the byte stream is
//! identical on every platform and pinned regardless of any external crate's
//! version churn — that determinism is what guarantees desktop/Android parity.

/// SplitMix64 — expands a 64-bit seed into well-mixed 64-bit words. Used only to
/// initialise xoshiro's 256-bit state (avoids the all-zero-state trap).
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// xoshiro256++ 1.0 — fast, well-distributed, fully specified.
pub struct Xoshiro256pp {
    s: [u64; 4],
}

impl Xoshiro256pp {
    /// Seed from a 64-bit value (handy for tests).
    pub fn from_seed_u64(seed: u64) -> Self {
        let mut sm = SplitMix64::new(seed);
        Self {
            s: [sm.next(), sm.next(), sm.next(), sm.next()],
        }
    }

    /// Seed from 32 bytes (e.g. a passphrase-derived seed). The bytes are folded
    /// into one 64-bit value and diffused through SplitMix64 so any seed (even
    /// all-zero) yields a valid, well-mixed state.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let mut acc = 0xD1B5_4A32_D192_ED03u64;
        for chunk in seed.chunks_exact(8) {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            acc = acc.rotate_left(17) ^ u64::from_le_bytes(b);
        }
        Self::from_seed_u64(acc)
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform integer in `[0, n)` via modulo-rejection (bias-free). Returns 0
    /// when `n == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let r = self.next_u64();
            if r < zone {
                return r % n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed() {
        let mut a = Xoshiro256pp::from_seed_u64(42);
        let mut b = Xoshiro256pp::from_seed_u64(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Xoshiro256pp::from_seed_u64(1);
        let mut b = Xoshiro256pp::from_seed_u64(2);
        // Vanishingly unlikely to match across 8 draws if seeds truly diverge.
        let mut any_diff = false;
        for _ in 0..8 {
            if a.next_u64() != b.next_u64() {
                any_diff = true;
            }
        }
        assert!(any_diff);
    }

    #[test]
    fn below_respects_bound() {
        let mut r = Xoshiro256pp::from_seed_u64(7);
        for _ in 0..10_000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn from_bytes_is_deterministic() {
        let seed = [1u8; 32];
        let mut a = Xoshiro256pp::from_bytes(&seed);
        let mut b = Xoshiro256pp::from_bytes(&seed);
        for _ in 0..256 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn from_bytes_is_stable_pinned_vector() {
        // Algorithm fingerprint: pins the first output for an all-0x01 seed so
        // any accidental change (which would silently break desktop/Android
        // parity) fails loudly here. Recompute only on a deliberate format bump.
        let seed = [1u8; 32];
        let mut r = Xoshiro256pp::from_bytes(&seed);
        assert_eq!(r.next_u64(), PINNED_FIRST_OUTPUT, "got {:#018x}", {
            let mut r2 = Xoshiro256pp::from_bytes(&[1u8; 32]);
            r2.next_u64()
        });
    }

    // Captured from the first green run; see test above.
    const PINNED_FIRST_OUTPUT: u64 = 0x518a_1dc6_f63f_9ceb;
}
