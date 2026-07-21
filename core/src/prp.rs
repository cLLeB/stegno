//! A keyed permutation of `0..n` that is **computed, never stored**.
//!
//! [`crate::seed::permutation`] materializes a Fisher–Yates shuffle as a
//! `Vec<u32>` — one `u32` per slot. That is fine for a thumbnail and ruinous for
//! anything real: an ordinary 12-megapixel photo has 36 million slots, so the
//! shuffle alone costs 137 MB, and a reveal builds one per cover while probing
//! layouts. Video is worse still.
//!
//! A permutation, though, only has to answer "what is the `i`-th element?". A
//! small Feistel network over a power-of-two domain answers that in constant
//! time and constant memory, and **cycle-walking** — re-applying the network
//! until the result lands below `n` — narrows the domain to exactly `0..n`
//! while staying a bijection.
//!
//! This is not a cryptographic primitive and does not need to be: secrecy is
//! AES-256-GCM's job (see [`crate::crypto`]), and the permutation only decides
//! *where* already-encrypted bits land. What it must be is a genuine bijection,
//! well mixed, and identical on every platform — hence fixed-width integer ops
//! throughout and no floating point.

/// Feistel rounds. Four is the usual floor for a well-mixed permutation; six
/// costs a few nanoseconds more and removes any doubt.
const ROUNDS: usize = 6;

/// SplitMix64's finalizer — strong avalanche for its cost, and trivially
/// portable.
#[inline]
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A bijection on `0..n`, evaluated on demand.
#[derive(Clone)]
pub struct Prp {
    n: u64,
    /// Bits in each Feistel half; the working domain is `2^(2 * half_bits)`.
    half_bits: u32,
    half_mask: u64,
    round_keys: [u64; ROUNDS],
}

impl Prp {
    /// Build the permutation of `0..n` keyed by `seed`.
    pub fn new(n: usize, seed: &[u8; 32]) -> Self {
        let n = n as u64;
        // Smallest even bit-width whose domain covers n, so the two Feistel
        // halves are equal and the network is a clean bijection.
        let mut bits = 0u32;
        while bits < 64 && (1u64 << bits) < n {
            bits += 1;
        }
        if bits % 2 == 1 {
            bits += 1;
        }
        let half_bits = (bits / 2).max(1);

        let mut round_keys = [0u64; ROUNDS];
        for (r, k) in round_keys.iter_mut().enumerate() {
            // Fold the whole seed into each round key so every seed byte counts.
            let mut acc = mix64(r as u64 + 0x9e37_79b9_7f4a_7c15);
            for chunk in seed.chunks_exact(8) {
                let word = u64::from_le_bytes(chunk.try_into().unwrap());
                acc = mix64(acc ^ word);
            }
            *k = acc;
        }

        Prp {
            n,
            half_bits,
            half_mask: (1u64 << half_bits) - 1,
            round_keys,
        }
    }

    /// One pass of the Feistel network over the working domain.
    #[inline]
    fn round_trip(&self, x: u64) -> u64 {
        let mut l = x >> self.half_bits;
        let mut r = x & self.half_mask;
        for k in self.round_keys {
            let f = mix64(k ^ r) & self.half_mask;
            let next_r = l ^ f;
            l = r;
            r = next_r;
        }
        (l << self.half_bits) | r
    }

    /// The `i`-th element of the permutation. `i` must be `< n`.
    #[inline]
    pub fn get(&self, i: usize) -> u32 {
        let mut x = i as u64;
        // Cycle-walking: the network permutes the padded domain, so stepping
        // from a point inside `0..n` always returns to `0..n`. The padded
        // domain is under twice `n`, so this averages well under two passes.
        loop {
            x = self.round_trip(x);
            if x < self.n {
                return x as u32;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.n as usize
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn seed(tag: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = tag.wrapping_add(i as u8).wrapping_mul(31);
        }
        s
    }

    /// The property everything else rests on: every input maps to a distinct
    /// output, and the outputs are exactly `0..n`.
    #[test]
    fn is_a_bijection_for_many_sizes() {
        for n in [1usize, 2, 3, 5, 8, 17, 64, 100, 255, 256, 1000, 4096, 6561] {
            let p = Prp::new(n, &seed(1));
            let seen: HashSet<u32> = (0..n).map(|i| p.get(i)).collect();
            assert_eq!(seen.len(), n, "n={n} produced collisions");
            assert!(seen.iter().all(|&x| (x as usize) < n), "n={n} out of range");
        }
    }

    #[test]
    fn is_deterministic_and_key_dependent() {
        let a = Prp::new(500, &seed(1));
        let b = Prp::new(500, &seed(1));
        let c = Prp::new(500, &seed(2));
        let av: Vec<u32> = (0..500).map(|i| a.get(i)).collect();
        let bv: Vec<u32> = (0..500).map(|i| b.get(i)).collect();
        let cv: Vec<u32> = (0..500).map(|i| c.get(i)).collect();
        assert_eq!(av, bv, "same key must give the same permutation");
        assert_ne!(av, cv, "different keys must differ");
    }

    #[test]
    fn does_not_leave_elements_in_place() {
        // A permutation that mostly maps i -> i would defeat the point.
        let n = 4096;
        let p = Prp::new(n, &seed(3));
        let fixed = (0..n).filter(|&i| p.get(i) as usize == i).count();
        assert!(fixed < n / 100, "{fixed} fixed points is too structured");
    }

    #[test]
    fn scatters_neighbours_apart() {
        // Consecutive inputs must not land near each other, or the payload
        // would sit in a contiguous run.
        let n = 65_536;
        let p = Prp::new(n, &seed(4));
        let close = (0..n - 1)
            .filter(|&i| (p.get(i) as i64 - p.get(i + 1) as i64).abs() < 16)
            .count();
        assert!(close < n / 100, "{close} adjacent pairs stayed close");
    }

    #[test]
    fn handles_trivial_sizes() {
        assert_eq!(Prp::new(1, &seed(5)).get(0), 0);
        let two = Prp::new(2, &seed(5));
        let got: HashSet<u32> = (0..2).map(|i| two.get(i)).collect();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn huge_domains_cost_nothing_to_build() {
        // The whole point: a 12 MP photo's slot space is instant and allocation
        // free, where materializing it would have been 137 MB.
        let p = Prp::new(36_000_000, &seed(6));
        assert!(p.get(0) < 36_000_000);
        assert!(p.get(35_999_999) < 36_000_000);
    }
}
