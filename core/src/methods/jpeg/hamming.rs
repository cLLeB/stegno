//! Hamming `(1, 2ᵏ−1, k)` matrix coding ("matrix encoding").
//!
//! Embeds `k` message bits into a group of `n = 2ᵏ − 1` carrier LSBs by changing
//! **at most one** of them. This is the classic trick (used by F5) for cutting the
//! number of carrier changes per payload bit — fewer changes means a smaller
//! statistical footprint for the same payload.
//!
//! The parity-check matrix `H` is the `k × n` matrix whose `i`-th column is the
//! binary representation of `i` (`1..=n`). The **syndrome** of the LSB vector `x`
//! is `H·x = ⨁{i : xᵢ=1} i`. To encode message `m` we need the syndrome to equal
//! `m`; flipping carrier `j` changes the syndrome by `j` (its column), so flipping
//! `j = syndrome ⊕ m` (when non-zero) lands exactly on `m`. The decoder just reads
//! the syndrome back. Flipping one LSB never costs more than one change.

/// Message bits embedded per group.
pub const K: u32 = 3;

/// Carriers per group: `2ᵏ − 1`.
pub const N: usize = (1 << K) - 1; // 7

/// Syndrome of a group's LSBs: XOR of the 1-based indices whose bit is set.
fn syndrome(lsbs: &[u8]) -> u32 {
    let mut s = 0u32;
    for (i, &b) in lsbs.iter().enumerate() {
        if b & 1 == 1 {
            s ^= (i as u32) + 1;
        }
    }
    s
}

/// Index (0-based) of the single carrier whose LSB must flip to encode `message`
/// into this group, or `None` if the group already encodes it. `message` is a
/// `k`-bit value (`0..2ᵏ`).
pub fn flip_index(lsbs: &[u8], message: u32) -> Option<usize> {
    let d = syndrome(lsbs) ^ message;
    if d == 0 {
        None
    } else {
        Some((d as usize) - 1) // d ∈ 1..=N
    }
}

/// The `k`-bit message encoded by a group's LSBs.
pub fn decode_group(lsbs: &[u8]) -> u32 {
    syndrome(lsbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive proof of correctness: for every possible group of `N` LSBs and
    /// every `k`-bit message, applying the prescribed (≤1) flip makes the group
    /// decode to exactly that message.
    #[test]
    fn every_group_and_message_roundtrips_with_at_most_one_change() {
        for pattern in 0u32..(1 << N) {
            let lsbs: Vec<u8> = (0..N).map(|i| ((pattern >> i) & 1) as u8).collect();
            for message in 0u32..(1 << K) {
                let mut g = lsbs.clone();
                let changes = match flip_index(&g, message) {
                    Some(j) => {
                        g[j] ^= 1;
                        1
                    }
                    None => 0,
                };
                assert!(changes <= 1);
                assert_eq!(decode_group(&g), message, "pattern={pattern} msg={message}");
            }
        }
    }

    #[test]
    fn no_change_when_already_encoded() {
        // A group whose syndrome already equals the message needs no flip.
        let lsbs = [1u8, 0, 0, 0, 0, 0, 0]; // syndrome = 1
        assert_eq!(flip_index(&lsbs, 1), None);
        assert_eq!(decode_group(&lsbs), 1);
    }

    #[test]
    fn dimensions_are_consistent() {
        assert_eq!(N, 7);
        assert_eq!(1u32 << K, (N as u32) + 1);
    }
}
