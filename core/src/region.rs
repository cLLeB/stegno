//! Partitioning a carrier's slot space into disjoint regions.
//!
//! Every "several secrets in one cover" feature — the decoy slot, N-recipient
//! covers, and the composite scheme that generalizes both — needs the same
//! thing: cut a slot space into `count` regions that provably never overlap,
//! then scatter each region's contents under its own passphrase.
//!
//! The construction has two layers:
//!
//! 1. A **public** permutation of all `n` slots, keyed by the fixed
//!    [`MASTER_SEED`]. Cutting it into `count` contiguous blocks yields disjoint
//!    position sets. It is deliberately *not* passphrase-derived: the extractor
//!    has to rebuild the same regions knowing only a passphrase.
//! 2. A **keyed** permutation *within* a region, seeded from the passphrase, so
//!    each party's bits are scattered and only they can reassemble them.
//!
//! Secrecy rests entirely on AES-256-GCM (see [`crate::crypto`]) — the regions
//! govern only *where* already-encrypted bits land. What they buy is
//! deniability: without the matching key, another party's region is
//! indistinguishable from untouched carrier noise.
//!
//! Both layers are [`crate::prp::Prp`]s, so a region is described in constant
//! memory and its `t`-th slot is computed on demand. Nothing here allocates per
//! slot, which is what makes large photos and long clips practical: the previous
//! materialized shuffle cost 137 MB for an ordinary 12-megapixel photo, once per
//! cover, and reveals built one for every layout they probed.
//!
//! This module is deliberately carrier-agnostic — it takes a slot *count*, not
//! image dimensions — which is what lets decoys, recipients and splitting work
//! on audio, text, documents and video exactly as they do on photos.

use crate::payload;
use crate::prp::Prp;
use crate::seed::Slot;

/// Fixed, non-secret seed defining the master ranking that regions are cut from.
pub const MASTER_SEED: [u8; 32] = *b"stegno/decoy/master-ranking/v1!!";

/// An addressable sequence of carrier slots.
///
/// Implemented both by [`Region`], which computes each slot, and by plain
/// slices, which the per-method LSB paths still hand over directly.
pub trait Slots {
    fn len(&self) -> usize;
    fn at(&self, i: usize) -> u32;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Slots for [u32] {
    fn len(&self) -> usize {
        <[u32]>::len(self)
    }
    fn at(&self, i: usize) -> u32 {
        self[i]
    }
}

impl Slots for Vec<u32> {
    fn len(&self) -> usize {
        self.as_slice().len()
    }
    fn at(&self, i: usize) -> u32 {
        self[i]
    }
}

/// Slot range `[start, end)` of region `index` of `count` equal partitions.
/// Multiplying before dividing keeps the partitions gap-free and exhaustive even
/// when `n` isn't a multiple of `count`.
pub fn bounds(n: usize, index: u32, count: u32) -> (usize, usize) {
    let count = count.max(1) as usize;
    let index = index as usize;
    (index * n / count, ((index + 1) * n / count).min(n))
}

/// The master ranking of a slot space. Cheap to build and cheap to hold, so
/// callers probing many layouts of one carrier can reuse a single instance.
pub struct Master {
    prp: Prp,
    n: usize,
}

impl Master {
    pub fn new(n: usize) -> Self {
        Master {
            prp: Prp::new(n.max(1), &MASTER_SEED),
            n,
        }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The slots of region `index` of `count`, visited in key-scattered order.
    pub fn region(&self, index: u32, count: u32, key_seed: &[u8; 32]) -> Region<'_> {
        if self.n == 0 || count == 0 || index >= count {
            return Region {
                master: &self.prp,
                inner: Prp::new(1, key_seed),
                start: 0,
                len: 0,
            };
        }
        let (start, end) = bounds(self.n, index, count);
        let len = end - start;
        Region {
            master: &self.prp,
            inner: Prp::new(len.max(1), key_seed),
            start,
            len,
        }
    }
}

/// One region of a slot space, addressed without being materialized.
///
/// `at(t)` composes the two permutations: the keyed one picks the `t`-th
/// position *within* the region, and the master one maps that to a carrier slot.
pub struct Region<'a> {
    master: &'a Prp,
    inner: Prp,
    start: usize,
    len: usize,
}

impl Slots for Region<'_> {
    fn len(&self) -> usize {
        self.len
    }
    fn at(&self, t: usize) -> u32 {
        self.master.get(self.start + self.inner.get(t) as usize)
    }
}

/// Region index for one half of a two-way decoy split. `Primary` takes the
/// first half, `Decoy` the second; they are keyed from different [`Slot`]
/// domains, which is why this is spelled out rather than inlined.
pub fn decoy_index(slot: Slot) -> u32 {
    match slot {
        Slot::Primary => 0,
        Slot::Decoy => 1,
    }
}

/// Usable payload bytes in one region of a `count`-way split, after subtracting
/// one frame's worth of framing and crypto overhead.
pub fn capacity_bytes(n: usize, count: u32) -> u64 {
    let per_region = n / count.max(1) as usize;
    ((per_region / 8) as u64).saturating_sub(payload::overhead() as u64)
}

/// Collect a region's slots into a plain vector. Only for the per-method LSB
/// paths that still expect a slice; anything payload-sized should index the
/// [`Region`] directly rather than allocating the whole thing.
pub fn to_vec(r: &dyn Slots) -> Vec<u32> {
    (0..r.len()).map(|i| r.at(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::derive_seed;
    use std::collections::HashSet;

    fn key(pw: &str) -> [u8; 32] {
        derive_seed(pw, Slot::Primary)
    }

    #[test]
    fn regions_are_disjoint_and_exhaustive() {
        let n = 3000;
        let m = Master::new(n);
        let k = key("k");
        for count in [1u32, 2, 3, 5, 8] {
            let mut seen: HashSet<u32> = HashSet::new();
            let mut total = 0usize;
            for index in 0..count {
                let r = m.region(index, count, &k);
                total += r.len();
                for i in 0..r.len() {
                    assert!(seen.insert(r.at(i)), "slot appears in two regions");
                }
            }
            assert_eq!(total, n, "count={count} must cover the whole space");
        }
    }

    #[test]
    fn a_region_is_a_permutation_of_its_bounds() {
        let n = 1000;
        let m = Master::new(n);
        let (start, end) = bounds(n, 2, 4);
        let expected: HashSet<u32> = (start..end).map(|j| m.prp.get(j)).collect();
        let r = m.region(2, 4, &key("pw"));
        let got: HashSet<u32> = (0..r.len()).map(|i| r.at(i)).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn different_keys_scatter_differently_within_one_region() {
        let m = Master::new(800);
        let ra = m.region(1, 4, &derive_seed("alpha", Slot::Primary));
        let rb = m.region(1, 4, &derive_seed("bravo", Slot::Primary));
        let a: Vec<u32> = (0..ra.len()).map(|i| ra.at(i)).collect();
        let b: Vec<u32> = (0..rb.len()).map(|i| rb.at(i)).collect();
        assert_ne!(a, b, "different keys must visit in a different order");
        // ...but they occupy the same positions.
        let sa: HashSet<u32> = a.into_iter().collect();
        let sb: HashSet<u32> = b.into_iter().collect();
        assert_eq!(sa, sb);
    }

    #[test]
    fn decoy_halves_never_overlap() {
        let m = Master::new(2000);
        let real = m.region(
            decoy_index(Slot::Primary),
            2,
            &derive_seed("real", Slot::Primary),
        );
        let decoy = m.region(
            decoy_index(Slot::Decoy),
            2,
            &derive_seed("decoy", Slot::Decoy),
        );
        let a: HashSet<u32> = (0..real.len()).map(|i| real.at(i)).collect();
        let b: HashSet<u32> = (0..decoy.len()).map(|i| decoy.at(i)).collect();
        assert!(a.is_disjoint(&b));
    }

    #[test]
    fn single_region_is_the_whole_space() {
        let m = Master::new(500);
        assert_eq!(m.region(0, 1, &key("k")).len(), 500);
    }

    #[test]
    fn out_of_range_region_is_empty() {
        let m = Master::new(500);
        assert_eq!(m.region(3, 3, &key("k")).len(), 0);
        assert_eq!(Master::new(0).region(0, 1, &key("k")).len(), 0);
    }

    #[test]
    fn capacity_shrinks_as_regions_multiply() {
        let one = capacity_bytes(80_000, 1);
        let four = capacity_bytes(80_000, 4);
        assert!(four < one);
        assert_eq!(capacity_bytes(80, 100), 0, "saturates rather than underflows");
    }

    #[test]
    fn a_huge_slot_space_is_free_to_describe() {
        // The reason this module exists: a 12 MP photo, previously 137 MB.
        let m = Master::new(36_000_000);
        let r = m.region(1, 3, &key("k"));
        assert_eq!(r.len(), 12_000_000);
        assert!(r.at(0) < 36_000_000);
        assert!(r.at(r.len() - 1) < 36_000_000);
    }
}
