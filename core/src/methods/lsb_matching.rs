//! `lsb_matching` — key-seeded LSB *matching* (±1 embedding) in PNG.
//!
//! Classic LSB *replacement* forces a channel's value into a fixed pair
//! (2k ↔ 2k+1), which leaves the well-known "pairs of values" / chi-square
//! signature. LSB *matching* instead nudges the value by ±1 when the LSB needs
//! to change, so the value can move either way and the artefact disappears,
//! while the recovered LSB is identical. Positions are key-seeded like
//! [`super::lsb_seeded`]; capacity is unchanged (3 bits/pixel).
//!
//! The ±1 direction is drawn from a deterministic, key-derived stream so embeds
//! are reproducible. It does not affect extraction (which only reads the LSB),
//! so no direction information is stored.

use super::lsb_common;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::prng::Xoshiro256pp;
use crate::StegnoError;

pub struct LsbMatching;

/// Domain-separated direction seed so the ±1 stream is independent of the
/// position-permutation stream (which derives from the same key).
fn direction_rng(seed: Option<&[u8; 32]>) -> Xoshiro256pp {
    match seed {
        Some(s) => {
            let mut tweaked = *s;
            // Flip a fixed byte so this stream != the permutation's stream.
            tweaked[0] ^= 0xA5;
            Xoshiro256pp::from_bytes(&tweaked)
        }
        None => Xoshiro256pp::from_seed_u64(0x6D61_7463_685F_6469), // "match_di"
    }
}

/// Nudge `value` so its LSB equals `bit`, changing it by at most ±1.
fn match_adjust(value: u8, bit: u8, rng: &mut Xoshiro256pp) -> u8 {
    if value & 1 == bit & 1 {
        return value;
    }
    match value {
        0 => 1,            // can't go below 0
        255 => 254,        // can't go above 255
        v => {
            if rng.next_u64() & 1 == 0 {
                v + 1
            } else {
                v - 1
            }
        }
    }
}

impl Method for LsbMatching {
    fn id(&self) -> &'static str {
        "lsb_matching"
    }
    fn display_name(&self) -> &'static str {
        "LSB Matching (PNG, ±1)"
    }
    fn media(&self) -> Media {
        Media::Image
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = crate::image_io::decode_rgba(cover)?;
        Ok(Capacity {
            usable_bytes: lsb_common::usable_capacity_bytes(img.width, img.height),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let (img, order) = lsb_common::prepare(cover, opts.seed.as_ref())?;
        let mut rng = direction_rng(opts.seed.as_ref());
        lsb_common::embed_with(img, payload, &order, move |value, bit| {
            match_adjust(value, bit, &mut rng)
        })
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        // The bit is in the LSB regardless of ±1 direction → shared reader.
        lsb_common::read_frame(stego, opts.seed.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{decode_rgba, encode_png as enc, RgbaImage};
    use crate::payload;
    use crate::seed::{derive_seed, Slot};

    fn cover(w: u32, h: u32, fill: u8) -> Vec<u8> {
        enc(&RgbaImage {
            width: w,
            height: h,
            pixels: vec![fill; (w * h * 4) as usize],
        })
        .unwrap()
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn matching_roundtrip() {
        let c = cover(64, 64, 100);
        let body = payload::frame(b"plus or minus one");
        let (eo, xo) = opts("key");
        let stego = LsbMatching.embed(&c, &body, &eo).unwrap();
        assert_eq!(LsbMatching.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn changes_are_at_most_one_per_channel() {
        let c = cover(64, 64, 100);
        let body = payload::frame(b"bounded perturbation");
        let (eo, _) = opts("key");
        let stego = LsbMatching.embed(&c, &body, &eo).unwrap();
        let before = decode_rgba(&c).unwrap();
        let after = decode_rgba(&stego).unwrap();
        for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!((*a as i16 - *b as i16).abs() <= 1);
        }
    }

    #[test]
    fn boundary_values_stay_in_range() {
        // All-0 and all-255 covers must never under/overflow.
        for fill in [0u8, 255u8] {
            let c = cover(48, 48, fill);
            let body = payload::frame(b"edge values");
            let (eo, xo) = opts("k");
            let stego = LsbMatching.embed(&c, &body, &eo).unwrap();
            assert_eq!(LsbMatching.extract(&stego, &xo).unwrap().unwrap(), body);
        }
    }

    #[test]
    fn wrong_seed_finds_no_frame() {
        let c = cover(64, 64, 80);
        let body = payload::frame(b"hidden");
        let (eo, _) = opts("right");
        let stego = LsbMatching.embed(&c, &body, &eo).unwrap();
        let (_, xo) = opts("wrong");
        assert_eq!(LsbMatching.extract(&stego, &xo).unwrap(), None);
    }
}
