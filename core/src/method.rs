//! The pluggable steganography method interface.
//!
//! Every technique (LSB, PVD, zero-width text, audio LSB, …) implements
//! `Method`. Methods receive already-encrypted, already-framed bytes, so they
//! never touch crypto directly.

use crate::StegnoError;

/// The carrier medium a method operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    Image,
    Audio,
    Text,
    File,
}

/// How much payload a cover can hold for a method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacity {
    /// Usable payload bytes after subtracting frame + crypto overhead.
    pub usable_bytes: u64,
}

/// Per-embed options.
///
/// `seed` keys the carrier-position permutation for seedable methods (the
/// LSB family, edge-adaptive). Methods that don't randomize positions (e.g.
/// the Phase-0 sequential `lsb_image`) ignore it.
#[derive(Debug, Clone, Default)]
pub struct EmbedOpts {
    pub seed: Option<[u8; 32]>,
}

/// Per-extract options. Mirrors [`EmbedOpts`] so seedable methods can rebuild
/// the same permutation at read time.
#[derive(Debug, Clone, Default)]
pub struct ExtractOpts {
    pub seed: Option<[u8; 32]>,
}

pub trait Method: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn media(&self) -> Media;

    /// Whether the stego output still *is* the cover the user supplied.
    ///
    /// Almost every method modifies a cover in place and returns something
    /// recognisably the same file. A generative method instead synthesizes a
    /// fresh carrier and discards the cover entirely — useful when you want
    /// innocuous-looking text out of nothing, catastrophic when you asked to
    /// hide something *in a particular file* and got unrelated word-salad back.
    /// The planner uses this so it never recommends throwing your cover away.
    fn preserves_cover(&self) -> bool {
        true
    }

    /// Usable capacity of `cover` for this method.
    ///
    /// Must return `Err(UnsupportedFormat)` when this method cannot actually
    /// carry *this* cover. Callers treat a successful result as a promise that
    /// [`Method::embed`] will work, and both the planner's ranking and the UI's
    /// capacity readout are built on that promise.
    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError>;

    /// Embed already-framed `payload` bytes into `cover`, returning stego bytes.
    fn embed(&self, cover: &[u8], payload: &[u8], opts: &EmbedOpts)
        -> Result<Vec<u8>, StegnoError>;

    /// Read the framed byte stream back out of `stego`. `Ok(None)` if no frame.
    fn extract(&self, stego: &[u8], opts: &ExtractOpts)
        -> Result<Option<Vec<u8>>, StegnoError>;
}
