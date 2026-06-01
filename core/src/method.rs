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

/// Per-embed options. Reserved for future methods (e.g. decoy slot, seed).
#[derive(Debug, Clone, Default)]
pub struct EmbedOpts;

pub trait Method: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn media(&self) -> Media;

    /// Usable capacity of `cover` for this method.
    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError>;

    /// Embed already-framed `payload` bytes into `cover`, returning stego bytes.
    fn embed(&self, cover: &[u8], payload: &[u8], opts: &EmbedOpts)
        -> Result<Vec<u8>, StegnoError>;

    /// Read the framed byte stream back out of `stego`. `Ok(None)` if no frame.
    fn extract(&self, stego: &[u8]) -> Result<Option<Vec<u8>>, StegnoError>;
}
