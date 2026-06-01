//! stegno-core: offline steganography engine.
//!
//! One audited engine shared by the Tauri desktop app and the native Android
//! app via UniFFI. Methods operate on already-encrypted, already-framed bytes,
//! so every technique inherits identical crypto for free.

pub mod crypto;
pub mod image_io;
pub mod method;
pub mod methods;
pub mod payload;
pub mod prng;
pub mod registry;
pub mod seed;

use payload::{Revealed, Secret};

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary. Messages are user-facing.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum StegnoError {
    #[error("image too small for this payload")]
    CoverTooSmall,
    #[error("unsupported or corrupt cover")]
    UnsupportedFormat,
    #[error("wrong passphrase or no hidden data")]
    AuthFailed,
    #[error("no hidden data found")]
    NoHiddenData,
    #[error("hidden data is corrupted")]
    CorruptPayload,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Describes one registered steganography method.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MethodInfo {
    pub id: String,
    pub display_name: String,
    pub media: String,
}

/// List every method the engine supports.
#[uniffi::export]
pub fn list_methods() -> Vec<MethodInfo> {
    registry::registry()
        .iter()
        .map(|m| MethodInfo {
            id: m.id().to_string(),
            display_name: m.display_name().to_string(),
            media: format!("{:?}", m.media()),
        })
        .collect()
}

/// Usable payload capacity (bytes) of a cover for a given method.
#[uniffi::export]
pub fn capacity(method_id: String, cover: Vec<u8>) -> Result<u64, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;
    Ok(m.capacity(&cover)?.usable_bytes)
}

/// Encrypt `secret`, frame it, and embed it into `cover`. Returns stego bytes
/// (PNG for image methods).
#[uniffi::export]
pub fn embed(
    method_id: String,
    cover: Vec<u8>,
    secret: Secret,
    passphrase: String,
) -> Result<Vec<u8>, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;
    let inner = payload::serialize_secret(&secret);
    let sealed =
        crypto::seal(&inner, &passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;
    let framed = payload::frame(&sealed);
    m.embed(&cover, &framed, &method::EmbedOpts::default())
}

/// Extract and decrypt a hidden payload from `stego`.
#[uniffi::export]
pub fn extract(
    method_id: String,
    stego: Vec<u8>,
    passphrase: String,
) -> Result<Revealed, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;
    let stream = match m.extract(&stego)? {
        Some(s) => s,
        None => return Ok(Revealed::None),
    };
    let sealed = match payload::unframe(&stream)? {
        Some(s) => s,
        None => return Ok(Revealed::None),
    };
    let inner = crypto::open(&sealed, &passphrase).map_err(|_| StegnoError::AuthFailed)?;
    Ok(match payload::deserialize_secret(&inner)? {
        Secret::Text { text } => Revealed::Text { text },
        Secret::File { name, bytes } => Revealed::File { name, bytes },
    })
}
