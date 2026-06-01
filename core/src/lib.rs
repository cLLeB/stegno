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

use method::{EmbedOpts, ExtractOpts};
use payload::{Revealed, Secret};
use seed::{derive_seed, Slot};

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
    let framed = seal_and_frame(&secret, &passphrase)?;
    let opts = EmbedOpts {
        seed: Some(derive_seed(&passphrase, Slot::Primary)),
    };
    m.embed(&cover, &framed, &opts)
}

/// Embed a **real** secret and a **decoy** secret into one cover, each sealed
/// under its own passphrase and placed in a disjoint, key-seeded region (LSB
/// replacement). Under coercion the user reveals only the decoy passphrase; the
/// real slot is indistinguishable from unused image noise without the real key.
///
/// Each slot holds ≈ half the image (see [`decoy_capacity`]); both secrets must
/// fit or `CoverTooSmall` is returned. Extract with the ordinary [`extract`] —
/// it unlocks whichever slot the supplied passphrase sealed.
#[uniffi::export]
pub fn embed_with_decoy(
    cover: Vec<u8>,
    real_secret: Secret,
    real_passphrase: String,
    decoy_secret: Secret,
    decoy_passphrase: String,
) -> Result<Vec<u8>, StegnoError> {
    use methods::lsb_common;
    let mut img = image_io::decode_rgba(&cover)?;
    let (w, h) = (img.width, img.height);

    let real_frame = seal_and_frame(&real_secret, &real_passphrase)?;
    let decoy_frame = seal_and_frame(&decoy_secret, &decoy_passphrase)?;

    let real_order = lsb_common::decoy_region_order(
        w,
        h,
        Slot::Primary,
        &derive_seed(&real_passphrase, Slot::Primary),
    );
    let decoy_order = lsb_common::decoy_region_order(
        w,
        h,
        Slot::Decoy,
        &derive_seed(&decoy_passphrase, Slot::Decoy),
    );

    lsb_common::embed_into(&mut img, &real_frame, &real_order, lsb_common::replace_lsb)?;
    lsb_common::embed_into(&mut img, &decoy_frame, &decoy_order, lsb_common::replace_lsb)?;
    image_io::encode_png(&img)
}

/// Usable payload bytes **per slot** when embedding with a decoy (≈ half image).
#[uniffi::export]
pub fn decoy_capacity(cover: Vec<u8>) -> Result<u64, StegnoError> {
    let img = image_io::decode_rgba(&cover)?;
    Ok(methods::lsb_common::decoy_slot_capacity_bytes(
        img.width, img.height,
    ))
}

/// Serialize, encrypt, and frame a secret — the layers above every `Method`.
fn seal_and_frame(secret: &Secret, passphrase: &str) -> Result<Vec<u8>, StegnoError> {
    let inner = payload::serialize_secret(secret);
    let sealed =
        crypto::seal(&inner, passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;
    Ok(payload::frame(&sealed))
}

/// Extract and decrypt a hidden payload from `stego`.
///
/// Handles ordinary stego images and decoy-mode images (see
/// [`embed_with_decoy`]) transparently: the passphrase unlocks whichever slot it
/// sealed, and reveals nothing about the other.
#[uniffi::export]
pub fn extract(
    method_id: String,
    stego: Vec<u8>,
    passphrase: String,
) -> Result<Revealed, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;
    let xopts = ExtractOpts {
        seed: Some(derive_seed(&passphrase, Slot::Primary)),
    };

    // 1) The method's ordinary read path.
    let mut frame_seen_wrong_pass = false;
    if let Some(stream) = m.extract(&stego, &xopts)? {
        if let Some(sealed) = payload::unframe(&stream)? {
            match crypto::open(&sealed, &passphrase) {
                Ok(inner) => return revealed_from_inner(&inner),
                // A frame existed but didn't decrypt — could be a decoy image
                // whose layout differs; keep trying before deciding.
                Err(_) => frame_seen_wrong_pass = true,
            }
        }
    }

    // 2) Decoy-mode fallback: try each region keyed by the matching slot.
    if let Some(rev) = try_decoy_slots(&stego, &passphrase)? {
        return Ok(rev);
    }

    if frame_seen_wrong_pass {
        return Err(StegnoError::AuthFailed);
    }
    Ok(Revealed::None)
}

fn revealed_from_inner(inner: &[u8]) -> Result<Revealed, StegnoError> {
    Ok(match payload::deserialize_secret(inner)? {
        Secret::Text { text } => Revealed::Text { text },
        Secret::File { name, bytes } => Revealed::File { name, bytes },
    })
}

/// Try both decoy regions; return the first that decrypts under `passphrase`.
/// Lenient: a coincidental header in the wrong region is skipped, not fatal.
fn try_decoy_slots(stego: &[u8], passphrase: &str) -> Result<Option<Revealed>, StegnoError> {
    let img = image_io::decode_rgba(stego)?;
    for slot in [Slot::Primary, Slot::Decoy] {
        let key = derive_seed(passphrase, slot);
        let order = methods::lsb_common::decoy_region_order(img.width, img.height, slot, &key);
        let framed = match methods::lsb_common::read_frame_with(&img, &order) {
            Ok(Some(f)) => f,
            _ => continue,
        };
        let sealed = match payload::unframe(&framed) {
            Ok(Some(s)) => s,
            _ => continue,
        };
        if let Ok(inner) = crypto::open(&sealed, passphrase) {
            return Ok(Some(revealed_from_inner(&inner)?));
        }
    }
    Ok(None)
}
