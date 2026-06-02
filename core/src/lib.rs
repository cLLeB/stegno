//! stegno-core: offline steganography engine.
//!
//! One audited engine shared by the Tauri desktop app and the native Android
//! app via UniFFI. Methods operate on already-encrypted, already-framed bytes,
//! so every technique inherits identical crypto for free.

pub mod analysis;
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
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, uniffi::Record, Serialize, Deserialize)]
pub struct ByteChunk {
    pub bytes: Vec<u8>,
}

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

/// Image-quality comparison between a cover and its stego version.
#[derive(Debug, Clone, uniffi::Record)]
pub struct QualityReport {
    /// Mean squared error over R/G/B (0 = identical).
    pub mse: f64,
    /// Peak signal-to-noise ratio in dB (higher = closer; ∞ for identical).
    pub psnr_db: f64,
    /// Structural similarity in [0,1] (1 = identical).
    pub ssim: f64,
}

/// How suspicious a single image looks for LSB steganography.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DetectionReport {
    /// Westfeld chi-square probability of LSB embedding, [0,1] (higher = more
    /// suspicious).
    pub chi_square_p: f64,
    /// RS regularity gap (R−S)/(R+S); a *smaller* value is more suspicious.
    pub rs_regularity_gap: f64,
    /// Sample-pair-analysis estimate of the LSB embedding rate, [0,1] (higher =
    /// more suspicious).
    pub sample_pair_rate: f64,
}

/// Compare a cover and its stego image. Both must decode and share dimensions.
#[uniffi::export]
pub fn quality(cover: Vec<u8>, stego: Vec<u8>) -> Result<QualityReport, StegnoError> {
    let a = image_io::decode_rgba(&cover)?;
    let b = image_io::decode_rgba(&stego)?;
    if a.width != b.width || a.height != b.height {
        return Err(StegnoError::Internal("images differ in size".into()));
    }
    Ok(QualityReport {
        mse: analysis::mse(&a, &b),
        psnr_db: analysis::psnr(&a, &b),
        ssim: analysis::ssim(&a, &b),
    })
}

/// Run LSB steganalysis on a single image.
#[uniffi::export]
pub fn detect_lsb(image: Vec<u8>) -> Result<DetectionReport, StegnoError> {
    let img = image_io::decode_rgba(&image)?;
    Ok(DetectionReport {
        chi_square_p: analysis::chi_square_lsb(&img),
        rs_regularity_gap: analysis::rs_regularity_gap(&img),
        sample_pair_rate: analysis::sample_pair_rate(&img),
    })
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
        Secret::Files { files } => Revealed::Files { files },
    })
}

/// Try both decoy regions; return the first that decrypts under `passphrase`.
/// Lenient: a coincidental header in the wrong region is skipped, not fatal.
fn try_decoy_slots(stego: &[u8], passphrase: &str) -> Result<Option<Revealed>, StegnoError> {
    // Decoy slots are an image (LSB) feature; a non-image cover simply has none.
    let img = match image_io::decode_rgba(stego) {
        Ok(img) => img,
        Err(_) => return Ok(None),
    };
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

/// Split a secret into multiple parts and embed them into multiple cover files.
/// N covers must be provided. The secret is encrypted and split into N chunks.
/// Each chunk is embedded into one cover. All resulting stego files are required
/// to reconstruct the secret.
#[uniffi::export]
pub fn embed_split(
    method_id: String,
    covers: Vec<ByteChunk>,
    secret: Secret,
    passphrase: String,
) -> Result<Vec<ByteChunk>, StegnoError> {
    if covers.is_empty() {
        return Err(StegnoError::Internal("at least one cover required".into()));
    }
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;

    let inner = payload::serialize_secret(&secret);
    let sealed = crypto::seal(&inner, &passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;

    let num_parts = covers.len();
    if num_parts > 255 {
        return Err(StegnoError::Internal("too many covers (max 255)".into()));
    }

    // Split the sealed ciphertext into chunks
    let chunk_size = (sealed.len() + num_parts - 1) / num_parts;
    let mut chunks = Vec::with_capacity(num_parts);
    for (i, chunk) in sealed.chunks(chunk_size).enumerate() {
        let mut chunk_with_meta = vec![num_parts as u8, i as u8];
        chunk_with_meta.extend_from_slice(chunk);
        chunks.push(chunk_with_meta);
    }

    let opts = EmbedOpts {
        seed: Some(derive_seed(&passphrase, Slot::Primary)),
    };

    let mut stegos = Vec::with_capacity(num_parts);
    for (i, cover) in covers.iter().enumerate() {
        let chunk_with_meta = &chunks[i];
        let framed = payload::frame(chunk_with_meta);
        let stego = m.embed(&cover.bytes, &framed, &opts)?;
        stegos.push(ByteChunk { bytes: stego });
    }

    Ok(stegos)
}

/// Extract a split secret from multiple stego files.
/// All N parts must be provided to reconstruct the secret.
#[uniffi::export]
pub fn extract_split(
    method_id: String,
    stegos: Vec<ByteChunk>,
    passphrase: String,
) -> Result<Revealed, StegnoError> {
    if stegos.is_empty() {
        return Err(StegnoError::Internal("at least one stego file required".into()));
    }
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;

    let xopts = ExtractOpts {
        seed: Some(derive_seed(&passphrase, Slot::Primary)),
    };

    let mut parts: Vec<Option<Vec<u8>>> = Vec::new();
    let mut total_parts = 0;

    for stego in &stegos {
        if let Some(stream) = m.extract(&stego.bytes, &xopts)? {
            if let Some(framed_body) = payload::unframe(&stream)? {
                if framed_body.len() < 2 {
                    return Err(StegnoError::CorruptPayload);
                }
                let expected_total = framed_body[0] as usize;
                let index = framed_body[1] as usize;

                if expected_total == 0 || index >= expected_total {
                    return Err(StegnoError::CorruptPayload);
                }

                if total_parts == 0 {
                    total_parts = expected_total;
                    parts.resize(total_parts, None);
                } else if total_parts != expected_total {
                    return Err(StegnoError::CorruptPayload);
                }

                if parts[index].is_none() {
                    parts[index] = Some(framed_body[2..].to_vec());
                }
            }
        }
    }

    if total_parts == 0 || parts.iter().any(|p| p.is_none()) {
        return Err(StegnoError::NoHiddenData);
    }

    // Reassemble ciphertext
    let mut sealed = Vec::new();
    for part in parts {
        sealed.extend_from_slice(&part.unwrap());
    }

    match crypto::open(&sealed, &passphrase) {
        Ok(inner) => revealed_from_inner(&inner),
        Err(_) => Err(StegnoError::AuthFailed),
    }
}
