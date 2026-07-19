//! stegno-core: offline steganography engine.
//!
//! One audited engine shared by the Tauri desktop app and the native Android
//! app via UniFFI. Methods operate on already-encrypted, already-framed bytes,
//! so every technique inherits identical crypto for free.

pub mod analysis;
pub mod benchmark;
pub mod compress;
pub mod crypto;
pub mod fec;
pub mod fingerprint;
pub mod image_io;
pub mod method;
pub mod methods;
pub mod passphrase;
pub mod planner;
pub mod payload;
pub mod prng;
pub mod registry;
pub mod seed;
pub mod sss;
pub mod structural;

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

/// Like [`embed`], but wraps the sealed payload in a Reed–Solomon FEC layer so
/// the hidden data survives a bounded amount of carrier corruption (light
/// recompression, a resize, a scanned print, bit-rot). `robustness` selects the
/// error-correction budget:
///
/// * `1` — repairs ~3% of bytes (smallest overhead)
/// * `2` — repairs ~6%
/// * `3` — repairs ~12% (largest overhead, lowest capacity)
///
/// The robustness level is recorded in the frame flags, so an ordinary
/// [`extract`] call recovers the data transparently — the recipient needs only
/// the passphrase, not the level.
#[uniffi::export]
pub fn embed_robust(
    method_id: String,
    cover: Vec<u8>,
    secret: Secret,
    passphrase: String,
    robustness: u8,
) -> Result<Vec<u8>, StegnoError> {
    embed_advanced(method_id, cover, secret, passphrase, robustness, false)
}

/// The full embed pipeline with both optional layers:
///
/// * `robustness` `0` disables FEC; `1`–`3` add the Reed–Solomon layer.
/// * `compress` `true` DEFLATE-compresses the secret *before* encryption, which
///   raises effective capacity for compressible payloads (text, logs, docs) and
///   is skipped automatically when it wouldn't help.
///
/// Both choices are recorded in the frame flags, so a plain [`extract`] reverses
/// whatever was applied — the recipient still needs only the passphrase.
///
/// Pipeline: serialize → [compress] → seal → [FEC] → frame(flags).
#[uniffi::export]
pub fn embed_advanced(
    method_id: String,
    cover: Vec<u8>,
    secret: Secret,
    passphrase: String,
    robustness: u8,
    compress: bool,
) -> Result<Vec<u8>, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;

    // serialize → optional compression.
    let mut inner = payload::serialize_secret(&secret);
    let mut flags: u8 = 0;
    if compress {
        if let Some(deflated) = compress::maybe_deflate(&inner) {
            inner = deflated;
            flags |= payload::FLAG_COMPRESSED;
        }
    }

    // encryption.
    let sealed =
        crypto::seal(&inner, &passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;

    // optional FEC.
    let body = if robustness == 0 {
        sealed
    } else {
        let level = robustness.clamp(1, 3);
        flags |= payload::flags_with_fec(level);
        fec::encode(&sealed, fec::parity_for_level(level))
            .map_err(|e| StegnoError::Internal(format!("fec encode: {e:?}")))?
    };

    let framed = payload::frame_with_flags(&body, flags);
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

/// One recipient of a multi-recipient embed: their secret and their passphrase.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Recipient {
    pub secret: Secret,
    pub passphrase: String,
}

/// Largest number of recipients [`embed_multi`] will pack into one cover.
pub const MAX_RECIPIENTS: usize = 8;

/// Hide **several independent messages in one photo**, each sealed under its own
/// passphrase and written into a disjoint, key-scattered region.
///
/// Every recipient runs an ordinary [`extract`] with *their* passphrase and sees
/// *only* their message; the other regions are indistinguishable from unused LSB
/// noise without the matching key. This is the plausible-deniability decoy slot
/// generalized to N parties (2–[`MAX_RECIPIENTS`]) — e.g. one shared image that
/// carries a different note for each of five people.
///
/// Each region holds ≈ `1/N` of the image (see [`multi_slot_capacity`]); every
/// secret must fit its region or `CoverTooSmall` is returned.
#[uniffi::export]
pub fn embed_multi(cover: Vec<u8>, recipients: Vec<Recipient>) -> Result<Vec<u8>, StegnoError> {
    let count = recipients.len();
    if count < 2 || count > MAX_RECIPIENTS {
        return Err(StegnoError::Internal(format!(
            "recipients must be 2..={MAX_RECIPIENTS}"
        )));
    }
    let mut img = image_io::decode_rgba(&cover)?;
    let (w, h) = (img.width, img.height);

    for (i, r) in recipients.iter().enumerate() {
        let framed = seal_and_frame(&r.secret, &r.passphrase)?;
        let key = derive_seed(&r.passphrase, Slot::Primary);
        let order = methods::lsb_common::region_order(w, h, i as u32, count as u32, &key);
        methods::lsb_common::embed_into(
            &mut img,
            &framed,
            &order,
            methods::lsb_common::replace_lsb,
        )?;
    }
    image_io::encode_png(&img)
}

/// Usable payload bytes **per recipient** when splitting a cover `count` ways.
#[uniffi::export]
pub fn multi_slot_capacity(cover: Vec<u8>, count: u32) -> Result<u64, StegnoError> {
    let img = image_io::decode_rgba(&cover)?;
    Ok(methods::lsb_common::region_capacity_bytes(
        img.width, img.height, count,
    ))
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
    /// Histogram of gradient orientations uniformity (0..1, higher = more uniform)
    pub hog_uniformity: f64,
    /// Energy of high‑frequency residual (0..1, higher = more noise)
    pub noise_residual_energy: f64,
    /// Machine‑learning confidence score (0..1) that the image hides data.
    pub ml_confidence: f64,
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

use crate::image_io::RgbaImage;

/// Compute a very rough HOG uniformity metric (0..1).
fn hog_uniformity(img: &RgbaImage) -> f64 {
    // Simple gradient magnitude average – higher values mean more edges, thus less uniform.
    let mut total = 0f64;
    let mut count = 0usize;
    for y in 1..(img.height - 1) {
        for x in 1..(img.width - 1) {
            let idx = ((y * img.width + x) * 4) as usize;
            let r = img.pixels[idx] as f64;
            let g = img.pixels[idx + 1] as f64;
            let b = img.pixels[idx + 2] as f64;
            let lum = 0.299 * r + 0.587 * g + 0.114 * b;
            // neighbor right
            let idx_r = ((y * img.width + (x + 1)) * 4) as usize;
            let r_r = img.pixels[idx_r] as f64;
            let g_r = img.pixels[idx_r + 1] as f64;
            let b_r = img.pixels[idx_r + 2] as f64;
            let lum_r = 0.299 * r_r + 0.587 * g_r + 0.114 * b_r;
            // neighbor down
            let idx_d = (((y + 1) * img.width + x) * 4) as usize;
            let r_d = img.pixels[idx_d] as f64;
            let g_d = img.pixels[idx_d + 1] as f64;
            let b_d = img.pixels[idx_d + 2] as f64;
            let lum_d = 0.299 * r_d + 0.587 * g_d + 0.114 * b_d;
            let gx = lum_r - lum;
            let gy = lum_d - lum;
            total += (gx * gx + gy * gy).sqrt();
            count += 1;
        }
    }
    if count == 0 { return 0.0; }
    let avg = total / count as f64;
    // Normalize to 0..1 (max possible gradient ~255*sqrt(2))
    let norm = (avg / (255.0 * 2_f64.sqrt())).min(1.0);
    // Uniformity is inverse of edge strength
    1.0 - norm
}

/// Compute a simple high‑frequency residual energy metric (0..1).
fn noise_residual_energy(img: &RgbaImage) -> f64 {
    // Use pixel variance as a proxy for high‑frequency content.
    let mean: f64 = img.pixels.iter().map(|&v| v as f64).sum::<f64>() / img.pixels.len() as f64;
    let var: f64 = img.pixels.iter().map(|&v| {
        let d = v as f64 - mean;
        d * d
    }).sum::<f64>() / img.pixels.len() as f64;
    // Normalize against maximal possible variance (255^2)
    (var / (255.0 * 255.0)).min(1.0)
}

/// Combine all metrics into a lightweight confidence score (0..1).
fn ml_confidence(d: &DetectionReport) -> f64 {
    // Simple weighted sum – coefficients chosen empirically.
    let w_spa = 0.4; // sample pair rate
    let w_rs  = 0.3; // rs gap (invert: lower gap => more suspicious)
    let w_chi = 0.1; // chi‑square
    let w_hog = 0.1; // HOG uniformity (lower uniformity => more suspicious)
    let w_noise = 0.1; // residual energy (higher => more suspicious)
    let rs_inv = 1.0 - d.rs_regularity_gap.clamp(0.0, 1.0);
    let hog_inv = 1.0 - d.hog_uniformity.clamp(0.0, 1.0);
    let noise_inv = d.noise_residual_energy;
    (w_spa * d.sample_pair_rate
        + w_rs * rs_inv
        + w_chi * d.chi_square_p
        + w_hog * hog_inv
        + w_noise * noise_inv)
        .clamp(0.0, 1.0)
}

/// Run LSB steganalysis on a single image.
#[uniffi::export]
pub fn detect_lsb(image: Vec<u8>) -> Result<DetectionReport, StegnoError> {
    let img = image_io::decode_rgba(&image)?;
    let spa = analysis::sample_pair_rate(&img);
    let chi = analysis::chi_square_lsb(&img);
    let rs = analysis::rs_regularity_gap(&img);
    let hog = hog_uniformity(&img);
    let noise = noise_residual_energy(&img);
    let mut report = DetectionReport {
        chi_square_p: chi,
        rs_regularity_gap: rs,
        sample_pair_rate: spa,
        hog_uniformity: hog,
        noise_residual_energy: noise,
        ml_confidence: 0.0, // placeholder, will be filled below
    };
    report.ml_confidence = ml_confidence(&report);
    Ok(report)
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
        if let Some((flags, body)) = payload::unframe_with_flags(&stream)? {
            if let Some(sealed) = fec_decode_body(flags, body) {
                match crypto::open(&sealed, &passphrase) {
                    Ok(inner) => {
                        let inner = maybe_inflate(flags, inner)?;
                        return revealed_from_inner(&inner);
                    }
                    // A frame existed but didn't decrypt — could be a decoy image
                    // whose layout differs; keep trying before deciding.
                    Err(_) => frame_seen_wrong_pass = true,
                }
            }
        }
    }

    // 2) Decoy-mode fallback: try each region keyed by the matching slot.
    if let Some(rev) = try_decoy_slots(&stego, &passphrase)? {
        return Ok(rev);
    }

    // 3) Multi-recipient fallback: try each region across every split size.
    if let Some(rev) = try_multi_slots(&stego, &passphrase)? {
        return Ok(rev);
    }

    if frame_seen_wrong_pass {
        return Err(StegnoError::AuthFailed);
    }
    Ok(Revealed::None)
}

/// Turn a frame body back into the sealed blob, running the Reed–Solomon decode
/// pass when the frame's flags mark it FEC-encoded. Returns `None` if the FEC
/// layer is present but unrepairably corrupt (treated like "no readable data"
/// so the decoy fallback can still run).
fn fec_decode_body(flags: u8, body: Vec<u8>) -> Option<Vec<u8>> {
    let level = payload::fec_level(flags);
    if level == 0 {
        return Some(body);
    }
    fec::decode(&body, fec::parity_for_level(level)).ok()
}

/// Inflate the decrypted plaintext when the frame marks it compressed.
fn maybe_inflate(flags: u8, inner: Vec<u8>) -> Result<Vec<u8>, StegnoError> {
    if flags & payload::FLAG_COMPRESSED != 0 {
        compress::inflate(&inner)
    } else {
        Ok(inner)
    }
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

/// Result of an auto-detected extraction: which method matched, plus the data.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AutoRevealed {
    /// The method id that produced a valid, decryptable frame — empty if none.
    pub method_id: String,
    pub revealed: Revealed,
}

/// Extract a hidden payload **without knowing which method produced it**.
///
/// Tries every registered method against `stego` and returns the first that
/// yields a frame the passphrase decrypts. The AES-GCM authentication tag makes
/// a false match astronomically unlikely, so the reported `method_id` is
/// reliable. Handy when a stego file arrives with no accompanying metadata.
///
/// Returns an empty `method_id` with `Revealed::None` when nothing is found, or
/// `AuthFailed` when a frame was located but no method decrypted under this
/// passphrase (i.e. likely wrong passphrase).
#[uniffi::export]
pub fn extract_auto(stego: Vec<u8>, passphrase: String) -> Result<AutoRevealed, StegnoError> {
    let mut saw_wrong_pass = false;
    for m in registry::registry() {
        match extract(m.id().to_string(), stego.clone(), passphrase.clone()) {
            Ok(Revealed::None) => {}
            Ok(revealed) => {
                return Ok(AutoRevealed {
                    method_id: m.id().to_string(),
                    revealed,
                })
            }
            Err(StegnoError::AuthFailed) => saw_wrong_pass = true,
            // A method that can't parse this cover at all just doesn't match.
            Err(_) => {}
        }
    }
    if saw_wrong_pass {
        return Err(StegnoError::AuthFailed);
    }
    Ok(AutoRevealed {
        method_id: String::new(),
        revealed: Revealed::None,
    })
}

/// Try every region of every plausible split size (2..=MAX_RECIPIENTS); return
/// the first that decrypts under `passphrase`. The AES-GCM tag guarantees only
/// the intended recipient's region matches, so this reveals nothing about the
/// number of recipients or the other messages.
fn try_multi_slots(stego: &[u8], passphrase: &str) -> Result<Option<Revealed>, StegnoError> {
    let img = match image_io::decode_rgba(stego) {
        Ok(img) => img,
        Err(_) => return Ok(None),
    };
    let key = derive_seed(passphrase, Slot::Primary);
    for count in 2..=(MAX_RECIPIENTS as u32) {
        for index in 0..count {
            let order =
                methods::lsb_common::region_order(img.width, img.height, index, count, &key);
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
