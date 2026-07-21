//! stegno-core: offline steganography engine.
//!
//! One audited engine shared by the Tauri desktop app and the native Android
//! app via UniFFI. Methods operate on already-encrypted, already-framed bytes,
//! so every technique inherits identical crypto for free.

pub mod analysis;
pub mod benchmark;
pub mod carrier;
pub mod compress;
pub mod crypto;
pub mod doctor;
pub mod fec;
pub mod fingerprint;
pub mod image_io;
pub mod method;
pub mod methods;
pub mod passphrase;
pub mod planner;
pub mod payload;
pub mod prng;
pub mod prp;
pub mod region;
pub mod registry;
pub mod sanitize;
pub mod seed;
pub mod sss;
pub mod structural;
pub mod video;
pub mod visualize;

use method::{EmbedOpts, ExtractOpts};
use payload::{Revealed, Secret};
// Brings Region::len/at into scope; the trait itself is never named here.
use region::Slots as _;
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
    let framed = build_frame(&secret, &passphrase, robustness, compress)?;
    let opts = EmbedOpts {
        seed: Some(derive_seed(&passphrase, Slot::Primary)),
    };
    m.embed(&cover, &framed, &opts)
}

/// Build the exact byte stream embedded into a carrier for one secret:
/// serialize → optional compression → AES-GCM seal → optional Reed–Solomon FEC →
/// framing (with the flags that let a plain extract reverse each step).
fn build_frame(
    secret: &Secret,
    passphrase: &str,
    robustness: u8,
    compress: bool,
) -> Result<Vec<u8>, StegnoError> {
    let mut inner = payload::serialize_secret(secret);
    let mut flags: u8 = 0;
    if compress {
        if let Some(deflated) = compress::maybe_deflate(&inner) {
            inner = deflated;
            flags |= payload::FLAG_COMPRESSED;
        }
    }
    let sealed =
        crypto::seal(&inner, passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;
    let body = if robustness == 0 {
        sealed
    } else {
        let level = robustness.clamp(1, 3);
        flags |= payload::flags_with_fec(level);
        fec::encode(&sealed, fec::parity_for_level(level))
            .map_err(|e| StegnoError::Internal(format!("fec encode: {e:?}")))?
    };
    Ok(payload::frame_with_flags(&body, flags))
}

/// Reverse [`build_frame`]: turn a raw framed byte stream back into a `Revealed`,
/// or `None` if it is not a valid frame that `passphrase` decrypts. A spurious
/// magic in random bytes (or an over-long length field) is treated as "not this
/// one" rather than an error, so composite extraction can keep scanning.
fn decode_frame(stream: &[u8], passphrase: &str) -> Result<Option<Revealed>, StegnoError> {
    let (flags, body) = match payload::unframe_with_flags(stream) {
        Ok(Some(fb)) => fb,
        _ => return Ok(None),
    };
    let sealed = match fec_decode_body(flags, body) {
        Some(s) => s,
        None => return Ok(None),
    };
    match crypto::open(&sealed, passphrase) {
        Ok(inner) => Ok(Some(revealed_from_inner(&maybe_inflate(flags, inner)?)?)),
        Err(_) => Ok(None),
    }
}

/// Spread `total` bytes across covers with capacities `caps`, as evenly as
/// possible while respecting each cap, so every cover carries a needed share and
/// all covers are required to rebuild. Deterministic in `(total, caps)` so the
/// extractor can replay it from the frame length alone. `None` if `total` can't
/// fit.
///
/// Covers are filled **smallest capacity first**. Now that a single embed can
/// mix media, capacities differ by orders of magnitude — a few hundred bytes in
/// a text cover beside tens of kilobytes in a photo. Filling in cover order
/// hands the early covers a fair share, then discovers the last one is too small
/// to take its own, with no room left to redistribute; a payload that comfortably
/// fits would be rejected. Taking the tightest cover first caps its share
/// immediately and lets the roomier ones absorb the rest.
fn split_sizes(total: usize, caps: &[usize]) -> Option<Vec<usize>> {
    let m = caps.len();
    let mut sizes = vec![0usize; m];
    let mut remaining = total;
    // Ties break on index, so the order is a pure function of `caps` and the
    // extractor derives the identical schedule.
    let mut order: Vec<usize> = (0..m).collect();
    order.sort_by_key(|&i| (caps[i], i));
    for (filled, &i) in order.iter().enumerate() {
        let covers_left = m - filled;
        let take = remaining.div_ceil(covers_left).min(caps[i]).min(remaining);
        sizes[i] = take;
        remaining -= take;
    }
    if remaining > 0 {
        None
    } else {
        Some(sizes)
    }
}

/// Embed a **real** secret and a **decoy** secret into one cover, each sealed
/// under its own passphrase and placed in a disjoint, key-seeded region. Under
/// coercion the user reveals only the decoy passphrase; the real slot is
/// indistinguishable from unused carrier noise without the real key.
///
/// Works on **any** cover — photo, audio, text, document, video, arbitrary file
/// — because it addresses the cover through a [`carrier::Carrier`] rather than
/// through pixels.
///
/// Each slot holds ≈ half the carrier (see [`decoy_capacity`]); both secrets
/// must fit or `CoverTooSmall` is returned. Extract with the ordinary
/// [`extract`] — it unlocks whichever slot the supplied passphrase sealed.
#[uniffi::export]
pub fn embed_with_decoy(
    cover: Vec<u8>,
    real_secret: Secret,
    real_passphrase: String,
    decoy_secret: Secret,
    decoy_passphrase: String,
) -> Result<Vec<u8>, StegnoError> {
    let mut c = carrier::open(&cover)?;
    let master = region::Master::new(c.slot_count());

    let real_frame = seal_and_frame(&real_secret, &real_passphrase)?;
    let decoy_frame = seal_and_frame(&decoy_secret, &decoy_passphrase)?;

    let real = master.region(
        region::decoy_index(Slot::Primary),
        2,
        &derive_seed(&real_passphrase, Slot::Primary),
    );
    let decoy = master.region(
        region::decoy_index(Slot::Decoy),
        2,
        &derive_seed(&decoy_passphrase, Slot::Decoy),
    );

    carrier::write_bytes(c.as_mut(), &real_frame, &real)?;
    carrier::write_bytes(c.as_mut(), &decoy_frame, &decoy)?;
    c.encode()
}

/// One recipient of a multi-recipient embed: their secret and their passphrase.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Recipient {
    pub secret: Secret,
    pub passphrase: String,
}

/// Largest number of recipients [`embed_multi`] will pack into one cover.
pub const MAX_RECIPIENTS: usize = 8;

/// Hide **several independent messages in one cover**, each sealed under its own
/// passphrase and written into a disjoint, key-scattered region.
///
/// Every recipient runs an ordinary [`extract`] with *their* passphrase and sees
/// *only* their message; the other regions are indistinguishable from unused
/// carrier noise without the matching key. This is the plausible-deniability
/// decoy slot generalized to N parties (2–[`MAX_RECIPIENTS`]) — e.g. one shared
/// file that carries a different note for each of five people.
///
/// The cover may be any medium (photo, audio, text, document, video, arbitrary
/// file). Each region holds ≈ `1/N` of the carrier (see
/// [`multi_slot_capacity`]); every secret must fit its region or
/// `CoverTooSmall` is returned.
#[uniffi::export]
pub fn embed_multi(cover: Vec<u8>, recipients: Vec<Recipient>) -> Result<Vec<u8>, StegnoError> {
    let count = recipients.len();
    if count < 2 || count > MAX_RECIPIENTS {
        return Err(StegnoError::Internal(format!(
            "recipients must be 2..={MAX_RECIPIENTS}"
        )));
    }
    let mut c = carrier::open(&cover)?;
    let master = region::Master::new(c.slot_count());

    for (i, r) in recipients.iter().enumerate() {
        let framed = seal_and_frame(&r.secret, &r.passphrase)?;
        let key = derive_seed(&r.passphrase, Slot::Primary);
        let r = master.region(i as u32, count as u32, &key);
        carrier::write_bytes(c.as_mut(), &framed, &r)?;
    }
    c.encode()
}

/// Usable payload bytes **per recipient** when splitting a cover `count` ways.
#[uniffi::export]
pub fn multi_slot_capacity(cover: Vec<u8>, count: u32) -> Result<u64, StegnoError> {
    let c = carrier::open(&cover)?;
    Ok(region::capacity_bytes(c.slot_count(), count))
}

/// Usable payload bytes **per slot** when embedding with a decoy (≈ half cover).
#[uniffi::export]
pub fn decoy_capacity(cover: Vec<u8>) -> Result<u64, StegnoError> {
    let c = carrier::open(&cover)?;
    Ok(region::capacity_bytes(c.slot_count(), 2))
}

/// What the engine can do with a given cover, so a UI can name the output file
/// and show honest capacity before anything is embedded.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CoverInfo {
    /// Carrier backing this cover: `image`, `audio`, `text`, `video`, `bytes`.
    pub kind: String,
    /// The container these bytes actually are — `png`, `jpeg`, `pdf`, `wav`,
    /// `y4m`, `text`, `unknown`.
    ///
    /// Distinct from [`Self::extension`], which predicts what a carrier embed
    /// will *emit*. The two differ for methods that keep a format the carrier
    /// would otherwise re-encode: the JPEG-domain methods return a JPEG, and
    /// naming that file from `extension` alone produced a JPEG called `.png`,
    /// which no viewer would open. Name output files from this field.
    pub format: String,
    /// Extension a stego file should use when the container isn't preserved.
    pub extension: String,
    pub mime: String,
    /// True when the stego output keeps the cover's own container and extension
    /// (appended-region carriers), false when it is re-encoded (image → PNG).
    pub preserves_container: bool,
    /// Addressable 1-bit slots in this cover.
    pub slots: u64,
    /// Usable payload bytes for a single secret filling the whole cover.
    pub capacity_bytes: u64,
}

/// Inspect any cover as a carrier — the call a UI makes to decide what to offer.
#[uniffi::export]
pub fn cover_info(cover: Vec<u8>) -> Result<CoverInfo, StegnoError> {
    let c = carrier::open(&cover)?;
    let kind = c.kind();
    let detected = structural::detect_container(&cover);
    Ok(CoverInfo {
        kind: format!("{kind:?}").to_lowercase(),
        format: detected.to_string(),
        // Prefer the container these bytes already are: an embed that preserved
        // the format (the JPEG methods) must not be renamed to the carrier's
        // default, and for a plain cover the two agree anyway.
        extension: match detected {
            "jpeg" => "jpg".to_string(),
            "png" | "gif" | "pdf" | "wav" | "y4m" => detected.to_string(),
            _ => kind.extension().to_string(),
        },
        mime: kind.mime().to_string(),
        preserves_container: kind.preserves_container(),
        slots: c.slot_count() as u64,
        capacity_bytes: region::capacity_bytes(c.slot_count(), 1),
    })
}

/// Largest number of independent entries one composite embed can carry.
pub const MAX_COMPOSITE_ENTRIES: usize = MAX_RECIPIENTS;

/// Hide several independent entries across one or more image covers in a single
/// call — the one primitive behind every "mix" the UI offers.
///
/// Each entry is a `(secret, passphrase)` pair (`secret` may be text, a file, or
/// many files). Entry `i` is placed at region index `i` of `entries.len()` in
/// **every** cover — regions are disjoint by construction, so entries never
/// collide — and its framed payload is split byte-wise across the covers in
/// order. This subsumes all the older modes:
///
/// * 1 entry, 1 cover → a plain hide;
/// * 2 entries, 1 cover → a real + decoy image (surrender either passphrase);
/// * N entries, 1 cover → a multi-recipient image;
/// * 1 entry, M covers → a secret split across covers (all required);
/// * N entries, M covers → multi-recipient **and** split at once.
///
/// Every cover produced together is required to rebuild any entry that spans
/// them. `robustness` (0..3 FEC) and `compress` apply to every entry. Returns one
/// stego image per input cover, in the same order.
#[uniffi::export]
pub fn embed_composite(
    covers: Vec<ByteChunk>,
    entries: Vec<Recipient>,
    robustness: u8,
    compress: bool,
) -> Result<Vec<ByteChunk>, StegnoError> {
    let n = entries.len();
    if n == 0 || n > MAX_COMPOSITE_ENTRIES {
        return Err(StegnoError::Internal(format!(
            "entries must be 1..={MAX_COMPOSITE_ENTRIES}"
        )));
    }
    if covers.is_empty() {
        return Err(StegnoError::Internal("at least one cover required".into()));
    }
    let mut carriers = covers
        .iter()
        .map(|c| carrier::open(&c.bytes))
        .collect::<Result<Vec<_>, _>>()?;
    // One master ranking per cover, reused by every entry.
    let masters: Vec<region::Master> = carriers
        .iter()
        .map(|c| region::Master::new(c.slot_count()))
        .collect();

    for (i, entry) in entries.iter().enumerate() {
        let frame = build_frame(&entry.secret, &entry.passphrase, robustness, compress)?;
        let key = derive_seed(&entry.passphrase, Slot::Primary);
        let regions: Vec<region::Region> = masters
            .iter()
            .map(|m| m.region(i as u32, n as u32, &key))
            .collect();
        let caps: Vec<usize> = regions.iter().map(|r| r.len() / 8).collect();
        let sizes = split_sizes(frame.len(), &caps).ok_or(StegnoError::CoverTooSmall)?;
        let mut pos = 0usize;
        for (c, (r, &size)) in carriers.iter_mut().zip(regions.iter().zip(sizes.iter())) {
            if size == 0 {
                continue;
            }
            carrier::write_bytes(c.as_mut(), &frame[pos..pos + size], r)?;
            pos += size;
        }
    }

    carriers
        .into_iter()
        .map(|c| {
            Ok(ByteChunk {
                bytes: c.encode()?,
            })
        })
        .collect()
}

/// Reveal the one entry a `passphrase` unlocks from a set of composite covers.
///
/// Pass every cover that was produced together, in the same order. Tries each
/// plausible entry count and index until the passphrase decrypts a frame; the
/// AES-GCM tag makes a false match negligible. Returns `Revealed::None` when
/// nothing matches (wrong passphrase, or a cover is missing).
#[uniffi::export]
pub fn extract_composite(
    stegos: Vec<ByteChunk>,
    passphrase: String,
) -> Result<Revealed, StegnoError> {
    if stegos.is_empty() {
        return Ok(Revealed::None);
    }
    let carriers = stegos
        .iter()
        .map(|c| carrier::open(&c.bytes))
        .collect::<Result<Vec<_>, _>>()?;
    // Probing 36 layouts below would otherwise rebuild each master ranking 36
    // times; on a large cover that alone dominates the reveal.
    let masters: Vec<region::Master> = carriers
        .iter()
        .map(|c| region::Master::new(c.slot_count()))
        .collect();
    let key = derive_seed(&passphrase, Slot::Primary);
    let hdr = payload::header_len();
    for count in 1..=(MAX_COMPOSITE_ENTRIES as u32) {
        for index in 0..count {
            let regions: Vec<region::Region> = masters
                .iter()
                .map(|m| m.region(index, count, &key))
                .collect();

            // Read the header alone first. A region can span an entire cover, so
            // pulling every region in full — 36 times over — would dominate the
            // reveal, and all but one layout is about to be discarded anyway.
            let head = carrier::read_bytes_n(carriers[0].as_ref(), &regions[0], hdr);
            let total = match payload::framed_len(&head) {
                Some(t) => t,
                None => continue,
            };

            // Region capacities are known without reading anything.
            let caps: Vec<usize> = regions.iter().map(|r| r.len() / 8).collect();
            let sizes = match split_sizes(total, &caps) {
                Some(s) => s,
                None => continue,
            };

            let mut frame = Vec::with_capacity(total);
            for ((c, r), &size) in carriers.iter().zip(regions.iter()).zip(sizes.iter()) {
                if size == 0 {
                    continue;
                }
                frame.extend_from_slice(&carrier::read_bytes_n(c.as_ref(), r, size));
            }
            if frame.len() == total {
                if let Some(rev) = decode_frame(&frame, &passphrase)? {
                    return Ok(rev);
                }
            }
        }
    }
    Ok(Revealed::None)
}

/// Usable bytes for **one entry** when `entry_count` entries share `covers`
/// (summed across every cover, minus one frame's overhead).
#[uniffi::export]
pub fn composite_capacity(covers: Vec<ByteChunk>, entry_count: u32) -> Result<u64, StegnoError> {
    if covers.is_empty() || entry_count == 0 {
        return Ok(0);
    }
    let mut total: u64 = 0;
    for c in &covers {
        let carrier = carrier::open(&c.bytes)?;
        let (start, end) = region::bounds(carrier.slot_count(), 0, entry_count);
        total += ((end - start) / 8) as u64;
    }
    Ok(total.saturating_sub(payload::overhead() as u64))
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

/// Combine the metrics into a confidence that this image hides LSB data (0..1).
///
/// Built only from the two estimators that have been checked to separate clean
/// images from embedded ones:
///
/// * **Chi-square** — the strongest signal in practice (≈0.00 clean, ≈1.00 for a
///   heavily embedded image).
/// * **RS regularity gap** — a clean image keeps a clear positive gap; embedding
///   drives it toward zero. Measured ≈0.08 clean against ≈0.02 embedded.
///
/// Three former inputs are deliberately excluded:
///
/// * `sample_pair_rate` claims to estimate the embedding *rate*, but returns
///   ≈0.80 for images with nothing hidden. At weight 0.4 it alone put a clean
///   photo at 60% confidence, which is why this score used to accuse every file
///   it was shown. It is still reported as a raw diagnostic, and must not be
///   trusted until the SPA solver is reworked and validated against a corpus.
/// * `hog_uniformity` and `noise_residual_energy` measure how *textured* a
///   picture is, not whether anything is hidden in it — a busy photograph is not
///   evidence of steganography.
fn ml_confidence(d: &DetectionReport) -> f64 {
    // A clean image's gap sits well above zero; embedding collapses it. Scale so
    // a healthy gap reads as innocent rather than merely "less guilty".
    const CLEAN_GAP: f64 = 0.06;
    let rs_suspicion = (1.0 - (d.rs_regularity_gap / CLEAN_GAP)).clamp(0.0, 1.0);
    (0.65 * d.chi_square_p + 0.35 * rs_suspicion).clamp(0.0, 1.0)
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

/// What one method's own read path made of a stego file.
enum MethodRead {
    Found(Revealed),
    /// A frame was there but this passphrase didn't open it.
    WrongPass,
    /// Nothing this method recognizes — including covers it can't even parse.
    Nothing,
}

/// Run a single method's read path. Never consults the region layouts, so
/// callers that try many methods can probe those once instead of once each.
fn read_with_method(
    m: &dyn method::Method,
    stego: &[u8],
    passphrase: &str,
) -> Result<MethodRead, StegnoError> {
    let xopts = ExtractOpts {
        seed: Some(derive_seed(passphrase, Slot::Primary)),
    };
    // A method that cannot parse this cover at all (an image method handed a
    // WAV, say) is simply not a match, not a failure.
    let stream = match m.extract(stego, &xopts) {
        Ok(Some(s)) => s,
        _ => return Ok(MethodRead::Nothing),
    };
    let (flags, body) = match payload::unframe_with_flags(&stream) {
        Ok(Some(fb)) => fb,
        _ => return Ok(MethodRead::Nothing),
    };
    let sealed = match fec_decode_body(flags, body) {
        Some(s) => s,
        None => return Ok(MethodRead::Nothing),
    };
    match crypto::open(&sealed, passphrase) {
        Ok(inner) => Ok(MethodRead::Found(revealed_from_inner(&maybe_inflate(
            flags, inner,
        )?)?)),
        // A frame existed but didn't decrypt — could be a cover whose real
        // payload lives in a region layout; keep looking before deciding.
        Err(_) => Ok(MethodRead::WrongPass),
    }
}

/// Extract and decrypt a hidden payload from `stego`.
///
/// Handles ordinary stego files and region-based ones — decoy slots (see
/// [`embed_with_decoy`]) and multi-recipient regions (see [`embed_multi`]) —
/// transparently, on any carrier: the passphrase unlocks whichever slot it
/// sealed, and reveals nothing about the others.
#[uniffi::export]
pub fn extract(
    method_id: String,
    stego: Vec<u8>,
    passphrase: String,
) -> Result<Revealed, StegnoError> {
    let m = registry::lookup(&method_id)
        .ok_or_else(|| StegnoError::Internal("unknown method".into()))?;

    let frame_seen_wrong_pass = match read_with_method(m.as_ref(), &stego, &passphrase)? {
        MethodRead::Found(rev) => return Ok(rev),
        MethodRead::WrongPass => true,
        MethodRead::Nothing => false,
    };

    if let Some(rev) = try_region_slots(&stego, &passphrase)? {
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

/// Probe every region layout this passphrase might have sealed: the two decoy
/// slots, then each region of every plausible recipient count.
///
/// Opens the carrier and builds the master ranking exactly once — both are
/// `O(slots)`, and this is called on covers large enough that repeating them per
/// layout (let alone per method) is the difference between an instant reveal and
/// an apparent hang.
///
/// Lenient throughout: a coincidental header in a region that isn't ours is
/// skipped rather than fatal, and the AES-GCM tag makes a false match
/// negligible. Nothing is learned about the other regions.
fn try_region_slots(stego: &[u8], passphrase: &str) -> Result<Option<Revealed>, StegnoError> {
    let c = match carrier::open(stego) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let master = region::Master::new(c.slot_count());

    // Decoy slots: two halves, each keyed from its own Slot domain.
    for slot in [Slot::Primary, Slot::Decoy] {
        let key = derive_seed(passphrase, slot);
        let r = master.region(region::decoy_index(slot), 2, &key);
        if let Some(rev) = read_framed_region(c.as_ref(), &r, passphrase)? {
            return Ok(Some(rev));
        }
    }

    // Multi-recipient regions: every region of every plausible split size.
    let key = derive_seed(passphrase, Slot::Primary);
    for count in 2..=(MAX_RECIPIENTS as u32) {
        for index in 0..count {
            let r = master.region(index, count, &key);
            if let Some(rev) = read_framed_region(c.as_ref(), &r, passphrase)? {
                return Ok(Some(rev));
            }
        }
    }
    Ok(None)
}

/// Read a frame that starts at the beginning of `order`, and decrypt it.
/// `None` covers every "not this region" case — no magic, a length that runs
/// past the region, or a body this passphrase doesn't open — so callers can keep
/// probing other layouts.
///
/// Reads the header first and only then the declared length, so probing a
/// layout that holds nothing costs eleven bytes rather than a whole region.
fn read_framed_region(
    c: &dyn carrier::Carrier,
    order: &dyn region::Slots,
    passphrase: &str,
) -> Result<Option<Revealed>, StegnoError> {
    let hdr = payload::header_len();
    if order.len() < hdr * 8 {
        return Ok(None);
    }
    let head = carrier::read_bytes_n(c, order, hdr);
    let total = match payload::framed_len(&head) {
        Some(t) => t,
        None => return Ok(None),
    };
    if total * 8 > order.len() {
        return Ok(None);
    }
    decode_frame(&carrier::read_bytes_n(c, order, total), passphrase)
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
        match read_with_method(m.as_ref(), &stego, &passphrase)? {
            MethodRead::Found(revealed) => {
                return Ok(AutoRevealed {
                    method_id: m.id().to_string(),
                    revealed,
                })
            }
            MethodRead::WrongPass => saw_wrong_pass = true,
            MethodRead::Nothing => {}
        }
    }
    // Region layouts don't depend on the method, so they are probed once here
    // rather than inside each of the loops above.
    if let Some(revealed) = try_region_slots(&stego, &passphrase)? {
        return Ok(AutoRevealed {
            method_id: String::new(),
            revealed,
        });
    }
    if saw_wrong_pass {
        return Err(StegnoError::AuthFailed);
    }
    Ok(AutoRevealed {
        method_id: String::new(),
        revealed: Revealed::None,
    })
}

/// Split a **typed** secret into Shamir shares — text, a named file, or many
/// files — so that recombining restores what it actually was.
///
/// [`sss::sss_split`] operates on raw bytes, which loses the distinction between
/// a message and a file and throws away filenames: a recombined document came
/// back as anonymous bytes. This wraps the same maths around the engine's
/// standard secret serialization, so a 2-of-3 split of `report.pdf` recombines
/// as `report.pdf`.
#[uniffi::export]
pub fn sss_split_secret(
    secret: Secret,
    threshold: u8,
    shares: u8,
) -> Result<Vec<sss::SecretShare>, StegnoError> {
    sss::sss_split(payload::serialize_secret(&secret), threshold, shares)
}

/// Recombine shares produced by [`sss_split_secret`], restoring the original
/// secret's type and any filenames.
///
/// Falls back to reporting raw bytes as a file named `recovered.bin` when the
/// shares came from the untyped [`sss::sss_split`], so both share formats
/// recombine through one call.
#[uniffi::export]
pub fn sss_combine_secret(shares: Vec<sss::SecretShare>) -> Result<Revealed, StegnoError> {
    let bytes = sss::sss_combine(shares)?;
    match payload::deserialize_secret(&bytes) {
        Ok(Secret::Text { text }) => Ok(Revealed::Text { text }),
        Ok(Secret::File { name, bytes }) => Ok(Revealed::File { name, bytes }),
        Ok(Secret::Files { files }) => Ok(Revealed::Files { files }),
        Err(_) => Ok(Revealed::File {
            name: "recovered.bin".into(),
            bytes,
        }),
    }
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
