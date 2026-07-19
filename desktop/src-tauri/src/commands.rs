//! Tauri commands — thin wrappers around `stegno-core` plus local file I/O.
//! All processing is in-process and offline.

use serde::{Deserialize, Serialize};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::ByteChunk;
use stegno_core::benchmark::detectability as core_detectability;
use stegno_core::fingerprint::fingerprint as core_fingerprint;
use stegno_core::passphrase::estimate_passphrase_strength as core_passphrase_strength;
use stegno_core::planner::plan_embedding as core_plan_embedding;
use stegno_core::sanitize::sanitize as core_sanitize;
use stegno_core::sss::{
    sss_combine as core_sss_combine, sss_split as core_sss_split, SecretShare,
};
use stegno_core::structural::scan_structure as core_scan_structure;
use stegno_core::{
    capacity as core_capacity, decoy_capacity as core_decoy_capacity, detect_lsb as core_detect,
    embed as core_embed, embed_advanced as core_embed_advanced, embed_robust as core_embed_robust,
    embed_split as core_embed_split, embed_with_decoy as core_embed_with_decoy,
    embed_multi as core_embed_multi, extract as core_extract, extract_auto as core_extract_auto,
    extract_split as core_extract_split, list_methods as core_list, multi_slot_capacity as core_multi_capacity,
    quality as core_quality, Recipient,
};

#[tauri::command]
pub fn list_methods() -> Vec<(String, String, String)> {
    core_list()
        .into_iter()
        .map(|m| (m.id, m.display_name, m.media))
        .collect()
}

#[tauri::command]
pub fn capacity(method_id: String, cover: Vec<u8>) -> Result<u64, String> {
    core_capacity(method_id, cover).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn embed_text(
    method_id: String,
    cover: Vec<u8>,
    text: String,
    passphrase: String,
) -> Result<Vec<u8>, String> {
    core_embed(method_id, cover, Secret::Text { text }, passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn embed_file(
    method_id: String,
    cover: Vec<u8>,
    name: String,
    bytes: Vec<u8>,
    passphrase: String,
) -> Result<Vec<u8>, String> {
    core_embed(method_id, cover, Secret::File { name, bytes }, passphrase)
        .map_err(|e| e.to_string())
}

/// Usable bytes **per slot** when hiding a real + decoy message (≈ half the
/// image each).
#[tauri::command]
pub fn decoy_capacity(cover: Vec<u8>) -> Result<u64, String> {
    core_decoy_capacity(cover).map_err(|e| e.to_string())
}

/// Hide a real message and a decoy message in one photo, each under its own
/// password. Revealing with the decoy password shows the decoy; the real
/// password shows the real message. Always produces a PNG photo.
#[tauri::command]
pub fn embed_text_with_decoy(
    cover: Vec<u8>,
    real_text: String,
    real_passphrase: String,
    decoy_text: String,
    decoy_passphrase: String,
) -> Result<Vec<u8>, String> {
    core_embed_with_decoy(
        cover,
        Secret::Text { text: real_text },
        real_passphrase,
        Secret::Text { text: decoy_text },
        decoy_passphrase,
    )
    .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SecretDto {
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
    Files { files: Vec<stegno_core::payload::FileRecord> },
}

impl From<SecretDto> for Secret {
    fn from(value: SecretDto) -> Self {
        match value {
            SecretDto::Text { text } => Secret::Text { text },
            SecretDto::File { name, bytes } => Secret::File { name, bytes },
            SecretDto::Files { files } => Secret::Files { files },
        }
    }
}

/// Hide a real message and a decoy message in one photo, each under its own
/// password. Supports either text or file payloads per slot. Always produces a
/// PNG photo.
#[tauri::command]
pub fn embed_with_decoy(
    cover: Vec<u8>,
    real: SecretDto,
    real_passphrase: String,
    decoy: SecretDto,
    decoy_passphrase: String,
) -> Result<Vec<u8>, String> {
    core_embed_with_decoy(
        cover,
        real.into(),
        real_passphrase,
        decoy.into(),
        decoy_passphrase,
    )
    .map_err(|e| e.to_string())
}

/// One recipient in a multi-recipient embed.
#[derive(Deserialize)]
pub struct RecipientDto {
    pub secret: SecretDto,
    pub passphrase: String,
}

/// Hide several independent messages in one photo, each under its own passphrase
/// in a disjoint keyed region. Each recipient reveals only their own message with
/// the ordinary `extract`. 2–8 recipients.
#[tauri::command]
pub fn embed_multi(cover: Vec<u8>, recipients: Vec<RecipientDto>) -> Result<Vec<u8>, String> {
    let core_recipients: Vec<Recipient> = recipients
        .into_iter()
        .map(|r| Recipient {
            secret: r.secret.into(),
            passphrase: r.passphrase,
        })
        .collect();
    core_embed_multi(cover, core_recipients).map_err(|e| e.to_string())
}

/// Usable bytes per recipient when splitting a cover `count` ways.
#[tauri::command]
pub fn multi_slot_capacity(cover: Vec<u8>, count: u32) -> Result<u64, String> {
    core_multi_capacity(cover, count).map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RevealedDto {
    None,
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
    Files { files: Vec<stegno_core::payload::FileRecord> },
}

#[tauri::command]
pub fn extract(
    method_id: String,
    stego: Vec<u8>,
    passphrase: String,
) -> Result<RevealedDto, String> {
    match core_extract(method_id, stego, passphrase).map_err(|e| e.to_string())? {
        Revealed::None => Ok(RevealedDto::None),
        Revealed::Text { text } => Ok(RevealedDto::Text { text }),
        Revealed::File { name, bytes } => Ok(RevealedDto::File { name, bytes }),
        Revealed::Files { files } => Ok(RevealedDto::Files { files }),
    }
}

/// Auto-detected extraction result: which method matched (empty if none).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoRevealedDto {
    pub method_id: String,
    pub revealed: RevealedDto,
}

/// Reveal a hidden payload without knowing which method hid it. Tries every
/// method and returns the first that decrypts under the passphrase.
#[tauri::command]
pub fn extract_auto(stego: Vec<u8>, passphrase: String) -> Result<AutoRevealedDto, String> {
    let found = core_extract_auto(stego, passphrase).map_err(|e| e.to_string())?;
    let revealed = match found.revealed {
        Revealed::None => RevealedDto::None,
        Revealed::Text { text } => RevealedDto::Text { text },
        Revealed::File { name, bytes } => RevealedDto::File { name, bytes },
        Revealed::Files { files } => RevealedDto::Files { files },
    };
    Ok(AutoRevealedDto {
        method_id: found.method_id,
        revealed,
    })
}

/// Unified hide command — accepts text, a single file, or multiple files.
#[tauri::command]
pub fn embed(
    method_id: String,
    cover: Vec<u8>,
    secret: SecretDto,
    passphrase: String,
) -> Result<Vec<u8>, String> {
    core_embed(method_id, cover, secret.into(), passphrase).map_err(|e| e.to_string())
}

/// Hide a secret with a Reed–Solomon error-correction layer so it survives
/// bounded carrier damage (light recompression, a resize, a scanned print).
/// `robustness` is 1 (smallest overhead) to 3 (most resilient). Recovered by the
/// ordinary `extract` command — the recipient needs only the passphrase.
#[tauri::command]
pub fn embed_robust(
    method_id: String,
    cover: Vec<u8>,
    secret: SecretDto,
    passphrase: String,
    robustness: u8,
) -> Result<Vec<u8>, String> {
    core_embed_robust(method_id, cover, secret.into(), passphrase, robustness)
        .map_err(|e| e.to_string())
}

/// Full hide pipeline with optional Reed–Solomon FEC (`robustness` 0–3) and an
/// optional compression pre-pass. Both are recorded in the frame so the ordinary
/// `extract` reverses them automatically.
#[tauri::command]
pub fn embed_advanced(
    method_id: String,
    cover: Vec<u8>,
    secret: SecretDto,
    passphrase: String,
    robustness: u8,
    compress: bool,
) -> Result<Vec<u8>, String> {
    core_embed_advanced(
        method_id,
        cover,
        secret.into(),
        passphrase,
        robustness,
        compress,
    )
    .map_err(|e| e.to_string())
}

/// Offline passphrase-strength estimate (score 0–4, entropy, crack time, tips).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseStrengthDto {
    pub score: u8,
    pub entropy_bits: f64,
    pub crack_time_display: String,
    pub warning: String,
    pub suggestions: Vec<String>,
}

#[tauri::command]
pub fn passphrase_strength(passphrase: String) -> PassphraseStrengthDto {
    let r = core_passphrase_strength(passphrase);
    PassphraseStrengthDto {
        score: r.score,
        entropy_bits: r.entropy_bits,
        crack_time_display: r.crack_time_display,
        warning: r.warning,
        suggestions: r.suggestions,
    }
}

#[tauri::command]
pub fn embed_split(
    method_id: String,
    covers: Vec<Vec<u8>>,
    secret: SecretDto,
    passphrase: String,
) -> Result<Vec<Vec<u8>>, String> {
    let core_covers: Vec<ByteChunk> = covers.into_iter().map(|b| ByteChunk { bytes: b }).collect();
    let result = core_embed_split(method_id, core_covers, secret.into(), passphrase)
        .map_err(|e| e.to_string())?;
    Ok(result.into_iter().map(|c| c.bytes).collect())
}

#[tauri::command]
pub fn extract_split(
    method_id: String,
    stegos: Vec<Vec<u8>>,
    passphrase: String,
) -> Result<RevealedDto, String> {
    let core_stegos: Vec<ByteChunk> = stegos.into_iter().map(|b| ByteChunk { bytes: b }).collect();
    match core_extract_split(method_id, core_stegos, passphrase).map_err(|e| e.to_string())? {
        Revealed::None => Ok(RevealedDto::None),
        Revealed::Text { text } => Ok(RevealedDto::Text { text }),
        Revealed::File { name, bytes } => Ok(RevealedDto::File { name, bytes }),
        Revealed::Files { files } => Ok(RevealedDto::Files { files }),
    }
}

/// Steganalysis scores for one image (how much it looks like it hides LSB data).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionDto {
    pub chi_square_p: f64,
    pub rs_regularity_gap: f64,
    pub sample_pair_rate: f64,
}

#[tauri::command]
pub fn detect_lsb(image: Vec<u8>) -> Result<DetectionDto, String> {
    let r = core_detect(image).map_err(|e| e.to_string())?;
    Ok(DetectionDto {
        chi_square_p: r.chi_square_p,
        rs_regularity_gap: r.rs_regularity_gap,
        sample_pair_rate: r.sample_pair_rate,
    })
}

/// Image-quality comparison between an original and its modified version.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityDto {
    pub mse: f64,
    pub psnr_db: f64,
    pub ssim: f64,
}

#[tauri::command]
pub fn quality(cover: Vec<u8>, stego: Vec<u8>) -> Result<QualityDto, String> {
    let r = core_quality(cover, stego).map_err(|e| e.to_string())?;
    Ok(QualityDto {
        mse: r.mse,
        psnr_db: r.psnr_db,
        ssim: r.ssim,
    })
}

/// One ranked method recommendation for a cover + payload size.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodRecommendationDto {
    pub method_id: String,
    pub display_name: String,
    pub media: String,
    pub usable_bytes: u64,
    pub fits: bool,
    pub fill_ratio: f64,
    pub stealth_tier: u8,
    pub note: String,
}

/// Rank the methods that can hide `payload_len` bytes in `cover`, best-first.
#[tauri::command]
pub fn plan_embedding(cover: Vec<u8>, payload_len: u64) -> Vec<MethodRecommendationDto> {
    core_plan_embedding(cover, payload_len)
        .into_iter()
        .map(|r| MethodRecommendationDto {
            method_id: r.method_id,
            display_name: r.display_name,
            media: r.media,
            usable_bytes: r.usable_bytes,
            fits: r.fits,
            fill_ratio: r.fill_ratio,
            stealth_tier: r.stealth_tier,
            note: r.note,
        })
        .collect()
}

/// One structural signal (mirrors `stegno_core::structural::StructuralFinding`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuralFindingDto {
    pub kind: String,
    pub detail: String,
    pub severity: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuralReportDto {
    pub format: String,
    pub findings: Vec<StructuralFindingDto>,
    pub suspicious: bool,
}

/// How detectable a planned embed would be (dry-run with random data).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectabilityDto {
    pub method_id: String,
    pub clean_confidence: f64,
    pub stego_confidence: f64,
    pub delta: f64,
    pub psnr_db: f64,
    pub verdict: String,
}

#[tauri::command]
pub fn detectability(
    method_id: String,
    cover: Vec<u8>,
    payload_len: u64,
) -> Result<DetectabilityDto, String> {
    let r = core_detectability(method_id, cover, payload_len).map_err(|e| e.to_string())?;
    Ok(DetectabilityDto {
        method_id: r.method_id,
        clean_confidence: r.clean_confidence,
        stego_confidence: r.stego_confidence,
        delta: r.delta,
        psnr_db: r.psnr_db,
        verdict: r.verdict,
    })
}

/// One ranked method-fingerprint guess.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodGuessDto {
    pub label: String,
    pub confidence: f64,
    pub reason: String,
}

/// Rank which steganography method most likely produced a file, best-first.
#[tauri::command]
pub fn fingerprint(data: Vec<u8>) -> Vec<MethodGuessDto> {
    core_fingerprint(data)
        .into_iter()
        .map(|g| MethodGuessDto {
            label: g.label,
            confidence: g.confidence,
            reason: g.reason,
        })
        .collect()
}

/// Counter-steganography: strip any hidden payload from a file (LSB planes,
/// appended data, polyglots, private chunks, zero-width text).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizeReportDto {
    pub cleaned: Vec<u8>,
    pub format: String,
    pub actions: Vec<String>,
    pub changed: bool,
}

#[tauri::command]
pub fn sanitize(data: Vec<u8>) -> SanitizeReportDto {
    let r = core_sanitize(data);
    SanitizeReportDto {
        cleaned: r.cleaned,
        format: r.format,
        actions: r.actions,
        changed: r.changed,
    }
}

/// Scan a file's container structure for signs of hidden data (appended data,
/// polyglots, private metadata chunks, zero-width text). No payload is decoded.
#[tauri::command]
pub fn scan_structure(data: Vec<u8>) -> StructuralReportDto {
    let r = core_scan_structure(data);
    StructuralReportDto {
        format: r.format,
        findings: r
            .findings
            .into_iter()
            .map(|f| StructuralFindingDto {
                kind: f.kind,
                detail: f.detail,
                severity: f.severity,
            })
            .collect(),
        suspicious: r.suspicious,
    }
}

/// One Shamir share (x-coordinate + per-byte evaluations).
#[derive(Serialize, Deserialize)]
pub struct SecretShareDto {
    pub x: u8,
    pub y: Vec<u8>,
}

/// Split a secret into `shares` pieces, any `threshold` of which reconstruct it.
#[tauri::command]
pub fn sss_split(
    secret: Vec<u8>,
    threshold: u8,
    shares: u8,
) -> Result<Vec<SecretShareDto>, String> {
    core_sss_split(secret, threshold, shares)
        .map(|v| {
            v.into_iter()
                .map(|s| SecretShareDto { x: s.x, y: s.y })
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Reconstruct a secret from a set of shares (need at least the threshold count).
#[tauri::command]
pub fn sss_combine(shares: Vec<SecretShareDto>) -> Result<Vec<u8>, String> {
    let core_shares = shares
        .into_iter()
        .map(|s| SecretShare { x: s.x, y: s.y })
        .collect();
    core_sss_combine(core_shares).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn read_file(path: String) -> Result<Vec<u8>, String> {
    std::fs::read(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_file(path: String, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())
}
