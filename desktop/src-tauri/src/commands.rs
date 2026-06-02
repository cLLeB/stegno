//! Tauri commands — thin wrappers around `stegno-core` plus local file I/O.
//! All processing is in-process and offline.

use serde::Serialize;
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{
    capacity as core_capacity, decoy_capacity as core_decoy_capacity, detect_lsb as core_detect,
    embed as core_embed, embed_with_decoy as core_embed_with_decoy, extract as core_extract,
    list_methods as core_list, quality as core_quality,
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

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RevealedDto {
    None,
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
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

#[tauri::command]
pub fn read_file(path: String) -> Result<Vec<u8>, String> {
    std::fs::read(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_file(path: String, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())
}
