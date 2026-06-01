//! Tauri commands — thin wrappers around `stegno-core` plus local file I/O.
//! All processing is in-process and offline.

use serde::Serialize;
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{
    capacity as core_capacity, embed as core_embed, extract as core_extract,
    list_methods as core_list,
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

#[tauri::command]
pub fn read_file(path: String) -> Result<Vec<u8>, String> {
    std::fs::read(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn write_file(path: String, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())
}
