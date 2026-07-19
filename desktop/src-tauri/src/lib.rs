mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_methods,
            commands::capacity,
            commands::plan_embedding,
            commands::embed,
            commands::embed_text,
            commands::embed_file,
            commands::embed_robust,
            commands::embed_advanced,
            commands::passphrase_strength,
            commands::embed_text_with_decoy,
            commands::embed_with_decoy,
            commands::embed_multi,
            commands::multi_slot_capacity,
            commands::embed_split,
            commands::decoy_capacity,
            commands::extract,
            commands::extract_auto,
            commands::extract_split,
            commands::detect_lsb,
            commands::scan_structure,
            commands::fingerprint,
            commands::sss_split,
            commands::sss_combine,
            commands::quality,
            commands::read_file,
            commands::write_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Stegno");
}
