mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_methods,
            commands::capacity,
            commands::embed,
            commands::embed_text,
            commands::embed_file,
            commands::embed_text_with_decoy,
            commands::embed_with_decoy,
            commands::embed_split,
            commands::decoy_capacity,
            commands::extract,
            commands::extract_split,
            commands::detect_lsb,
            commands::quality,
            commands::read_file,
            commands::write_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Stegno");
}
