//! Method implementations. Each phase adds modules here and registers them in
//! `crate::registry`.

pub mod adaptive_cost;
pub mod append_eof;
pub mod bitvec;
pub mod crc32;
pub mod dwt_haar;
pub mod edge_adaptive;
pub mod hill;
pub mod jpeg;
pub mod mimic_words;
pub mod polyglot;
pub mod lsb_common;
pub mod lsb_high;
pub mod lsb_image;
pub mod lsb_matching;
pub mod lsb_seeded;
pub mod lsbmr;
pub mod mp3_id3;
pub mod mp4_free;
pub mod pdf_object;
pub mod png_text;
pub mod pvd;
pub mod stl_attrib;
pub mod unicode_tags;
pub mod wav_lsb;
pub mod whitespace;
pub mod zero_width;
pub mod zip_comment;
