//! Method implementations. Each phase adds modules here and registers them in
//! `crate::registry`.

pub mod append_eof;
pub mod bitvec;
pub mod edge_adaptive;
pub mod lsb_common;
pub mod lsb_image;
pub mod lsb_matching;
pub mod lsb_seeded;
pub mod png_text;
pub mod pvd;
pub mod wav_lsb;
pub mod whitespace;
pub mod zero_width;
