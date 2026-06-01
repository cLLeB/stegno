//! Method registry — the extension point. Every phase adds methods here.

use crate::method::Method;
use crate::methods::append_eof::AppendEof;
use crate::methods::edge_adaptive::EdgeAdaptive;
use crate::methods::lsb_image::LsbImage;
use crate::methods::lsb_matching::LsbMatching;
use crate::methods::lsb_seeded::LsbSeeded;
use crate::methods::png_text::PngText;
use crate::methods::pvd::Pvd;
use crate::methods::whitespace::Whitespace;
use crate::methods::zero_width::ZeroWidth;

/// All methods the engine knows about.
pub fn registry() -> Vec<Box<dyn Method>> {
    vec![
        Box::new(LsbImage),
        Box::new(LsbSeeded),
        Box::new(LsbMatching),
        Box::new(EdgeAdaptive),
        Box::new(Pvd),
        Box::new(ZeroWidth),
        Box::new(Whitespace),
        Box::new(AppendEof),
        Box::new(PngText),
    ]
}

/// Look up a method by its stable id.
pub fn lookup(id: &str) -> Option<Box<dyn Method>> {
    registry().into_iter().find(|m| m.id() == id)
}
