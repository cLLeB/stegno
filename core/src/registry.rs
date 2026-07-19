//! Method registry — the extension point. Every phase adds methods here.

use crate::method::Method;
use crate::methods::adaptive_cost::AdaptiveCost;
use crate::methods::append_eof::AppendEof;
use crate::methods::dwt_haar::DwtHaar;
use crate::methods::edge_adaptive::EdgeAdaptive;
use crate::methods::jpeg::{JpegF5, JpegJsteg, JpegMc, JpegOutguess};
use crate::methods::mimic_words::MimicWords;
use crate::methods::polyglot::Polyglot;
use crate::methods::lsb_high::LsbHigh;
use crate::methods::lsb_image::LsbImage;
use crate::methods::lsb_matching::LsbMatching;
use crate::methods::lsb_seeded::LsbSeeded;
use crate::methods::lsbmr::Lsbmr;
use crate::methods::png_text::PngText;
use crate::methods::pvd::Pvd;
use crate::methods::unicode_tags::UnicodeTags;
use crate::methods::wav_lsb::WavLsb;
use crate::methods::whitespace::Whitespace;
use crate::methods::zero_width::ZeroWidth;

/// All methods the engine knows about.
pub fn registry() -> Vec<Box<dyn Method>> {
    vec![
        Box::new(LsbImage),
        Box::new(LsbSeeded),
        Box::new(LsbMatching),
        Box::new(Lsbmr),
        Box::new(LsbHigh),
        Box::new(EdgeAdaptive),
        Box::new(Pvd),
        Box::new(ZeroWidth),
        Box::new(UnicodeTags),
        Box::new(Whitespace),
        Box::new(AppendEof),
        Box::new(PngText),
        Box::new(WavLsb),
        Box::new(DwtHaar),
        Box::new(JpegJsteg),
        Box::new(JpegF5),
        Box::new(JpegOutguess),
        Box::new(JpegMc),
        Box::new(AdaptiveCost),
        Box::new(MimicWords),
        Box::new(Polyglot),
    ]
}

/// Look up a method by its stable id.
pub fn lookup(id: &str) -> Option<Box<dyn Method>> {
    registry().into_iter().find(|m| m.id() == id)
}
