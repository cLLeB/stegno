//! Method registry — the extension point. Every phase adds methods here.

use crate::method::Method;
use crate::methods::edge_adaptive::EdgeAdaptive;
use crate::methods::lsb_image::LsbImage;
use crate::methods::lsb_matching::LsbMatching;
use crate::methods::lsb_seeded::LsbSeeded;

/// All methods the engine knows about.
pub fn registry() -> Vec<Box<dyn Method>> {
    vec![
        Box::new(LsbImage),
        Box::new(LsbSeeded),
        Box::new(LsbMatching),
        Box::new(EdgeAdaptive),
    ]
}

/// Look up a method by its stable id.
pub fn lookup(id: &str) -> Option<Box<dyn Method>> {
    registry().into_iter().find(|m| m.id() == id)
}
