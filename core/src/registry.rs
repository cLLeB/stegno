//! Method registry — the extension point. Every phase adds methods here.

use crate::method::Method;
use crate::methods::lsb_image::LsbImage;

/// All methods the engine knows about.
pub fn registry() -> Vec<Box<dyn Method>> {
    vec![Box::new(LsbImage)]
}

/// Look up a method by its stable id.
pub fn lookup(id: &str) -> Option<Box<dyn Method>> {
    registry().into_iter().find(|m| m.id() == id)
}
