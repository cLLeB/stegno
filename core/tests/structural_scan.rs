//! Cross-checks: the structural scanner must detect the engine's own output.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::Secret;
use stegno_core::structural::scan_structure;
use stegno_core::{embed, list_methods};

fn png_cover(w: u32, h: u32) -> Vec<u8> {
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels: vec![120u8; (w * h * 4) as usize],
    })
    .unwrap()
}

fn has_method(id: &str) -> bool {
    list_methods().into_iter().any(|m| m.id == id)
}

#[test]
fn detects_append_eof_output() {
    if !has_method("append_eof") {
        return;
    }
    let stego = embed(
        "append_eof".into(),
        png_cover(64, 64),
        Secret::Text { text: "payload after the end marker".into() },
        "pw".into(),
    )
    .unwrap();

    let report = scan_structure(stego);
    assert!(
        report.findings.iter().any(|f| f.kind == "trailing_data"),
        "scanner missed appended data; findings: {:?}",
        report.findings
    );
    assert!(report.suspicious);
}

#[test]
fn detects_zero_width_output() {
    if !has_method("zero_width") {
        return;
    }
    let carrier = "The quick brown fox jumps over the lazy dog. ".repeat(20);
    let stego = embed(
        "zero_width".into(),
        carrier.into_bytes(),
        Secret::Text { text: "hi".into() },
        "pw".into(),
    )
    .unwrap();

    let report = scan_structure(stego);
    assert!(
        report.findings.iter().any(|f| f.kind == "zero_width"),
        "scanner missed zero-width carriers; findings: {:?}",
        report.findings
    );
}

#[test]
fn clean_cover_is_quiet() {
    let report = scan_structure(png_cover(64, 64));
    assert_eq!(report.format, "png");
    assert!(!report.suspicious, "clean PNG flagged: {:?}", report.findings);
}
