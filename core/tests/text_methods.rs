//! Phase 2 (text & file-structure) methods, end-to-end via the public API.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed, extract, list_methods};

fn png(w: u32, h: u32) -> Vec<u8> {
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels: vec![140u8; (w * h * 4) as usize],
    })
    .unwrap()
}

const TEXT_COVER: &[u8] = b"Dear team, please find the quarterly report attached. Regards.";

#[test]
fn phase2_methods_are_registered() {
    let ids: Vec<String> = list_methods().into_iter().map(|m| m.id).collect();
    for m in ["zero_width", "whitespace", "append_eof", "png_text"] {
        assert!(ids.iter().any(|id| id == m), "missing {m}");
    }
}

#[test]
fn mimic_words_end_to_end() {
    // Generative: cover is ignored; output is fresh word-salad text.
    let stego = embed(
        "mimic_words".into(),
        b"ignored cover".to_vec(),
        Secret::Text {
            text: "the eagle lands at dawn".into(),
        },
        "pw".into(),
    )
    .unwrap();
    // Output should be human-readable ASCII words.
    assert!(String::from_utf8(stego.clone()).unwrap().contains(' '));
    assert_eq!(
        extract("mimic_words".into(), stego, "pw".into()).unwrap(),
        Revealed::Text {
            text: "the eagle lands at dawn".into()
        }
    );
}

#[test]
fn zero_width_end_to_end() {
    let stego = embed(
        "zero_width".into(),
        TEXT_COVER.to_vec(),
        Secret::Text {
            text: "meet at noon".into(),
        },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("zero_width".into(), stego, "pw".into()).unwrap(),
        Revealed::Text {
            text: "meet at noon".into()
        }
    );
}

#[test]
fn whitespace_end_to_end() {
    let stego = embed(
        "whitespace".into(),
        TEXT_COVER.to_vec(),
        Secret::Text { text: "psst".into() },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("whitespace".into(), stego, "pw".into()).unwrap(),
        Revealed::Text { text: "psst".into() }
    );
}

#[test]
fn append_eof_end_to_end_file() {
    let stego = embed(
        "append_eof".into(),
        png(16, 16),
        Secret::File {
            name: "payload.dat".into(),
            bytes: (0u8..=255).collect(),
        },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("append_eof".into(), stego, "pw".into()).unwrap(),
        Revealed::File {
            name: "payload.dat".into(),
            bytes: (0u8..=255).collect()
        }
    );
}

#[test]
fn png_text_end_to_end() {
    let stego = embed(
        "png_text".into(),
        png(24, 24),
        Secret::Text {
            text: "hidden in metadata".into(),
        },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("png_text".into(), stego, "pw".into()).unwrap(),
        Revealed::Text {
            text: "hidden in metadata".into()
        }
    );
}

#[test]
fn clean_text_cover_reveals_none_not_error() {
    // Regression: the image-only decoy fallback must not error on a text cover.
    assert_eq!(
        extract("zero_width".into(), TEXT_COVER.to_vec(), "pw".into()).unwrap(),
        Revealed::None
    );
}

#[test]
fn wrong_passphrase_does_not_reveal() {
    let stego = embed(
        "append_eof".into(),
        png(16, 16),
        Secret::Text {
            text: "classified".into(),
        },
        "right".into(),
    )
    .unwrap();
    // append_eof finds the frame regardless of key, so the crypto layer rejects.
    assert!(extract("append_eof".into(), stego, "wrong".into()).is_err());
}
