//! End-to-end + property tests through the public API.

use proptest::prelude::*;
use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{capacity, embed, extract, list_methods};

fn cover(w: u32, h: u32) -> Vec<u8> {
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels: vec![100u8; (w * h * 4) as usize],
    })
    .unwrap()
}

#[test]
fn lists_lsb_image() {
    assert!(list_methods().iter().any(|m| m.id == "lsb_image"));
}

#[test]
fn capacity_is_positive_for_reasonable_image() {
    assert!(capacity("lsb_image".into(), cover(128, 128)).unwrap() > 1000);
}

#[test]
fn text_end_to_end() {
    let stego = embed(
        "lsb_image".into(),
        cover(128, 128),
        Secret::Text { text: "hello".into() },
        "pw".into(),
    )
    .unwrap();
    let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
    assert_eq!(r, Revealed::Text { text: "hello".into() });
}

#[test]
fn file_end_to_end() {
    let stego = embed(
        "lsb_image".into(),
        cover(128, 128),
        Secret::File {
            name: "note.txt".into(),
            bytes: b"contents".to_vec(),
        },
        "pw".into(),
    )
    .unwrap();
    let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
    assert_eq!(
        r,
        Revealed::File {
            name: "note.txt".into(),
            bytes: b"contents".to_vec()
        }
    );
}

#[test]
fn wrong_passphrase_errors() {
    let stego = embed(
        "lsb_image".into(),
        cover(128, 128),
        Secret::Text { text: "hi".into() },
        "right".into(),
    )
    .unwrap();
    assert!(extract("lsb_image".into(), stego, "wrong".into()).is_err());
}

#[test]
fn clean_image_reveals_none() {
    assert_eq!(
        extract("lsb_image".into(), cover(64, 64), "pw".into()).unwrap(),
        Revealed::None
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn random_text_roundtrips(s in ".{0,300}") {
        let stego = embed("lsb_image".into(), cover(256, 256),
            Secret::Text { text: s.clone() }, "pw".into()).unwrap();
        let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
        prop_assert_eq!(r, Revealed::Text { text: s });
    }

    #[test]
    fn random_file_roundtrips(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let stego = embed("lsb_image".into(), cover(256, 256),
            Secret::File { name: "f.bin".into(), bytes: bytes.clone() }, "pw".into()).unwrap();
        let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
        prop_assert_eq!(r, Revealed::File { name: "f.bin".into(), bytes });
    }
}
