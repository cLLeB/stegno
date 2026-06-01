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

/// A textured cover so edge-adaptive and PVD have varied local content.
fn textured(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 37) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(50);
        px[2] = v.wrapping_mul(3);
        px[3] = 255;
    }
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels,
    })
    .unwrap()
}

/// Every registered Phase-0/1 image method.
const IMAGE_METHODS: [&str; 5] = [
    "lsb_image",
    "lsb_seeded",
    "lsb_matching",
    "edge_adaptive",
    "pvd",
];

#[test]
fn registry_lists_all_phase1_methods() {
    let ids: Vec<String> = list_methods().into_iter().map(|m| m.id).collect();
    for m in IMAGE_METHODS {
        assert!(ids.iter().any(|id| id == m), "missing method {m}");
    }
}

#[test]
fn every_method_text_roundtrips() {
    for m in IMAGE_METHODS {
        let stego = embed(
            m.into(),
            textured(160, 160),
            Secret::Text {
                text: "shared secret across methods".into(),
            },
            "pw".into(),
        )
        .unwrap_or_else(|e| panic!("{m} embed: {e}"));
        let r = extract(m.into(), stego, "pw".into()).unwrap_or_else(|e| panic!("{m} extract: {e}"));
        assert_eq!(
            r,
            Revealed::Text {
                text: "shared secret across methods".into()
            },
            "method {m}"
        );
    }
}

#[test]
fn every_method_file_roundtrips() {
    for m in IMAGE_METHODS {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let stego = embed(
            m.into(),
            textured(200, 200),
            Secret::File {
                name: "all-bytes.bin".into(),
                bytes: bytes.clone(),
            },
            "pw".into(),
        )
        .unwrap_or_else(|e| panic!("{m} embed: {e}"));
        let r = extract(m.into(), stego, "pw".into()).unwrap_or_else(|e| panic!("{m} extract: {e}"));
        assert_eq!(
            r,
            Revealed::File {
                name: "all-bytes.bin".into(),
                bytes
            },
            "method {m}"
        );
    }
}

#[test]
fn every_method_capacity_positive() {
    for m in IMAGE_METHODS {
        assert!(
            capacity(m.into(), textured(128, 128)).unwrap() > 500,
            "method {m}"
        );
    }
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

// PVD has the trickiest reversibility (fall-off-boundary): hammer it with random
// payloads and random covers to flush out any non-reversible pair.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn pvd_random_payload_roundtrips(bytes in proptest::collection::vec(any::<u8>(), 0..120)) {
        let stego = embed("pvd".into(), textured(128, 128),
            Secret::File { name: "f".into(), bytes: bytes.clone() }, "pw".into()).unwrap();
        let r = extract("pvd".into(), stego, "pw".into()).unwrap();
        prop_assert_eq!(r, Revealed::File { name: "f".into(), bytes });
    }

    #[test]
    fn pvd_random_cover_roundtrips(seed in any::<u64>()) {
        // A pseudo-random cover (xorshift) stresses every range and boundary.
        let mut pixels = vec![0u8; 96 * 96 * 4];
        let mut s = seed | 1;
        for px in pixels.chunks_exact_mut(4) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            px[0] = s as u8;
            px[1] = (s >> 8) as u8;
            px[2] = (s >> 16) as u8;
            px[3] = 255;
        }
        let cover = encode_png(&RgbaImage { width: 96, height: 96, pixels }).unwrap();
        let stego = embed("pvd".into(), cover,
            Secret::Text { text: "reversible".into() }, "k".into()).unwrap();
        prop_assert_eq!(
            extract("pvd".into(), stego, "k".into()).unwrap(),
            Revealed::Text { text: "reversible".into() }
        );
    }
}
