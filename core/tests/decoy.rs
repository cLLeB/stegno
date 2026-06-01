//! Plausible-deniability decoy slot — end-to-end via the public API.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{decoy_capacity, embed_with_decoy, extract};

fn cover(w: u32, h: u32) -> Vec<u8> {
    // Mildly textured so LSBs are not all identical.
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = (i % 251) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(33);
        px[2] = v.wrapping_mul(7);
        px[3] = 255;
    }
    encode_png(&RgbaImage {
        width: w,
        height: h,
        pixels,
    })
    .unwrap()
}

#[test]
fn real_passphrase_reveals_real_secret() {
    let c = cover(128, 128);
    let stego = embed_with_decoy(
        c,
        Secret::Text {
            text: "launch codes: 1234".into(),
        },
        "real-pass".into(),
        Secret::Text {
            text: "grocery list".into(),
        },
        "decoy-pass".into(),
    )
    .unwrap();

    let revealed = extract("lsb_seeded".into(), stego, "real-pass".into()).unwrap();
    assert_eq!(
        revealed,
        Revealed::Text {
            text: "launch codes: 1234".into()
        }
    );
}

#[test]
fn decoy_passphrase_reveals_only_decoy() {
    let c = cover(128, 128);
    let stego = embed_with_decoy(
        c,
        Secret::Text {
            text: "the real one".into(),
        },
        "real-pass".into(),
        Secret::Text {
            text: "nothing to see here".into(),
        },
        "decoy-pass".into(),
    )
    .unwrap();

    let revealed = extract("lsb_seeded".into(), stego, "decoy-pass".into()).unwrap();
    assert_eq!(
        revealed,
        Revealed::Text {
            text: "nothing to see here".into()
        }
    );
}

#[test]
fn unrelated_passphrase_reveals_nothing() {
    let c = cover(128, 128);
    let stego = embed_with_decoy(
        c,
        Secret::Text { text: "a".into() },
        "real-pass".into(),
        Secret::Text { text: "b".into() },
        "decoy-pass".into(),
    )
    .unwrap();

    // A third party's guess unlocks neither slot.
    let revealed = extract("lsb_seeded".into(), stego, "intruder".into()).unwrap();
    assert_eq!(revealed, Revealed::None);
}

#[test]
fn both_slots_survive_each_other() {
    // Embedding the decoy must not corrupt the real slot, and vice-versa.
    let c = cover(160, 160);
    let stego = embed_with_decoy(
        c,
        Secret::File {
            name: "secret.bin".into(),
            bytes: (0u8..200).collect(),
        },
        "alpha".into(),
        Secret::File {
            name: "decoy.bin".into(),
            bytes: vec![9u8; 150],
        },
        "bravo".into(),
    )
    .unwrap();

    assert_eq!(
        extract("lsb_seeded".into(), stego.clone(), "alpha".into()).unwrap(),
        Revealed::File {
            name: "secret.bin".into(),
            bytes: (0u8..200).collect()
        }
    );
    assert_eq!(
        extract("lsb_seeded".into(), stego, "bravo".into()).unwrap(),
        Revealed::File {
            name: "decoy.bin".into(),
            bytes: vec![9u8; 150]
        }
    );
}

#[test]
fn ordinary_extract_still_works_after_decoy_changes() {
    // A normal (non-decoy) embed/extract must be unaffected by the decoy path.
    let c = cover(96, 96);
    let stego =
        stegno_core::embed("lsb_seeded".into(), c, Secret::Text { text: "plain".into() }, "pw".into())
            .unwrap();
    assert_eq!(
        extract("lsb_seeded".into(), stego.clone(), "pw".into()).unwrap(),
        Revealed::Text {
            text: "plain".into()
        }
    );
    // Wrong passphrase must never reveal the secret. For a key-seeded method the
    // frame can't even be located with the wrong key, so the honest result is
    // "no hidden data" (sequential lsb_image, where positions are key-independent,
    // is what yields an explicit AuthFailed — covered in roundtrip.rs).
    assert_eq!(
        extract("lsb_seeded".into(), stego, "nope".into()).unwrap(),
        Revealed::None
    );
}

#[test]
fn decoy_capacity_is_about_half() {
    let c = cover(128, 128);
    let full = stegno_core::capacity("lsb_seeded".into(), c.clone()).unwrap();
    let per_slot = decoy_capacity(c).unwrap();
    // Each slot is ~half; allow generous slack for overhead accounting.
    assert!(per_slot < full);
    assert!(per_slot > full / 3);
}
