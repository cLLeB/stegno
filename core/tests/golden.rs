//! Cross-platform parity.
//!
//! Embedding isn't byte-deterministic (random salt/nonce per seal), so the real
//! interop guarantee is that *recovery* is stable: whatever desktop embeds,
//! Android extracts to the identical `Revealed`, and vice-versa. Since both use
//! this one crate, asserting recovery stability here protects that contract.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed, extract};

#[test]
fn cross_platform_recovery_is_stable() {
    let cover = encode_png(&RgbaImage {
        width: 100,
        height: 100,
        pixels: vec![200u8; 100 * 100 * 4],
    })
    .unwrap();
    let secret = Secret::File {
        name: "note.txt".into(),
        bytes: b"parity".to_vec(),
    };
    let stego = embed("lsb_image".into(), cover, secret, "k".into()).unwrap();
    let got = extract("lsb_image".into(), stego, "k".into()).unwrap();
    assert_eq!(
        got,
        Revealed::File {
            name: "note.txt".into(),
            bytes: b"parity".to_vec()
        }
    );
}

#[test]
fn binary_payload_with_all_byte_values_roundtrips() {
    let cover = encode_png(&RgbaImage {
        width: 64,
        height: 64,
        pixels: vec![17u8; 64 * 64 * 4],
    })
    .unwrap();
    let all_bytes: Vec<u8> = (0..=255u8).collect();
    let stego = embed(
        "lsb_image".into(),
        cover,
        Secret::File {
            name: "x".into(),
            bytes: all_bytes.clone(),
        },
        "pw".into(),
    )
    .unwrap();
    let got = extract("lsb_image".into(), stego, "pw".into()).unwrap();
    assert_eq!(got, Revealed::File { name: "x".into(), bytes: all_bytes });
}
