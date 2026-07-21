//! Tests for `extract_auto` — recovering a payload without knowing the method.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed, embed_robust, extract_auto, StegnoError};

fn textured(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 37) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(50);
        px[2] = v.wrapping_mul(3);
        px[3] = 255;
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

#[test]
fn identifies_a_valid_decoding_method() {
    let pass = "auto-detect-me";
    // `lsb_seeded` and `lsb_matching` share an identical read path (both read the
    // LSB at the same seeded positions), so either is a correct decoder for the
    // other's output. Every other method has a distinct read path.
    let acceptable: &[(&str, &[&str])] = &[
        ("lsb_image", &["lsb_image"]),
        ("lsb_seeded", &["lsb_seeded", "lsb_matching"]),
        ("lsb_matching", &["lsb_seeded", "lsb_matching"]),
        ("edge_adaptive", &["edge_adaptive"]),
        ("pvd", &["pvd"]),
    ];
    for (method, ok_decoders) in acceptable {
        let stego = embed(
            (*method).into(),
            textured(160, 160),
            Secret::Text { text: "hidden".into() },
            pass.into(),
        )
        .unwrap();

        let found = extract_auto(stego, pass.into()).unwrap();
        assert!(
            ok_decoders.contains(&found.method_id.as_str()),
            "embedded with {method}, auto-detect reported {} (allowed: {ok_decoders:?})",
            found.method_id
        );
        assert!(matches!(found.revealed, Revealed::Text { text } if text == "hidden"));
    }
}

#[test]
fn auto_detects_fec_payloads_too() {
    let pass = "pw";
    let stego = embed_robust(
        "lsb_seeded".into(),
        textured(200, 200),
        Secret::Text { text: "robust+auto".into() },
        pass.into(),
        2,
    )
    .unwrap();
    let found = extract_auto(stego, pass.into()).unwrap();
    assert_eq!(found.method_id, "lsb_seeded");
    assert!(matches!(found.revealed, Revealed::Text { text } if text == "robust+auto"));
}

#[test]
fn nothing_hidden_returns_empty() {
    let found = extract_auto(textured(64, 64), "pw".into()).unwrap();
    assert!(found.method_id.is_empty());
    assert!(matches!(found.revealed, Revealed::None));
}

#[test]
fn wrong_passphrase_reports_auth_failed() {
    // `lsb_image` is sequential (unseeded), so the frame is always located and a
    // wrong passphrase fails the GCM tag → AuthFailed. (Seeded methods instead
    // hide the frame's very existence under a wrong passphrase.)
    let stego = embed(
        "lsb_image".into(),
        textured(160, 160),
        Secret::Text { text: "secret".into() },
        "right".into(),
    )
    .unwrap();
    assert!(matches!(
        extract_auto(stego, "wrong".into()),
        Err(StegnoError::AuthFailed)
    ));
}
