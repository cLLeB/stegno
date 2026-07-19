//! Multi-recipient embedding: one photo, N messages, N passphrases.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed_multi, extract, multi_slot_capacity, Recipient, StegnoError};

fn cover(w: u32, h: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 41) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(70);
        px[2] = v.wrapping_mul(3);
        px[3] = 255;
    }
    encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap()
}

fn text(s: &str) -> Secret {
    Secret::Text { text: s.into() }
}

#[test]
fn each_recipient_sees_only_their_message() {
    let recipients = vec![
        Recipient { secret: text("alice: rendezvous at pier 7"), passphrase: "alice-key".into() },
        Recipient { secret: text("bob: the package is under the bench"), passphrase: "bob-key".into() },
        Recipient { secret: text("carol: abort, we are watched"), passphrase: "carol-key".into() },
    ];
    let stego = embed_multi(cover(200, 200), recipients).unwrap();

    let expect = [
        ("alice-key", "alice: rendezvous at pier 7"),
        ("bob-key", "bob: the package is under the bench"),
        ("carol-key", "carol: abort, we are watched"),
    ];
    for (pass, msg) in expect {
        let revealed = extract("lsb_seeded".into(), stego.clone(), pass.into()).unwrap();
        assert!(
            matches!(&revealed, Revealed::Text { text } if text == msg),
            "pass {pass} got {revealed:?}"
        );
    }
}

#[test]
fn stranger_passphrase_reveals_nothing() {
    let recipients = vec![
        Recipient { secret: text("secret one"), passphrase: "one".into() },
        Recipient { secret: text("secret two"), passphrase: "two".into() },
    ];
    let stego = embed_multi(cover(160, 160), recipients).unwrap();
    let revealed = extract("lsb_seeded".into(), stego, "not-a-recipient".into()).unwrap();
    assert!(matches!(revealed, Revealed::None));
}

#[test]
fn works_for_all_supported_group_sizes() {
    for count in 2u32..=8 {
        let recipients: Vec<Recipient> = (0..count)
            .map(|i| Recipient {
                secret: text(&format!("message for recipient {i}")),
                passphrase: format!("pass-{i}"),
            })
            .collect();
        let stego = embed_multi(cover(256, 256), recipients).unwrap();

        for i in 0..count {
            let revealed =
                extract("lsb_seeded".into(), stego.clone(), format!("pass-{i}")).unwrap();
            assert!(
                matches!(&revealed, Revealed::Text { text } if *text == format!("message for recipient {i}")),
                "count {count}, recipient {i}: {revealed:?}"
            );
        }
    }
}

#[test]
fn capacity_shrinks_with_more_recipients() {
    let c = cover(128, 128);
    let two = multi_slot_capacity(c.clone(), 2).unwrap();
    let four = multi_slot_capacity(c.clone(), 4).unwrap();
    assert!(two > four, "more recipients should mean less room each");
}

#[test]
fn too_few_or_too_many_rejected() {
    let one = vec![Recipient { secret: text("x"), passphrase: "p".into() }];
    assert!(matches!(embed_multi(cover(64, 64), one), Err(StegnoError::Internal(_))));

    let nine: Vec<Recipient> = (0..9)
        .map(|i| Recipient { secret: text("x"), passphrase: format!("p{i}") })
        .collect();
    assert!(matches!(embed_multi(cover(256, 256), nine), Err(StegnoError::Internal(_))));
}
