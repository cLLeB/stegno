//! Composite embedding: N independent entries across M covers in one call.
//! One scheme that is a plain hide, a decoy, a multi-recipient image, a split,
//! or any mix of those at once — with text or file secrets.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{
    composite_capacity, embed_composite, extract_composite, ByteChunk, Recipient,
};

fn cover(w: u32, h: u32, salt: u8) -> ByteChunk {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 41 + salt as usize) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(70);
        px[2] = v.wrapping_mul(3);
        px[3] = 255;
    }
    ByteChunk { bytes: encode_png(&RgbaImage { width: w, height: h, pixels }).unwrap() }
}

fn text(s: &str) -> Secret {
    Secret::Text { text: s.into() }
}
fn entry(secret: Secret, pass: &str) -> Recipient {
    Recipient { secret, passphrase: pass.into() }
}
fn reveal_text(r: &Revealed) -> Option<&str> {
    match r {
        Revealed::Text { text } => Some(text),
        _ => None,
    }
}

#[test]
fn one_entry_one_cover_is_a_plain_hide() {
    let stego = embed_composite(vec![cover(120, 120, 0)], vec![entry(text("just me"), "k")], 0, false).unwrap();
    let out = extract_composite(stego.clone(), "k".into()).unwrap();
    assert_eq!(reveal_text(&out), Some("just me"));
    // Wrong passphrase reveals nothing.
    assert!(matches!(extract_composite(stego, "nope".into()).unwrap(), Revealed::None));
}

#[test]
fn two_entries_one_cover_is_a_decoy() {
    let entries = vec![entry(text("the real plan"), "real"), entry(text("nothing to see"), "decoy")];
    let stego = embed_composite(vec![cover(160, 160, 1)], entries, 0, false).unwrap();
    assert_eq!(reveal_text(&extract_composite(stego.clone(), "real".into()).unwrap()), Some("the real plan"));
    assert_eq!(reveal_text(&extract_composite(stego, "decoy".into()).unwrap()), Some("nothing to see"));
}

#[test]
fn n_entries_one_cover_is_multi_recipient() {
    let entries = vec![
        entry(text("alice msg"), "alice"),
        entry(text("bob msg"), "bob"),
        entry(text("carol msg"), "carol"),
    ];
    let stego = embed_composite(vec![cover(200, 200, 2)], entries, 0, false).unwrap();
    for (pass, msg) in [("alice", "alice msg"), ("bob", "bob msg"), ("carol", "carol msg")] {
        assert_eq!(reveal_text(&extract_composite(stego.clone(), pass.into()).unwrap()), Some(msg));
    }
}

#[test]
fn one_entry_many_covers_is_a_split() {
    let covers = vec![cover(120, 120, 3), cover(120, 120, 4), cover(120, 120, 5)];
    let long = "SPLIT-".repeat(300); // larger than one small cover region holds
    let stego = embed_composite(covers, vec![entry(text(&long), "k")], 0, false).unwrap();
    assert_eq!(stego.len(), 3);
    // All covers together rebuild it.
    assert_eq!(reveal_text(&extract_composite(stego.clone(), "k".into()).unwrap()), Some(long.as_str()));
    // A missing cover means it cannot be rebuilt.
    let missing = vec![stego[0].clone(), stego[1].clone()];
    assert!(matches!(extract_composite(missing, "k".into()).unwrap(), Revealed::None));
}

#[test]
fn n_entries_m_covers_mixes_everything() {
    let covers = vec![cover(200, 200, 6), cover(200, 200, 7)];
    let big = "MIX-".repeat(400);
    let entries = vec![
        entry(text(&big), "one"),
        entry(text("second entry"), "two"),
        entry(Secret::File { name: "note.bin".into(), bytes: vec![7u8; 900] }, "three"),
    ];
    let stego = embed_composite(covers, entries, 0, false).unwrap();
    assert_eq!(stego.len(), 2);

    assert_eq!(reveal_text(&extract_composite(stego.clone(), "one".into()).unwrap()), Some(big.as_str()));
    assert_eq!(reveal_text(&extract_composite(stego.clone(), "two".into()).unwrap()), Some("second entry"));
    match extract_composite(stego.clone(), "three".into()).unwrap() {
        Revealed::File { name, bytes } => {
            assert_eq!(name, "note.bin");
            assert_eq!(bytes, vec![7u8; 900]);
        }
        other => panic!("expected a file, got {other:?}"),
    }
    assert!(matches!(extract_composite(stego, "wrong".into()).unwrap(), Revealed::None));
}

#[test]
fn robustness_and_compression_survive_a_mix() {
    let covers = vec![cover(220, 220, 8), cover(220, 220, 9)];
    let entries = vec![entry(text(&"z".repeat(2000)), "a"), entry(text("b's note"), "b")];
    let stego = embed_composite(covers, entries, 2, true).unwrap();
    assert_eq!(reveal_text(&extract_composite(stego.clone(), "a".into()).unwrap()), Some("z".repeat(2000).as_str()));
    assert_eq!(reveal_text(&extract_composite(stego, "b".into()).unwrap()), Some("b's note"));
}

/// Reveal must not depend on the order the covers are handed back.
///
/// A split writes each cover a different slice of the frame, so reassembling
/// them in the wrong sequence yields nothing — and a file picker returns files
/// in whatever order it likes (alphabetical, by date, by click order), which is
/// not necessarily the order they were made in. This reported as a flat
/// "no hidden data found" on files that were perfectly intact.
#[test]
fn covers_reveal_in_any_order() {
    let covers = vec![cover(140, 140, 21), cover(140, 140, 22), cover(140, 140, 23)];
    let long = "ORDER-".repeat(200);
    let stego = embed_composite(
        covers,
        vec![entry(text(&long), "a"), entry(text("second"), "b")],
        0,
        false,
    )
    .unwrap();
    assert_eq!(stego.len(), 3);

    // Every arrangement of the three parts must rebuild both secrets.
    let idx = [
        [0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0],
    ];
    for order in idx {
        let shuffled: Vec<ByteChunk> = order.iter().map(|&i| stego[i].clone()).collect();
        assert_eq!(
            reveal_text(&extract_composite(shuffled.clone(), "a".into()).unwrap()),
            Some(long.as_str()),
            "order {order:?} failed for the first secret"
        );
        assert_eq!(
            reveal_text(&extract_composite(shuffled, "b".into()).unwrap()),
            Some("second"),
            "order {order:?} failed for the second secret"
        );
    }
}

#[test]
fn a_missing_part_still_reveals_nothing_whatever_the_order() {
    // Order-independence must not weaken the all-parts-required guarantee.
    let covers = vec![cover(140, 140, 31), cover(140, 140, 32), cover(140, 140, 33)];
    let long = "NEEDED-".repeat(200);
    let stego = embed_composite(covers, vec![entry(text(&long), "k")], 0, false).unwrap();
    for drop in 0..3 {
        let partial: Vec<ByteChunk> = stego
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != drop)
            .map(|(_, c)| c.clone())
            .collect();
        assert!(
            matches!(
                extract_composite(partial, "k".into()).unwrap(),
                Revealed::None
            ),
            "dropping part {drop} must not rebuild"
        );
    }
}

#[test]
fn capacity_grows_with_covers_and_shrinks_with_entries() {
    let one = vec![cover(200, 200, 0)];
    let three = vec![cover(200, 200, 0), cover(200, 200, 1), cover(200, 200, 2)];
    let cap_1cover_1entry = composite_capacity(one.clone(), 1).unwrap();
    let cap_3cover_1entry = composite_capacity(three.clone(), 1).unwrap();
    let cap_1cover_4entry = composite_capacity(one, 4).unwrap();
    assert!(cap_3cover_1entry > cap_1cover_1entry, "more covers => more room");
    assert!(cap_1cover_4entry < cap_1cover_1entry, "more entries => less room each");
}

#[test]
fn too_small_cover_errors() {
    let tiny = vec![cover(16, 16, 0)];
    let huge = entry(text(&"x".repeat(100_000)), "k");
    assert!(embed_composite(tiny, vec![huge], 0, false).is_err());
}
