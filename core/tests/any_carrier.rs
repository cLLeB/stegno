//! Every feature against every carrier.
//!
//! The engine's region features (decoy slots, multi-recipient regions, splitting
//! across covers, and any mix of them) used to be written against RGBA pixels,
//! so they worked on photos and nothing else. They now address covers through
//! `carrier::Carrier`, and this suite is the proof: the same behaviours must
//! hold for audio, plain text, documents, video containers and arbitrary blobs
//! — with file payloads, not just text.

use stegno_core::image_io::{encode_png, RgbaImage};
use stegno_core::payload::{FileRecord, Revealed, Secret};
use stegno_core::{
    composite_capacity, cover_info, decoy_capacity, embed_composite, embed_multi,
    embed_with_decoy, extract, extract_composite, multi_slot_capacity, ByteChunk, Recipient,
};

/* ----------------------------- cover builders ---------------------------- */

fn png_cover(w: u32, h: u32, salt: u8) -> Vec<u8> {
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    for (i, px) in pixels.chunks_exact_mut(4).enumerate() {
        let v = ((i * 41 + salt as usize) % 256) as u8;
        px[0] = v;
        px[1] = v.wrapping_add(70);
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

fn wav_cover(samples: usize) -> Vec<u8> {
    let data_len = samples * 2;
    let mut v = Vec::new();
    v.extend_from_slice(b"RIFF");
    v.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
    v.extend_from_slice(b"WAVE");
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&16u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&44100u32.to_le_bytes());
    v.extend_from_slice(&88200u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(b"data");
    v.extend_from_slice(&(data_len as u32).to_le_bytes());
    for i in 0..samples {
        v.extend_from_slice(&((i as i16).wrapping_mul(7)).to_le_bytes());
    }
    v
}

/// A book-length text cover. Zero-width embedding spends three bytes per bit,
/// and the budget is capped so the file doesn't visibly balloon, so a text
/// carrier holds well under 2% of its own length — and that has to be divided
/// again across regions when several secrets share it. Carrying four secrets
/// therefore needs a genuinely long document, not a letter.
fn text_cover() -> Vec<u8> {
    "Dear Alice,\nThe weather has been lovely and the garden is coming along.\n"
        .repeat(3200)
        .into_bytes()
}

/// A PDF: a real container the engine has no codec for, so it lands on the
/// universal appended-region carrier.
fn pdf_cover() -> Vec<u8> {
    let mut v = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    v.extend((0..30_000u32).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8));
    v.extend_from_slice(b"\n%%EOF\n");
    v
}

/// A Matroska container: EBML magic plus payload-shaped noise. The engine has
/// no codec for it, so it rides the appended-region carrier — the clip still
/// plays, and the payload survives copying but not a re-encode.
fn video_cover() -> Vec<u8> {
    let mut v = vec![0x1A, 0x45, 0xDF, 0xA3];
    v.extend((0..60_000u32).map(|i| (i.wrapping_mul(40503) >> 8) as u8));
    v
}

/// A lossless YUV4MPEG2 clip — the format that gets true frame-level embedding,
/// with the payload spread across the luma planes of every frame.
fn y4m_cover(w: usize, h: usize, frames: usize) -> Vec<u8> {
    let mut v = format!("YUV4MPEG2 W{w} H{h} F30:1 Ip A1:1 C420\n").into_bytes();
    let chroma = 2 * (w.div_ceil(2) * h.div_ceil(2));
    for f in 0..frames {
        v.extend_from_slice(b"FRAME\n");
        for i in 0..w * h {
            v.push(((i * 7 + f * 31) % 256) as u8);
        }
        v.extend(std::iter::repeat_n(128u8, chroma));
    }
    v
}

/// Every carrier backing, so each test can sweep all of them.
fn all_covers() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("image", png_cover(220, 220, 1)),
        ("audio", wav_cover(120_000)),
        ("text", text_cover()),
        ("pdf", pdf_cover()),
        ("video-container", video_cover()),
        ("video-frames", y4m_cover(96, 96, 24)),
    ]
}

/* -------------------------------- helpers -------------------------------- */

fn text(s: &str) -> Secret {
    Secret::Text { text: s.into() }
}
fn file(name: &str, n: usize) -> Secret {
    Secret::File {
        name: name.into(),
        bytes: (0..n).map(|i| (i % 251) as u8).collect(),
    }
}
fn entry(secret: Secret, pass: &str) -> Recipient {
    Recipient {
        secret,
        passphrase: pass.into(),
    }
}
fn chunk(bytes: &[u8]) -> ByteChunk {
    ByteChunk {
        bytes: bytes.to_vec(),
    }
}
fn as_text(r: &Revealed) -> Option<&str> {
    match r {
        Revealed::Text { text } => Some(text),
        _ => None,
    }
}
fn as_file(r: &Revealed) -> Option<(&str, &[u8])> {
    match r {
        Revealed::File { name, bytes } => Some((name, bytes)),
        _ => None,
    }
}

/* ------------------------------ cover_info ------------------------------- */

#[test]
fn every_cover_type_opens_as_a_carrier() {
    for (label, bytes) in all_covers() {
        let info = cover_info(bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(
            info.capacity_bytes > 0,
            "{label} reported no usable capacity"
        );
        assert!(info.slots > 0, "{label} reported no slots");
    }
}

#[test]
fn non_image_covers_keep_their_container() {
    // A photo is re-encoded to PNG; everything else must come back in its own
    // container so a .pdf stays a .pdf and a video still plays.
    assert!(!cover_info(png_cover(32, 32, 0)).unwrap().preserves_container);
    for (label, bytes) in [("pdf", pdf_cover()), ("video", video_cover())] {
        assert!(
            cover_info(bytes).unwrap().preserves_container,
            "{label} must not be transcoded"
        );
    }
}

#[test]
fn appended_carriers_leave_the_original_bytes_untouched() {
    // The cover must survive as an exact prefix, or the file stops opening.
    for (label, cover) in [("pdf", pdf_cover()), ("video", video_cover())] {
        let stego = embed_composite(
            vec![chunk(&cover)],
            vec![entry(text("hi"), "k")],
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            &stego[0].bytes[..cover.len()],
            &cover[..],
            "{label} cover must be an untouched prefix"
        );
    }
}

/* --------------------------- decoy, any carrier --------------------------- */

#[test]
fn decoy_works_on_every_carrier() {
    for (label, cover) in all_covers() {
        assert!(
            decoy_capacity(cover.clone()).unwrap() > 0,
            "{label}: no decoy capacity"
        );
        let stego = embed_with_decoy(
            cover,
            text("the real plan"),
            "real".into(),
            text("nothing to see here"),
            "decoy".into(),
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));

        let real = extract("lsb_seeded".into(), stego.clone(), "real".into()).unwrap();
        assert_eq!(as_text(&real), Some("the real plan"), "{label}: real slot");

        let decoy = extract("lsb_seeded".into(), stego.clone(), "decoy".into()).unwrap();
        assert_eq!(
            as_text(&decoy),
            Some("nothing to see here"),
            "{label}: decoy slot"
        );
    }
}

#[test]
fn decoy_carries_files_not_just_text() {
    for (label, cover) in all_covers() {
        let stego = embed_with_decoy(
            cover,
            file("real.bin", 700),
            "real".into(),
            file("boring.txt", 300),
            "decoy".into(),
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));

        let real = extract("lsb_seeded".into(), stego.clone(), "real".into()).unwrap();
        let (name, bytes) = as_file(&real).unwrap_or_else(|| panic!("{label}: expected a file"));
        assert_eq!(name, "real.bin");
        assert_eq!(bytes.len(), 700);

        let decoy = extract("lsb_seeded".into(), stego, "decoy".into()).unwrap();
        assert_eq!(as_file(&decoy).unwrap().0, "boring.txt", "{label}");
    }
}

/* ----------------------- multi-recipient, any carrier ---------------------- */

#[test]
fn multi_recipient_works_on_every_carrier() {
    for (label, cover) in all_covers() {
        assert!(
            multi_slot_capacity(cover.clone(), 3).unwrap() > 0,
            "{label}: no per-recipient capacity"
        );
        let stego = embed_multi(
            cover,
            vec![
                entry(text("for alice"), "alice"),
                entry(text("for bob"), "bob"),
                entry(file("carol.dat", 400), "carol"),
            ],
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));

        for (pass, msg) in [("alice", "for alice"), ("bob", "for bob")] {
            let got = extract("lsb_seeded".into(), stego.clone(), pass.into()).unwrap();
            assert_eq!(as_text(&got), Some(msg), "{label}/{pass}");
        }
        let carol = extract("lsb_seeded".into(), stego, "carol".into()).unwrap();
        assert_eq!(as_file(&carol).unwrap().0, "carol.dat", "{label}/carol");
    }
}

/* ------------------------- composite, any carrier ------------------------- */

#[test]
fn composite_decoy_works_on_every_carrier() {
    for (label, cover) in all_covers() {
        let stego = embed_composite(
            vec![chunk(&cover)],
            vec![
                entry(text("real message"), "real"),
                entry(text("decoy message"), "decoy"),
            ],
            0,
            false,
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));

        for (pass, msg) in [("real", "real message"), ("decoy", "decoy message")] {
            let got = extract_composite(stego.clone(), pass.into()).unwrap();
            assert_eq!(as_text(&got), Some(msg), "{label}/{pass}");
        }
        assert!(matches!(
            extract_composite(stego, "wrong".into()).unwrap(),
            Revealed::None
        ));
    }
}

#[test]
fn split_across_covers_works_on_every_carrier() {
    let long = "SPLIT-PAYLOAD-".repeat(200);
    for (label, cover) in all_covers() {
        let covers = vec![chunk(&cover), chunk(&cover), chunk(&cover)];
        let stego = embed_composite(covers, vec![entry(text(&long), "k")], 0, false)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(stego.len(), 3, "{label}");

        let all = extract_composite(stego.clone(), "k".into()).unwrap();
        assert_eq!(as_text(&all), Some(long.as_str()), "{label}: all parts");

        // Every part is required.
        let missing = vec![stego[0].clone(), stego[1].clone()];
        assert!(
            matches!(
                extract_composite(missing, "k".into()).unwrap(),
                Revealed::None
            ),
            "{label}: a missing part must not rebuild"
        );
    }
}

#[test]
fn split_with_multiple_recipients_works_on_every_carrier() {
    // The combination the old engine could not express at all: several covers
    // AND several recipients AND a decoy, at once.
    for (label, cover) in all_covers() {
        let covers = vec![chunk(&cover), chunk(&cover)];
        let long = "LONG-".repeat(150);
        let stego = embed_composite(
            covers,
            vec![
                entry(text(&long), "alice"),
                entry(text("bob's note"), "bob"),
                entry(file("carol.bin", 500), "carol"),
                entry(text("plausible cover story"), "decoy"),
            ],
            0,
            false,
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(stego.len(), 2, "{label}");

        assert_eq!(
            as_text(&extract_composite(stego.clone(), "alice".into()).unwrap()),
            Some(long.as_str()),
            "{label}/alice"
        );
        assert_eq!(
            as_text(&extract_composite(stego.clone(), "bob".into()).unwrap()),
            Some("bob's note"),
            "{label}/bob"
        );
        let carol = extract_composite(stego.clone(), "carol".into()).unwrap();
        assert_eq!(as_file(&carol).unwrap().0, "carol.bin", "{label}/carol");
        assert_eq!(
            as_text(&extract_composite(stego, "decoy".into()).unwrap()),
            Some("plausible cover story"),
            "{label}/decoy"
        );
    }
}

#[test]
fn covers_of_different_media_can_be_mixed_in_one_embed() {
    // A photo, a sound clip, a text file and a video sharing one split payload.
    let covers = vec![
        chunk(&png_cover(200, 200, 3)),
        chunk(&wav_cover(90_000)),
        chunk(&text_cover()),
        chunk(&video_cover()),
    ];
    let long = "MIXED-CARRIER-".repeat(180);
    let stego = embed_composite(
        covers,
        vec![
            entry(text(&long), "one"),
            entry(file("two.bin", 600), "two"),
        ],
        0,
        false,
    )
    .unwrap();
    assert_eq!(stego.len(), 4);

    assert_eq!(
        as_text(&extract_composite(stego.clone(), "one".into()).unwrap()),
        Some(long.as_str())
    );
    let two = extract_composite(stego, "two".into()).unwrap();
    assert_eq!(as_file(&two).unwrap().0, "two.bin");
}

#[test]
fn a_tight_cover_does_not_sink_a_split_that_fits() {
    // Mixed media means capacities differing by orders of magnitude. A small
    // text cover alongside roomy ones must cap its own share and let the others
    // absorb the rest — filling in cover order used to reject a payload that
    // comfortably fit, and put the tight cover last where nothing could
    // redistribute.
    let small_text = "a brief note to nobody in particular.\n".repeat(120);
    let covers = vec![
        chunk(&png_cover(240, 240, 5)),
        chunk(&pdf_cover()),
        chunk(&small_text.into_bytes()),
    ];
    let payload = "TIGHT-".repeat(500);
    let stego = embed_composite(covers, vec![entry(text(&payload), "k")], 0, false)
        .expect("a payload that fits overall must not be refused");
    assert_eq!(
        as_text(&extract_composite(stego.clone(), "k".into()).unwrap()),
        Some(payload.as_str())
    );
    // Every cover still carries a required share.
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
            "dropping cover {drop} must break the rebuild"
        );
    }
}

#[test]
fn many_files_survive_a_mixed_carrier_split() {
    let covers = vec![chunk(&pdf_cover()), chunk(&wav_cover(100_000))];
    let files = Secret::Files {
        files: vec![
            FileRecord {
                name: "a.txt".into(),
                bytes: b"first file".to_vec(),
            },
            FileRecord {
                name: "b.bin".into(),
                bytes: vec![9u8; 400],
            },
        ],
    };
    let stego = embed_composite(covers, vec![entry(files, "k")], 0, false).unwrap();
    match extract_composite(stego, "k".into()).unwrap() {
        Revealed::Files { files } => {
            assert_eq!(files.len(), 2);
            assert_eq!(files[0].name, "a.txt");
            assert_eq!(files[1].bytes.len(), 400);
        }
        other => panic!("expected several files, got {other:?}"),
    }
}

#[test]
fn robustness_and_compression_hold_on_every_carrier() {
    for (label, cover) in all_covers() {
        let body = "y".repeat(1500);
        let stego = embed_composite(
            vec![chunk(&cover), chunk(&cover)],
            vec![entry(text(&body), "a"), entry(text("b note"), "b")],
            2,
            true,
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(
            as_text(&extract_composite(stego.clone(), "a".into()).unwrap()),
            Some(body.as_str()),
            "{label}/a"
        );
        assert_eq!(
            as_text(&extract_composite(stego, "b".into()).unwrap()),
            Some("b note"),
            "{label}/b"
        );
    }
}

#[test]
fn capacity_is_reported_for_every_carrier() {
    for (label, cover) in all_covers() {
        let one = composite_capacity(vec![chunk(&cover)], 1).unwrap();
        let four = composite_capacity(vec![chunk(&cover)], 4).unwrap();
        let two_covers = composite_capacity(vec![chunk(&cover), chunk(&cover)], 1).unwrap();
        assert!(one > 0, "{label}: no capacity");
        assert!(four < one, "{label}: more entries must mean less room each");
        assert!(
            two_covers > one,
            "{label}: more covers must mean more room"
        );
    }
}

#[test]
fn frame_level_video_is_embedded_in_the_pixels_not_appended() {
    // A y4m clip must come back exactly the same size, with every change a ±1
    // nudge of a luma sample — i.e. genuinely inside the frames.
    let cover = y4m_cover(96, 96, 24);
    let stego = embed_composite(
        vec![chunk(&cover)],
        vec![
            entry(text("across the frames"), "real"),
            entry(text("a cover story"), "decoy"),
        ],
        0,
        false,
    )
    .unwrap();
    let out = &stego[0].bytes;
    assert_eq!(out.len(), cover.len(), "no bytes appended to the clip");
    assert!(
        out.iter().zip(cover.iter()).any(|(a, b)| a != b),
        "the clip must actually carry something"
    );
    for (a, b) in cover.iter().zip(out.iter()) {
        assert!((*a as i16 - *b as i16).abs() <= 1, "changes stay at ±1");
    }
    assert_eq!(
        as_text(&extract_composite(stego.clone(), "real".into()).unwrap()),
        Some("across the frames")
    );
    assert_eq!(
        as_text(&extract_composite(stego, "decoy".into()).unwrap()),
        Some("a cover story")
    );
}

#[test]
fn frame_level_video_is_labelled_as_the_raw_stream_it_is() {
    // encode() emits YUV4MPEG2, not a muxed container. Claiming .mkv would hand
    // the user a file whose extension lies about its contents.
    let info = cover_info(y4m_cover(64, 64, 4)).unwrap();
    assert_eq!(info.kind, "video");
    assert_eq!(info.extension, "y4m");
    assert!(!info.preserves_container, "y4m is rewritten, not appended to");
}

#[test]
fn frame_level_video_capacity_scales_with_frame_count() {
    let short = cover_info(y4m_cover(96, 96, 8)).unwrap();
    let long = cover_info(y4m_cover(96, 96, 32)).unwrap();
    assert_eq!(short.kind, "video");
    assert!(
        long.capacity_bytes > short.capacity_bytes * 3,
        "more frames must mean proportionally more room"
    );
}

#[test]
fn text_covers_keep_their_visible_content() {
    let cover = text_cover();
    let stego = embed_composite(
        vec![chunk(&cover)],
        vec![entry(text("hidden"), "k")],
        0,
        false,
    )
    .unwrap();
    let out = String::from_utf8(stego[0].bytes.clone()).unwrap();
    let visible: String = out
        .chars()
        .filter(|&c| c != '\u{200B}' && c != '\u{200C}')
        .collect();
    assert_eq!(visible.as_bytes(), &cover[..]);
}
