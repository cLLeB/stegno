//! Typed Shamir key-shares.
//!
//! The untyped `sss_split` splits raw bytes, so anything recombined came back as
//! anonymous bytes — a shared document lost both its name and the fact that it
//! *was* a document. `sss_split_secret` wraps the same maths around the engine's
//! standard secret serialization so a split survives as what it started as.

use stegno_core::payload::{FileRecord, Revealed, Secret};
use stegno_core::sss::{sss_combine, sss_split};
use stegno_core::{sss_combine_secret, sss_split_secret};

#[test]
fn a_text_secret_recombines_as_text() {
    let shares = sss_split_secret(
        Secret::Text {
            text: "the vault passphrase".into(),
        },
        2,
        3,
    )
    .unwrap();
    match sss_combine_secret(shares[..2].to_vec()).unwrap() {
        Revealed::Text { text } => assert_eq!(text, "the vault passphrase"),
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn a_file_secret_keeps_its_name() {
    let bytes: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
    let shares = sss_split_secret(
        Secret::File {
            name: "report.pdf".into(),
            bytes: bytes.clone(),
        },
        3,
        5,
    )
    .unwrap();
    // Any 3 of the 5 rebuild it — take a non-contiguous subset.
    let subset = vec![shares[4].clone(), shares[0].clone(), shares[2].clone()];
    match sss_combine_secret(subset).unwrap() {
        Revealed::File { name, bytes: got } => {
            assert_eq!(name, "report.pdf");
            assert_eq!(got, bytes);
        }
        other => panic!("expected a named file, got {other:?}"),
    }
}

#[test]
fn several_files_survive_a_split() {
    let shares = sss_split_secret(
        Secret::Files {
            files: vec![
                FileRecord {
                    name: "key.pem".into(),
                    bytes: b"-----BEGIN-----".to_vec(),
                },
                FileRecord {
                    name: "notes.txt".into(),
                    bytes: vec![7u8; 300],
                },
            ],
        },
        2,
        2,
    )
    .unwrap();
    match sss_combine_secret(shares).unwrap() {
        Revealed::Files { files } => {
            assert_eq!(files.len(), 2);
            assert_eq!(files[0].name, "key.pem");
            assert_eq!(files[1].bytes.len(), 300);
        }
        other => panic!("expected several files, got {other:?}"),
    }
}

#[test]
fn too_few_shares_cannot_rebuild() {
    let shares = sss_split_secret(
        Secret::Text {
            text: "need three of five".into(),
        },
        3,
        5,
    )
    .unwrap();
    // Two shares of a 3-of-5 split must not reconstruct the secret.
    let rebuilt = sss_combine_secret(shares[..2].to_vec());
    let recovered_text = matches!(
        rebuilt,
        Ok(Revealed::Text { ref text }) if text == "need three of five"
    );
    assert!(!recovered_text, "under-threshold shares must not rebuild");
}

#[test]
fn untyped_shares_still_recombine() {
    // Shares made by the raw byte API predate the typed format; combining them
    // must degrade to a named blob rather than erroring.
    let shares = sss_split(b"raw bytes with no type byte".to_vec(), 2, 3).unwrap();
    match sss_combine_secret(shares[..2].to_vec()).unwrap() {
        Revealed::File { name, .. } => assert_eq!(name, "recovered.bin"),
        Revealed::Text { .. } => { /* a leading 0x00 would read as text; also fine */ }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn typed_and_untyped_apis_share_the_same_maths() {
    // A typed split is just the serialized secret run through the same scheme.
    let secret = Secret::Text { text: "abc".into() };
    let typed = sss_split_secret(secret, 2, 3).unwrap();
    let combined = sss_combine(typed[..2].to_vec()).unwrap();
    assert_eq!(
        combined,
        stegno_core::payload::serialize_secret(&Secret::Text { text: "abc".into() })
    );
}
