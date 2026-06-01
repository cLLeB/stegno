//! WAV LSB audio method, end-to-end via the public API.

use stegno_core::payload::{Revealed, Secret};
use stegno_core::{capacity, embed, extract, list_methods};

/// Minimal mono 16-bit PCM WAV with `n` samples.
fn wav(n: usize) -> Vec<u8> {
    let data_len = n * 2;
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
    for i in 0..n {
        v.extend_from_slice(&((i as i16).wrapping_mul(11)).to_le_bytes());
    }
    v
}

#[test]
fn wav_lsb_registered() {
    assert!(list_methods().iter().any(|m| m.id == "wav_lsb"));
}

#[test]
fn wav_text_end_to_end() {
    let stego = embed(
        "wav_lsb".into(),
        wav(8000),
        Secret::Text {
            text: "voices carry".into(),
        },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("wav_lsb".into(), stego, "pw".into()).unwrap(),
        Revealed::Text {
            text: "voices carry".into()
        }
    );
}

#[test]
fn wav_file_end_to_end() {
    let stego = embed(
        "wav_lsb".into(),
        wav(12000),
        Secret::File {
            name: "blob".into(),
            bytes: (0u8..=255).collect(),
        },
        "pw".into(),
    )
    .unwrap();
    assert_eq!(
        extract("wav_lsb".into(), stego, "pw".into()).unwrap(),
        Revealed::File {
            name: "blob".into(),
            bytes: (0u8..=255).collect()
        }
    );
}

#[test]
fn wav_capacity_positive() {
    assert!(capacity("wav_lsb".into(), wav(8000)).unwrap() > 500);
}

#[test]
fn wav_clean_reveals_none() {
    assert_eq!(
        extract("wav_lsb".into(), wav(2000), "pw".into()).unwrap(),
        Revealed::None
    );
}
