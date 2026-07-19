//! Payload framing.
//!
//! Two layers:
//!   * inner  — `Secret` (text or named file) serialized to bytes, then encrypted.
//!   * outer  — a versioned frame written into the cover's LSB stream.
//!
//! Outer frame: `MAGIC(4) | version(1) | flags(1) | slot(1) | len(u32 BE) | body`.

use crate::crypto::CRYPTO_OVERHEAD;
use crate::StegnoError;
use serde::{Deserialize, Serialize};

const MAGIC: [u8; 4] = *b"STG0";
const VERSION: u8 = 1;
const HDR_LEN: usize = 4 + 1 + 1 + 1 + 4; // magic + version + flags + slot + len

/// `flags` bit 0: the body is Reed–Solomon FEC-encoded (see [`crate::fec`]).
pub const FLAG_FEC: u8 = 0x01;
/// `flags` bits 1–2: the FEC robustness level (1–3) when [`FLAG_FEC`] is set.
pub const FLAG_FEC_LEVEL_SHIFT: u8 = 1;
pub const FLAG_FEC_LEVEL_MASK: u8 = 0b0000_0110;
/// `flags` bit 3: the inner plaintext was DEFLATE-compressed before encryption
/// (see [`crate::compress`]).
pub const FLAG_COMPRESSED: u8 = 0x08;

/// Pack a FEC robustness level (1–3) into the frame flags byte.
pub fn flags_with_fec(level: u8) -> u8 {
    FLAG_FEC | ((level & 0b11) << FLAG_FEC_LEVEL_SHIFT)
}

/// Read the FEC robustness level back out of a flags byte (0 if FEC absent).
pub fn fec_level(flags: u8) -> u8 {
    if flags & FLAG_FEC == 0 {
        0
    } else {
        (flags & FLAG_FEC_LEVEL_MASK) >> FLAG_FEC_LEVEL_SHIFT
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record, Serialize, Deserialize)]
pub struct FileRecord {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A secret the user wants to hide.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Secret {
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
    Files { files: Vec<FileRecord> },
}

/// The result of an extraction.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Revealed {
    None,
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
    Files { files: Vec<FileRecord> },
}

/// Bytes added on top of the encrypted secret by framing + crypto.
/// Used by methods to compute usable capacity.
pub fn overhead() -> usize {
    HDR_LEN + CRYPTO_OVERHEAD + 1 // +1 for the inner type byte
}

pub fn header_len() -> usize {
    HDR_LEN
}

/// Serialize a `Secret` to inner plaintext bytes (pre-encryption).
pub fn serialize_secret(s: &Secret) -> Vec<u8> {
    match s {
        Secret::Text { text } => {
            let mut v = vec![0x00u8];
            v.extend_from_slice(text.as_bytes());
            v
        }
        Secret::File { name, bytes } => {
            let nb = name.as_bytes();
            let mut v = vec![0x01u8];
            v.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            v.extend_from_slice(nb);
            v.extend_from_slice(bytes);
            v
        }
        Secret::Files { files } => {
            let mut v = vec![0x02u8];
            v.extend_from_slice(&(files.len() as u16).to_be_bytes());
            for f in files {
                let nb = f.name.as_bytes();
                v.extend_from_slice(&(nb.len() as u16).to_be_bytes());
                v.extend_from_slice(nb);
                v.extend_from_slice(&(f.bytes.len() as u32).to_be_bytes());
                v.extend_from_slice(&f.bytes);
            }
            v
        }
    }
}

/// Parse inner plaintext bytes back into a `Secret`.
pub fn deserialize_secret(inner: &[u8]) -> Result<Secret, StegnoError> {
    let kind = *inner.first().ok_or(StegnoError::CorruptPayload)?;
    match kind {
        0x00 => Ok(Secret::Text {
            text: String::from_utf8(inner[1..].to_vec())
                .map_err(|_| StegnoError::CorruptPayload)?,
        }),
        0x01 => {
            if inner.len() < 3 {
                return Err(StegnoError::CorruptPayload);
            }
            let nlen = u16::from_be_bytes([inner[1], inner[2]]) as usize;
            if inner.len() < 3 + nlen {
                return Err(StegnoError::CorruptPayload);
            }
            let name = String::from_utf8(inner[3..3 + nlen].to_vec())
                .map_err(|_| StegnoError::CorruptPayload)?;
            Ok(Secret::File {
                name,
                bytes: inner[3 + nlen..].to_vec(),
            })
        }
        0x02 => {
            if inner.len() < 3 {
                return Err(StegnoError::CorruptPayload);
            }
            let num_files = u16::from_be_bytes([inner[1], inner[2]]) as usize;
            let mut offset = 3;
            let mut files = Vec::with_capacity(num_files);
            for _ in 0..num_files {
                if offset + 2 > inner.len() {
                    return Err(StegnoError::CorruptPayload);
                }
                let nlen = u16::from_be_bytes([inner[offset], inner[offset + 1]]) as usize;
                offset += 2;
                if offset + nlen > inner.len() {
                    return Err(StegnoError::CorruptPayload);
                }
                let name = String::from_utf8(inner[offset..offset + nlen].to_vec())
                    .map_err(|_| StegnoError::CorruptPayload)?;
                offset += nlen;
                if offset + 4 > inner.len() {
                    return Err(StegnoError::CorruptPayload);
                }
                let flen = u32::from_be_bytes([
                    inner[offset],
                    inner[offset + 1],
                    inner[offset + 2],
                    inner[offset + 3],
                ]) as usize;
                offset += 4;
                if offset + flen > inner.len() {
                    return Err(StegnoError::CorruptPayload);
                }
                let bytes = inner[offset..offset + flen].to_vec();
                offset += flen;
                files.push(FileRecord { name, bytes });
            }
            Ok(Secret::Files { files })
        }
        _ => Err(StegnoError::CorruptPayload),
    }
}

/// Wrap a body (the sealed blob) in the outer frame.
pub fn frame(body: &[u8]) -> Vec<u8> {
    frame_with_flags(body, 0)
}

/// Wrap a body in the outer frame with explicit `flags` (e.g. [`FLAG_FEC`]).
pub fn frame_with_flags(body: &[u8], flags: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(HDR_LEN + body.len());
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(flags);
    v.push(0); // slot_type: 0 = primary
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Read the outer frame from a byte stream.
///
/// `Ok(None)` if MAGIC is absent (no hidden data). `Err(CorruptPayload)` if the
/// header is present but the declared length runs past the buffer.
pub fn unframe(stream: &[u8]) -> Result<Option<Vec<u8>>, StegnoError> {
    Ok(unframe_with_flags(stream)?.map(|(_flags, body)| body))
}

/// Like [`unframe`] but also returns the `flags` byte, so callers can tell
/// whether the body needs a FEC-decode pass before decryption.
pub fn unframe_with_flags(stream: &[u8]) -> Result<Option<(u8, Vec<u8>)>, StegnoError> {
    if stream.len() < HDR_LEN || stream[..4] != MAGIC {
        return Ok(None);
    }
    let flags = stream[5];
    let len = u32::from_be_bytes([stream[7], stream[8], stream[9], stream[10]]) as usize;
    let end = HDR_LEN + len;
    if stream.len() < end {
        return Err(StegnoError::CorruptPayload);
    }
    Ok(Some((flags, stream[HDR_LEN..end].to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_secret_roundtrips_inner() {
        let s = Secret::Text { text: "hi".into() };
        let inner = serialize_secret(&s);
        assert_eq!(deserialize_secret(&inner).unwrap(), s);
    }

    #[test]
    fn file_secret_roundtrips_inner() {
        let s = Secret::File {
            name: "a.bin".into(),
            bytes: vec![1, 2, 3],
        };
        let inner = serialize_secret(&s);
        assert_eq!(deserialize_secret(&inner).unwrap(), s);
    }

    #[test]
    fn frame_unframe_roundtrips() {
        let body = vec![9u8; 40];
        let framed = frame(&body);
        assert_eq!(unframe(&framed).unwrap(), Some(body));
    }

    #[test]
    fn unframe_rejects_bad_magic() {
        assert_eq!(unframe(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap(), None);
    }

    #[test]
    fn unframe_detects_truncation() {
        let mut framed = frame(&vec![7u8; 20]);
        framed.truncate(HDR_LEN + 5);
        assert!(matches!(unframe(&framed), Err(StegnoError::CorruptPayload)));
    }
}
