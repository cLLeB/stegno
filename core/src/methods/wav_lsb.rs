//! `wav_lsb` — key-seeded LSB embedding in WAV/PCM audio.
//!
//! Each payload bit replaces the least-significant bit of one audio sample's
//! low byte (little-endian), spread across a passphrase-keyed permutation of
//! sample positions. Works for 8/16/24/32-bit PCM and float WAV alike, since
//! the low byte's LSB is the least-significant either way. Only the `data`
//! chunk's sample bytes are touched; every other byte (headers, other chunks)
//! is preserved, so the file stays a valid WAV.
//!
//! Like image LSB this is **bit-exact** (required by AES-GCM). The lossy audio
//! techniques in the roadmap (echo hiding, spread-spectrum) are intentionally
//! deferred: they don't guarantee exact bit recovery, so they can't carry an
//! authenticated-encryption payload without frequent decryption failures.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::seed;
use crate::StegnoError;

pub struct WavLsb;

/// Located `data` chunk plus the bytes-per-sample stride.
struct WavInfo {
    data_off: usize,
    data_len: usize,
    bytes_per_sample: usize,
}

fn parse_wav(bytes: &[u8]) -> Result<WavInfo, StegnoError> {
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(StegnoError::UnsupportedFormat);
    }
    let mut pos = 12;
    let mut bytes_per_sample = 0usize;
    let mut data: Option<(usize, usize)> = None;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let sz = u32::from_le_bytes([bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]])
            as usize;
        let body = pos + 8;
        if body + sz > bytes.len() {
            return Err(StegnoError::UnsupportedFormat); // truncated chunk
        }
        if id == b"fmt " && sz >= 16 {
            let bits = u16::from_le_bytes([bytes[body + 14], bytes[body + 15]]) as usize;
            bytes_per_sample = bits / 8;
        } else if id == b"data" {
            data = Some((body, sz));
        }
        pos = body + sz + (sz & 1); // chunks are padded to even length
    }
    let (data_off, data_len) = data.ok_or(StegnoError::UnsupportedFormat)?;
    if !(1..=4).contains(&bytes_per_sample) {
        return Err(StegnoError::UnsupportedFormat);
    }
    Ok(WavInfo {
        data_off,
        data_len,
        bytes_per_sample,
    })
}

/// One carrier byte (the sample's low byte) per sample unit.
fn sample_offsets(info: &WavInfo) -> Vec<usize> {
    let units = info.data_len / info.bytes_per_sample;
    (0..units)
        .map(|u| info.data_off + u * info.bytes_per_sample)
        .collect()
}

fn order(units: usize, seed: Option<&[u8; 32]>) -> Vec<u32> {
    match seed {
        Some(s) => seed::permutation(units, s),
        None => (0..units as u32).collect(),
    }
}

impl Method for WavLsb {
    fn id(&self) -> &'static str {
        "wav_lsb"
    }
    fn display_name(&self) -> &'static str {
        "WAV LSB (audio)"
    }
    fn media(&self) -> Media {
        Media::Audio
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let info = parse_wav(cover)?;
        let units = info.data_len / info.bytes_per_sample;
        Ok(Capacity {
            usable_bytes: ((units / 8) as u64).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let info = parse_wav(cover)?;
        let offsets = sample_offsets(&info);
        if payload.len() * 8 > offsets.len() {
            return Err(StegnoError::CoverTooSmall);
        }
        let ord = order(offsets.len(), opts.seed.as_ref());
        let mut out = cover.to_vec();
        let mut bit = 0usize;
        for &byte in payload {
            for shift in (0..8).rev() {
                let b = (byte >> shift) & 1;
                let off = offsets[ord[bit] as usize];
                out[off] = (out[off] & 0xFE) | b;
                bit += 1;
            }
        }
        Ok(out)
    }

    fn extract(&self, stego: &[u8], opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let info = parse_wav(stego)?;
        let offsets = sample_offsets(&info);
        let ord = order(offsets.len(), opts.seed.as_ref());
        let total_units = ord.len();

        let read_byte = |byte_idx: usize| -> u8 {
            let mut out = 0u8;
            for shift in (0..8).rev() {
                let rank = byte_idx * 8 + (7 - shift);
                let off = offsets[ord[rank] as usize];
                out |= (stego[off] & 1) << shift;
            }
            out
        };

        let hdr = payload::header_len();
        if total_units < hdr * 8 {
            return Ok(None);
        }
        let mut head = Vec::with_capacity(hdr);
        for i in 0..hdr {
            head.push(read_byte(i));
        }
        if head[..4] != *b"STG0" {
            return Ok(None);
        }
        let len = u32::from_be_bytes([head[7], head[8], head[9], head[10]]) as usize;
        let need = hdr + len;
        if need * 8 > total_units {
            return Err(StegnoError::CorruptPayload);
        }
        let mut buf = Vec::with_capacity(need);
        for i in 0..need {
            buf.push(read_byte(i));
        }
        Ok(Some(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{derive_seed, Slot};

    /// Minimal mono 16-bit PCM WAV with `n` samples (ascending values).
    fn make_wav(n: usize) -> Vec<u8> {
        let data_len = n * 2;
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
        v.extend_from_slice(b"WAVE");
        // fmt chunk
        v.extend_from_slice(b"fmt ");
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // PCM
        v.extend_from_slice(&1u16.to_le_bytes()); // mono
        v.extend_from_slice(&44100u32.to_le_bytes());
        v.extend_from_slice(&88200u32.to_le_bytes()); // byte rate
        v.extend_from_slice(&2u16.to_le_bytes()); // block align
        v.extend_from_slice(&16u16.to_le_bytes()); // bits/sample
        // data chunk
        v.extend_from_slice(b"data");
        v.extend_from_slice(&(data_len as u32).to_le_bytes());
        for i in 0..n {
            v.extend_from_slice(&((i as i16).wrapping_mul(7)).to_le_bytes());
        }
        v
    }

    fn opts(pw: &str) -> (EmbedOpts, ExtractOpts) {
        let s = derive_seed(pw, Slot::Primary);
        (EmbedOpts { seed: Some(s) }, ExtractOpts { seed: Some(s) })
    }

    #[test]
    fn wav_roundtrip_seeded() {
        let cover = make_wav(4000);
        let body = payload::frame(b"audio steganography");
        let (eo, xo) = opts("key");
        let stego = WavLsb.embed(&cover, &body, &eo).unwrap();
        assert_eq!(WavLsb.extract(&stego, &xo).unwrap().unwrap(), body);
    }

    #[test]
    fn headers_and_nonsample_bytes_preserved() {
        let cover = make_wav(2000);
        let body = payload::frame(b"x");
        let (eo, _) = opts("k");
        let stego = WavLsb.embed(&cover, &body, &eo).unwrap();
        // Everything up to the data chunk body (offset 44 in this layout) is intact.
        assert_eq!(&stego[..44], &cover[..44]);
        // Sample changes are bounded to the LSB (±1).
        for (a, b) in cover[44..].iter().zip(stego[44..].iter()) {
            assert!((*a as i16 - *b as i16).abs() <= 1);
        }
    }

    #[test]
    fn too_small_errors() {
        let cover = make_wav(20); // 20 bits capacity
        let body = vec![0u8; 50];
        let (eo, _) = opts("k");
        assert!(matches!(
            WavLsb.embed(&cover, &body, &eo),
            Err(StegnoError::CoverTooSmall)
        ));
    }

    #[test]
    fn clean_wav_returns_none() {
        let cover = make_wav(1000);
        let (_, xo) = opts("k");
        assert_eq!(WavLsb.extract(&cover, &xo).unwrap(), None);
    }

    #[test]
    fn non_wav_is_unsupported() {
        assert!(matches!(
            WavLsb.capacity(b"not a wav file at all"),
            Err(StegnoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn capacity_matches_samples() {
        let cover = make_wav(8000); // 8000 bits = 1000 bytes raw
        let cap = WavLsb.capacity(&cover).unwrap();
        assert_eq!(cap.usable_bytes, 1000 - payload::overhead() as u64);
    }
}
