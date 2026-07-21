//! `mp3_id3` — hide inside an ID3v2 private frame on an MP3.
//!
//! An MP3 is a bare sequence of audio frames; the tag block that players read
//! for title and artwork is ID3v2, prepended to the file. The spec reserves
//! `PRIV` frames for application-specific data and requires readers to skip any
//! frame they do not recognise, so a payload there is ignored by every player
//! while the file stays a well-formed MP3.
//!
//! The audio frames are not touched at all — decoded output is bit-identical.
//! That is the difference from stapling bytes past the end of the file, which
//! some players and streaming pipelines will read as a corrupt final frame.
//!
//! The tag is rewritten rather than extended, so re-embedding replaces the
//! previous payload instead of growing the file each time. Any pre-existing tag
//! is preserved ahead of ours, so artwork and track titles survive.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct Mp3Id3;

const ID3_HEADER: usize = 10;
/// Owner identifier inside our PRIV frame; also how we find it again.
const OWNER: &[u8] = b"stegno\0";
const SOFT_CAPACITY: u64 = 1 << 24;

/// Length of the ID3v2 tag at the start of `data`, if there is one.
fn id3_len(data: &[u8]) -> Option<usize> {
    if data.len() < ID3_HEADER || &data[..3] != b"ID3" {
        return None;
    }
    // The size is 28 bits, seven per byte, high bit always clear.
    let size = ((data[6] as usize & 0x7F) << 21)
        | ((data[7] as usize & 0x7F) << 14)
        | ((data[8] as usize & 0x7F) << 7)
        | (data[9] as usize & 0x7F);
    let total = ID3_HEADER + size;
    if total <= data.len() {
        Some(total)
    } else {
        None
    }
}

/// Is there a *valid* MPEG audio frame header at `i`?
///
/// The 11-bit sync alone is worthless as a format test: `FF Ex` turns up by
/// chance in any binary, and treating that as proof let this method claim PDFs
/// and Office documents and then destroy their headers. Every reserved field
/// has to check out too.
fn valid_frame_header(data: &[u8], i: usize) -> bool {
    if i + 4 > data.len() {
        return false;
    }
    let (b1, b2) = (data[i + 1], data[i + 2]);
    if data[i] != 0xFF || (b1 & 0xE0) != 0xE0 {
        return false;
    }
    let version = (b1 >> 3) & 0b11;
    let layer = (b1 >> 1) & 0b11;
    let bitrate = (b2 >> 4) & 0b1111;
    let samplerate = (b2 >> 2) & 0b11;
    // 01 is a reserved MPEG version; 00 a reserved layer; bitrate 0000 means
    // "free format" and 1111 is invalid; samplerate 11 is reserved.
    version != 0b01 && layer != 0b00 && bitrate != 0b0000 && bitrate != 0b1111 && samplerate != 0b11
}

/// Offset of the first genuine MPEG audio frame at or after `from`.
fn find_audio_start(data: &[u8], from: usize) -> Option<usize> {
    (from..data.len().saturating_sub(4)).find(|&i| valid_frame_header(data, i))
}

/// Does this look like an MP3?
///
/// Either it opens with an ID3 tag followed by audio, or the very first bytes
/// are a valid frame header. Anything that merely contains a sync-like pair
/// somewhere inside is not an MP3.
fn is_mp3(data: &[u8]) -> bool {
    match id3_len(data) {
        // A tag is a strong signal, but audio must actually follow it.
        Some(end) => find_audio_start(data, end).map(|i| i < end + 4096).unwrap_or(false),
        // No tag: the file must *begin* with a frame.
        None => valid_frame_header(data, 0),
    }
}

/// Encode `n` as a 28-bit synchsafe integer.
fn synchsafe(n: usize) -> [u8; 4] {
    [
        ((n >> 21) & 0x7F) as u8,
        ((n >> 14) & 0x7F) as u8,
        ((n >> 7) & 0x7F) as u8,
        (n & 0x7F) as u8,
    ]
}

/// Our PRIV frame, ready to sit alongside whatever frames already exist.
fn priv_frame(payload: &[u8]) -> Vec<u8> {
    let body_len = OWNER.len() + payload.len();
    let mut f = Vec::with_capacity(10 + body_len);
    f.extend_from_slice(b"PRIV");
    f.extend_from_slice(&synchsafe(body_len)); // frame size
    f.extend_from_slice(&[0, 0]); // frame flags
    f.extend_from_slice(OWNER);
    f.extend_from_slice(payload);
    f
}

/// Build a single ID3v2.4 tag from `keep` (existing frames) plus our payload.
///
/// One tag, not two: a reader parses the first `ID3` header it sees and trusts
/// its declared size, so a second tag appended behind it is invisible — which
/// silently lost the payload whenever the track already had artwork or a title.
fn build_tag(keep: &[u8], payload: &[u8]) -> Vec<u8> {
    let frame = priv_frame(payload);
    let size = keep.len() + frame.len();
    let mut tag = Vec::with_capacity(ID3_HEADER + size);
    tag.extend_from_slice(b"ID3");
    tag.push(4); // version 2.4
    tag.push(0); // revision
    tag.push(0); // flags
    tag.extend_from_slice(&synchsafe(size));
    tag.extend_from_slice(keep);
    tag.extend_from_slice(&frame);
    tag
}

/// The existing tag's frames with any PRIV frame of ours removed, so a repeat
/// embed replaces the payload instead of stacking copies.
fn frames_without_ours(data: &[u8]) -> Vec<u8> {
    let Some(tag_end) = id3_len(data) else {
        return Vec::new();
    };
    let hay = &data[..tag_end];
    let mut kept = Vec::new();
    let mut i = ID3_HEADER;
    while i + 10 <= hay.len() {
        let id = &hay[i..i + 4];
        let size = ((hay[i + 4] as usize & 0x7F) << 21)
            | ((hay[i + 5] as usize & 0x7F) << 14)
            | ((hay[i + 6] as usize & 0x7F) << 7)
            | (hay[i + 7] as usize & 0x7F);
        let body = i + 10;
        if size == 0 || body + size > hay.len() {
            break; // padding or malformed: stop, keep what we have
        }
        let ours = id == b"PRIV" && hay[body..].starts_with(OWNER);
        if !ours {
            kept.extend_from_slice(&hay[i..body + size]);
        }
        i = body + size;
    }
    kept
}

/// Our payload inside an ID3 tag, if present.
fn read_priv(data: &[u8]) -> Option<Vec<u8>> {
    let tag_end = id3_len(data)?;
    let hay = &data[..tag_end];
    // Locate `PRIV` whose owner string is ours.
    let mut i = ID3_HEADER;
    while i + 10 <= hay.len() {
        let id = &hay[i..i + 4];
        let size = ((hay[i + 4] as usize & 0x7F) << 21)
            | ((hay[i + 5] as usize & 0x7F) << 14)
            | ((hay[i + 6] as usize & 0x7F) << 7)
            | (hay[i + 7] as usize & 0x7F);
        let body = i + 10;
        if size == 0 || body + size > hay.len() {
            break;
        }
        if id == b"PRIV" && hay[body..].starts_with(OWNER) {
            return Some(hay[body + OWNER.len()..body + size].to_vec());
        }
        i = body + size;
    }
    None
}

impl Method for Mp3Id3 {
    fn id(&self) -> &'static str {
        "mp3_id3"
    }
    fn display_name(&self) -> &'static str {
        "Music track (MP3 ID3 tag)"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        if !is_mp3(cover) {
            return Err(StegnoError::UnsupportedFormat);
        }
        Ok(Capacity {
            usable_bytes: SOFT_CAPACITY.saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        if !is_mp3(cover) {
            return Err(StegnoError::UnsupportedFormat);
        }
        // Rebuild one tag: the track's own frames (artwork, titles) plus ours.
        // The audio after the tag is copied through untouched.
        let existing_end = id3_len(cover).unwrap_or(0);
        let keep = frames_without_ours(cover);

        let mut out = Vec::with_capacity(cover.len() + payload.len() + 64);
        out.extend_from_slice(&build_tag(&keep, payload));
        out.extend_from_slice(&cover[existing_end..]);
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        Ok(read_priv(stego))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in MP3: optional tag then bytes beginning with a sync word.
    fn mp3(with_tag: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if with_tag {
            let body = b"TIT2\0\0\0\x05\0\0\0Song";
            v.extend_from_slice(b"ID3");
            v.extend_from_slice(&[4, 0, 0]);
            v.extend_from_slice(&synchsafe(body.len()));
            v.extend_from_slice(body);
        }
        // Real MPEG-1 Layer III headers: FF FB = sync + version 1 + layer III,
        // 0x90 = 128 kbps at 44.1 kHz. The payload bytes after each header are
        // arbitrary, but the header itself has to validate.
        for i in 0..400u32 {
            v.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            v.push((i % 251) as u8);
            v.push(((i * 7) % 251) as u8);
        }
        v
    }

    #[test]
    fn roundtrips_through_a_priv_frame() {
        for tagged in [false, true] {
            let cover = mp3(tagged);
            let body = payload::frame(b"hidden in a track");
            let stego = Mp3Id3.embed(&cover, &body, &EmbedOpts::default()).unwrap();
            assert_eq!(
                Mp3Id3.extract(&stego, &ExtractOpts::default()).unwrap(),
                Some(body),
                "tagged={tagged}"
            );
        }
    }

    #[test]
    fn audio_frames_are_untouched() {
        let cover = mp3(false);
        let body = payload::frame(&vec![9u8; 500]);
        let stego = Mp3Id3.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        // The audio is whatever follows the tag; it must match the original.
        let start = id3_len(&stego).unwrap();
        assert_eq!(&stego[start..], &cover[..], "audio data was modified");
    }

    #[test]
    fn an_existing_tag_is_preserved() {
        let cover = mp3(true);
        let body = payload::frame(b"x");
        let stego = Mp3Id3.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert!(
            stego.windows(4).any(|w| w == b"TIT2"),
            "the original title frame was destroyed"
        );
    }

    #[test]
    fn re_embedding_replaces_rather_than_accumulates() {
        let cover = mp3(false);
        let a = Mp3Id3.embed(&cover, &payload::frame(b"one"), &EmbedOpts::default()).unwrap();
        let b = Mp3Id3.embed(&a, &payload::frame(b"two"), &EmbedOpts::default()).unwrap();
        assert_eq!(
            Mp3Id3.extract(&b, &ExtractOpts::default()).unwrap(),
            Some(payload::frame(b"two"))
        );
        assert!(b.len() <= a.len() + 8, "file grew on re-embed");
    }

    #[test]
    fn a_clean_track_yields_nothing() {
        assert_eq!(Mp3Id3.extract(&mp3(true), &ExtractOpts::default()).unwrap(), None);
    }

    #[test]
    fn non_mp3_covers_are_declined() {
        assert!(matches!(
            Mp3Id3.capacity(b"%PDF-1.7 definitely not audio"),
            Err(StegnoError::UnsupportedFormat)
        ));
    }

    /// A stray `FF Ex` pair inside a document must not make it look like audio.
    /// Accepting one prepended an ID3 tag and destroyed the real header.
    #[test]
    fn binaries_containing_a_sync_like_pair_are_declined() {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend_from_slice(&[0x00, 0xFF, 0xE3, 0x11, 0x22]); // looks like sync
        pdf.extend(std::iter::repeat_n(0x41u8, 500));
        assert!(
            matches!(Mp3Id3.capacity(&pdf), Err(StegnoError::UnsupportedFormat)),
            "a PDF containing FF E3 was accepted as an MP3"
        );

        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        zip.extend(std::iter::repeat_n(0x00u8, 400));
        assert!(
            matches!(Mp3Id3.capacity(&zip), Err(StegnoError::UnsupportedFormat)),
            "a ZIP containing a sync word was accepted as an MP3"
        );
    }

    #[test]
    fn reserved_header_fields_are_rejected() {
        // Valid sync bits but a reserved MPEG version / free-format bitrate.
        assert!(!valid_frame_header(&[0xFF, 0xEB, 0x90, 0x00], 0), "reserved version");
        assert!(!valid_frame_header(&[0xFF, 0xFB, 0x00, 0x00], 0), "free-format bitrate");
        assert!(!valid_frame_header(&[0xFF, 0xFB, 0xF0, 0x00], 0), "invalid bitrate");
        assert!(!valid_frame_header(&[0xFF, 0xFB, 0x9C, 0x00], 0), "reserved samplerate");
        assert!(valid_frame_header(&[0xFF, 0xFB, 0x90, 0x00], 0), "a normal MPEG-1 L3 frame");
    }
}
