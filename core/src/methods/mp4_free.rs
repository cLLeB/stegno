//! `mp4_free` — hide inside an ISO-BMFF `free` box.
//!
//! MP4, M4A, M4V and MOV are all ISO Base Media Format: a flat sequence of
//! length-prefixed boxes. The spec defines `free` (and `skip`) as padding whose
//! contents carry no meaning and **must be ignored** by readers, which is
//! exactly the guarantee a carrier wants. A player, a phone's gallery and
//! ffmpeg all skip straight over it.
//!
//! The box is appended at the **very end** of the file, after every existing
//! box. That placement is not cosmetic: `moov`'s sample tables (`stco`/`co64`)
//! store *absolute file offsets* into `mdat`, so inserting even one byte ahead
//! of the media data shifts every sample out from under them and the video
//! decodes to garbage. Appending leaves all existing offsets valid, and a
//! trailing top-level `free` box is as legal as one anywhere else.
//!
//! This is what a compressed video or an AAC track should use instead of the
//! generic [`crate::methods::append_eof`], whose trailing bytes sit outside the
//! box structure entirely and mark the file as tampered with to any parser that
//! validates length.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct Mp4Free;

/// Header of a box: 32-bit size then the four-character type.
const BOX_HEADER: usize = 8;
/// Our marker inside the `free` box, so we only read back our own padding.
const MARKER: &[u8; 4] = b"STG4";
const SOFT_CAPACITY: u64 = 1 << 24;

/// Walk the top-level boxes, returning `(offset, size, type)` for each.
///
/// `None` if the file isn't a coherent box structure, which is what keeps this
/// method from claiming covers it would damage.
fn top_level_boxes(data: &[u8]) -> Option<Vec<(usize, usize, [u8; 4])>> {
    let mut boxes = Vec::new();
    let mut off = 0usize;
    while off + BOX_HEADER <= data.len() {
        let size = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            as usize;
        let kind = [data[off + 4], data[off + 5], data[off + 6], data[off + 7]];
        let actual = match size {
            // 0 means "extends to end of file".
            0 => data.len() - off,
            // 1 means a 64-bit size follows the type field.
            1 => {
                if off + 16 > data.len() {
                    return None;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&data[off + 8..off + 16]);
                u64::from_be_bytes(b) as usize
            }
            n if n < BOX_HEADER => return None, // malformed
            n => n,
        };
        if actual == 0 || off + actual > data.len() {
            return None;
        }
        boxes.push((off, actual, kind));
        off += actual;
    }
    // A real ISO-BMFF file starts with ftyp and consumes exactly.
    if off != data.len() || boxes.is_empty() {
        return None;
    }
    if boxes.iter().any(|(_, _, k)| k == b"ftyp") {
        Some(boxes)
    } else {
        None
    }
}

/// Our `free` box, if one is present.
fn find_our_free(data: &[u8]) -> Option<(usize, usize)> {
    let boxes = top_level_boxes(data)?;
    boxes.into_iter().find_map(|(off, size, kind)| {
        let body = off + BOX_HEADER;
        if (&kind == b"free" || &kind == b"skip")
            && size >= BOX_HEADER + MARKER.len()
            && &data[body..body + MARKER.len()] == MARKER
        {
            Some((off, size))
        } else {
            None
        }
    })
}

impl Method for Mp4Free {
    fn id(&self) -> &'static str {
        "mp4_free"
    }
    fn display_name(&self) -> &'static str {
        "Video or audio (MP4/M4A free box)"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        top_level_boxes(cover).ok_or(StegnoError::UnsupportedFormat)?;
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
        let boxes = top_level_boxes(cover).ok_or(StegnoError::UnsupportedFormat)?;
        let total = BOX_HEADER + MARKER.len() + payload.len();
        if total > u32::MAX as usize {
            return Err(StegnoError::CoverTooSmall);
        }

        // Drop any free box we previously wrote, so re-embedding replaces
        // rather than accumulating.
        let mut base: Vec<u8> = Vec::with_capacity(cover.len());
        for (off, size, _) in &boxes {
            if find_our_free(cover) == Some((*off, *size)) {
                continue;
            }
            base.extend_from_slice(&cover[*off..*off + *size]);
        }

        // Append, never insert: every byte already in the file keeps its offset,
        // which is what the sample tables depend on.
        let mut out = Vec::with_capacity(base.len() + total);
        out.extend_from_slice(&base);
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(b"free");
        out.extend_from_slice(MARKER);
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let Some((off, size)) = find_our_free(stego) else {
            return Ok(None);
        };
        let start = off + BOX_HEADER + MARKER.len();
        Ok(Some(stego[start..off + size].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bx(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((BOX_HEADER + body.len()) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(body);
        v
    }

    fn mp4() -> Vec<u8> {
        let mut v = bx(b"ftyp", b"isom\0\0\x02\0isomiso2");
        v.extend_from_slice(&bx(b"moov", &vec![0x11u8; 200]));
        v.extend_from_slice(&bx(b"mdat", &vec![0x22u8; 500]));
        v
    }

    #[test]
    fn roundtrips_through_a_free_box() {
        let cover = mp4();
        let body = payload::frame(b"hidden in an mp4");
        let stego = Mp4Free.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(Mp4Free.extract(&stego, &ExtractOpts::default()).unwrap(), Some(body));
    }

    #[test]
    fn the_result_is_still_a_valid_box_structure() {
        let cover = mp4();
        let body = payload::frame(b"x");
        let stego = Mp4Free.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        let boxes = top_level_boxes(&stego).expect("must still parse as ISO-BMFF");
        assert!(boxes.iter().any(|(_, _, k)| k == b"free"));
        // Every original box survives unchanged.
        for kind in [b"ftyp", b"moov", b"mdat"] {
            assert!(boxes.iter().any(|(_, _, k)| k == kind));
        }
    }

    /// Every existing box must keep both its bytes **and its offset**.
    ///
    /// `moov`'s sample tables store absolute file offsets into `mdat`, so a box
    /// inserted before the media data silently invalidates all of them: the
    /// container still parses and the payload still round-trips, but the video
    /// decodes to garbage. Comparing contents alone missed exactly that — this
    /// compares positions too.
    #[test]
    fn existing_boxes_keep_their_offsets() {
        let cover = mp4();
        let body = payload::frame(&vec![7u8; 300]);
        let stego = Mp4Free.embed(&cover, &body, &EmbedOpts::default()).unwrap();

        let before = top_level_boxes(&cover).unwrap();
        let after = top_level_boxes(&stego).unwrap();
        for (off, size, kind) in &before {
            let found = after
                .iter()
                .find(|(_, _, k)| k == kind)
                .unwrap_or_else(|| panic!("{} disappeared", String::from_utf8_lossy(kind)));
            assert_eq!(
                (found.0, found.1),
                (*off, *size),
                "{} moved from {off} to {}",
                String::from_utf8_lossy(kind),
                found.0
            );
            assert_eq!(&stego[*off..*off + *size], &cover[*off..*off + *size]);
        }
        // The whole original file is therefore an untouched prefix.
        assert_eq!(&stego[..cover.len()], &cover[..]);
    }

    #[test]
    fn re_embedding_replaces_rather_than_accumulates() {
        let cover = mp4();
        let first = Mp4Free
            .embed(&cover, &payload::frame(b"one"), &EmbedOpts::default())
            .unwrap();
        let second = Mp4Free
            .embed(&first, &payload::frame(b"two"), &EmbedOpts::default())
            .unwrap();
        let frees = top_level_boxes(&second)
            .unwrap()
            .iter()
            .filter(|(_, _, k)| k == b"free")
            .count();
        assert_eq!(frees, 1, "a second embed must not stack free boxes");
        assert_eq!(
            Mp4Free.extract(&second, &ExtractOpts::default()).unwrap(),
            Some(payload::frame(b"two"))
        );
    }

    #[test]
    fn a_clean_file_yields_nothing() {
        assert_eq!(Mp4Free.extract(&mp4(), &ExtractOpts::default()).unwrap(), None);
    }

    #[test]
    fn non_iso_covers_are_declined() {
        assert!(matches!(
            Mp4Free.capacity(b"%PDF-1.7 certainly not an mp4"),
            Err(StegnoError::UnsupportedFormat)
        ));
        // A ZIP has no ftyp box.
        assert!(matches!(
            Mp4Free.capacity(b"PK\x03\x04and some archive bytes here"),
            Err(StegnoError::UnsupportedFormat)
        ));
    }
}
