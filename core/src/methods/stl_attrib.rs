//! `stl_attrib` — hide inside a binary STL's per-triangle attribute words.
//!
//! A binary STL is an 80-byte header of arbitrary text, a triangle count, then
//! 50 bytes per triangle: twelve `f32` values for the normal and vertices, then
//! a 16-bit **attribute byte count**. That last field is vestigial. The de-facto
//! standard is to write zero, and every mainstream slicer and CAD tool ignores
//! it entirely.
//!
//! So the payload rides in the attribute words and the 80-byte header, and the
//! **geometry is never touched** — not one coordinate changes. The mesh a slicer
//! produces is bit-identical to the original, which is what separates this from
//! nudging vertex positions (visible in fine detail, and destroyed by any
//! re-export) or from stapling bytes past the end of the file.
//!
//! Capacity is two bytes per triangle plus the header, so a 20 000-triangle
//! model carries about 40 KB.

use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct StlAttrib;

const HEADER_LEN: usize = 80;
const COUNT_LEN: usize = 4;
const TRI_LEN: usize = 50;
/// Bytes of the triangle record before its attribute word.
const TRI_GEOMETRY: usize = 48;
/// Our marker, written into the tail of the 80-byte header.
const MARKER: &[u8; 4] = b"STGL";

/// Triangle count if `data` is a well-formed binary STL.
///
/// ASCII STLs start with `solid` and have no attribute words, so they are
/// declined rather than mangled.
fn triangle_count(data: &[u8]) -> Option<usize> {
    if data.len() < HEADER_LEN + COUNT_LEN {
        return None;
    }
    // An ASCII STL begins with "solid"; a binary one may too, so the deciding
    // test is whether the declared triangle count matches the file length.
    let n = u32::from_le_bytes([
        data[HEADER_LEN],
        data[HEADER_LEN + 1],
        data[HEADER_LEN + 2],
        data[HEADER_LEN + 3],
    ]) as usize;
    let expected = HEADER_LEN + COUNT_LEN + n.checked_mul(TRI_LEN)?;
    if expected == data.len() && n > 0 {
        Some(n)
    } else {
        None
    }
}

/// Byte offset of triangle `i`'s attribute word.
fn attr_offset(i: usize) -> usize {
    HEADER_LEN + COUNT_LEN + i * TRI_LEN + TRI_GEOMETRY
}

/// Bytes carried in the header: everything after the marker.
fn header_slots() -> usize {
    HEADER_LEN - MARKER.len() - 4 // marker + u32 payload length
}

impl Method for StlAttrib {
    fn id(&self) -> &'static str {
        "stl_attrib"
    }
    fn display_name(&self) -> &'static str {
        "3D model (STL attribute words)"
    }
    fn media(&self) -> Media {
        Media::File
    }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let n = triangle_count(cover).ok_or(StegnoError::UnsupportedFormat)?;
        let raw = header_slots() + n * 2;
        Ok(Capacity {
            usable_bytes: (raw as u64).saturating_sub(payload::overhead() as u64),
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        _opts: &EmbedOpts,
    ) -> Result<Vec<u8>, StegnoError> {
        let n = triangle_count(cover).ok_or(StegnoError::UnsupportedFormat)?;
        if payload.len() > header_slots() + n * 2 {
            return Err(StegnoError::CoverTooSmall);
        }
        let mut out = cover.to_vec();

        // Header: marker, length, then as much payload as fits.
        out[..MARKER.len()].copy_from_slice(MARKER);
        let len_at = MARKER.len();
        out[len_at..len_at + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let head_take = payload.len().min(header_slots());
        let head_start = MARKER.len() + 4;
        out[head_start..head_start + head_take].copy_from_slice(&payload[..head_take]);
        // Any unused header space is zeroed so the field reads consistently.
        for b in out[head_start + head_take..HEADER_LEN].iter_mut() {
            *b = 0;
        }

        // Remainder: two bytes per triangle, geometry untouched.
        let rest = &payload[head_take..];
        for (i, pair) in rest.chunks(2).enumerate() {
            let at = attr_offset(i);
            out[at] = pair[0];
            out[at + 1] = if pair.len() > 1 { pair[1] } else { 0 };
        }
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        let Some(n) = triangle_count(stego) else {
            return Ok(None);
        };
        if &stego[..MARKER.len()] != MARKER {
            return Ok(None);
        }
        let len_at = MARKER.len();
        let len = u32::from_le_bytes([
            stego[len_at],
            stego[len_at + 1],
            stego[len_at + 2],
            stego[len_at + 3],
        ]) as usize;
        if len > header_slots() + n * 2 {
            return Ok(None); // not ours, or damaged
        }
        let mut out = Vec::with_capacity(len);
        let head_start = MARKER.len() + 4;
        let head_take = len.min(header_slots());
        out.extend_from_slice(&stego[head_start..head_start + head_take]);
        let mut i = 0;
        while out.len() < len {
            let at = attr_offset(i);
            out.push(stego[at]);
            if out.len() < len {
                out.push(stego[at + 1]);
            }
            i += 1;
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stl(triangles: usize) -> Vec<u8> {
        let mut v = vec![b' '; HEADER_LEN];
        v[..14].copy_from_slice(b"solid exported");
        v.extend_from_slice(&(triangles as u32).to_le_bytes());
        for t in 0..triangles {
            for k in 0..12 {
                v.extend_from_slice(&((t * 12 + k) as f32).to_le_bytes());
            }
            v.extend_from_slice(&0u16.to_le_bytes()); // attribute word
        }
        v
    }

    #[test]
    fn roundtrips_across_header_and_attributes() {
        let cover = stl(400);
        let body = payload::frame(&(0..500u16).map(|i| i as u8).collect::<Vec<_>>());
        let stego = StlAttrib.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            StlAttrib.extract(&stego, &ExtractOpts::default()).unwrap(),
            Some(body)
        );
    }

    /// The whole point: not one coordinate moves.
    #[test]
    fn geometry_is_bit_identical() {
        let cover = stl(300);
        let body = payload::frame(&vec![0xABu8; 400]);
        let stego = StlAttrib.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(stego.len(), cover.len(), "file size must not change");
        let n = triangle_count(&cover).unwrap();
        for i in 0..n {
            let g = HEADER_LEN + COUNT_LEN + i * TRI_LEN;
            assert_eq!(
                &stego[g..g + TRI_GEOMETRY],
                &cover[g..g + TRI_GEOMETRY],
                "triangle {i} geometry changed"
            );
        }
        // The triangle count itself must also be intact.
        assert_eq!(
            &stego[HEADER_LEN..HEADER_LEN + COUNT_LEN],
            &cover[HEADER_LEN..HEADER_LEN + COUNT_LEN]
        );
    }

    #[test]
    fn capacity_scales_with_triangles() {
        let small = StlAttrib.capacity(&stl(100)).unwrap().usable_bytes;
        let large = StlAttrib.capacity(&stl(1000)).unwrap().usable_bytes;
        assert!(large > small * 5);
    }

    #[test]
    fn a_clean_model_yields_nothing() {
        assert_eq!(
            StlAttrib.extract(&stl(50), &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn non_stl_and_ascii_stl_are_declined() {
        assert!(matches!(
            StlAttrib.capacity(b"solid ascii\nfacet normal 0 0 0\n"),
            Err(StegnoError::UnsupportedFormat)
        ));
        assert!(matches!(
            StlAttrib.capacity(&vec![0u8; 200]),
            Err(StegnoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn oversized_payload_is_refused() {
        let cover = stl(10);
        assert!(matches!(
            StlAttrib.embed(&cover, &vec![0u8; 5000], &EmbedOpts::default()),
            Err(StegnoError::CoverTooSmall)
        ));
    }
}
