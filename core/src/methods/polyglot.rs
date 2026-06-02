//! `polyglot` — emit a file that is simultaneously a valid PNG (or any cover)
//! **and** a valid ZIP archive carrying the payload.
//!
//! PNG decoders read from the front and ignore trailing bytes; ZIP readers scan
//! from the back for the end-of-central-directory record and follow absolute
//! offsets. So appending a well-formed ZIP (whose offsets account for the cover
//! prefix) yields one file that opens as a picture in a viewer *and* unzips to
//! reveal `stegno.bin` in an archiver — the secret hides in plain sight as "just
//! a zip". Single stored (uncompressed) entry ⇒ bit-exact.

use super::crc32::crc32;
use crate::method::{Capacity, EmbedOpts, ExtractOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct Polyglot;

const ENTRY_NAME: &[u8] = b"stegno.bin";
const LOCAL_SIG: u32 = 0x0403_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const SOFT_CAPACITY: u64 = 1 << 24;

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

impl Method for Polyglot {
    fn id(&self) -> &'static str {
        "polyglot"
    }
    fn display_name(&self) -> &'static str {
        "Photo that opens as a ZIP too"
    }
    fn media(&self) -> Media {
        Media::Image // output still opens as the cover image
    }

    fn capacity(&self, _cover: &[u8]) -> Result<Capacity, StegnoError> {
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
        let crc = crc32(payload);
        let size = payload.len() as u32;
        let name_len = ENTRY_NAME.len() as u16;

        let mut out = cover.to_vec();
        let local_off = out.len() as u32; // absolute offset of local header

        // Local file header + name + data (stored, no compression).
        out.extend_from_slice(&le32(LOCAL_SIG));
        out.extend_from_slice(&le16(20)); // version needed
        out.extend_from_slice(&le16(0)); // flags
        out.extend_from_slice(&le16(0)); // method = stored
        out.extend_from_slice(&le16(0)); // mod time
        out.extend_from_slice(&le16(0)); // mod date
        out.extend_from_slice(&le32(crc));
        out.extend_from_slice(&le32(size)); // compressed
        out.extend_from_slice(&le32(size)); // uncompressed
        out.extend_from_slice(&le16(name_len));
        out.extend_from_slice(&le16(0)); // extra len
        out.extend_from_slice(ENTRY_NAME);
        out.extend_from_slice(payload);

        let cd_off = out.len() as u32; // central directory starts here

        // Central directory header.
        out.extend_from_slice(&le32(CD_SIG));
        out.extend_from_slice(&le16(20)); // version made by
        out.extend_from_slice(&le16(20)); // version needed
        out.extend_from_slice(&le16(0)); // flags
        out.extend_from_slice(&le16(0)); // method
        out.extend_from_slice(&le16(0)); // time
        out.extend_from_slice(&le16(0)); // date
        out.extend_from_slice(&le32(crc));
        out.extend_from_slice(&le32(size));
        out.extend_from_slice(&le32(size));
        out.extend_from_slice(&le16(name_len));
        out.extend_from_slice(&le16(0)); // extra
        out.extend_from_slice(&le16(0)); // comment
        out.extend_from_slice(&le16(0)); // disk number start
        out.extend_from_slice(&le16(0)); // internal attrs
        out.extend_from_slice(&le32(0)); // external attrs
        out.extend_from_slice(&le32(local_off)); // offset of local header
        out.extend_from_slice(ENTRY_NAME);

        let cd_size = out.len() as u32 - cd_off;

        // End of central directory.
        out.extend_from_slice(&le32(EOCD_SIG));
        out.extend_from_slice(&le16(0)); // disk number
        out.extend_from_slice(&le16(0)); // disk with CD
        out.extend_from_slice(&le16(1)); // entries this disk
        out.extend_from_slice(&le16(1)); // total entries
        out.extend_from_slice(&le32(cd_size));
        out.extend_from_slice(&le32(cd_off));
        out.extend_from_slice(&le16(0)); // comment len
        Ok(out)
    }

    fn extract(&self, stego: &[u8], _opts: &ExtractOpts) -> Result<Option<Vec<u8>>, StegnoError> {
        // Find EOCD by scanning back for its signature (no archive comment).
        let n = stego.len();
        if n < 22 {
            return Ok(None);
        }
        let eocd = match find_eocd(stego) {
            Some(p) => p,
            None => return Ok(None),
        };
        // EOCD: ... [16] cd_offset(4 LE) at eocd+16.
        let cd_off = read_le32(stego, eocd + 16) as usize;
        if cd_off + 46 > n || read_le32(stego, cd_off) != CD_SIG {
            return Ok(None);
        }
        // Central dir: local header offset at cd_off+42 (4 LE).
        let local_off = read_le32(stego, cd_off + 42) as usize;
        if local_off + 30 > n || read_le32(stego, local_off) != LOCAL_SIG {
            return Ok(None);
        }
        let usize_data = read_le32(stego, local_off + 22) as usize; // uncompressed size
        let nlen = read_le16(stego, local_off + 26) as usize;
        let elen = read_le16(stego, local_off + 28) as usize;
        let data_start = local_off + 30 + nlen + elen;
        if data_start + usize_data > n {
            return Err(StegnoError::CorruptPayload);
        }
        Ok(Some(stego[data_start..data_start + usize_data].to_vec()))
    }
}

fn read_le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn read_le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Scan backwards for the EOCD signature.
fn find_eocd(b: &[u8]) -> Option<usize> {
    if b.len() < 22 {
        return None;
    }
    let mut i = b.len() - 22;
    loop {
        if read_le32(b, i) == EOCD_SIG {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_io::{decode_rgba, encode_png, RgbaImage};

    fn png() -> Vec<u8> {
        encode_png(&RgbaImage {
            width: 12,
            height: 12,
            pixels: vec![77u8; 12 * 12 * 4],
        })
        .unwrap()
    }

    #[test]
    fn polyglot_roundtrip() {
        let cover = png();
        let body = payload::frame(b"valid as png and zip");
        let stego = Polyglot.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            Polyglot
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }

    #[test]
    fn output_still_decodes_as_png() {
        let cover = png();
        let stego = Polyglot
            .embed(&cover, &payload::frame(b"x"), &EmbedOpts::default())
            .unwrap();
        // Cover is an untouched prefix and the whole thing still decodes.
        assert_eq!(&stego[..cover.len()], &cover[..]);
        let img = decode_rgba(&stego).unwrap();
        assert_eq!((img.width, img.height), (12, 12));
    }

    #[test]
    fn output_has_valid_zip_structure() {
        let cover = png();
        let body = payload::frame(b"archive me");
        let stego = Polyglot.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        // EOCD present, signatures consistent.
        let eocd = find_eocd(&stego).expect("eocd");
        assert_eq!(read_le32(&stego, eocd), EOCD_SIG);
        let cd_off = read_le32(&stego, eocd + 16) as usize;
        assert_eq!(read_le32(&stego, cd_off), CD_SIG);
    }

    #[test]
    fn clean_file_returns_none() {
        assert_eq!(
            Polyglot.extract(&png(), &ExtractOpts::default()).unwrap(),
            None
        );
    }

    #[test]
    fn binary_payload_roundtrips() {
        let cover = png();
        let body = payload::frame(&(0u8..=255).collect::<Vec<u8>>());
        let stego = Polyglot.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        assert_eq!(
            Polyglot
                .extract(&stego, &ExtractOpts::default())
                .unwrap()
                .unwrap(),
            body
        );
    }
}
