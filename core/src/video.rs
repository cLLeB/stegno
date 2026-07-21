//! Frame-level video steganography.
//!
//! Real per-frame pixel embedding: the payload is spread across the luma bytes
//! of every frame in the clip, exactly as image LSB spreads across one photo's
//! pixels. With thousands of frames a video carries far more than any single
//! still, and the changes are ±1 on individual luma samples.
//!
//! ## Why lossless containers only
//!
//! AES-GCM authenticates the payload, so a *single* flipped bit fails the tag.
//! That makes lossy video codecs (H.264, VP9, AV1 at normal settings)
//! fundamentally unable to carry this scheme through a re-encode — the codec
//! discards precisely the low-order detail the payload lives in. Frame-level
//! embedding is therefore implemented against **lossless raw video**:
//! YUV4MPEG2 (`.y4m`), the standard interchange format that every video tool
//! reads and writes.
//!
//! The practical workflow is to transcode to y4m, embed, and either keep the
//! y4m or re-encode with a *lossless* codec (FFV1, x264 `-qp 0`, x265
//! `-lossless`). A lossy re-encode destroys the payload, which is a property of
//! the codec rather than of this implementation.
//!
//! Compressed containers (MP4, MKV, WebM) still work as covers through the
//! universal appended-region carrier in [`crate::carrier`] — the clip plays
//! identically and the payload survives copying, just not re-encoding.
//!
//! Only luma (Y) is used. Chroma planes are left untouched: luma is the largest
//! plane, and confining changes to it keeps the statistical footprint low and
//! avoids colour fringing on subsampled formats.

use crate::carrier::{Carrier, CarrierKind};
use crate::StegnoError;

const MAGIC: &[u8] = b"YUV4MPEG2";
const FRAME_MAGIC: &[u8] = b"FRAME";

/// Most slots a clip will expose.
///
/// Slot indices are `u32` throughout the carrier interface, and a long 4K clip
/// has more luma samples than that — seventeen seconds of 2160p already passes
/// four billion. The cap keeps every index addressable; anything larger strides.
///
/// It is deliberately generous. It used to be 8 M, because the position
/// permutations were materialized `Vec<u32>`s and ten seconds of 1080p would
/// have wanted 2.5 GB for the master ranking alone. [`crate::prp`] computes them
/// instead, so the only remaining constraint is the index width.
const MAX_SLOTS: usize = 1 << 30;

/// A parsed y4m stream: the header, plus where each frame's luma plane starts.
pub struct Y4mCarrier {
    bytes: Vec<u8>,
    /// Byte offset of every frame's luma plane, in stream order.
    luma_offsets: Vec<usize>,
    /// Luma bytes per frame (`width * height`).
    luma_len: usize,
    /// Visit every `stride`-th luma sample. Derived from the clip's own
    /// dimensions and frame count, so the extractor recomputes it identically.
    /// Striding rather than truncating keeps the payload spread over the whole
    /// clip instead of piling it into the opening frames.
    stride: usize,
}

/// How many luma samples to skip between slots, so a clip of any length stays
/// within [`MAX_SLOTS`]. Derived from the clip alone, so the extractor
/// recomputes it identically without being told.
fn stride_for(total_luma: usize) -> usize {
    total_luma.div_ceil(MAX_SLOTS).max(1)
}

/// Chroma plane bytes per frame for a colorspace tag.
///
/// Deliberately an exact whitelist rather than a prefix test: `420jpeg`,
/// `420paldv` and `420mpeg2` differ only in siting and share 8-bit 4:2:0 sizing,
/// but `420p10` is *sixteen* bits per sample with a completely different layout.
/// Matching it on its `420` prefix would write into the wrong bytes and corrupt
/// the clip, so anything not listed here is declined and falls through to the
/// generic byte carrier.
fn chroma_extra(colorspace: &str, w: usize, h: usize) -> Option<usize> {
    match colorspace {
        "420" | "420jpeg" | "420paldv" | "420mpeg2" => Some(2 * (w.div_ceil(2) * h.div_ceil(2))),
        "422" => Some(2 * (w.div_ceil(2) * h)),
        "444" => Some(2 * (w * h)),
        "mono" => Some(0),
        _ => None,
    }
}

impl Y4mCarrier {
    /// Parse a y4m stream. `None` if this isn't y4m, or uses a pixel format the
    /// engine doesn't lay out (10-bit, alpha) — those fall through to the
    /// generic byte carrier rather than risking a corrupted clip.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
            return None;
        }
        let hdr_end = bytes.iter().position(|&b| b == b'\n')?;
        let header = std::str::from_utf8(&bytes[..hdr_end]).ok()?;

        let mut w = 0usize;
        let mut h = 0usize;
        let mut colorspace = "420".to_string();
        for tag in header.split_ascii_whitespace().skip(1) {
            let (k, v) = tag.split_at(1);
            match k {
                "W" => w = v.parse().ok()?,
                "H" => h = v.parse().ok()?,
                "C" => colorspace = v.to_string(),
                _ => {}
            }
        }
        if w == 0 || h == 0 {
            return None;
        }
        let luma_len = w.checked_mul(h)?;
        let frame_len = luma_len.checked_add(chroma_extra(&colorspace, w, h)?)?;

        // Walk the frame list: each is `FRAME[ params]\n` then the planes.
        let mut luma_offsets = Vec::new();
        let mut pos = hdr_end + 1;
        while pos < bytes.len() {
            if pos + FRAME_MAGIC.len() > bytes.len()
                || &bytes[pos..pos + FRAME_MAGIC.len()] != FRAME_MAGIC
            {
                break; // trailing garbage; keep the frames we found
            }
            let nl = bytes[pos..].iter().position(|&b| b == b'\n')? + pos;
            let data = nl + 1;
            if data + frame_len > bytes.len() {
                break; // truncated final frame
            }
            luma_offsets.push(data);
            pos = data + frame_len;
        }
        if luma_offsets.is_empty() {
            return None;
        }
        let total_luma = luma_offsets.len().checked_mul(luma_len)?;
        Some(Y4mCarrier {
            bytes: bytes.to_vec(),
            luma_offsets,
            luma_len,
            stride: stride_for(total_luma),
        })
    }

    /// Frames available to carry payload.
    pub fn frame_count(&self) -> usize {
        self.luma_offsets.len()
    }

    /// Slot `s` → the luma byte holding it, walking every `stride`-th sample
    /// across the whole clip: frame `i / luma_len`, pixel `i % luma_len`.
    #[inline]
    fn offset(&self, slot: u32) -> Option<usize> {
        let i = (slot as usize).checked_mul(self.stride)?;
        let frame = i / self.luma_len;
        let px = i % self.luma_len;
        self.luma_offsets.get(frame).map(|&base| base + px)
    }
}

impl Carrier for Y4mCarrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::Video
    }
    fn slot_count(&self) -> usize {
        (self.luma_offsets.len() * self.luma_len) / self.stride
    }
    fn get_bit(&self, slot: u32) -> u8 {
        self.offset(slot)
            .and_then(|o| self.bytes.get(o))
            .map_or(0, |v| v & 1)
    }
    fn set_bit(&mut self, slot: u32, bit: u8) {
        if let Some(o) = self.offset(slot) {
            if let Some(v) = self.bytes.get_mut(o) {
                *v = (*v & 0xFE) | (bit & 1);
            }
        }
    }
    fn encode(&self) -> Result<Vec<u8>, StegnoError> {
        Ok(self.bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::{read_bytes, write_bytes};

    /// A y4m clip: `frames` frames of `w`x`h` 4:2:0, with varied pixel values.
    fn y4m(w: usize, h: usize, frames: usize) -> Vec<u8> {
        let mut v = format!("YUV4MPEG2 W{w} H{h} F30:1 Ip A1:1 C420\n").into_bytes();
        let chroma = 2 * (w.div_ceil(2) * h.div_ceil(2));
        for f in 0..frames {
            v.extend_from_slice(b"FRAME\n");
            for i in 0..w * h {
                v.push(((i * 7 + f * 13) % 256) as u8);
            }
            v.extend(std::iter::repeat_n(128u8, chroma));
        }
        v
    }

    #[test]
    fn parses_frames_and_reports_luma_slots() {
        let c = Y4mCarrier::parse(&y4m(16, 16, 5)).unwrap();
        assert_eq!(c.frame_count(), 5);
        assert_eq!(c.slot_count(), 16 * 16 * 5);
    }

    #[test]
    fn payload_roundtrips_across_frames() {
        let mut c = Y4mCarrier::parse(&y4m(32, 32, 8)).unwrap();
        let payload: Vec<u8> = (0..200u16).map(|i| (i * 3) as u8).collect();
        // Spread deliberately across the whole clip, not just frame 0.
        let step = c.slot_count() / (payload.len() * 8);
        let order: Vec<u32> = (0..payload.len() * 8).map(|i| (i * step) as u32).collect();
        write_bytes(&mut c, &payload, &order).unwrap();
        let encoded = c.encode().unwrap();

        let back = Y4mCarrier::parse(&encoded).unwrap();
        assert_eq!(read_bytes(&back, &order), payload);
    }

    #[test]
    fn chroma_planes_are_never_touched() {
        let src = y4m(16, 16, 4);
        let mut c = Y4mCarrier::parse(&src).unwrap();
        for s in 0..c.slot_count() {
            c.set_bit(s as u32, 1);
        }
        let out = c.encode().unwrap();
        // Chroma is a constant 128 everywhere in the fixture; it must stay so.
        let hdr = src.iter().position(|&b| b == b'\n').unwrap() + 1;
        let luma = 16 * 16;
        let chroma = 2 * 8 * 8;
        let mut pos = hdr;
        for _ in 0..4 {
            let data = pos + b"FRAME\n".len();
            let cstart = data + luma;
            assert!(out[cstart..cstart + chroma].iter().all(|&v| v == 128));
            pos = data + luma + chroma;
        }
    }

    #[test]
    fn luma_changes_are_bounded_to_one_step() {
        let src = y4m(24, 24, 3);
        let mut c = Y4mCarrier::parse(&src).unwrap();
        let payload = vec![0xA5u8; 60];
        let order: Vec<u32> = (0..(payload.len() * 8) as u32).collect();
        write_bytes(&mut c, &payload, &order).unwrap();
        let out = c.encode().unwrap();
        assert_eq!(out.len(), src.len(), "container size must not change");
        for (a, b) in src.iter().zip(out.iter()) {
            assert!((*a as i16 - *b as i16).abs() <= 1);
        }
    }

    #[test]
    fn header_and_frame_markers_survive() {
        let src = y4m(16, 16, 3);
        let mut c = Y4mCarrier::parse(&src).unwrap();
        c.set_bit(0, 1);
        let out = c.encode().unwrap();
        let hdr_end = src.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(&out[..hdr_end], &src[..hdr_end], "header intact");
        assert_eq!(
            out.windows(FRAME_MAGIC.len()).filter(|w| *w == FRAME_MAGIC).count(),
            src.windows(FRAME_MAGIC.len()).filter(|w| *w == FRAME_MAGIC).count()
        );
    }

    #[test]
    fn subsampling_modes_are_sized_correctly() {
        for (cs, per_frame) in [("420", 16 * 16 * 3 / 2), ("422", 16 * 16 * 2), ("444", 16 * 16 * 3)] {
            let mut v = format!("YUV4MPEG2 W16 H16 F30:1 C{cs}\n").into_bytes();
            v.extend_from_slice(b"FRAME\n");
            v.extend(std::iter::repeat_n(90u8, per_frame));
            v.extend_from_slice(b"FRAME\n");
            v.extend(std::iter::repeat_n(90u8, per_frame));
            let c = Y4mCarrier::parse(&v).unwrap_or_else(|| panic!("C{cs} failed to parse"));
            assert_eq!(c.frame_count(), 2, "C{cs}");
            assert_eq!(c.slot_count(), 16 * 16 * 2, "C{cs} luma slots");
        }
    }

    #[test]
    fn truncated_final_frame_is_dropped_not_fatal() {
        let mut v = y4m(16, 16, 3);
        v.truncate(v.len() - 50);
        let c = Y4mCarrier::parse(&v).unwrap();
        assert_eq!(c.frame_count(), 2, "the incomplete frame is ignored");
    }

    #[test]
    fn stride_keeps_any_clip_addressable() {
        // Slot indices are u32; a long 4K clip has more luma than that, so the
        // stride has to grow rather than let indices overflow.
        assert_eq!(stride_for(1000), 1, "small clips are walked sample by sample");
        assert_eq!(stride_for(MAX_SLOTS), 1, "exactly at the cap still fits");
        assert_eq!(stride_for(MAX_SLOTS * 2), 2);
        assert_eq!(stride_for(MAX_SLOTS * 3 + 1), 4);
        // 30 seconds of 2160p — well past what a u32 index could reach.
        let huge = 3840usize * 2160 * 30 * 30;
        assert!(huge / stride_for(huge) <= MAX_SLOTS);
        assert!(huge / stride_for(huge) < u32::MAX as usize);
    }

    #[test]
    fn striding_spreads_across_the_whole_clip_and_roundtrips() {
        // Force a stride the fixture is far too small to trigger naturally, and
        // check both that it reaches the final frame and that it reads back.
        let src = y4m(64, 64, 12);
        let mut c = Y4mCarrier::parse(&src).unwrap();
        c.stride = 7;

        let last = c.offset(c.slot_count() as u32 - 1).unwrap();
        assert!(
            last >= *c.luma_offsets.last().unwrap(),
            "striding must still reach the last frame, not truncate to the start"
        );

        let payload: Vec<u8> = (0..200u16).map(|i| (i * 5) as u8).collect();
        let order: Vec<u32> = (0..(payload.len() * 8) as u32).collect();
        write_bytes(&mut c, &payload, &order).unwrap();
        let encoded = c.encode().unwrap();

        // Re-parse computes stride 1, so read back through a matching carrier.
        let mut back = Y4mCarrier::parse(&encoded).unwrap();
        back.stride = 7;
        assert_eq!(read_bytes(&back, &order), payload);
    }

    #[test]
    fn non_y4m_is_rejected() {
        assert!(Y4mCarrier::parse(b"not a video").is_none());
        assert!(Y4mCarrier::parse(b"YUV4MPEG2 W0 H0\nFRAME\n").is_none());
        // A header with no frames at all carries nothing.
        assert!(Y4mCarrier::parse(b"YUV4MPEG2 W16 H16 C420\n").is_none());
    }

    #[test]
    fn unsupported_pixel_format_falls_through() {
        // 10-bit 4:2:0 has a plane layout we don't compute; better to decline
        // than to write into the wrong bytes and corrupt the clip.
        let mut v = b"YUV4MPEG2 W16 H16 C420p10\n".to_vec();
        v.extend_from_slice(b"FRAME\n");
        v.extend(std::iter::repeat_n(0u8, 16 * 16 * 3));
        assert!(Y4mCarrier::parse(&v).is_none());
    }
}
