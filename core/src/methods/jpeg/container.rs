//! Minimal baseline-JPEG container: writes a standards-compliant JFIF stream
//! (SOI · APP0 · DQT×2 · SOF0 · DHT×4 · SOS · entropy · EOI) and parses one back
//! out far enough to recover the image geometry and the entropy segment.
//!
//! We always emit 8-bit, 4:4:4 (no chroma subsampling), three components, the
//! Annex-K standard quantization and Huffman tables, and a single non-restart
//! scan. Because the encoder and decoder share these fixed tables, the entropy
//! stream is a lossless container for the quantized coefficients — exactly what
//! `jpeg_jsteg` needs for bit-exact extraction.

use super::tables::{HuffSpec, AC_CHROMA, AC_LUMA, CHROMA_QUANT, DC_CHROMA, DC_LUMA, LUMA_QUANT, ZIGZAG};

/// Geometry recovered from an SOF0 header.
pub struct Geometry {
    pub width: u32,
    pub height: u32,
}

impl Geometry {
    pub fn blocks_wide(&self) -> usize {
        (self.width as usize + 7) / 8
    }
    pub fn blocks_high(&self) -> usize {
        (self.height as usize + 7) / 8
    }
    /// One MCU per 8×8 block at 4:4:4.
    pub fn num_blocks(&self) -> usize {
        self.blocks_wide() * self.blocks_high()
    }
}

fn push_marker(out: &mut Vec<u8>, marker: u8) {
    out.push(0xFF);
    out.push(marker);
}

/// A length-prefixed segment: `FF marker | len(2, includes the 2 len bytes) | body`.
fn push_segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) {
    push_marker(out, marker);
    let len = (body.len() + 2) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
}

/// DQT body: precision/id byte then 64 quant values in zig-zag order.
fn dqt_body(id: u8, q: &[u16; 64]) -> Vec<u8> {
    let mut b = Vec::with_capacity(65);
    b.push(id); // Pq=0 (8-bit) << 4 | Tq=id
    for k in 0..64 {
        b.push(q[ZIGZAG[k]] as u8);
    }
    b
}

/// DHT body: class/id byte, 16 length-counts, then the symbol values.
fn dht_body(class_id: u8, spec: &HuffSpec) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + 16 + spec.values.len());
    b.push(class_id);
    b.extend_from_slice(&spec.counts);
    b.extend_from_slice(spec.values);
    b
}

/// Assemble a full baseline-JPEG byte stream around a finished entropy segment.
pub fn write_jpeg(width: u32, height: u32, entropy: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entropy.len() + 700);
    push_marker(&mut out, 0xD8); // SOI

    // APP0 / JFIF.
    push_segment(
        &mut out,
        0xE0,
        &[
            b'J', b'F', b'I', b'F', 0x00, // identifier
            0x01, 0x01, // version 1.1
            0x00, // density units: none
            0x00, 0x01, 0x00, 0x01, // X/Y density
            0x00, 0x00, // no thumbnail
        ],
    );

    // Quantization tables.
    push_segment(&mut out, 0xDB, &dqt_body(0, &LUMA_QUANT));
    push_segment(&mut out, 0xDB, &dqt_body(1, &CHROMA_QUANT));

    // SOF0 (baseline): precision, dims, 3 components at 4:4:4.
    let mut sof = Vec::with_capacity(15);
    sof.push(8); // sample precision
    sof.extend_from_slice(&(height as u16).to_be_bytes());
    sof.extend_from_slice(&(width as u16).to_be_bytes());
    sof.push(3); // components
    sof.extend_from_slice(&[1, 0x11, 0]); // Y : id1, 1×1 sampling, quant 0
    sof.extend_from_slice(&[2, 0x11, 1]); // Cb: id2, 1×1 sampling, quant 1
    sof.extend_from_slice(&[3, 0x11, 1]); // Cr: id3, 1×1 sampling, quant 1
    push_segment(&mut out, 0xC0, &sof);

    // Huffman tables (class<<4 | id): DC0, AC0 luma; DC1, AC1 chroma.
    push_segment(&mut out, 0xC4, &dht_body(0x00, &DC_LUMA));
    push_segment(&mut out, 0xC4, &dht_body(0x10, &AC_LUMA));
    push_segment(&mut out, 0xC4, &dht_body(0x01, &DC_CHROMA));
    push_segment(&mut out, 0xC4, &dht_body(0x11, &AC_CHROMA));

    // SOS: 3 components mapping to (DC,AC) table ids; full spectral selection.
    let mut sos = Vec::with_capacity(10);
    sos.push(3);
    sos.extend_from_slice(&[1, 0x00]); // Y  → DC0/AC0
    sos.extend_from_slice(&[2, 0x11]); // Cb → DC1/AC1
    sos.extend_from_slice(&[3, 0x11]); // Cr → DC1/AC1
    sos.extend_from_slice(&[0, 63, 0]); // Ss, Se, Ah/Al
    push_segment(&mut out, 0xDA, &sos);

    out.extend_from_slice(entropy);
    push_marker(&mut out, 0xD9); // EOI
    out
}

/// Walk the markers far enough to read dimensions and isolate the entropy bytes
/// between the SOS header and the trailing EOI. Returns `None` on anything that
/// doesn't match the shape we write.
pub fn parse_jpeg(bytes: &[u8]) -> Option<(Geometry, &[u8])> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None; // missing SOI
    }
    let mut i = 2usize;
    let mut dims: Option<(u32, u32)> = None;
    loop {
        if i + 4 > bytes.len() || bytes[i] != 0xFF {
            return None;
        }
        let marker = bytes[i + 1];
        let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        if i + 2 + len > bytes.len() {
            return None;
        }
        match marker {
            0xC0 => {
                // SOF0: precision, height, width, ...
                let h = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
                let w = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
                dims = Some((w, h));
            }
            0xDA => {
                // SOS: entropy follows the header, runs to the final EOI.
                let (w, h) = dims?;
                let entropy_start = i + 2 + len;
                let end = bytes.len().checked_sub(2)?;
                if entropy_start > end || bytes[end] != 0xFF || bytes[end + 1] != 0xD9 {
                    return None;
                }
                return Some((Geometry { width: w, height: h }, &bytes[entropy_start..end]));
            }
            _ => {}
        }
        i += 2 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_roundtrips_geometry_and_entropy() {
        let entropy = vec![0x12, 0x34, 0xFF, 0x00, 0x56];
        let jpeg = write_jpeg(57, 42, &entropy);
        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]); // SOI
        assert_eq!(&jpeg[jpeg.len() - 2..], &[0xFF, 0xD9]); // EOI
        let (geo, body) = parse_jpeg(&jpeg).unwrap();
        assert_eq!((geo.width, geo.height), (57, 42));
        assert_eq!(geo.blocks_wide(), 8); // ceil(57/8)
        assert_eq!(geo.blocks_high(), 6); // ceil(42/8)
        assert_eq!(body, &entropy[..]);
    }

    #[test]
    fn rejects_non_jpeg() {
        assert!(parse_jpeg(&[0u8; 4]).is_none());
        assert!(parse_jpeg(&[0xFF, 0xD8]).is_none());
    }
}
