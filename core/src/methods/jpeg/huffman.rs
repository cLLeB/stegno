//! Huffman code generation, JPEG bit I/O (with 0xFF byte-stuffing), and the
//! magnitude (category) coding used for DC/AC coefficients.

use super::tables::HuffSpec;

/// Encoder lookup: symbol → (code, bit-length).
pub struct HuffEnc {
    table: [(u16, u8); 256],
}

impl HuffEnc {
    pub fn new(spec: &HuffSpec) -> Self {
        let mut table = [(0u16, 0u8); 256];
        let mut code: u16 = 0;
        let mut k = 0usize;
        for len in 1..=16u8 {
            for _ in 0..spec.counts[(len - 1) as usize] {
                let sym = spec.values[k] as usize;
                table[sym] = (code, len);
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        Self { table }
    }

    #[inline]
    pub fn get(&self, symbol: u8) -> (u16, u8) {
        self.table[symbol as usize]
    }
}

/// Decoder: canonical (code, length) → symbol, searched by growing the code.
pub struct HuffDec {
    /// Per length (1..=16): (first_code, symbols-at-this-length as slice indices).
    codes: Vec<(u8, u16, u8)>, // (length, code, symbol)
}

impl HuffDec {
    pub fn new(spec: &HuffSpec) -> Self {
        let mut codes = Vec::new();
        let mut code: u16 = 0;
        let mut k = 0usize;
        for len in 1..=16u8 {
            for _ in 0..spec.counts[(len - 1) as usize] {
                codes.push((len, code, spec.values[k]));
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        Self { codes }
    }

    /// Decode one symbol from the reader, growing the code one bit at a time.
    pub fn decode(&self, r: &mut BitReader) -> Option<u8> {
        let mut code: u16 = 0;
        for len in 1..=16u8 {
            code = (code << 1) | r.read_bit()? as u16;
            for &(l, c, sym) in &self.codes {
                if l == len && c == code {
                    return Some(sym);
                }
            }
        }
        None
    }
}

/// MSB-first bit writer with JPEG 0xFF→0xFF00 byte stuffing.
pub struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    pub fn write_bits(&mut self, value: u32, len: u8) {
        if len == 0 {
            return;
        }
        self.acc = (self.acc << len) | (value & ((1u32 << len) - 1));
        self.nbits += len as u32;
        while self.nbits >= 8 {
            self.nbits -= 8;
            let byte = ((self.acc >> self.nbits) & 0xFF) as u8;
            self.out.push(byte);
            if byte == 0xFF {
                self.out.push(0x00); // stuff
            }
        }
    }

    /// Flush, padding the final partial byte with 1-bits (per spec).
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.write_bits((1u32 << pad) - 1, pad as u8);
        }
        self.out
    }
}

/// MSB-first bit reader over a JPEG entropy segment, un-stuffing 0xFF00 and
/// stopping at a real marker (0xFF followed by non-zero).
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    nbits: u32,
    done: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            acc: 0,
            nbits: 0,
            done: false,
        }
    }

    fn fill(&mut self) -> bool {
        if self.done || self.pos >= self.data.len() {
            return false;
        }
        let b = self.data[self.pos];
        if b == 0xFF {
            let next = self.data.get(self.pos + 1).copied().unwrap_or(0xFF);
            if next == 0x00 {
                self.pos += 2; // stuffed byte
            } else {
                self.done = true; // marker — end of entropy data
                return false;
            }
        } else {
            self.pos += 1;
        }
        self.acc = (self.acc << 8) | b as u32;
        self.nbits += 8;
        true
    }

    pub fn read_bit(&mut self) -> Option<u8> {
        if self.nbits == 0 && !self.fill() {
            return None;
        }
        self.nbits -= 1;
        Some(((self.acc >> self.nbits) & 1) as u8)
    }

    pub fn read_bits(&mut self, len: u8) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..len {
            v = (v << 1) | self.read_bit()? as u32;
        }
        Some(v)
    }
}

/// Category (number of magnitude bits) of a signed coefficient value.
pub fn magnitude_category(value: i32) -> u8 {
    let mut a = value.unsigned_abs();
    let mut c = 0u8;
    while a > 0 {
        c += 1;
        a >>= 1;
    }
    c
}

/// The `size` magnitude bits for a signed value (JPEG one's-complement scheme).
pub fn magnitude_bits(value: i32, size: u8) -> u32 {
    let v = if value >= 0 {
        value
    } else {
        value - 1 // negative: low bits of (value-1)
    };
    (v as u32) & ((1u32 << size) - 1)
}

/// Inverse of [`magnitude_bits`]: reconstruct the signed value (EXTEND).
pub fn extend(bits: u32, size: u8) -> i32 {
    if size == 0 {
        return 0;
    }
    let half = 1i32 << (size - 1);
    let v = bits as i32;
    if v < half {
        v - (1 << size) + 1
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::super::tables::{AC_LUMA, DC_LUMA};
    use super::*;

    #[test]
    fn magnitude_roundtrip() {
        for v in -2047..=2047i32 {
            let size = magnitude_category(v);
            let bits = magnitude_bits(v, size);
            assert_eq!(extend(bits, size), v, "value {v}");
        }
    }

    #[test]
    fn huffman_symbol_roundtrip() {
        // Encode a stream of DC symbols, decode them back.
        let enc = HuffEnc::new(&DC_LUMA);
        let dec = HuffDec::new(&DC_LUMA);
        let syms = [0u8, 1, 2, 5, 11, 3, 0, 7];
        let mut w = BitWriter::new();
        for &s in &syms {
            let (code, len) = enc.get(s);
            w.write_bits(code as u32, len);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &s in &syms {
            assert_eq!(dec.decode(&mut r), Some(s));
        }
    }

    #[test]
    fn ac_huffman_and_magnitude_together() {
        let enc = HuffEnc::new(&AC_LUMA);
        let dec = HuffDec::new(&AC_LUMA);
        // (run<<4 | size) symbols with magnitude payloads.
        let items: [(u8, i32); 4] = [(0x01, 1), (0x23, -5), (0x00, 0), (0xF0, 0)];
        let mut w = BitWriter::new();
        for &(sym, val) in &items {
            let (code, len) = enc.get(sym);
            w.write_bits(code as u32, len);
            let size = sym & 0x0F;
            if size > 0 {
                w.write_bits(magnitude_bits(val, size), size);
            }
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &(sym, val) in &items {
            let s = dec.decode(&mut r).unwrap();
            assert_eq!(s, sym);
            let size = s & 0x0F;
            let got = if size > 0 {
                extend(r.read_bits(size).unwrap(), size)
            } else {
                0
            };
            assert_eq!(got, val);
        }
    }

    #[test]
    fn byte_stuffing_roundtrips() {
        // Force 0xFF bytes in the stream and ensure un-stuffing recovers bits.
        let mut w = BitWriter::new();
        for _ in 0..50 {
            w.write_bits(0xFF, 8);
        }
        let bytes = w.finish();
        // Every 0xFF must be followed by 0x00 in the encoded stream.
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0xFF {
                assert_eq!(bytes.get(i + 1), Some(&0x00));
                i += 2;
            } else {
                i += 1;
            }
        }
        let mut r = BitReader::new(&bytes);
        for _ in 0..50 {
            assert_eq!(r.read_bits(8), Some(0xFF));
        }
    }
}
