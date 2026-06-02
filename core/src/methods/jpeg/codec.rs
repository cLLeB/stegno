//! Baseline entropy (Huffman) coding of quantized coefficient blocks, in
//! zig-zag order, MCU-interleaved (4:4:4 → one Y, Cb, Cr block per MCU).

use super::huffman::{
    extend, magnitude_bits, magnitude_category, BitReader, BitWriter, HuffDec, HuffEnc,
};
use super::tables::{AC_CHROMA, AC_LUMA, DC_CHROMA, DC_LUMA};

/// Per-component Huffman encoders.
struct Encoders {
    dc_l: HuffEnc,
    ac_l: HuffEnc,
    dc_c: HuffEnc,
    ac_c: HuffEnc,
}

fn encoders() -> Encoders {
    Encoders {
        dc_l: HuffEnc::new(&DC_LUMA),
        ac_l: HuffEnc::new(&AC_LUMA),
        dc_c: HuffEnc::new(&DC_CHROMA),
        ac_c: HuffEnc::new(&AC_CHROMA),
    }
}

fn encode_block(w: &mut BitWriter, zz: &[i32; 64], prev_dc: &mut i32, dc: &HuffEnc, ac: &HuffEnc) {
    // DC: differential.
    let diff = zz[0] - *prev_dc;
    *prev_dc = zz[0];
    let size = magnitude_category(diff);
    let (code, len) = dc.get(size);
    w.write_bits(code as u32, len);
    if size > 0 {
        w.write_bits(magnitude_bits(diff, size), size);
    }
    // AC: run-length of zeros + (run,size) symbols, EOB at the end.
    let mut run = 0;
    let mut last_nonzero = 0;
    for k in 1..64 {
        if zz[k] != 0 {
            last_nonzero = k;
        }
    }
    for k in 1..64 {
        if k > last_nonzero {
            break;
        }
        if zz[k] == 0 {
            run += 1;
            continue;
        }
        while run > 15 {
            let (c, l) = ac.get(0xF0); // ZRL
            w.write_bits(c as u32, l);
            run -= 16;
        }
        let size = magnitude_category(zz[k]);
        let sym = ((run as u8) << 4) | size;
        let (c, l) = ac.get(sym);
        w.write_bits(c as u32, l);
        w.write_bits(magnitude_bits(zz[k], size), size);
        run = 0;
    }
    if last_nonzero < 63 {
        let (c, l) = ac.get(0x00); // EOB
        w.write_bits(c as u32, l);
    }
}

/// Encode all components' blocks (each in zig-zag order) into one entropy
/// segment, MCU-interleaved.
pub fn encode_scan(y: &[[i32; 64]], cb: &[[i32; 64]], cr: &[[i32; 64]]) -> Vec<u8> {
    let enc = encoders();
    let mut w = BitWriter::new();
    let (mut dy, mut dcb, mut dcr) = (0i32, 0i32, 0i32);
    for n in 0..y.len() {
        encode_block(&mut w, &y[n], &mut dy, &enc.dc_l, &enc.ac_l);
        encode_block(&mut w, &cb[n], &mut dcb, &enc.dc_c, &enc.ac_c);
        encode_block(&mut w, &cr[n], &mut dcr, &enc.dc_c, &enc.ac_c);
    }
    w.finish()
}

struct Decoders {
    dc_l: HuffDec,
    ac_l: HuffDec,
    dc_c: HuffDec,
    ac_c: HuffDec,
}

fn decoders() -> Decoders {
    Decoders {
        dc_l: HuffDec::new(&DC_LUMA),
        ac_l: HuffDec::new(&AC_LUMA),
        dc_c: HuffDec::new(&DC_CHROMA),
        ac_c: HuffDec::new(&AC_CHROMA),
    }
}

fn decode_block(
    r: &mut BitReader,
    prev_dc: &mut i32,
    dc: &HuffDec,
    ac: &HuffDec,
) -> Option<[i32; 64]> {
    let mut zz = [0i32; 64];
    let size = dc.decode(r)?;
    let diff = if size > 0 {
        extend(r.read_bits(size)?, size)
    } else {
        0
    };
    *prev_dc += diff;
    zz[0] = *prev_dc;

    let mut k = 1usize;
    while k < 64 {
        let sym = ac.decode(r)?;
        let run = (sym >> 4) as usize;
        let size = sym & 0x0F;
        if size == 0 {
            if run == 15 {
                k += 16; // ZRL
                continue;
            }
            break; // EOB
        }
        k += run;
        if k >= 64 {
            break;
        }
        zz[k] = extend(r.read_bits(size)?, size);
        k += 1;
    }
    Some(zz)
}

/// Decode `num_blocks` MCUs back into per-component zig-zag blocks.
pub fn decode_scan(
    entropy: &[u8],
    num_blocks: usize,
) -> Option<(Vec<[i32; 64]>, Vec<[i32; 64]>, Vec<[i32; 64]>)> {
    let dec = decoders();
    let mut r = BitReader::new(entropy);
    let (mut dy, mut dcb, mut dcr) = (0i32, 0i32, 0i32);
    let mut y = Vec::with_capacity(num_blocks);
    let mut cb = Vec::with_capacity(num_blocks);
    let mut cr = Vec::with_capacity(num_blocks);
    for _ in 0..num_blocks {
        y.push(decode_block(&mut r, &mut dy, &dec.dc_l, &dec.ac_l)?);
        cb.push(decode_block(&mut r, &mut dcb, &dec.dc_c, &dec.ac_c)?);
        cr.push(decode_block(&mut r, &mut dcr, &dec.dc_c, &dec.ac_c)?);
    }
    Some((y, cb, cr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(seed: i32) -> [i32; 64] {
        let mut b = [0i32; 64];
        b[0] = seed * 3 - 50; // DC
        // a few scattered AC coefficients including negatives and runs
        b[1] = 5;
        b[2] = -3;
        b[5] = 1;
        b[9] = -1;
        b[20] = (seed % 7) - 3;
        b[40] = 2;
        b
    }

    #[test]
    fn scan_roundtrips() {
        let n = 6;
        let y: Vec<[i32; 64]> = (0..n).map(|i| sample_block(i as i32)).collect();
        let cb: Vec<[i32; 64]> = (0..n).map(|i| sample_block(i as i32 + 1)).collect();
        let cr: Vec<[i32; 64]> = (0..n).map(|i| sample_block(i as i32 + 2)).collect();
        let entropy = encode_scan(&y, &cb, &cr);
        let (y2, cb2, cr2) = decode_scan(&entropy, n).unwrap();
        assert_eq!(y, y2);
        assert_eq!(cb, cb2);
        assert_eq!(cr, cr2);
    }

    #[test]
    fn all_zero_ac_block_roundtrips() {
        let mut b = [0i32; 64];
        b[0] = 7;
        let blocks = vec![b];
        let entropy = encode_scan(&blocks, &blocks, &blocks);
        let (y2, _, _) = decode_scan(&entropy, 1).unwrap();
        assert_eq!(blocks[0], y2[0]);
    }
}
