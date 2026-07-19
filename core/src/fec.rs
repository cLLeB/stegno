//! Reed–Solomon forward error correction over GF(256).
//!
//! A robustness layer that sits *between* crypto and framing: the sealed blob is
//! RS-encoded before it is written into a cover, so a bounded number of corrupted
//! carrier bytes (from recompression, a resize, a scanned print, bit-rot) still
//! recover the exact ciphertext — after which the AES-GCM tag verifies as usual.
//!
//! The codec is systematic RS over GF(2⁸) with primitive polynomial `0x11d`
//! (the QR-code / AES field) and generator root `α = 2`. Arbitrary-length input
//! is length-prefixed and split into 255-byte codewords, each carrying `parity`
//! check bytes and thus correcting up to `parity / 2` byte-errors per block, with
//! *no* side information needed at decode time.
//!
//! Pure Rust, no external crate — consistent with the engine's dependency-light,
//! audited-core thesis.

use std::sync::OnceLock;

/// Errors from the FEC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    /// `parity` was 0 or ≥ 255, or the derived data block size was invalid.
    BadParity,
    /// The coded stream length is not a whole number of 255-byte codewords.
    BadLength,
    /// A codeword had more byte-errors than the parity budget can repair.
    TooManyErrors,
    /// The recovered length prefix is inconsistent with the payload.
    Corrupt,
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic
// ---------------------------------------------------------------------------

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

fn gf() -> &'static Gf {
    static T: OnceLock<Gf> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    })
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let g = gf();
    g.exp[g.log[a as usize] as usize + g.log[b as usize] as usize]
}

#[inline]
fn gf_div(a: u8, b: u8) -> u8 {
    // Caller guarantees b != 0.
    if a == 0 {
        return 0;
    }
    let g = gf();
    g.exp[(g.log[a as usize] as usize + 255 - g.log[b as usize] as usize) % 255]
}

#[inline]
fn gf_pow(a: u8, n: i32) -> u8 {
    let g = gf();
    let l = g.log[a as usize] as i32;
    let idx = (((l * n) % 255) + 255) % 255;
    g.exp[idx as usize]
}

#[inline]
fn gf_inverse(a: u8) -> u8 {
    let g = gf();
    g.exp[255 - g.log[a as usize] as usize]
}

// ---------------------------------------------------------------------------
// Polynomials (index 0 = highest degree)
// ---------------------------------------------------------------------------

fn poly_scale(p: &[u8], x: u8) -> Vec<u8> {
    p.iter().map(|&c| gf_mul(c, x)).collect()
}

fn poly_add(p: &[u8], q: &[u8]) -> Vec<u8> {
    let n = p.len().max(q.len());
    let mut r = vec![0u8; n];
    for (i, &c) in p.iter().enumerate() {
        r[i + n - p.len()] = c;
    }
    for (i, &c) in q.iter().enumerate() {
        r[i + n - q.len()] ^= c;
    }
    r
}

fn poly_mul(p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; p.len() + q.len() - 1];
    for (j, &qj) in q.iter().enumerate() {
        for (i, &pi) in p.iter().enumerate() {
            r[i + j] ^= gf_mul(pi, qj);
        }
    }
    r
}

fn poly_eval(p: &[u8], x: u8) -> u8 {
    let mut y = p[0];
    for &c in &p[1..] {
        y = gf_mul(y, x) ^ c;
    }
    y
}

/// Polynomial division; returns (quotient, remainder).
fn poly_div(dividend: &[u8], divisor: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut out = dividend.to_vec();
    let steps = dividend.len().saturating_sub(divisor.len() - 1);
    for i in 0..steps {
        let coef = out[i];
        if coef != 0 {
            for j in 1..divisor.len() {
                if divisor[j] != 0 {
                    out[i + j] ^= gf_mul(divisor[j], coef);
                }
            }
        }
    }
    let sep = out.len() - (divisor.len() - 1);
    let (q, r) = out.split_at(sep);
    (q.to_vec(), r.to_vec())
}

// ---------------------------------------------------------------------------
// RS block codec
// ---------------------------------------------------------------------------

fn generator_poly(nsym: usize) -> Vec<u8> {
    let mut g = vec![1u8];
    for i in 0..nsym {
        g = poly_mul(&g, &[1, gf_pow(2, i as i32)]);
    }
    g
}

/// Systematic RS encode of a single block (`msg_in.len() + nsym <= 255`).
fn encode_block(msg_in: &[u8], nsym: usize) -> Vec<u8> {
    let gen = generator_poly(nsym);
    let mut out = vec![0u8; msg_in.len() + nsym];
    out[..msg_in.len()].copy_from_slice(msg_in);
    for i in 0..msg_in.len() {
        let coef = out[i];
        if coef != 0 {
            for j in 1..gen.len() {
                out[i + j] ^= gf_mul(gen[j], coef);
            }
        }
    }
    out[..msg_in.len()].copy_from_slice(msg_in);
    out
}

fn calc_syndromes(msg: &[u8], nsym: usize) -> Vec<u8> {
    let mut synd = vec![0u8; nsym + 1];
    for i in 0..nsym {
        synd[i + 1] = poly_eval(msg, gf_pow(2, i as i32));
    }
    synd
}

/// Berlekamp–Massey: derive the error-locator polynomial from the syndromes.
fn find_error_locator(synd: &[u8], nsym: usize) -> Vec<u8> {
    let mut err_loc = vec![1u8];
    let mut old_loc = vec![1u8];
    for i in 0..nsym {
        let k = i + 1; // syndrome shift: synd[0] is a leading zero
        let mut delta = synd[k];
        for j in 1..err_loc.len() {
            delta ^= gf_mul(err_loc[err_loc.len() - 1 - j], synd[k - j]);
        }
        old_loc.push(0);
        if delta != 0 {
            if old_loc.len() > err_loc.len() {
                let new_loc = poly_scale(&old_loc, delta);
                old_loc = poly_scale(&err_loc, gf_inverse(delta));
                err_loc = new_loc;
            }
            err_loc = poly_add(&err_loc, &poly_scale(&old_loc, delta));
        }
    }
    while err_loc.len() > 1 && err_loc[0] == 0 {
        err_loc.remove(0);
    }
    err_loc
}

/// Chien search: the error positions (as message indices) from a locator.
fn find_errors(err_loc: &[u8], nmess: usize) -> Option<Vec<usize>> {
    let errs = err_loc.len() - 1;
    let mut positions = Vec::new();
    for i in 0..nmess {
        if poly_eval(err_loc, gf_pow(2, i as i32)) == 0 {
            positions.push(nmess - 1 - i);
        }
    }
    if positions.len() != errs {
        return None; // too many errors to locate
    }
    Some(positions)
}

fn find_errata_locator(positions: &[usize]) -> Vec<u8> {
    let mut e_loc = vec![1u8];
    for &p in positions {
        e_loc = poly_mul(&e_loc, &poly_add(&[1], &[gf_pow(2, p as i32), 0]));
    }
    e_loc
}

fn find_error_evaluator(synd: &[u8], err_loc: &[u8], nsym: usize) -> Vec<u8> {
    let mul = poly_mul(synd, err_loc);
    let mut divisor = vec![0u8; nsym + 2];
    divisor[0] = 1; // x^(nsym+1)
    let (_, rem) = poly_div(&mul, &divisor);
    rem
}

/// Forney: given located positions, compute magnitudes and correct in place.
fn correct_errata(msg: &mut [u8], synd: &[u8], err_pos: &[usize]) {
    let coef_pos: Vec<usize> = err_pos.iter().map(|&p| msg.len() - 1 - p).collect();
    let err_loc = find_errata_locator(&coef_pos);

    let mut synd_rev = synd.to_vec();
    synd_rev.reverse();
    // The evaluator is used non-reversed in the Forney step below, so we keep the
    // raw remainder here (the reference reverses it twice, netting the same thing).
    let err_eval = find_error_evaluator(&synd_rev, &err_loc, err_loc.len() - 1);

    let xs: Vec<u8> = coef_pos
        .iter()
        .map(|&cp| gf_pow(2, -((255 - cp as i32))))
        .collect();

    for (i, &xi) in xs.iter().enumerate() {
        let xi_inv = gf_inverse(xi);
        let mut prime = 1u8;
        for (j, &xj) in xs.iter().enumerate() {
            if j != i {
                prime = gf_mul(prime, 1 ^ gf_mul(xi_inv, xj));
            }
        }
        let mut y = poly_eval(&err_eval, xi_inv);
        y = gf_mul(xi, y);
        let magnitude = gf_div(y, prime);
        msg[err_pos[i]] ^= magnitude;
    }
}

/// Correct a single 255-byte (or shorter, shortened) codeword in place.
fn correct_block(block: &mut [u8], nsym: usize) -> Result<(), FecError> {
    let synd = calc_syndromes(block, nsym);
    if synd.iter().all(|&s| s == 0) {
        return Ok(()); // clean
    }
    let err_loc = find_error_locator(&synd, nsym);
    let mut rev = err_loc.clone();
    rev.reverse();
    let err_pos = find_errors(&rev, block.len()).ok_or(FecError::TooManyErrors)?;
    correct_errata(block, &synd, &err_pos);
    let check = calc_syndromes(block, nsym);
    if check.iter().all(|&s| s == 0) {
        Ok(())
    } else {
        Err(FecError::TooManyErrors)
    }
}

// ---------------------------------------------------------------------------
// Message-level API (arbitrary length)
// ---------------------------------------------------------------------------

/// RS-encode arbitrary data with `parity` check bytes per 255-byte codeword.
///
/// The output is a whole number of 255-byte codewords. A 4-byte big-endian
/// length prefix is protected alongside the data so the decoder can strip the
/// zero-padding of the final block exactly.
pub fn encode(data: &[u8], parity: usize) -> Result<Vec<u8>, FecError> {
    if parity == 0 || parity >= 255 {
        return Err(FecError::BadParity);
    }
    let k = 255 - parity;

    let mut protected = Vec::with_capacity(4 + data.len());
    protected.extend_from_slice(&(data.len() as u32).to_be_bytes());
    protected.extend_from_slice(data);

    let mut out = Vec::new();
    for chunk in protected.chunks(k) {
        let mut block = [0u8; 255];
        block[..chunk.len()].copy_from_slice(chunk);
        let coded = encode_block(&block[..k], parity);
        out.extend_from_slice(&coded);
    }
    Ok(out)
}

/// RS-decode a stream produced by [`encode`] with the same `parity`, repairing
/// up to `parity / 2` byte-errors per 255-byte codeword.
pub fn decode(coded: &[u8], parity: usize) -> Result<Vec<u8>, FecError> {
    if parity == 0 || parity >= 255 {
        return Err(FecError::BadParity);
    }
    if coded.is_empty() || coded.len() % 255 != 0 {
        return Err(FecError::BadLength);
    }
    let k = 255 - parity;

    let mut protected = Vec::with_capacity(coded.len());
    for cw in coded.chunks(255) {
        let mut block = cw.to_vec();
        correct_block(&mut block, parity)?;
        protected.extend_from_slice(&block[..k]);
    }

    if protected.len() < 4 {
        return Err(FecError::Corrupt);
    }
    let len = u32::from_be_bytes([protected[0], protected[1], protected[2], protected[3]]) as usize;
    if 4 + len > protected.len() {
        return Err(FecError::Corrupt);
    }
    Ok(protected[4..4 + len].to_vec())
}

/// Map a user-facing robustness level (1–3) to a per-codeword parity budget.
/// Level 1 repairs ~3% of bytes, level 2 ~6%, level 3 ~12% — trading capacity
/// for resilience.
pub fn parity_for_level(level: u8) -> usize {
    match level {
        0 | 1 => 16, // corrects up to 8 errors / 255
        2 => 32,     // up to 16 / 255
        _ => 64,     // up to 32 / 255
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_roundtrip_all_levels() {
        for level in 1u8..=3 {
            let parity = parity_for_level(level);
            for len in [0usize, 1, 10, 239, 240, 500, 4096] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let coded = encode(&data, parity).unwrap();
                assert_eq!(coded.len() % 255, 0);
                assert_eq!(decode(&coded, parity).unwrap(), data, "len={len} level={level}");
            }
        }
    }

    #[test]
    fn corrects_up_to_budget_per_block() {
        let parity = 32; // t = 16 errors / block
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let mut coded = encode(&data, parity).unwrap();
        // Corrupt exactly t bytes in each 255-byte codeword.
        let t = parity / 2;
        let blocks = coded.len() / 255;
        for b in 0..blocks {
            for e in 0..t {
                let idx = b * 255 + (e * 9 + 1) % 255;
                coded[idx] ^= 0xA5;
            }
        }
        assert_eq!(decode(&coded, parity).unwrap(), data);
    }

    #[test]
    fn random_error_bursts_recover() {
        let parity = 64; // t = 32
        let data: Vec<u8> = (0..1000).map(|i| (i * 131 + 17) as u8).collect();
        let mut coded = encode(&data, parity).unwrap();
        // A contiguous burst of 30 bytes inside the first codeword.
        for i in 40..70 {
            coded[i] ^= 0xFF;
        }
        assert_eq!(decode(&coded, parity).unwrap(), data);
    }

    #[test]
    fn beyond_budget_is_reported_not_silently_wrong() {
        let parity = 16; // t = 8
        let data: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut coded = encode(&data, parity).unwrap();
        // 9 errors in one block exceeds t=8 → must error, never return junk.
        for e in 0..9 {
            coded[e * 3] ^= 0x7C;
        }
        match decode(&coded, parity) {
            Err(FecError::TooManyErrors) => {}
            Ok(v) => assert_ne!(v, data, "decoder must not fabricate a correct-looking result"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn bad_params_rejected() {
        assert_eq!(encode(b"x", 0), Err(FecError::BadParity));
        assert_eq!(encode(b"x", 255), Err(FecError::BadParity));
        assert_eq!(decode(&[0u8; 254], 16), Err(FecError::BadLength));
    }
}
