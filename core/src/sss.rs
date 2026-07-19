//! Shamir Secret Sharing over GF(256).
//!
//! Splits a secret (a passphrase, a key, any bytes) into `n` shares such that
//! *any* `k` of them reconstruct it and any `k−1` reveal **nothing** —
//! information-theoretic security, not merely computational. Useful for
//! distributing recovery across people or carriers: e.g. split a master
//! passphrase 2-of-3 and hide one share in each of three photos.
//!
//! Each secret byte becomes the constant term of an independent random degree
//! `k−1` polynomial over GF(2⁸) (primitive polynomial `0x11d`); a share is that
//! polynomial family evaluated at a distinct nonzero x-coordinate. Recovery is
//! Lagrange interpolation at `x = 0`.
//!
//! Pure Rust, `getrandom` for coefficients — no new dependency.

use std::sync::OnceLock;

use crate::StegnoError;

/// One share: its x-coordinate and the polynomial evaluations for every secret
/// byte. All shares of a split have the same `y` length (the secret length).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecretShare {
    /// Distinct nonzero x-coordinate (1..=255) identifying this share.
    pub x: u8,
    /// One field element per secret byte.
    pub y: Vec<u8>,
}

// --- GF(256) ---------------------------------------------------------------

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
fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let g = gf();
    g.exp[g.log[a as usize] as usize + g.log[b as usize] as usize]
}

#[inline]
fn div(a: u8, b: u8) -> u8 {
    // b != 0 required.
    if a == 0 {
        return 0;
    }
    let g = gf();
    g.exp[(g.log[a as usize] as usize + 255 - g.log[b as usize] as usize) % 255]
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("OS RNG unavailable");
    v
}

// --- API -------------------------------------------------------------------

/// Split `secret` into `shares` pieces, any `threshold` of which reconstruct it.
///
/// Requires `1 <= threshold <= shares <= 255` and a non-empty secret.
#[uniffi::export]
pub fn sss_split(
    secret: Vec<u8>,
    threshold: u8,
    shares: u8,
) -> Result<Vec<SecretShare>, StegnoError> {
    if secret.is_empty() {
        return Err(StegnoError::Internal("secret is empty".into()));
    }
    if threshold < 1 || shares < 1 || threshold > shares {
        return Err(StegnoError::Internal(
            "need 1 <= threshold <= shares <= 255".into(),
        ));
    }

    let k = threshold as usize;
    // x-coordinates 1..=shares (never 0 — that's where the secret lives).
    let mut out: Vec<SecretShare> = (1..=shares)
        .map(|x| SecretShare {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    for &byte in &secret {
        // Random polynomial: coeffs[0] = secret byte, coeffs[1..k] random.
        let mut coeffs = Vec::with_capacity(k);
        coeffs.push(byte);
        coeffs.extend(rand_bytes(k - 1));

        for share in out.iter_mut() {
            share.y.push(eval(&coeffs, share.x));
        }
    }
    Ok(out)
}

/// Reconstruct the secret from `shares` (at least `threshold` distinct shares).
///
/// Errors if fewer than one share is given, shares disagree on length, or two
/// shares share an x-coordinate. Fewer than the original threshold simply yields
/// the wrong bytes — by design, no error can distinguish that case.
#[uniffi::export]
pub fn sss_combine(shares: Vec<SecretShare>) -> Result<Vec<u8>, StegnoError> {
    if shares.is_empty() {
        return Err(StegnoError::Internal("no shares provided".into()));
    }
    let len = shares[0].y.len();
    if len == 0 || shares.iter().any(|s| s.y.len() != len) {
        return Err(StegnoError::CorruptPayload);
    }
    // Distinct, nonzero x-coordinates.
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    if xs.iter().any(|&x| x == 0) {
        return Err(StegnoError::CorruptPayload);
    }
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err(StegnoError::CorruptPayload);
            }
        }
    }

    let mut secret = Vec::with_capacity(len);
    for byte_idx in 0..len {
        // Lagrange interpolation at x = 0.
        let mut acc = 0u8;
        for i in 0..shares.len() {
            let xi = xs[i];
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, &xj) in xs.iter().enumerate() {
                if j != i {
                    num = mul(num, xj); // (0 - x_j) == x_j in GF(2ⁿ)
                    den = mul(den, xi ^ xj); // (x_i - x_j) == x_i ^ x_j
                }
            }
            let basis = div(num, den);
            acc ^= mul(shares[i].y[byte_idx], basis);
        }
        secret.push(acc);
    }
    Ok(secret)
}

/// Evaluate polynomial (coeffs[0] = constant term) at `x` via Horner.
fn eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_subset_recovers() {
        let secret = b"correct horse battery staple".to_vec();
        let shares = sss_split(secret.clone(), 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Every 3-of-5 combination reconstructs.
        for i in 0..5 {
            for j in (i + 1)..5 {
                for l in (j + 1)..5 {
                    let subset = vec![shares[i].clone(), shares[j].clone(), shares[l].clone()];
                    assert_eq!(sss_combine(subset).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn all_shares_recover() {
        let secret = vec![1u8, 2, 3, 250, 128, 0, 255];
        let shares = sss_split(secret.clone(), 4, 7).unwrap();
        assert_eq!(sss_combine(shares).unwrap(), secret);
    }

    #[test]
    fn two_of_two() {
        let secret = b"k".to_vec();
        let shares = sss_split(secret.clone(), 2, 2).unwrap();
        assert_eq!(sss_combine(shares).unwrap(), secret);
    }

    #[test]
    fn fewer_than_threshold_does_not_recover() {
        // 2 of a 3-threshold split must not equal the secret (near-certainly).
        let secret = b"top secret value".to_vec();
        let shares = sss_split(secret.clone(), 3, 5).unwrap();
        let two = vec![shares[0].clone(), shares[1].clone()];
        assert_ne!(sss_combine(two).unwrap(), secret);
    }

    #[test]
    fn threshold_one_is_trivial_copy() {
        // k=1 means every share's y IS the secret.
        let secret = vec![9u8, 8, 7];
        let shares = sss_split(secret.clone(), 1, 3).unwrap();
        for s in &shares {
            assert_eq!(s.y, secret);
        }
    }

    #[test]
    fn bad_params_rejected() {
        assert!(sss_split(vec![], 2, 3).is_err());
        assert!(sss_split(vec![1], 0, 3).is_err());
        assert!(sss_split(vec![1], 4, 3).is_err()); // threshold > shares
    }

    #[test]
    fn duplicate_or_zero_x_rejected() {
        let a = SecretShare { x: 1, y: vec![10] };
        let dup = SecretShare { x: 1, y: vec![20] };
        assert!(sss_combine(vec![a.clone(), dup]).is_err());
        let zero = SecretShare { x: 0, y: vec![5] };
        assert!(sss_combine(vec![zero]).is_err());
    }

    #[test]
    fn mismatched_lengths_rejected() {
        let a = SecretShare { x: 1, y: vec![1, 2, 3] };
        let b = SecretShare { x: 2, y: vec![1, 2] };
        assert!(sss_combine(vec![a, b]).is_err());
    }
}
