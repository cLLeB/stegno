//! Tiny MSB-first byte↔bit helpers shared by the text methods.

/// Expand bytes into a bit vector, most-significant bit first.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1);
        }
    }
    bits
}

/// Pack bits (MSB-first) back into bytes. Trailing bits that don't fill a final
/// byte are dropped (the frame's length field bounds what we actually need).
pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() / 8);
    let mut acc = 0u8;
    let mut n = 0u8;
    for &bit in bits {
        acc = (acc << 1) | (bit & 1);
        n += 1;
        if n == 8 {
            out.push(acc);
            acc = 0;
            n = 0;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let data = b"\x00\xFF\xA5\x5A hello";
        assert_eq!(bits_to_bytes(&bytes_to_bits(data)), data);
    }

    #[test]
    fn known_vector() {
        assert_eq!(bytes_to_bits(&[0b1010_0001]), vec![1, 0, 1, 0, 0, 0, 0, 1]);
    }
}
