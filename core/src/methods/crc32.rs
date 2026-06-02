//! Standard CRC-32 (reflected, polynomial 0xEDB88320) — shared by the PNG and
//! ZIP writers. Bytewise (no table); fast enough for our payloads.

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"IEND"), 0xAE42_6082); // PNG IEND constant
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926); // CRC-32 check value
    }
}
