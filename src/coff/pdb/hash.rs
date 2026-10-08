//! Hash functions fixed by the PDB format: they must match Microsoft's exactly.

/// `Hasher::lhashPbCb`: names in hash tables, string tables and GSI buckets.
pub fn hash_string_v1(s: &[u8]) -> u32 {
    let mut result: u32 = 0;
    let (longs, rest) = s.as_chunks::<4>();
    for l in longs {
        result ^= u32::from_le_bytes(*l);
    }
    let mut rest = rest;
    if rest.len() >= 2 {
        result ^= u16::from_le_bytes([rest[0], rest[1]]) as u32;
        rest = &rest[2..];
    }
    if rest.len() == 1 {
        result ^= rest[0] as u32;
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^ (result >> 16)
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// `SigForPbCb`: CRC-32 starting from 0, without the final inversion (what
/// LLVM calls JamCRC with a zero seed). Hashes type records.
pub fn hash_buffer_v8(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &b in buf {
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ b as u32) & 0xFF) as usize];
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_hashes() {
        assert_eq!(hash_string_v1(b"a"), hash_string_v1(b"A"));
        assert_eq!(hash_string_v1(b"MAIN"), hash_string_v1(b"main"));
        assert_ne!(hash_string_v1(b"main"), hash_string_v1(b"mian"));
        assert_eq!(hash_buffer_v8(b""), 0);
        assert_eq!(hash_buffer_v8(b"123456789"), 0x2DFD_2D88);
    }
}
