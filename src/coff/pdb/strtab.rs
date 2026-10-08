//! The PDB string table (`/names`).

use std::collections::HashMap;

use super::hash::hash_string_v1;

#[derive(Default)]
pub struct StringTable {
    buf: Vec<u8>,
    offsets: HashMap<Vec<u8>, u32>,
    order: Vec<u32>,
}

impl StringTable {
    pub fn new() -> StringTable {
        StringTable {
            buf: vec![0],
            offsets: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn insert(&mut self, s: &[u8]) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&o) = self.offsets.get(s) {
            return o;
        }
        let o = self.buf.len() as u32;
        self.buf.extend_from_slice(s);
        self.buf.push(0);
        self.offsets.insert(s.to_vec(), o);
        self.order.push(o);
        o
    }

    pub fn finish(&self) -> Vec<u8> {
        let mut buckets = 1u32;
        for count in 1..=self.order.len() as u32 {
            if buckets * 3 / 4 < count {
                buckets = buckets * 3 / 2 + 1;
            }
        }
        let mut table = vec![0u32; buckets as usize];
        for &o in &self.order {
            let s = &self.buf[o as usize..];
            let s = &s[..s.iter().position(|&b| b == 0).unwrap()];
            let h = hash_string_v1(s);
            for i in 0..buckets {
                let slot = ((h + i) % buckets) as usize;
                if table[slot] == 0 {
                    table[slot] = o;
                    break;
                }
            }
        }
        let mut out = Vec::with_capacity(12 + self.buf.len() + 8 + 4 * table.len());
        out.extend_from_slice(&0xEFFE_EFFEu32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(self.buf.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.buf);
        out.extend_from_slice(&buckets.to_le_bytes());
        for t in &table {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out.extend_from_slice(&(self.order.len() as u32).to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interns_and_serializes() {
        let mut t = StringTable::new();
        assert_eq!(t.insert(b""), 0);
        let a = t.insert(b"C:\\src\\main.rs");
        let b = t.insert(b"lib.rs");
        assert_eq!(t.insert(b"C:\\src\\main.rs"), a);
        assert_eq!((a, b), (1, 16));
        let out = t.finish();
        assert_eq!(&out[..4], &0xEFFE_EFFEu32.to_le_bytes());
        let size = u32::from_le_bytes(out[8..12].try_into().unwrap()) as usize;
        assert_eq!(size, 1 + 15 + 7);
        let nbuckets = u32::from_le_bytes(out[12 + size..16 + size].try_into().unwrap());
        assert_eq!(nbuckets, 4);
        let count = u32::from_le_bytes(out[out.len() - 4..].try_into().unwrap());
        assert_eq!(count, 2);
    }
}
