//! MSF 7.00, the container format of a PDB.

use std::path::Path;

use rayon::prelude::*;

use crate::diag::Result;
use crate::err;

pub const BLOCK: usize = 4096;
const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// The free block maps live at blocks 1 and 2 of every 4096-block interval.
fn is_fpm_block(b: u32) -> bool {
    let r = b as usize % BLOCK;
    r == 1 || r == 2
}

struct Allocator {
    next: u32,
}

impl Allocator {
    fn alloc(&mut self, bytes: usize) -> Vec<u32> {
        let n = bytes.div_ceil(BLOCK);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if !is_fpm_block(self.next) {
                out.push(self.next);
            }
            self.next += 1;
        }
        out
    }
}

pub fn write(path: &Path, streams: &[&[u8]]) -> Result<()> {
    let mut a = Allocator { next: 3 };
    let blocks: Vec<Vec<u32>> = streams.iter().map(|s| a.alloc(s.len())).collect();

    let mut dir = Vec::new();
    dir.extend_from_slice(&(streams.len() as u32).to_le_bytes());
    for s in streams {
        dir.extend_from_slice(&(s.len() as u32).to_le_bytes());
    }
    for b in blocks.iter().flatten() {
        dir.extend_from_slice(&b.to_le_bytes());
    }
    let dir_blocks = a.alloc(dir.len());
    if dir_blocks.len() * 4 > BLOCK {
        return Err(err!(
            "the PDB is too large for 4 KiB blocks ({} directory blocks)",
            dir_blocks.len()
        ));
    }
    let map_block = a.alloc(BLOCK)[0];
    let mut map = Vec::with_capacity(BLOCK);
    for b in &dir_blocks {
        map.extend_from_slice(&b.to_le_bytes());
    }
    let num_blocks = a.next;

    let mut out = crate::fileio::OutputFile::create(path, num_blocks as usize * BLOCK)
        .map_err(|e| err!("cannot create '{}': {e}", path.display()))?;
    let buf = out.bytes();

    let mut sources: Vec<Option<&[u8]>> = vec![None; num_blocks as usize];
    for (s, bl) in streams.iter().zip(&blocks) {
        for (i, &b) in bl.iter().enumerate() {
            let start = i * BLOCK;
            sources[b as usize] = Some(&s[start..(start + BLOCK).min(s.len())]);
        }
    }
    for (i, &b) in dir_blocks.iter().enumerate() {
        let start = i * BLOCK;
        sources[b as usize] = Some(&dir[start..(start + BLOCK).min(dir.len())]);
    }
    sources[map_block as usize] = Some(&map);

    buf.par_chunks_mut(BLOCK)
        .zip(sources.par_iter())
        .for_each(|(dst, src)| {
            if let Some(src) = src {
                dst[..src.len()].copy_from_slice(src);
            }
        });

    buf[..32].copy_from_slice(MAGIC);
    let mut put = |off: usize, v: u32| buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(32, BLOCK as u32);
    put(36, 1); // free block map block
    put(40, num_blocks);
    put(44, dir.len() as u32);
    put(48, 0);
    put(52, map_block);

    let intervals = (num_blocks as usize).div_ceil(BLOCK);
    for k in 0..intervals {
        if k * BLOCK + 1 >= num_blocks as usize {
            break;
        }
        let fpm = &mut buf[(k * BLOCK + 1) * BLOCK..(k * BLOCK + 2) * BLOCK];
        for (byte_idx, byte) in fpm.iter_mut().enumerate() {
            let first = (k * BLOCK + byte_idx) * 8;
            let mut v = 0u8;
            for bit in 0..8 {
                if first + bit >= num_blocks as usize {
                    v |= 1 << bit;
                }
            }
            *byte = v;
        }
    }

    out.commit(num_blocks as usize * BLOCK)
        .map_err(|e| err!("cannot write '{}': {e}", path.display()))
}

#[cfg(test)]
pub fn read(data: &[u8]) -> Vec<Vec<u8>> {
    let u32at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    assert_eq!(&data[..32], MAGIC);
    let dir_len = u32at(44);
    let map = u32at(52);
    let mut dir = Vec::new();
    for i in 0..dir_len.div_ceil(BLOCK) {
        let b = u32at(map * BLOCK + i * 4);
        dir.extend_from_slice(&data[b * BLOCK..(b + 1) * BLOCK]);
    }
    let d = |o: usize| u32::from_le_bytes(dir[o..o + 4].try_into().unwrap()) as usize;
    let n = d(0);
    let sizes: Vec<usize> = (0..n).map(|i| d(4 + 4 * i)).collect();
    let mut pos = 4 + 4 * n;
    sizes
        .iter()
        .map(|&size| {
            let mut s = Vec::new();
            for _ in 0..size.div_ceil(BLOCK) {
                let b = d(pos);
                pos += 4;
                s.extend_from_slice(&data[b * BLOCK..(b + 1) * BLOCK]);
            }
            s.truncate(size);
            s
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_round_trip_across_fpm_intervals() {
        let big: Vec<u8> = (0..(BLOCK * 4100)).map(|i| (i % 253) as u8).collect();
        let streams: Vec<Vec<u8>> = vec![vec![], b"info".to_vec(), big, vec![7; 10]];
        let refs: Vec<&[u8]> = streams.iter().map(|s| s.as_slice()).collect();
        let dir = std::env::temp_dir().join(format!("hyprlnk-msf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pdb");
        write(&path, &refs).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(read(&data), streams);
        assert_eq!(data.len() % BLOCK, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
