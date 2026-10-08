//! The global and public symbol streams and their hash tables.

use rayon::prelude::*;

use super::hash::hash_string_v1;
use super::modules::{S_CONSTANT, S_PUB32, S_UDT, symbol_name};

const IPHR_HASH: usize = 4096;
const BITMAP_WORDS: usize = IPHR_HASH.div_ceil(32) + 1;

pub struct Public {
    pub name: Vec<u8>,
    pub segment: u16,
    pub offset: u32,
    pub flags: u32,
}

pub struct Gsi {
    pub records: Vec<u8>,
    pub globals: Vec<u8>,
    pub publics: Vec<u8>,
}

fn public_record(p: &Public) -> Vec<u8> {
    let mut c = Vec::with_capacity(11 + p.name.len());
    c.extend_from_slice(&p.flags.to_le_bytes());
    c.extend_from_slice(&p.offset.to_le_bytes());
    c.extend_from_slice(&p.segment.to_le_bytes());
    c.extend_from_slice(&p.name);
    c.push(0);
    super::modules::record(S_PUB32, &c)
}

/// The order names are kept in within a hash bucket: shorter first, then
/// case-insensitively (as the reader's binary search expects).
fn gsi_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| {
        if a.is_ascii() && b.is_ascii() {
            a.iter()
                .map(|c| c.to_ascii_lowercase())
                .cmp(b.iter().map(|c| c.to_ascii_lowercase()))
        } else {
            a.cmp(b)
        }
    })
}

fn hash_table(entries: &[(&[u8], u32)]) -> Vec<u8> {
    let buckets: Vec<u16> = entries
        .par_iter()
        .map(|(n, _)| (hash_string_v1(n) as usize % IPHR_HASH) as u16)
        .collect();
    let mut starts = vec![0u32; IPHR_HASH + 1];
    for &b in &buckets {
        starts[b as usize + 1] += 1;
    }
    for i in 0..IPHR_HASH {
        starts[i + 1] += starts[i];
    }
    let mut cursor = starts.clone();
    let mut slots = vec![0u32; entries.len()];
    for (i, &b) in buckets.iter().enumerate() {
        slots[cursor[b as usize] as usize] = i as u32;
        cursor[b as usize] += 1;
    }
    let mut ranges: Vec<&mut [u32]> = Vec::with_capacity(IPHR_HASH);
    let mut rest: &mut [u32] = &mut slots;
    for b in 0..IPHR_HASH {
        let n = (starts[b + 1] - starts[b]) as usize;
        let (a, r) = std::mem::take(&mut rest).split_at_mut(n);
        ranges.push(a);
        rest = r;
    }
    ranges.par_iter_mut().for_each(|r| {
        r.sort_by(|&x, &y| {
            let (xn, xo) = entries[x as usize];
            let (yn, yo) = entries[y as usize];
            gsi_cmp(xn, yn).then(xo.cmp(&yo))
        })
    });

    let mut out = Vec::with_capacity(16 + entries.len() * 8 + BITMAP_WORDS * 4 + IPHR_HASH * 4);
    let mut bitmap = [0u32; BITMAP_WORDS];
    let mut bucket_offsets = Vec::new();
    for b in 0..IPHR_HASH {
        if starts[b + 1] > starts[b] {
            bitmap[b / 32] |= 1 << (b % 32);
            // As if records were 12 bytes (the reference's in-memory size).
            bucket_offsets.push(starts[b] * 12);
        }
    }
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    out.extend_from_slice(&(0xEFFE_0000u32 + 19_990_810).to_le_bytes());
    out.extend_from_slice(&((entries.len() * 8) as u32).to_le_bytes());
    out.extend_from_slice(&(((BITMAP_WORDS + bucket_offsets.len()) * 4) as u32).to_le_bytes());
    for &i in &slots {
        out.extend_from_slice(&(entries[i as usize].1 + 1).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    for w in bitmap {
        out.extend_from_slice(&w.to_le_bytes());
    }
    for o in bucket_offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out
}

fn records_of(buf: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 4 <= buf.len() {
        let len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize + 2;
        out.push((p as u32, len as u32));
        p += len;
    }
    out
}

pub fn build(mut publics: Vec<Public>, module_globals: &[Vec<u8>]) -> Gsi {
    publics.par_sort_unstable_by(|a, b| a.name.cmp(&b.name).then(a.offset.cmp(&b.offset)));
    let mut records = Vec::new();
    let mut pub_offsets = Vec::with_capacity(publics.len());
    for p in &publics {
        pub_offsets.push(records.len() as u32);
        records.extend_from_slice(&public_record(p));
    }
    let pub_bytes = records.len();

    let per_module: Vec<Vec<(u32, u32)>> =
        module_globals.par_iter().map(|g| records_of(g)).collect();
    let mut keyed: Vec<(u128, u32, u32)> = per_module
        .par_iter()
        .enumerate()
        .flat_map_iter(|(m, recs)| {
            let g = &module_globals[m];
            recs.iter().enumerate().filter_map(move |(k, &(o, len))| {
                let r = &g[o as usize..(o + len) as usize];
                let kind = u16::from_le_bytes([r[2], r[3]]);
                (kind == S_UDT || kind == S_CONSTANT)
                    .then(|| (xxhash_rust::xxh3::xxh3_128(r), m as u32, k as u32))
            })
        })
        .collect();
    keyed.par_sort_unstable();
    let mut drop_list: Vec<(u32, u32)> = Vec::new();
    for w in keyed.windows(2) {
        if w[0].0 == w[1].0 {
            drop_list.push((w[1].1, w[1].2));
        }
    }
    let mut keep: Vec<Vec<bool>> = per_module.iter().map(|r| vec![true; r.len()]).collect();
    for (m, k) in drop_list {
        keep[m as usize][k as usize] = false;
    }

    let sizes: Vec<usize> = per_module
        .iter()
        .zip(&keep)
        .map(|(recs, keep)| {
            recs.iter()
                .zip(keep)
                .filter(|(_, k)| **k)
                .map(|(r, _)| r.1 as usize)
                .sum()
        })
        .collect();
    let total: usize = sizes.iter().sum();
    records.resize(pub_bytes + total, 0);
    let mut starts = Vec::with_capacity(sizes.len());
    let mut acc = pub_bytes;
    for s in &sizes {
        starts.push(acc);
        acc += s;
    }
    {
        let mut rest: &mut [u8] = &mut records[pub_bytes..];
        let mut slices = Vec::with_capacity(sizes.len());
        for &s in &sizes {
            let (a, r) = std::mem::take(&mut rest).split_at_mut(s);
            slices.push(a);
            rest = r;
        }
        slices.into_par_iter().enumerate().for_each(|(m, dst)| {
            let g = &module_globals[m];
            let mut pos = 0;
            for (&(o, len), &k) in per_module[m].iter().zip(&keep[m]) {
                if k {
                    dst[pos..pos + len as usize]
                        .copy_from_slice(&g[o as usize..(o + len) as usize]);
                    pos += len as usize;
                }
            }
        });
    }
    let glob_entries: Vec<(&[u8], u32)> = (0..module_globals.len())
        .into_par_iter()
        .flat_map_iter(|m| {
            let mut pos = starts[m];
            let records = &records;
            per_module[m]
                .iter()
                .zip(&keep[m])
                .filter(|(_, k)| **k)
                .map(move |(&(_, len), _)| {
                    let at = pos;
                    pos += len as usize;
                    (symbol_name(&records[at..at + len as usize]), at as u32)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let pub_entries: Vec<(&[u8], u32)> = publics
        .iter()
        .zip(&pub_offsets)
        .map(|(p, &o)| (p.name.as_slice(), o))
        .collect();
    let (globals_stream, pub_hash) =
        rayon::join(|| hash_table(&glob_entries), || hash_table(&pub_entries));

    let npub = publics.len();
    let mut by_addr: Vec<u32> = (0..npub as u32).collect();
    by_addr.par_sort_unstable_by(|&a, &b| {
        let (a, b) = (&publics[a as usize], &publics[b as usize]);
        (a.segment, a.offset, &a.name).cmp(&(b.segment, b.offset, &b.name))
    });
    let mut publics_stream = Vec::with_capacity(28 + pub_hash.len() + 4 * npub);
    publics_stream.extend_from_slice(&(pub_hash.len() as u32).to_le_bytes());
    publics_stream.extend_from_slice(&((npub * 4) as u32).to_le_bytes());
    publics_stream.extend_from_slice(&[0; 20]);
    publics_stream.extend_from_slice(&pub_hash);
    for i in by_addr {
        publics_stream.extend_from_slice(&pub_offsets[i as usize].to_le_bytes());
    }
    Gsi {
        records,
        globals: globals_stream,
        publics: publics_stream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tables() {
        let publics = vec![
            Public {
                name: b"main".to_vec(),
                segment: 1,
                offset: 0x10,
                flags: 2,
            },
            Public {
                name: b"abc".to_vec(),
                segment: 1,
                offset: 0x5,
                flags: 0,
            },
        ];
        let udt = super::super::modules::record(S_UDT, &[0x74, 0, 0, 0, b'T', 0]);
        let mut both = udt.clone();
        both.extend_from_slice(&udt);
        let g = build(publics, &[both]);
        let header_hr = u32::from_le_bytes(g.globals[8..12].try_into().unwrap());
        assert_eq!(header_hr, 8);
        let pub_hash_size = u32::from_le_bytes(g.publics[0..4].try_into().unwrap()) as usize;
        let addr_map = &g.publics[28 + pub_hash_size..];
        assert_eq!(u32::from_le_bytes(addr_map[0..4].try_into().unwrap()), 0);
        assert_eq!(addr_map.len(), 8);
        assert_eq!(gsi_cmp(b"ab", b"AB"), std::cmp::Ordering::Equal);
        assert_eq!(gsi_cmp(b"zz", b"aaa"), std::cmp::Ordering::Less);
    }
}
