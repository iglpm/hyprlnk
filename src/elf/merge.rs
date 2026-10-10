//! SHF_MERGE sections (`.rodata.str*`, `.rodata.cst*`, `.debug_str`): split into strings or
//! fixed-size entries and deduplicated.
//!
//! 1. Split: every input section is split and its pieces hashed (128-bit) on whichever thread
//!    takes it; each thread appends a record per piece to its own buffer for the piece's shard.
//! 2. Dedupe: each shard, on its own thread, streams the records of its buffers through a hash
//!    table small enough to stay in cache. Equal 128-bit hashes mean equal contents, so no
//!    piece's bytes are read twice. A unique piece's place is where it first occurs (lowest
//!    member, then offset), whatever thread saw it first: the output is the same on every run.
//! 3. Fill in: every input section looks its pieces' output offsets up where the dedupe step
//!    left them. Each piece remembers its record's shard and slot in its thread's buffer, so the
//!    section's own table is written in order and the lookups stay in cache.

use std::sync::Mutex;
use std::sync::atomic::Ordering;

use hashbrown::HashTable;
use rayon::prelude::*;

use super::layout::output_name;
use super::object::{FL_COMPRESSED, Object, SecKind};
use super::resolve::Ctx;
use super::target::Target;
use super::*;
use crate::diag::Timer;

const SHARD_BITS: u32 = 8;
const SHARDS: usize = 1 << SHARD_BITS;
const JUMP_SHIFT: u32 = 8;

pub struct Member {
    pub obj: u32,
    pub sec: u32,
    /// Per piece: [start offset in the input section, offset in the merged section] — side by
    /// side, so a lookup touches one cache line.
    pub pieces: Vec<[u32; 2]>,
    /// The piece containing byte `b << JUMP_SHIFT`, for each `b`: lookups start there.
    jump: Vec<u32>,
    /// The thread buffer holding this section's records.
    thread: u32,
}

pub struct MergedSec<'a> {
    pub name: &'a [u8],
    pub flags: u64,
    pub entsize: u64,
    pub p2align: u8,
    pub members: Vec<Member>,
    /// Unique pieces per shard, in output order: (bytes, offset in shard).
    pub uniq: Vec<Vec<(&'a [u8], u32)>>,
    pub shard_base: Vec<u64>,
    pub size: u64,
    /// Output address (allocated) or file offset (not allocated).
    pub addr: u64,
    pub file_off: u64,
    /// Output section index.
    pub out: u32,
}

/// One piece, as its shard sees it. Its bytes are found through its member's table.
#[derive(Clone, Copy)]
struct Rec {
    hash: [u64; 2],
    member: u32,
    piece: u32,
}

#[inline]
fn shard_of(h: [u64; 2]) -> usize {
    (h[0] >> (64 - SHARD_BITS)) as usize
}

#[inline]
fn hash(b: &[u8]) -> [u64; 2] {
    let h = xxhash_rust::xxh3::xxh3_128(b);
    [h as u64, (h >> 64) as u64]
}

/// Split one input section into pieces — strings with their NUL, or `entsize` entries —
/// calling `f(start, end)` for each.
fn split(data: &[u8], strings: bool, entsize: usize, mut f: impl FnMut(usize, usize)) {
    if strings && entsize == 1 {
        // Eight bytes at a time, every NUL among them found at once: most strings are short,
        // and a search per string costs more than the string.
        const LO7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
        let mut start = 0;
        let mut i = 0;
        while i + 8 <= data.len() {
            let x = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
            // The top bit of each byte that is zero (exactly: no borrow between bytes).
            let mut z = !(((x & LO7) + LO7) | x | LO7);
            while z != 0 {
                let end = i + (z.trailing_zeros() / 8) as usize + 1;
                f(start, end);
                start = end;
                z &= z - 1;
            }
            i += 8;
        }
        for (j, &b) in data.iter().enumerate().skip(i) {
            if b == 0 {
                f(start, j + 1);
                start = j + 1;
            }
        }
        if start < data.len() {
            f(start, data.len());
        }
    } else if strings {
        // Wide strings: NUL is `entsize` zero bytes, aligned.
        let mut pos = 0;
        while pos < data.len() {
            let mut end = pos;
            loop {
                if end + entsize > data.len() {
                    end = data.len();
                    break;
                }
                let z = data[end..end + entsize].iter().all(|&b| b == 0);
                end += entsize;
                if z {
                    break;
                }
            }
            f(pos, end);
            pos = end;
        }
    } else {
        let mut pos = 0;
        while pos < data.len() {
            let end = (pos + entsize).min(data.len());
            f(pos, end);
            pos = end;
        }
    }
}

/// A thread's records, by shard.
struct Bufs {
    shards: Vec<Vec<Rec>>,
}

impl Member {
    /// Where input offset `off` went, relative to the merged section.
    #[inline]
    pub fn lookup(&self, off: u64) -> Option<u64> {
        let mut i = *self.jump.get((off >> JUMP_SHIFT) as usize)? as usize;
        let p = &self.pieces;
        while i + 1 < p.len() && p[i + 1][0] as u64 <= off {
            i += 1;
        }
        let [start, out] = *p.get(i)?;
        if start as u64 > off {
            return None;
        }
        Some(out as u64 + (off - start as u64))
    }
}

/// Mergeable sections that become one merged section: the key (output name, allocated,
/// strings, entry size) and the members, with their contents (`None` until decompressed).
pub struct Group<'a> {
    pub name: &'a [u8],
    pub alloc: bool,
    pub strings: bool,
    pub entsize: u64,
    pub members: Vec<(u32, u32, u8, Option<&'a [u8]>)>,
}

/// Give compressed members their decompressed contents: `done` is sorted by (object, section).
pub fn fill_inflated<'a>(groups: &mut [Group<'a>], done: &[(u32, u32, Option<&'a [u8]>)]) {
    for g in groups {
        for m in &mut g.members {
            if m.3.is_none()
                && let Ok(k) = done.binary_search_by_key(&(m.0, m.1), |d| (d.0, d.1))
            {
                m.3 = done[k].2;
            }
        }
    }
}

/// Merge one group: split every member, deduplicate by shard, fill in each member's table.
pub fn merge_group<'a>(g: Group<'a>) -> MergedSec<'a> {
    let Group {
        name,
        alloc,
        strings,
        entsize,
        members,
    } = g;
    let nthreads = rayon::current_num_threads().max(1);
    let data_of = |mi: usize| members[mi].3.unwrap_or(&[]);
    let p2align = members.iter().map(|m| m.2).max().unwrap_or(0);
    // Sub-steps of the big ones, with HYPRLNK_PROF.
    let mut mk = (members.len() > 100).then(super::prof::Marks::new);
    // 1. Split.
    // Room for a generous estimate of each buffer's share (pieces average well over 32
    // bytes): growing them would copy them, and capacity that is never touched costs nothing.
    let bytes: u64 = (0..members.len()).map(|mi| data_of(mi).len() as u64).sum();
    let per_buf = (bytes / 32 / nthreads as u64 / SHARDS as u64) as usize;
    let bufs: Vec<Mutex<Bufs>> = (0..nthreads + 1)
        .map(|t| {
            let cap = if t < nthreads { per_buf } else { 0 };
            Mutex::new(Bufs {
                shards: (0..SHARDS).map(|_| Vec::with_capacity(cap)).collect(),
            })
        })
        .collect();
    let mut mems: Vec<Member> = members
        .par_iter()
        .enumerate()
        .map(|(mi, &(oi, si, _, _))| {
            let data = data_of(mi);
            let t = rayon::current_thread_index()
                .unwrap_or(nthreads)
                .min(nthreads);
            let mut b = bufs[t].lock().unwrap();
            let mut offs: Vec<[u32; 2]> = Vec::with_capacity(data.len() / 48 + 1);
            split(data, strings, entsize as usize, |start, end| {
                let h = hash(&data[start..end]);
                let s = shard_of(h);
                let slot = b.shards[s].len();
                // Until step 3: the record's shard and slot.
                assert!(
                    slot < 1 << 24,
                    "more than 2^24 pieces in one shard of one thread"
                );
                b.shards[s].push(Rec {
                    hash: h,
                    member: mi as u32,
                    piece: offs.len() as u32,
                });
                offs.push([start as u32, ((s as u32) << 24) | slot as u32]);
            });
            drop(b);
            let mut jump = Vec::with_capacity((data.len() >> JUMP_SHIFT) + 1);
            let mut p = 0usize;
            for blk in 0..=(data.len() >> JUMP_SHIFT) {
                let at = (blk << JUMP_SHIFT) as u32;
                while p + 1 < offs.len() && offs[p + 1][0] <= at {
                    p += 1;
                }
                jump.push(p as u32);
            }
            Member {
                obj: oi,
                sec: si,
                pieces: offs,
                jump,
                thread: t as u32,
            }
        })
        .collect();
    let bufs: Vec<Bufs> = bufs.into_iter().map(|b| b.into_inner().unwrap()).collect();
    if let Some(m) = &mut mk {
        m.mark("merge: split");
    }

    // 2. Dedupe, shard by shard.
    // Each piece keeps the alignment its section had (code may rely on it: `ldm` of a string
    // in a `.str1.4` section).
    let piece_align = (entsize.max(1)).max(1u64 << p2align);
    let mems_ref = &mems;
    type Shard<'s> = (Vec<(&'s [u8], u32)>, u64, Vec<Vec<u32>>);
    let shards: Vec<Shard<'a>> = (0..SHARDS)
        .into_par_iter()
        .map(|s| {
            // (hash, first occurrence (member, piece)) per unique piece.
            let mut table: HashTable<u32> = HashTable::new();
            let mut uniq: Vec<([u64; 2], u64)> = Vec::new();
            let mut which: Vec<Vec<u32>> = Vec::with_capacity(bufs.len());
            for b in &bufs {
                let recs = &b.shards[s];
                let mut w = Vec::with_capacity(recs.len());
                for r in recs {
                    let first = ((r.member as u64) << 32) | r.piece as u64;
                    let u = match table.find(r.hash[1], |&u| uniq[u as usize].0 == r.hash) {
                        Some(&u) => {
                            let e = &mut uniq[u as usize];
                            e.1 = e.1.min(first);
                            u
                        }
                        None => {
                            let u = uniq.len() as u32;
                            uniq.push((r.hash, first));
                            table.insert_unique(r.hash[1], u, |&x| uniq[x as usize].0[1]);
                            u
                        }
                    };
                    w.push(u);
                }
                which.push(w);
            }
            drop(table);
            // Output order: first occurrence.
            let mut order: Vec<u32> = (0..uniq.len() as u32).collect();
            order.sort_unstable_by_key(|&u| uniq[u as usize].1);
            let mut off_of = vec![0u32; uniq.len()];
            let mut out = Vec::with_capacity(uniq.len());
            let mut cur = 0u64;
            for &u in &order {
                let first = uniq[u as usize].1;
                cur = align_up(cur, piece_align);
                off_of[u as usize] = cur as u32;
                let mi = (first >> 32) as usize;
                let m = &mems_ref[mi];
                let p = first as u32 as usize;
                let data = data_of(mi);
                let start = m.pieces[p][0] as usize;
                let end = m.pieces.get(p + 1).map_or(data.len(), |n| n[0] as usize);
                out.push((&data[start..end], cur as u32));
                cur += (end - start) as u64;
            }
            for w in &mut which {
                for u in w.iter_mut() {
                    *u = off_of[*u as usize];
                }
            }
            (out, cur, which)
        })
        .collect();
    let mut base = Vec::with_capacity(SHARDS + 1);
    let mut off = 0u64;
    let shard_align = (1u64 << p2align).max(piece_align);
    for (_, size, _) in &shards {
        off = align_up(off, shard_align);
        base.push(off);
        off += size;
    }
    base.push(off);
    if let Some(m) = &mut mk {
        m.mark("merge: dedupe");
    }

    // 3. Fill in each section's table, in order.
    drop(bufs);
    let base32: Vec<u32> = base.iter().map(|&b| b as u32).collect();
    mems.par_iter_mut().for_each(|m| {
        let t = m.thread as usize;
        for p in &mut m.pieces {
            let (s, slot) = ((p[1] >> 24) as usize, (p[1] & 0xff_ffff) as usize);
            p[1] = base32[s] + shards[s].2[t][slot];
        }
    });
    if let Some(m) = &mut mk {
        m.mark("merge: fill in");
    }
    let mut uniq = Vec::with_capacity(SHARDS);
    for (u, _, _) in shards {
        uniq.push(u);
    }
    MergedSec {
        name,
        flags: if alloc { SHF_ALLOC } else { 0 }
            | if strings { SHF_STRINGS } else { 0 }
            | SHF_MERGE,
        entsize,
        p2align,
        members: mems,
        uniq,
        shard_base: base,
        size: off,
        addr: 0,
        file_off: 0,
        out: NONE,
    }
}

impl<'a, T: Target> Ctx<'a, T> {
    /// The groups of mergeable sections to merge, in first-seen order: the allocated ones
    /// (after garbage collection), or the others, which only depend on which files are linked.
    pub fn merge_groups(&self, alloc: bool) -> Vec<Group<'a>> {
        let keep = self.cfg.z_keep_text_section_prefix;
        let strip = self.cfg.strip;
        // Alignment is part of the key: every piece keeps its section's alignment.
        type Key<'k> = (&'k [u8], bool, u64, u8);
        type Found<'k> = (Key<'k>, (u32, u32, u8, Option<&'k [u8]>));
        // Each object's members on all threads, then grouped in object order.
        let found: Vec<Vec<Found<'a>>> = self
            .objs
            .par_iter()
            .enumerate()
            .map(|(oi, o)| {
                let mut v = Vec::new();
                if !o.alive.load(Ordering::Relaxed) || !o.has_merge {
                    return v;
                }
                for (si, s) in o.secs.iter().enumerate() {
                    if s.kind != SecKind::Merge
                        || s.has(SHF_ALLOC) != alloc
                        || alloc && !s.is_live()
                    {
                        continue;
                    }
                    let h = o.shdr::<T>(si as u32);
                    let n = cstr(o.shstrtab, h.name as usize);
                    if !alloc
                        && strip != super::config::Strip::None
                        && (n.starts_with(b".debug") || strip == super::config::Strip::All)
                    {
                        continue;
                    }
                    let key = (
                        output_name(n, keep),
                        h.flags & SHF_STRINGS != 0,
                        h.entsize,
                        s.p2align,
                    );
                    let data = (s.fl & FL_COMPRESSED == 0).then(|| o.sec_data(si as u32));
                    v.push((key, (oi as u32, si as u32, s.p2align, data)));
                }
                v
            })
            .collect();
        let mut keys: Vec<Key<'a>> = Vec::new();
        let mut groups: Vec<Group<'a>> = Vec::new();
        for (key, member) in found.into_iter().flatten() {
            let k = match keys.iter().position(|k| *k == key) {
                Some(k) => k,
                None => {
                    keys.push(key);
                    groups.push(Group {
                        name: key.0,
                        alloc,
                        strings: key.1,
                        entsize: key.2,
                        members: Vec::new(),
                    });
                    keys.len() - 1
                }
            };
            groups[k].members.push(member);
        }
        groups
    }

    /// Merge the allocated groups, then take in `others` (merged beside garbage collection):
    /// each member section learns its merged section and index (in `aux` and `nrel`).
    pub fn merge(&mut self, timer: &mut Timer, others: Vec<MergedSec<'a>>) {
        let u0 = super::prof::usage();
        let mut merged: Vec<MergedSec<'a>> = others;
        merged.extend(self.merge_groups(true).into_iter().map(merge_group));
        for (k, m) in merged.iter().enumerate() {
            for (mi, mb) in m.members.iter().enumerate() {
                let s = &mut self.objs[mb.obj as usize].secs[mb.sec as usize];
                s.aux = k as u32;
                s.nrel = mi as u32;
            }
        }
        // The linker's own line in `.comment`, after the compilers' (as GNU ld, lld and mold do).
        // At the end of the last shard, so no other piece moves.
        if let Some(m) = merged.iter_mut().find(|m| {
            m.name == b".comment"
                && m.flags & SHF_ALLOC == 0
                && m.flags & SHF_STRINGS != 0
                && m.entsize == 1
        }) {
            const ID: &[u8] =
                concat!("Linker: hyprlnk ", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
            if !m.uniq.iter().flatten().any(|&(b, _)| b == ID) {
                let last = m.uniq.len() - 1;
                let at = align_up(m.size, 1 << m.p2align);
                m.uniq[last].push((ID, (at - m.shard_base[last]) as u32));
                m.size = at + ID.len() as u64;
                m.shard_base[last + 1] = m.size;
            }
        }
        if timer.enabled() {
            for m in &merged {
                let pieces: usize = m.members.iter().map(|x| x.pieces.len()).sum();
                let unique: usize = m.uniq.iter().map(Vec::len).sum();
                let input: u64 = m
                    .members
                    .iter()
                    .map(|x| self.objs[x.obj as usize].secs[x.sec as usize].size as u64)
                    .sum();
                timer.detail(format!(
                    "{}: {} sections, {} pieces ({} bytes), {} unique ({} bytes)",
                    String::from_utf8_lossy(m.name),
                    m.members.len(),
                    pieces,
                    input,
                    unique,
                    m.size
                ));
            }
        }
        self.merged = merged;
        super::prof::report_usage("merge", u0);
        timer.phase("merge strings and constants");
    }

    /// The output address of offset `off` of mergeable section `si` of `o`.
    #[inline]
    pub fn merged_addr(&self, o: &Object<'a>, si: u32, off: u64) -> Option<u64> {
        let (m, mb) = self.merged_member(o, si)?;
        Some(m.addr + mb.lookup(off)?)
    }

    /// The merged section and member record of mergeable section `si` of `o`.
    #[inline]
    pub fn merged_member(&self, o: &Object<'a>, si: u32) -> Option<(&MergedSec<'a>, &Member)> {
        let s = &o.secs[si as usize];
        let m = self.merged.get(s.aux as usize)?;
        Some((m, m.members.get(s.nrel as usize)?))
    }

    pub fn write_merged(&self, out: OutBuf) {
        self.merged.par_iter().enumerate().for_each(|(mi, m)| {
            m.uniq.par_iter().enumerate().for_each(|(s, pieces)| {
                let base = m.file_off + m.shard_base[s];
                for &(bytes, off) in pieces {
                    out.slice(base + off as u64, bytes.len() as u64)
                        .copy_from_slice(bytes);
                }
                if self.bid.on {
                    let len = m.shard_base[s + 1] - m.shard_base[s];
                    let slot = self.bid.merged_base[mi] as usize + s;
                    self.bid.put(slot, out.slice(base, len), base);
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(data: &[u8], strings: bool, entsize: usize) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        split(data, strings, entsize, |a, b| v.push((a, b)));
        v
    }

    #[test]
    fn word_at_a_time_split_matches_a_byte_by_byte_one() {
        // Zeros next to 0x01 and 0x80..0xff bytes, where borrow-based zero tests go wrong.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let data: Vec<u8> = (0..4099)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                [0, 0, 1, 0x80, 0xff, b'a'][(x % 6) as usize]
            })
            .collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 4098, 4099] {
            let d = &data[..len];
            let mut naive = Vec::new();
            let mut start = 0;
            for (j, &b) in d.iter().enumerate() {
                if b == 0 {
                    naive.push((start, j + 1));
                    start = j + 1;
                }
            }
            if start < d.len() {
                naive.push((start, d.len()));
            }
            assert_eq!(pieces(d, true, 1), naive, "{len}");
        }
    }

    #[test]
    fn splits_strings_and_entries() {
        assert_eq!(
            pieces(b"ab\0c\0ab\0", true, 1),
            vec![(0, 3), (3, 5), (5, 8)]
        );
        assert_eq!(hash(b"ab\0"), hash(&b"ab\0c\0ab\0"[5..8]));
        assert_eq!(pieces(b"abc", true, 1), vec![(0, 3)]);
        assert_eq!(
            pieces(&[1, 0, 0, 0, 1, 0, 0, 0], false, 4),
            vec![(0, 4), (4, 8)]
        );
        assert_eq!(
            pieces(&[b'a', 0, 0, 0, b'b', 0, b'c', 0, 0, 0], true, 2),
            vec![(0, 4), (4, 10)]
        );
    }
}
