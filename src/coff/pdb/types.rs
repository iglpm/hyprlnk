//! Type merging into the TPI/IPI streams. Records are hashed with nested type indices replaced by
//! their targets' hashes; the earliest copy of each type wins, so output is independent of thread timing.

use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

pub const LF_FIELDLIST: u16 = 0x1203;
pub const LF_TYPESERVER2: u16 = 0x1515;
pub const LF_PRECOMP: u16 = 0x1509;
pub const LF_FUNC_ID: u16 = 0x1601;
pub const LF_MFUNC_ID: u16 = 0x1602;
pub const LF_UDT_SRC_LINE: u16 = 0x1606;
pub const LF_UDT_MOD_SRC_LINE: u16 = 0x1607;
const LF_NUMERIC: u16 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TiRef {
    pub offset: u32,
    pub count: u32,
    pub id: bool,
}

const fn t(offset: u32, count: u32) -> TiRef {
    TiRef {
        offset,
        count,
        id: false,
    }
}
const fn i(offset: u32, count: u32) -> TiRef {
    TiRef {
        offset,
        count,
        id: true,
    }
}

pub fn is_id_kind(kind: u16) -> bool {
    (0x1601..=0x1607).contains(&kind)
}

fn u16at(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

pub fn numeric_len(d: &[u8]) -> usize {
    let n = u16at(d, 0);
    if n < LF_NUMERIC {
        return 2;
    }
    2 + match n {
        0x8000 => 1,                   // LF_CHAR
        0x8001 | 0x8002 | 0x801c => 2, // LF_SHORT, LF_USHORT, LF_REAL16
        0x8003..=0x8005 => 4,          // LF_LONG, LF_ULONG, LF_REAL32
        0x8006 | 0x8009 | 0x800a | 0x801a => 8,
        0x8007 => 10,
        0x8008 | 0x8017 | 0x8018 | 0x8019 => 16,
        0x8010 => 2 + u16at(d, 2) as usize, // LF_VARSTRING
        0x801b => d[2..].iter().position(|&b| b == 0).map_or(0, |p| p + 1),
        _ => 0,
    }
}

fn cstr_len(d: &[u8]) -> usize {
    d.iter().position(|&b| b == 0).map_or(d.len(), |p| p + 1)
}

fn is_intro_virtual(attrs: u16) -> bool {
    let kind = (attrs >> 2) & 7;
    kind == 4 || kind == 6
}

pub fn type_refs(kind: u16, c: &[u8], out: &mut Vec<TiRef>) {
    match kind {
        0x1601 => out.extend([i(0, 1), t(4, 1)]),      // LF_FUNC_ID
        0x1602 => out.push(t(0, 2)),                   // LF_MFUNC_ID
        0x1605 => out.push(i(0, 1)),                   // LF_STRING_ID
        0x1604 => out.push(i(4, u32at(c, 0))),         // LF_SUBSTR_LIST
        0x1603 => out.push(i(2, u16at(c, 0) as u32)),  // LF_BUILDINFO
        0x1606 => out.extend([t(0, 1), i(4, 1)]),      // LF_UDT_SRC_LINE
        0x1607 => out.push(t(0, 1)),                   // LF_UDT_MOD_SRC_LINE
        0x1001 => out.push(t(0, 1)),                   // LF_MODIFIER
        0x1008 => out.extend([t(0, 1), t(8, 1)]),      // LF_PROCEDURE
        0x1009 => out.extend([t(0, 3), t(16, 1)]),     // LF_MFUNCTION
        0x1201 => out.push(t(4, u32at(c, 0))),         // LF_ARGLIST
        0x1503 => out.push(t(0, 2)),                   // LF_ARRAY
        0x1504 | 0x1505 | 0x1519 => out.push(t(4, 3)), // LF_CLASS/STRUCTURE/INTERFACE
        0x1506 => out.push(t(4, 1)),                   // LF_UNION
        0x1507 => out.push(t(4, 2)),                   // LF_ENUM
        0x1205 => out.push(t(0, 1)),                   // LF_BITFIELD
        0x151d => out.push(t(0, 2)),                   // LF_VFTABLE
        0x1002 => {
            // LF_POINTER: pointee, and the class of a pointer to member.
            out.push(t(0, 1));
            let mode = (u32at(c, 4) >> 5) & 7;
            if mode == 2 || mode == 3 {
                out.push(t(8, 1));
            }
        }
        0x1206 => {
            // LF_METHODLIST
            let mut off = 0usize;
            while off + 8 <= c.len() {
                out.push(t(off as u32 + 4, 1));
                off += if is_intro_virtual(u16at(c, off)) {
                    12
                } else {
                    8
                };
            }
        }
        LF_FIELDLIST => field_list_refs(c, out),
        _ => {}
    }
}

fn field_list_refs(c: &[u8], out: &mut Vec<TiRef>) {
    let mut off = 0usize;
    while off + 2 <= c.len() {
        let d = &c[off..];
        let o = off as u32;
        let len = match u16at(d, 0) {
            0x1400 => {
                // LF_BCLASS
                out.push(t(o + 4, 1));
                8 + numeric_len(&d[8.min(d.len())..])
            }
            0x1401 | 0x1402 => {
                // LF_VBCLASS, LF_IVBCLASS
                out.push(t(o + 4, 2));
                let mut n = 12;
                n += numeric_len(&d[n.min(d.len())..]);
                n += numeric_len(&d[n.min(d.len())..]);
                n
            }
            0x1502 => {
                // LF_ENUMERATE
                let n = 4 + numeric_len(&d[4.min(d.len())..]);
                n + cstr_len(&d[n.min(d.len())..])
            }
            0x150d => {
                // LF_MEMBER
                out.push(t(o + 4, 1));
                let n = 8 + numeric_len(&d[8.min(d.len())..]);
                n + cstr_len(&d[n.min(d.len())..])
            }
            0x150e..=0x1510 => {
                // LF_METHOD, LF_NESTTYPE, LF_STMEMBER
                out.push(t(o + 4, 1));
                8 + cstr_len(&d[8.min(d.len())..])
            }
            0x1511 => {
                // LF_ONEMETHOD
                out.push(t(o + 4, 1));
                let n = if is_intro_virtual(u16at(d, 2)) { 12 } else { 8 };
                n + cstr_len(&d[n.min(d.len())..])
            }
            0x1409 | 0x1404 => {
                // LF_VFUNCTAB, LF_INDEX
                out.push(t(o + 4, 1));
                8
            }
            _ => return,
        };
        off += len;
        if let Some(&p) = c.get(off)
            && p >= 0xF0
        {
            off += (p & 0x0F) as usize;
        }
    }
}

pub struct ObjTypes<'a> {
    pub data: &'a [u8],
    pub records: Vec<(u32, u32)>,
    pub hashes: Vec<u128>,
    pub external: bool,
}

pub fn hash_object(data: &[u8]) -> ObjTypes<'_> {
    let mut t = ObjTypes {
        data,
        records: Vec::new(),
        hashes: Vec::new(),
        external: false,
    };
    if data.len() < 4 || u32at(data, 0) != 4 {
        return t;
    }
    let mut off = 4usize;
    while off + 4 <= data.len() {
        let len = u16at(data, off) as usize + 2;
        if len < 4 || off + len > data.len() {
            break;
        }
        t.records.push((off as u32, len as u32));
        off += len;
    }
    if let Some(&(o, _)) = t.records.first() {
        let kind = u16at(data, o as usize + 2);
        if kind == LF_TYPESERVER2 || kind == LF_PRECOMP {
            t.external = true;
            t.records.clear();
            return t;
        }
    }
    let mut refs = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    t.hashes.reserve(t.records.len());
    for (idx, &(o, len)) in t.records.iter().enumerate() {
        let rec = &data[o as usize..(o + len) as usize];
        let kind = u16at(rec, 2);
        let content = &rec[4..];
        refs.clear();
        type_refs(kind, content, &mut refs);
        if refs.is_empty() {
            t.hashes.push(xxhash_rust::xxh3::xxh3_128(&rec[2..]));
            continue;
        }
        buf.clear();
        buf.extend_from_slice(&rec[2..4]);
        let mut pos = 0usize;
        for r in &refs {
            let start = (r.offset as usize).min(content.len());
            if pos < start {
                buf.extend_from_slice(&content[pos..start]);
            }
            for k in 0..r.count as usize {
                let ti = u32at(content, start + 4 * k);
                let local = ti.wrapping_sub(0x1000);
                if ti < 0x1000 {
                    buf.extend_from_slice(&ti.to_le_bytes());
                } else if local < idx as u32 {
                    buf.extend_from_slice(&t.hashes[local as usize].to_le_bytes());
                } else {
                    buf.extend_from_slice(b"fwd");
                    buf.extend_from_slice(&ti.to_le_bytes());
                }
            }
            pos = (start + 4 * r.count as usize).min(content.len());
        }
        buf.extend_from_slice(&content[pos.min(content.len())..]);
        t.hashes.push(xxhash_rust::xxh3::xxh3_128(&buf));
    }
    t
}

pub const STREAM_HEADER: usize = 56;

pub struct Merged {
    pub tpi: Vec<u8>,
    pub ipi: Vec<u8>,
    pub tpi_offsets: Vec<u32>,
    pub ipi_offsets: Vec<u32>,
    pub maps: Vec<Vec<u32>>,
}

impl Merged {
    #[inline]
    pub fn map(&self, obj: usize, ti: u32) -> u32 {
        if ti < 0x1000 {
            return ti;
        }
        self.maps[obj]
            .get((ti - 0x1000) as usize)
            .copied()
            .unwrap_or(0)
    }

    pub fn ipi_record(&self, ti: u32) -> Option<&[u8]> {
        let i = ti.checked_sub(0x1000)? as usize;
        let records = &self.ipi[STREAM_HEADER..];
        let start = *self.ipi_offsets.get(i)? as usize;
        let end = self
            .ipi_offsets
            .get(i + 1)
            .map_or(records.len(), |&e| e as usize);
        Some(&records[start..end])
    }
}

pub fn merge(objs: &[Option<ObjTypes>]) -> Merged {
    let total: usize = objs.iter().flatten().map(|o| o.records.len()).sum();
    let cap = (total * 2).next_power_of_two().max(16);
    let mask = cap as u64 - 1;
    let cells: Vec<AtomicU64> = (0..cap).map(|_| AtomicU64::new(0)).collect();
    let hash_of = |cell: u64| -> u128 {
        let o = (cell >> 32) as usize - 1;
        objs[o].as_ref().unwrap().hashes[(cell & 0xFFFF_FFFF) as usize]
    };
    let loc = |oi: usize, ri: usize| ((oi as u64 + 1) << 32) | ri as u64;

    objs.par_iter().enumerate().for_each(|(oi, o)| {
        let Some(o) = o else { return };
        for (ri, &h) in o.hashes.iter().enumerate() {
            let me = loc(oi, ri);
            let mut slot = (h as u64) & mask;
            loop {
                let cell = &cells[slot as usize];
                let mut cur = cell.load(Ordering::Acquire);
                if cur == 0 {
                    match cell.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => break,
                        Err(actual) => cur = actual,
                    }
                }
                if hash_of(cur) == h {
                    while me < cur {
                        match cell.compare_exchange(cur, me, Ordering::AcqRel, Ordering::Acquire) {
                            Ok(_) => break,
                            Err(actual) => cur = actual,
                        }
                    }
                    break;
                }
                slot = (slot + 1) & mask;
            }
        }
    });

    let winners: Vec<Vec<u64>> = objs
        .par_iter()
        .map(|o| {
            let Some(o) = o else { return Vec::new() };
            o.hashes
                .iter()
                .map(|&h| {
                    let mut slot = (h as u64) & mask;
                    loop {
                        let cur = cells[slot as usize].load(Ordering::Relaxed);
                        if hash_of(cur) == h {
                            return cur;
                        }
                        slot = (slot + 1) & mask;
                    }
                })
                .collect()
        })
        .collect();
    drop(cells);
    let kind_of = |oi: usize, ri: usize| -> u16 {
        let o = objs[oi].as_ref().unwrap();
        u16at(o.data, o.records[ri].0 as usize + 2)
    };
    let counts: Vec<[u64; 4]> = (0..objs.len())
        .into_par_iter()
        .map(|oi| {
            let mut c = [0u64; 4];
            if let Some(o) = &objs[oi] {
                for (ri, &w) in winners[oi].iter().enumerate() {
                    if w == loc(oi, ri) {
                        let id = is_id_kind(kind_of(oi, ri)) as usize;
                        c[id] += 1;
                        c[2 + id] += (o.records[ri].1 as u64).next_multiple_of(4);
                    }
                }
            }
            c
        })
        .collect();
    let mut bases = Vec::with_capacity(objs.len());
    let mut acc = [0u64; 4];
    for c in &counts {
        bases.push(acc);
        for k in 0..4 {
            acc[k] += c[k];
        }
    }
    let (n_tpi, n_ipi, tpi_bytes, ipi_bytes) = (acc[0], acc[1], acc[2], acc[3]);

    let own: Vec<Vec<u32>> = (0..objs.len())
        .into_par_iter()
        .map(|oi| {
            let Some(o) = &objs[oi] else {
                return Vec::new();
            };
            let mut next = [bases[oi][0] as u32 + 0x1000, bases[oi][1] as u32 + 0x1000];
            (0..o.records.len())
                .map(|ri| {
                    if winners[oi][ri] == loc(oi, ri) {
                        let id = is_id_kind(kind_of(oi, ri)) as usize;
                        next[id] += 1;
                        next[id] - 1
                    } else {
                        0
                    }
                })
                .collect()
        })
        .collect();
    let maps: Vec<Vec<u32>> = winners
        .par_iter()
        .map(|ws| {
            ws.iter()
                .map(|&w| own[(w >> 32) as usize - 1][(w & 0xFFFF_FFFF) as usize])
                .collect()
        })
        .collect();

    let mut tpi = vec![0u8; STREAM_HEADER + tpi_bytes as usize];
    let mut ipi = vec![0u8; STREAM_HEADER + ipi_bytes as usize];
    let mut tpi_offsets = vec![0u32; n_tpi as usize];
    let mut ipi_offsets = vec![0u32; n_ipi as usize];
    {
        let mut tpi_rest: &mut [u8] = &mut tpi[STREAM_HEADER..];
        let mut ipi_rest: &mut [u8] = &mut ipi[STREAM_HEADER..];
        let mut tpo_rest: &mut [u32] = &mut tpi_offsets;
        let mut ipo_rest: &mut [u32] = &mut ipi_offsets;
        let mut pieces = Vec::with_capacity(objs.len());
        for (oi, c) in counts.iter().enumerate() {
            let (a, r) = std::mem::take(&mut tpi_rest).split_at_mut(c[2] as usize);
            tpi_rest = r;
            let (b, r) = std::mem::take(&mut ipi_rest).split_at_mut(c[3] as usize);
            ipi_rest = r;
            let (to, r) = std::mem::take(&mut tpo_rest).split_at_mut(c[0] as usize);
            tpo_rest = r;
            let (io, r) = std::mem::take(&mut ipo_rest).split_at_mut(c[1] as usize);
            ipo_rest = r;
            pieces.push((oi, a, b, to, io));
        }
        pieces
            .into_par_iter()
            .for_each(|(oi, tdst, idst, toffs, ioffs)| {
                let Some(o) = &objs[oi] else { return };
                let map = &maps[oi];
                let mut pos = [0usize; 2];
                let mut nth = [0usize; 2];
                let base_bytes = [bases[oi][2], bases[oi][3]];
                let mut refs = Vec::new();
                for (ri, &(off, len)) in o.records.iter().enumerate() {
                    if winners[oi][ri] != loc(oi, ri) {
                        continue;
                    }
                    let rec = &o.data[off as usize..(off + len) as usize];
                    let kind = u16at(rec, 2);
                    let id = is_id_kind(kind) as usize;
                    let size = (len as usize).next_multiple_of(4);
                    let dst = if id == 1 {
                        &mut idst[pos[1]..pos[1] + size]
                    } else {
                        &mut tdst[pos[0]..pos[0] + size]
                    };
                    dst[..rec.len()].copy_from_slice(rec);
                    for (k, b) in dst[rec.len()..].iter_mut().enumerate() {
                        *b = 0xF0 | (size - rec.len() - k) as u8;
                    }
                    dst[..2].copy_from_slice(&((size - 2) as u16).to_le_bytes());
                    refs.clear();
                    type_refs(kind, &rec[4..], &mut refs);
                    for r in &refs {
                        for k in 0..r.count as usize {
                            let at = 4 + r.offset as usize + 4 * k;
                            if at + 4 > rec.len() {
                                break;
                            }
                            let ti = u32at(dst, at);
                            let new = if ti < 0x1000 {
                                ti
                            } else {
                                map.get((ti - 0x1000) as usize).copied().unwrap_or(0)
                            };
                            dst[at..at + 4].copy_from_slice(&new.to_le_bytes());
                        }
                    }
                    let offs: &mut [u32] = if id == 1 { ioffs } else { toffs };
                    offs[nth[id]] = (base_bytes[id] as usize + pos[id]) as u32;
                    nth[id] += 1;
                    pos[id] += size;
                }
            });
    }
    Merged {
        tpi,
        ipi,
        tpi_offsets,
        ipi_offsets,
        maps,
    }
}

type TagNames<'a> = (u16, &'a [u8], Option<&'a [u8]>);

pub fn record_hash(rec: &[u8]) -> u32 {
    let kind = u16at(rec, 2);
    let c = &rec[4..];
    let name_at = |fixed: usize| -> Option<TagNames> {
        let opts = u16at(c, 2);
        let n = fixed + numeric_len(c.get(fixed..)?);
        let name_end = n + c.get(n..)?.iter().position(|&b| b == 0)?;
        let name = &c[n..name_end];
        let unique = if opts & 0x200 != 0 {
            let u = name_end + 1;
            let ue = u + c.get(u..)?.iter().position(|&b| b == 0)?;
            Some(&c[u..ue])
        } else {
            None
        };
        Some((opts, name, unique))
    };
    let tag = match kind {
        0x1504 | 0x1505 | 0x1519 => name_at(16),
        0x1506 => name_at(8),
        0x1507 => {
            let opts = u16at(c, 2);
            let n = 12usize;
            c.get(n..).and_then(|rest| {
                let e = n + rest.iter().position(|&b| b == 0)?;
                let unique = if opts & 0x200 != 0 {
                    let u = e + 1;
                    let ue = u + c.get(u..)?.iter().position(|&b| b == 0)?;
                    Some(&c[u..ue])
                } else {
                    None
                };
                Some((opts, &c[n..e], unique))
            })
        }
        LF_UDT_SRC_LINE | LF_UDT_MOD_SRC_LINE => {
            return super::hash::hash_string_v1(&c[..4.min(c.len())]);
        }
        _ => None,
    };
    if let Some((opts, name, unique)) = tag {
        let forward = opts & 0x80 != 0;
        let scoped = opts & 0x100 != 0;
        let anonymous = unique.is_some() && is_anonymous(name);
        if !forward && !scoped && !anonymous {
            return super::hash::hash_string_v1(name);
        }
        if !forward
            && !anonymous
            && let Some(u) = unique
        {
            return super::hash::hash_string_v1(u);
        }
    }
    super::hash::hash_buffer_v8(rec)
}

fn is_anonymous(name: &[u8]) -> bool {
    name == b"<unnamed-tag>"
        || name == b"__unnamed"
        || name.ends_with(b"::<unnamed-tag>")
        || name.ends_with(b"::__unnamed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: u16, content: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        let mut c = content.to_vec();
        while !(c.len() + 4).is_multiple_of(4) {
            c.push(0xF0 | (4 - (c.len() + 4) % 4) as u8);
        }
        r.extend_from_slice(&((c.len() + 2) as u16).to_le_bytes());
        r.extend_from_slice(&kind.to_le_bytes());
        r.extend_from_slice(&c);
        r
    }

    fn debug_t(records: &[Vec<u8>]) -> Vec<u8> {
        let mut d = 4u32.to_le_bytes().to_vec();
        for r in records {
            d.extend_from_slice(r);
        }
        d
    }

    fn pointer(ti: u32) -> Vec<u8> {
        let mut c = ti.to_le_bytes().to_vec();
        c.extend_from_slice(&0x0001_000Cu32.to_le_bytes());
        rec(0x1002, &c)
    }

    fn string_id(s: &str) -> Vec<u8> {
        let mut c = 0u32.to_le_bytes().to_vec();
        c.extend_from_slice(s.as_bytes());
        c.push(0);
        rec(0x1605, &c)
    }

    #[test]
    fn equal_types_merge_across_objects() {
        let a = debug_t(&[pointer(0x74), pointer(0x1000), string_id("a")]);
        let b = debug_t(&[string_id("b"), pointer(0x74), pointer(0x1001)]);
        let objs = vec![Some(hash_object(&a)), None, Some(hash_object(&b))];
        assert_eq!(
            objs[0].as_ref().unwrap().hashes[1],
            objs[2].as_ref().unwrap().hashes[2]
        );
        let m = merge(&objs);
        assert_eq!(m.tpi_offsets.len(), 2);
        assert_eq!(m.ipi_offsets.len(), 2);
        assert_eq!(m.maps[0], vec![0x1000, 0x1001, 0x1000]);
        assert_eq!(m.maps[2], vec![0x1001, 0x1000, 0x1001]);
        let second = &m.tpi[STREAM_HEADER + m.tpi_offsets[1] as usize..];
        assert_eq!(u32at(second, 4), 0x1000);
        assert_eq!(m.map(2, 0x74), 0x74);
    }

    #[test]
    fn field_lists_and_type_servers() {
        let mut c = Vec::new();
        c.extend_from_slice(&0x150du16.to_le_bytes());
        c.extend_from_slice(&3u16.to_le_bytes());
        c.extend_from_slice(&0x1000u32.to_le_bytes());
        c.extend_from_slice(&8u16.to_le_bytes());
        c.extend_from_slice(b"x\0");
        c.extend_from_slice(&[0xF2, 0xF1]);
        c.extend_from_slice(&0x1502u16.to_le_bytes());
        c.extend_from_slice(&3u16.to_le_bytes());
        c.extend_from_slice(&5u16.to_le_bytes());
        c.extend_from_slice(b"E\0");
        let mut refs = Vec::new();
        type_refs(LF_FIELDLIST, &c, &mut refs);
        assert_eq!(refs, vec![t(4, 1)]);
        let ts = debug_t(&[rec(LF_TYPESERVER2, &[0; 24])]);
        assert!(hash_object(&ts).external);
    }

    #[test]
    fn udt_hashes_use_names() {
        let mut c = Vec::new();
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(&[0; 12]);
        c.extend_from_slice(&4u16.to_le_bytes());
        c.extend_from_slice(b"Foo\0");
        let r = rec(0x1505, &c);
        assert_eq!(record_hash(&r), super::super::hash::hash_string_v1(b"Foo"));
    }
}
