//! `/OPT:ICF`: iterated parallel hashing (as in mold) until the partition is stable; equal hashes fold.

use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;

use rayon::prelude::*;

use super::object::NONE;
use super::resolve::Linker;
use super::symtab::Def;
use super::*;

#[derive(Clone, Copy)]
enum Ref {
    Candidate { idx: u32, offset: u32 },
    Fixed(u64),
}

fn read_uleb(d: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *d.get(*pos)?;
        *pos += 1;
        v |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

impl Linker<'_> {
    fn section_label(&self, obj: u32, sec: u32) -> String {
        let o = &self.objs[obj as usize];
        let s = &o.sections[sec as usize];
        match s.comdat {
            Some(c) if c.leader != NONE => {
                String::from_utf8_lossy(o.sym_name(c.leader)).into_owned()
            }
            _ => String::from_utf8_lossy(s.name).into_owned(),
        }
    }

    pub fn fold_identical_sections(&mut self) -> usize {
        let keep_unique: Vec<Vec<bool>> = self
            .objs
            .par_iter()
            .enumerate()
            .map(|(oi, o)| {
                let Some(table) = o.sections.iter().find(|s| s.name == b".llvm_addrsig") else {
                    return vec![true; o.sections.len()];
                };
                let mut keep = vec![false; o.sections.len()];
                let mut pos = 0;
                while let Some(idx) = read_uleb(table.data, &mut pos) {
                    let sec = match o.sym_ids.get(idx as usize) {
                        Some(&id) if id != NONE => match self.symtab.get(id).def {
                            Def::Defined { obj, sec, .. } if obj as usize == oi => Some(sec),
                            _ => None,
                        },
                        _ => o
                            .raw_sym(idx as u32)
                            .filter(|r| r.section > 0)
                            .map(|r| (r.section - 1) as u32),
                    };
                    if let Some(s) = sec
                        && let Some(k) = keep.get_mut(s as usize)
                    {
                        *k = true;
                    }
                }
                keep
            })
            .collect();

        let mut cands: Vec<(u32, u32)> = Vec::new();
        for (oi, o) in self.objs.iter().enumerate() {
            for (si, s) in o.sections.iter().enumerate() {
                if !s.is_live() || !s.is_comdat() || s.chars & IMAGE_SCN_MEM_WRITE != 0 {
                    continue;
                }
                let base = s.name.split(|&b| b == b'$').next().unwrap_or(s.name);
                let code = s.chars & IMAGE_SCN_MEM_EXECUTE != 0;
                if code || base == b".pdata" || base == b".xdata" || !keep_unique[oi][si] {
                    cands.push((oi as u32, si as u32));
                }
            }
        }
        if cands.len() < 2 {
            return 0;
        }
        let index: HashMap<(u32, u32), u32> = cands
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i as u32))
            .collect();

        let target_of = |oi: u32, idx: u32| -> Ref {
            let o = &self.objs[oi as usize];
            let loc = match o.sym_ids.get(idx as usize) {
                Some(&id) if id != NONE => match self.symtab.get(id).def {
                    Def::Defined { obj, sec, value } => Some((obj, sec, value)),
                    _ => return Ref::Fixed(id as u64 | 1 << 63),
                },
                _ => o
                    .raw_sym(idx)
                    .filter(|r| r.section > 0)
                    .map(|r| (oi, (r.section - 1) as u32, r.value)),
            };
            match loc {
                Some((obj, sec, value)) => match index.get(&(obj, sec)) {
                    Some(&c) => Ref::Candidate {
                        idx: c,
                        offset: value,
                    },
                    None => Ref::Fixed(
                        ((obj as u64) << 40) ^ ((sec as u64) << 20) ^ value as u64 ^ (1 << 62),
                    ),
                },
                None => Ref::Fixed(u64::MAX - idx as u64),
            }
        };
        let info: Vec<(Vec<Ref>, Vec<u32>, u128)> = cands
            .par_iter()
            .map(|&(oi, si)| {
                let o = &self.objs[oi as usize];
                let s = &o.sections[si as usize];
                let mut buf = Vec::with_capacity(16 + s.data.len() + s.relocs.len());
                buf.extend_from_slice(&s.chars.to_le_bytes());
                buf.extend_from_slice(&s.size.to_le_bytes());
                buf.extend_from_slice(s.data);
                let mut refs = Vec::with_capacity(s.nrelocs());
                for r in s.relocs.as_chunks::<10>().0 {
                    buf.extend_from_slice(&r[0..4]);
                    buf.extend_from_slice(&r[8..10]);
                    let t = target_of(oi, u32le(r, 4));
                    match t {
                        Ref::Fixed(id) => buf.extend_from_slice(&id.to_le_bytes()),
                        Ref::Candidate { offset, .. } => {
                            buf.extend_from_slice(&offset.to_le_bytes())
                        }
                    }
                    refs.push(t);
                }
                let mut children = Vec::new();
                let mut c = s.assoc_child;
                while c != NONE {
                    match index.get(&(oi, c)) {
                        Some(&ci) => children.push(ci),
                        None => {
                            let child = &o.sections[c as usize];
                            if child.is_live() && !child.debug {
                                buf.extend_from_slice(
                                    &((oi as u64) << 32 | c as u64).to_le_bytes(),
                                );
                            }
                        }
                    }
                    c = o.sections[c as usize].assoc_next;
                }
                (refs, children, xxhash_rust::xxh3::xxh3_128(&buf))
            })
            .collect();

        let mut hashes: Vec<u128> = info.iter().map(|i| i.2).collect();
        let distinct = |h: &[u128]| {
            let mut v = h.to_vec();
            v.par_sort_unstable();
            v.dedup();
            v.len()
        };
        let mut classes = distinct(&hashes);
        for _ in 0..64 {
            let next: Vec<u128> = info
                .par_iter()
                .enumerate()
                .map(|(i, (refs, children, _))| {
                    let mut buf = Vec::with_capacity(16 * (1 + refs.len() + children.len()));
                    buf.extend_from_slice(&hashes[i].to_le_bytes());
                    for r in refs {
                        if let Ref::Candidate { idx, .. } = r {
                            buf.extend_from_slice(&hashes[*idx as usize].to_le_bytes());
                        }
                    }
                    for &c in children {
                        buf.extend_from_slice(&hashes[c as usize].to_le_bytes());
                    }
                    xxhash_rust::xxh3::xxh3_128(&buf)
                })
                .collect();
            let n = distinct(&next);
            hashes = next;
            if n == classes {
                break;
            }
            classes = n;
        }

        // Associated sections (unwind data) are part of their parent's hash and fold with it.
        let mut leader: HashMap<u128, u32> = HashMap::new();
        let mut folds = Vec::new();
        for (i, &h) in hashes.iter().enumerate() {
            let (oi, si) = cands[i];
            if let Some(c) = self.objs[oi as usize].sections[si as usize].comdat
                && c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE
            {
                continue;
            }
            match leader.get(&h) {
                Some(&l) => folds.push((i as u32, l)),
                None => {
                    leader.insert(h, i as u32);
                }
            }
        }
        for &(f, l) in &folds {
            let (fo, fs) = cands[f as usize];
            let (lo, ls) = cands[l as usize];
            if self.cfg.verbose {
                crate::diag::note(format!(
                    "ICF: folded {} into {}",
                    self.section_label(fo, fs),
                    self.section_label(lo, ls)
                ));
            }
            let s = &mut self.objs[fo as usize].sections[fs as usize];
            s.live.store(false, Relaxed);
            s.folded_into = Some((lo, ls));
            let mut c = s.assoc_child;
            while c != NONE {
                let child = &self.objs[fo as usize].sections[c as usize];
                child.live.store(false, Relaxed);
                c = child.assoc_next;
            }
        }
        let mut leader: HashMap<u128, u32> = HashMap::new();
        let mut shared = 0;
        for (i, &h) in hashes.iter().enumerate() {
            let (oi, si) = cands[i];
            let s = &self.objs[oi as usize].sections[si as usize];
            let assoc = s
                .comdat
                .is_some_and(|c| c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE);
            if !assoc || !s.is_live() {
                continue;
            }
            match leader.get(&h) {
                Some(&l) => {
                    let (lo, ls) = cands[l as usize];
                    let s = &mut self.objs[oi as usize].sections[si as usize];
                    s.live.store(false, Relaxed);
                    s.folded_into = Some((lo, ls));
                    shared += 1;
                }
                None => {
                    leader.insert(h, i as u32);
                }
            }
        }
        folds.len() + shared
    }
}
