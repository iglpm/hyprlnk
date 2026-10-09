//! Between marking and layout: slots for stubs, GOT and TLV pointers, deduplicated literals,
//! common symbols and dylib ordinals.

use std::sync::atomic::Ordering::Relaxed;

use rayon::prelude::*;

use super::object::*;
use super::resolve::Linker;
use super::symtab::{
    Def, LIVE, NEEDS_AUTH_GOT, NEEDS_GOT, NEEDS_STUB, NEEDS_TLVP, SymId, Synthetic,
};
use super::*;
use crate::bail;
use crate::diag::{self, Result, Timer};

impl Linker<'_> {
    pub fn scan(&mut self, timer: &mut Timer) -> Result<()> {
        if !self.text_relocs.is_empty() {
            let mut msgs = std::mem::take(&mut self.text_relocs);
            msgs.sort();
            msgs.dedup();
            for m in msgs.iter().take(10) {
                diag::error(m);
            }
            bail!(
                "{} absolute pointer(s) in read-only sections (text relocations aren't allowed in position-independent images)",
                msgs.len()
            );
        }
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            let f = s.flags.load(Relaxed);
            if f & (NEEDS_GOT | NEEDS_STUB | NEEDS_TLVP | NEEDS_AUTH_GOT) == 0 {
                continue;
            }
            if f & NEEDS_AUTH_GOT != 0 {
                let i = self.auth_got.len() as u32;
                self.auth_got.push(id);
                self.symtab.get_mut(id).auth_got = i;
            }
            let (mut got, mut stub, mut tlvp) = (u32::MAX, u32::MAX, u32::MAX);
            if f & NEEDS_GOT != 0 {
                got = self.got.len() as u32;
                self.got.push(id);
            }
            if f & NEEDS_STUB != 0 {
                stub = self.stubs.len() as u32;
                self.stubs.push(id);
            }
            if f & NEEDS_TLVP != 0 {
                tlvp = self.tlvps.len() as u32;
                self.tlvps.push(id);
            }
            let s = self.symtab.get_mut(id);
            s.got = got;
            s.stub = stub;
            s.tlvp = tlvp;
        }
        self.dedup_literals();
        self.allocate_commons();
        self.assign_ordinals();
        timer.phase("synthetic sections");
        Ok(())
    }

    fn dedup_literals(&mut self) {
        let cfg = &self.cfg;
        let mut keys: Vec<(u64, u32, u32)> = self
            .objs
            .par_iter()
            .enumerate()
            .flat_map_iter(|(oi, obj)| {
                let mut v = Vec::new();
                for s in &obj.sections {
                    if !s.kind.is_literal() {
                        continue;
                    }
                    let (seg, sect) = super::layout::output_name(cfg, s);
                    let mut h0 = xxhash_rust::xxh3::Xxh3::new();
                    h0.update(seg);
                    h0.update(b",");
                    h0.update(sect);
                    let salt = h0.digest();
                    for ai in s.atoms.clone() {
                        let a = &obj.atoms[ai as usize];
                        if !a.is_live() {
                            continue;
                        }
                        let bytes = &s.data[a.off as usize..(a.off + a.size) as usize];
                        let h = xxhash_rust::xxh3::xxh3_64_with_seed(bytes, salt);
                        v.push((h, oi as u32, ai));
                    }
                }
                v
            })
            .collect();
        keys.par_sort_unstable();
        let objs = &self.objs;
        let content = |o: u32, a: u32| -> (&[u8], &[u8], &[u8]) {
            let obj = &objs[o as usize];
            let at = &obj.atoms[a as usize];
            let s = &obj.sections[at.sec as usize];
            let (seg, sect) = super::layout::output_name(cfg, s);
            (
                seg,
                sect,
                &s.data[at.off as usize..(at.off + at.size) as usize],
            )
        };
        // For each literal: the position (in `keys`) of the copy that is written.
        let mut rep_of: Vec<u32> = vec![0; keys.len()];
        let mut i = 0;
        while i < keys.len() {
            let mut j = i + 1;
            while j < keys.len() && keys[j].0 == keys[i].0 {
                j += 1;
            }
            rep_of[i] = i as u32;
            for k in i + 1..j {
                let cur = content(keys[k].1, keys[k].2);
                // Equal hashes almost always mean equal contents; check, and fall back to
                // the first equal one in this run (or this one, on a true collision).
                rep_of[k] = (i..k)
                    .find(|&r| rep_of[r] == r as u32 && content(keys[r].1, keys[r].2) == cur)
                    .unwrap_or(k) as u32;
            }
            i = j;
        }
        let mut lit_of: Vec<u32> = vec![u32::MAX; keys.len()];
        for k in 0..keys.len() {
            let (_, o, a) = keys[k];
            let r = rep_of[k] as usize;
            if r == k {
                let l = self.lits.len() as u32;
                self.lits.push((o, a));
                lit_of[k] = l;
                self.objs[o as usize].atoms[a as usize].aux = l;
            } else {
                let l = lit_of[r];
                let at = &mut self.objs[o as usize].atoms[a as usize];
                at.flags |= ATOM_DUPLICATE;
                at.aux = l;
                let align = at.align;
                let (ro, ra) = self.lits[l as usize];
                let rep = &mut self.objs[ro as usize].atoms[ra as usize];
                rep.align = rep.align.max(align);
            }
        }
    }

    fn allocate_commons(&mut self) {
        let mut off = 0u64;
        let mut max_align = 0u8;
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            let Def::Common { size, align, .. } = s.def else {
                continue;
            };
            if !s.has(LIVE) && self.cfg.dead_strip {
                continue;
            }
            let align = if align == 0 {
                (size.max(1).trailing_zeros() as u8).min(3)
            } else {
                align.min(15)
            };
            off = align_up(off, 1 << align);
            let idx = self.commons.len() as u32;
            self.commons.push((id, off));
            off += size;
            max_align = max_align.max(align);
            self.symtab.get_mut(id).def = Def::Synthetic(Synthetic::Common(idx));
        }
        self.commons_size = off;
        self.commons_align = max_align;
    }

    /// Ordinals for the dylibs that get a load command, in command-line order.
    fn assign_ordinals(&mut self) {
        let mut n = 0;
        for d in &mut self.dylibs {
            let used = d.used.load(Relaxed);
            let keep = if d.explicit {
                used || d.flags.needed || d.flags.reexport || !self.cfg.dead_strip_dylibs
            } else {
                used
            };
            if keep {
                n += 1;
                d.ordinal = n;
            }
        }
    }
}
