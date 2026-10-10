//! `--gc-sections`: mark sections reachable from the roots through relocations, in parallel
//! with work stealing. A live section's FDE keeps what it references (its LSDA), and
//! `__start_`/`__stop_` references keep the sections they bound.

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use rayon::prelude::*;

use super::object::{Object, Sec, SecKind};
use super::resolve::{Ctx, FileRef, Synth};
use super::scan::ScanState;
use super::symbols::*;
use super::target::Target;
use super::*;
use crate::diag::{self, Result, Timer};

/// Sections a task marks before handing half of its backlog to another thread.
const SPLIT: usize = 64;

impl<T: Target> Ctx<'_, T> {
    pub fn gc(&mut self, timer: &mut Timer) -> Result<()> {
        self.parse_eh_frames()?;
        timer.phase("parse .eh_frame");
        let mut mk = super::prof::Marks::new();
        let gc = self.cfg.gc_sections;
        // Without GC every section of a loaded file is live; with it, only the always-kept ones
        // start out live, the rest is marked from them.
        let start_stop: HashSet<Vec<u8>> = self
            .internal
            .iter()
            .filter_map(|s| match &s.kind {
                Synth::Start(n) | Synth::Stop(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        let roots: Vec<(u32, u32)> = self
            .objs
            .par_iter()
            .enumerate()
            .flat_map_iter(|(oi, o)| {
                let mut r = Vec::new();
                if !o.alive.load(Ordering::Relaxed) {
                    return r;
                }
                for (si, s) in o.secs.iter().enumerate() {
                    let keep = match s.kind {
                        SecKind::Ignore | SecKind::Discarded => false,
                        SecKind::NonAlloc => true,
                        // Kept with the code they describe.
                        SecKind::EhFrame | SecKind::Exidx => !gc,
                        SecKind::Alloc | SecKind::Merge => {
                            !gc || !s.has(SHF_ALLOC) || self.always_kept(o, s, &start_stop)
                        }
                    };
                    if keep {
                        s.live.store(true, Ordering::Relaxed);
                        if gc && matches!(s.kind, SecKind::Alloc | SecKind::Merge) {
                            r.push((oi as u32, si as u32));
                        }
                    }
                }
                r
            })
            .collect();
        mk.mark("gc: roots");
        if gc {
            let mut sym_roots: Vec<SymId> = self.roots.clone();
            let exported: Vec<SymId> = self
                .syms
                .par_filter(|s| s.has(EXPORTED) || s.has(REF_BY_DSO));
            sym_roots.extend(exported);
            for name in [self.cfg.init.as_bytes(), self.cfg.fini.as_bytes()] {
                if let Some(id) = self.syms.find(name) {
                    sym_roots.push(id);
                }
            }
            let mut seeds = roots;
            // CIEs are shared by every FDE of their object: what they reference (the
            // personality routine's pointer) stays.
            let cie_targets: Vec<(u32, u32)> = self
                .objs
                .par_iter()
                .enumerate()
                .flat_map_iter(|(oi, o)| {
                    let eh = &self.ehframe.objs[oi];
                    let mut v = Vec::new();
                    for c in &eh.cies {
                        for r in &eh.rels[c.rel_start as usize..c.rel_end as usize] {
                            if let Some(t) = self.reloc_target(o, oi as u32, r.sym) {
                                v.push(t);
                            }
                        }
                    }
                    v
                })
                .collect();
            for (oi, si) in cie_targets {
                if self.mark(oi, si) {
                    seeds.push((oi, si));
                }
            }
            for id in sym_roots {
                if let Some((o, i)) = self.def_obj(id) {
                    let s = o.sym::<T>(i);
                    if s.shndx < SHN_LORESERVE && s.shndx != SHN_UNDEF {
                        let oi = self.obj_index(o);
                        if self.mark(oi, s.shndx) {
                            seeds.push((oi, s.shndx));
                        }
                    }
                }
            }
            if T::M == Machine::Arm {
                self.arm_exidx = self
                    .objs
                    .par_iter()
                    .map(|o| {
                        let mut v: Vec<(u32, u32)> = Vec::new();
                        if o.alive.load(Ordering::Relaxed) {
                            for (si, s) in o.secs.iter().enumerate() {
                                if s.kind == SecKind::Exidx {
                                    v.push((o.shdr::<T>(si as u32).link, si as u32));
                                }
                            }
                        }
                        v.sort_unstable();
                        v
                    })
                    .collect();
            }
            mk.mark("gc: seeds");
            let this = &*self;
            rayon::scope(|scope| {
                for chunk in seeds.chunks(SPLIT) {
                    let v = chunk.to_vec();
                    scope.spawn(move |s| this.mark_from(s, v));
                }
            });
            mk.mark("gc: marking");
            if self.cfg.print_gc_sections {
                for o in &self.objs {
                    if !o.alive.load(Ordering::Relaxed) {
                        continue;
                    }
                    for (si, s) in o.secs.iter().enumerate() {
                        if matches!(s.kind, SecKind::Alloc | SecKind::Merge) && !s.is_live() {
                            diag::note(format!(
                                "removing unused section {}:({})",
                                o.name,
                                String::from_utf8_lossy(o.sec_name::<T>(si as u32))
                            ));
                        }
                    }
                }
            }
        }
        self.mark_exidx();
        self.size_eh_frame();
        mk.mark("gc: .eh_frame size");
        if timer.enabled() {
            let (live, total): (usize, usize) = self
                .objs
                .par_iter()
                .filter(|o| o.alive.load(Ordering::Relaxed))
                .map(|o| {
                    let alloc = o
                        .secs
                        .iter()
                        .filter(|s| matches!(s.kind, SecKind::Alloc | SecKind::Merge));
                    let n = alloc.clone().count();
                    (alloc.filter(|s| s.is_live()).count(), n)
                })
                .reduce(|| (0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
            timer.detail(format!("{live} of {total} allocated sections live"));
        }
        timer.phase(if gc { "gc sections" } else { "mark sections" });
        Ok(())
    }

    pub fn obj_index(&self, o: &Object<'_>) -> u32 {
        match self.file(o.prio) {
            FileRef::Obj(i) => i,
            _ => unreachable!(),
        }
    }

    fn always_kept(&self, o: &Object<'_>, s: &Sec, start_stop: &HashSet<Vec<u8>>) -> bool {
        if s.has(SHF_GNU_RETAIN)
            || matches!(
                s.ty,
                SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY | SHT_NOTE
            )
        {
            return true;
        }
        // Names are long (`.text.<mangled name>`) and only their starts matter: compare in
        // place instead of finding their ends.
        let rest = o.shstrtab.get(s.name as usize..).unwrap_or(&[]);
        let ends = |p: &[u8], dot: bool| {
            rest.starts_with(p)
                && match rest.get(p.len()) {
                    None | Some(0) => true,
                    Some(b'.') => dot,
                    _ => false,
                }
        };
        if rest.first() == Some(&b'.') {
            return ends(b".init_array", true)
                || ends(b".fini_array", true)
                || ends(b".preinit_array", true)
                || ends(b".ctors", true)
                || ends(b".dtors", true)
                || ends(b".init", false)
                || ends(b".fini", false)
                || ends(b".jcr", false)
                || rest.starts_with(b".note.");
        }
        // `__start_`/`__stop_` sections have C identifier names, never a leading dot.
        !start_stop.is_empty() && start_stop.contains(cstr(o.shstrtab, s.name as usize))
    }

    /// Mark section `si` of object `oi`; true if it wasn't live yet.
    #[inline]
    fn mark(&self, oi: u32, si: u32) -> bool {
        let o = &self.objs[oi as usize];
        let Some(s) = o.secs.get(si as usize) else {
            return false;
        };
        if !matches!(s.kind, SecKind::Alloc | SecKind::Merge) {
            return false;
        }
        !s.live.load(Ordering::Relaxed) && !s.live.swap(true, Ordering::Relaxed)
    }

    /// The section a relocation's symbol lives in: (object, section).
    #[inline]
    fn reloc_target(&self, o: &Object<'_>, oi: u32, sym: u32) -> Option<(u32, u32)> {
        if sym < o.first_global {
            let s = o.sym::<T>(sym);
            if s.shndx != SHN_UNDEF && s.shndx < SHN_LORESERVE {
                return Some((oi, s.shndx));
            }
            return None;
        }
        let id = o.global_id(sym);
        if id == NONE {
            return None;
        }
        let (d, i) = self.def_obj(id)?;
        let s = d.sym::<T>(i);
        if s.shndx != SHN_UNDEF && s.shndx < SHN_LORESERVE {
            Some((self.obj_index(d), s.shndx))
        } else {
            None
        }
    }

    fn mark_from<'s>(&'s self, scope: &rayon::Scope<'s>, mut stack: Vec<(u32, u32)>) {
        while let Some((oi, si)) = stack.pop() {
            let o = &self.objs[oi as usize];
            let (raw, rela) = o.rel_data::<T>(si);
            let n = o.rel_count::<T>(si);
            for k in 0..n {
                let r = T::decode_rel(raw, k, rela);
                if let Some((oj, sj)) = self.reloc_target(o, oi, r.sym)
                    && self.mark(oj, sj)
                {
                    stack.push((oj, sj));
                }
            }
            // What the relocations need is decided now, while they are in cache: nothing in
            // it depends on what else is live.
            let s = &o.secs[si as usize];
            if n > 0 && matches!(s.kind, SecKind::Alloc | SecKind::Merge) {
                let mut st = ScanState::default();
                T::scan(self, o, si, &mut st);
                if st.nrel != 0 || st.nsym != 0 {
                    o.scanned.lock().unwrap().push((si, st.nrel, st.nsym));
                }
            }
            let eh = &self.ehframe.objs[oi as usize];
            for f in eh.fdes_of(si) {
                // Skip pc_begin (the function itself); the rest is the LSDA and personality.
                for r in &eh.rels[f.rel_start as usize..f.rel_end as usize] {
                    if r.offset == f.off as u64 + 8 {
                        continue;
                    }
                    if let Some((oj, sj)) = self.reloc_target(o, oi, r.sym)
                        && self.mark(oj, sj)
                    {
                        stack.push((oj, sj));
                    }
                }
            }
            // ARM: the unwind index entry of live code keeps its unwind data and personality.
            if let Some(ex) = self.arm_exidx.get(oi as usize) {
                let a = ex.partition_point(|e| e.0 < si);
                for &(_, e) in ex[a..].iter().take_while(|e| e.0 == si) {
                    let es = &o.secs[e as usize];
                    if es.live.swap(true, Ordering::Relaxed) {
                        continue;
                    }
                    let (raw, rela) = o.rel_data::<T>(e);
                    for k in 0..o.rel_count::<T>(e) {
                        let r = T::decode_rel(raw, k, rela);
                        if let Some((oj, sj)) = self.reloc_target(o, oi, r.sym)
                            && self.mark(oj, sj)
                        {
                            stack.push((oj, sj));
                        }
                    }
                }
            }
            if stack.len() > SPLIT {
                let half = stack.split_off(stack.len() / 2);
                scope.spawn(move |s| self.mark_from(s, half));
            }
        }
    }

    /// `.ARM.exidx` sections live with the code they describe (`sh_link`).
    fn mark_exidx(&self) {
        if T::M != Machine::Arm {
            return;
        }
        self.objs.par_iter().for_each(|o| {
            if !o.alive.load(Ordering::Relaxed) {
                return;
            }
            for (si, s) in o.secs.iter().enumerate() {
                if s.kind == SecKind::Exidx {
                    let link = o.shdr::<T>(si as u32).link;
                    let live = o.secs.get(link as usize).is_some_and(|t| t.is_live());
                    s.live.store(live, Ordering::Relaxed);
                }
            }
        });
    }
}
