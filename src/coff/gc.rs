//! Which sections are written.
//!
//! With `/OPT:REF` (the default unless `/DEBUG`), as in `link.exe`: every
//! non-COMDAT section is kept, and a COMDAT section is kept only if something
//! kept refers to it. Rust and C++ put every function and most data in its
//! own COMDAT, so this drops most of what libraries bring in unused.

use std::sync::atomic::Ordering::Relaxed;

use rayon::prelude::*;

use super::object::NONE;
use super::resolve::Linker;
use super::symtab::{Def, SymId};
use super::*;

impl Linker<'_> {
    pub fn mark_live(&mut self) {
        for obj in &mut self.objs {
            obj.propagate_discards();
        }
        let gc = self.cfg.gc.unwrap_or(!self.cfg.debug);
        if !gc {
            for obj in &self.objs {
                for s in &obj.sections {
                    s.live.store(!s.discarded, Relaxed);
                }
            }
            for imp in &self.imports {
                imp.live.store(true, Relaxed);
                imp.thunk_live.store(imp.kind == IMPORT_CODE, Relaxed);
            }
            return;
        }

        let mut stack: Vec<(u32, u32)> = Vec::new();
        for (oi, obj) in self.objs.iter().enumerate() {
            for (si, s) in obj.sections.iter().enumerate() {
                if !s.discarded && !s.is_comdat() {
                    s.live.store(true, Relaxed);
                    stack.push((oi as u32, si as u32));
                }
            }
        }
        let mut roots: Vec<SymId> = self.gc_roots.clone();
        roots.extend(self.entry);
        roots.extend(self.exports.iter().map(|e| e.sym));
        roots.extend(self.symtab.find(b"_tls_used"));
        roots.extend(self.symtab.find(b"_load_config_used"));
        for id in roots {
            self.mark_sym(id, &mut stack);
        }

        // Breadth-first, one frontier at a time; a large frontier is scanned
        // on all threads (marking is an atomic swap, so each section is
        // claimed once).
        let mut frontier = stack;
        while !frontier.is_empty() {
            frontier = if frontier.len() < 256 {
                let mut next = Vec::new();
                for &(oi, si) in &frontier {
                    self.visit(oi, si, &mut next);
                }
                next
            } else {
                frontier
                    .par_chunks(64)
                    .flat_map_iter(|chunk| {
                        let mut next = Vec::new();
                        for &(oi, si) in chunk {
                            self.visit(oi, si, &mut next);
                        }
                        next
                    })
                    .collect()
            };
        }
    }

    /// Mark what a live section refers to.
    fn visit(&self, oi: u32, si: u32, next: &mut Vec<(u32, u32)>) {
        let obj = &self.objs[oi as usize];
        let s = &obj.sections[si as usize];
        let mut child = s.assoc_child;
        while child != NONE {
            self.mark_section(oi, child, next);
            child = obj.sections[child as usize].assoc_next;
        }
        for r in s.relocs.as_chunks::<10>().0 {
            let idx = u32le(r, 4);
            match obj.sym_ids.get(idx as usize) {
                Some(&id) if id != NONE => self.mark_sym(id, next),
                _ => {
                    if let Some(raw) = obj.raw_sym(idx)
                        && raw.section > 0
                    {
                        self.mark_section(oi, (raw.section - 1) as u32, next);
                    }
                }
            }
        }
    }

    fn mark_sym(&self, id: SymId, stack: &mut Vec<(u32, u32)>) {
        match self.symtab.get(id).def {
            Def::Defined { obj, sec, .. } => self.mark_section(obj, sec, stack),
            Def::Import { imp } => self.imports[imp as usize].live.store(true, Relaxed),
            Def::Thunk { imp } => {
                let i = &self.imports[imp as usize];
                i.live.store(true, Relaxed);
                i.thunk_live.store(true, Relaxed);
            }
            Def::LocalImport { slot } => {
                let target = self.local_imports[slot as usize];
                if target != id {
                    self.mark_sym(target, stack);
                }
            }
            _ => {}
        }
    }

    #[inline]
    fn mark_section(&self, obj: u32, sec: u32, stack: &mut Vec<(u32, u32)>) {
        let Some(s) = self.objs[obj as usize].sections.get(sec as usize) else {
            return;
        };
        if !s.discarded && !s.live.swap(true, Relaxed) {
            stack.push((obj, sec));
        }
    }
}
