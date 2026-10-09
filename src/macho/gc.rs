//! Liveness (`-dead_strip`) and, in the same walk over the relocations of everything kept,
//! what each reference needs: a stub, a GOT slot, a TLV pointer, a rebase or a bind.

use std::sync::atomic::Ordering::Relaxed;

use super::arch::{self, Kind};
use super::config::OutputKind;
use super::object::*;
use super::resolve::Linker;
use super::symtab::{Def, LIVE, NEEDS_AUTH_GOT, NEEDS_GOT, NEEDS_STUB, NEEDS_TLVP, SymId};
use super::*;

/// A pointer in the image that dyld must slide (`Rebase`) or bind to an imported symbol.
#[derive(Debug, Clone, Copy)]
pub struct Site {
    pub obj: u32,
    pub atom: u32,
    pub off: u32,
    pub bind: SymId,
    pub addend: i64,
    /// arm64e: a signed pointer (see [`auth`]), or 0.
    pub auth: u32,
}

/// A pointer-authentication schema: key, address diversity and extra diversity, packed.
pub fn auth(key: u64, addr_div: bool, diversity: u64) -> u32 {
    0x8000_0000
        | ((key as u32 & 3) << 17)
        | (u32::from(addr_div) << 16)
        | (diversity as u32 & 0xffff)
}

impl Site {
    pub fn is_rebase(&self) -> bool {
        self.bind == NONE
    }
}

pub const ATOM_COALESCED: u8 = 64;

type Work = (u32, u32);

#[derive(Default)]
struct Found {
    next: Vec<Work>,
    sites: Vec<Site>,
    text_relocs: Vec<String>,
}

impl Linker<'_> {
    pub fn mark_live(&mut self) {
        let mut found = Found::default();
        for &id in &self.roots.clone() {
            self.mark_sym(id, &mut found);
        }
        for &id in &self.header_syms {
            self.symtab.get(id).set(LIVE);
        }
        if let (Some(m), false) = (self.objc_msgsend, self.objc_stubs.is_empty()) {
            self.mark_sym(m, &mut found);
            self.symtab.get(m).set(NEEDS_GOT);
        }
        let export_all = self.cfg.kind != OutputKind::Execute || self.cfg.export_dynamic;
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            let exported = export_all && !s.private_extern && self.is_exported_name(s.name);
            let keep = s.no_dead_strip
                || s.referenced_dynamically
                || exported
                || (!self.cfg.exported.is_empty()
                    && self.cfg.exported.contains(s.name)
                    && !s.private_extern);
            if keep
                && matches!(
                    s.def,
                    Def::Defined { .. } | Def::Absolute { .. } | Def::Common { .. }
                )
            {
                self.mark_sym(id, &mut found);
            }
        }
        for (oi, obj) in self.objs.iter().enumerate() {
            for (ai, a) in obj.atoms.iter().enumerate() {
                let root = if self.cfg.dead_strip {
                    a.flags & ATOM_NO_DEAD_STRIP != 0
                } else {
                    a.flags & (ATOM_CIE | ATOM_FDE | ATOM_COALESCED) == 0
                };
                if root {
                    self.mark_atom(oi as u32, ai as u32, &mut found);
                }
            }
        }
        // Work stealing: each task drains its own stack and hands half of it to a new task
        // when it grows, so deep call chains don't serialize into one-atom frontiers.
        let done: std::sync::Mutex<Vec<Found>> = std::sync::Mutex::new(Vec::new());
        let roots = std::mem::take(&mut found.next);
        let this = &*self;
        rayon::scope(|s| {
            for chunk in roots.chunks(256) {
                let stack = chunk.to_vec();
                let done = &done;
                s.spawn(move |s| this.mark_task(s, stack, done));
            }
        });
        let mut sites = std::mem::take(&mut found.sites);
        let mut text_relocs = std::mem::take(&mut found.text_relocs);
        for mut f in done.into_inner().unwrap() {
            sites.append(&mut f.sites);
            text_relocs.append(&mut f.text_relocs);
        }
        self.sites = sites;
        self.text_relocs = text_relocs;
    }

    fn mark_task<'s>(
        &'s self,
        scope: &rayon::Scope<'s>,
        stack: Vec<Work>,
        done: &'s std::sync::Mutex<Vec<Found>>,
    ) {
        let mut f = Found {
            next: stack,
            ..Found::default()
        };
        while let Some((o, a)) = f.next.pop() {
            self.visit(o, a, &mut f);
            if f.next.len() > 64 {
                let half = f.next.split_off(f.next.len() / 2);
                scope.spawn(move |s| self.mark_task(s, half, done));
            }
        }
        if !f.sites.is_empty() || !f.text_relocs.is_empty() {
            done.lock().unwrap().push(f);
        }
    }

    pub fn is_exported_name(&self, name: &[u8]) -> bool {
        if self.cfg.no_exported_symbols {
            return false;
        }
        if !self.cfg.exported.is_empty() && !self.cfg.exported.contains(name) {
            return false;
        }
        !self.cfg.unexported.contains(name)
    }

    fn mark_sym(&self, id: SymId, f: &mut Found) {
        let s = self.symtab.get(id);
        s.set(LIVE);
        match s.def {
            Def::Defined { obj, atom, .. } => self.mark_atom(obj, atom, f),
            Def::Dylib { dylib } => self.dylibs[dylib as usize].used.store(true, Relaxed),
            _ => {}
        }
    }

    #[inline]
    fn mark_atom(&self, obj: u32, atom: u32, f: &mut Found) {
        let Some(a) = self.objs[obj as usize].atoms.get(atom as usize) else {
            return;
        };
        if a.flags & ATOM_COALESCED == 0 && !a.is_live() && !a.live.swap(true, Relaxed) {
            f.next.push((obj, atom));
        }
    }

    fn mark_ref(&self, obj: u32, r: Ref, f: &mut Found) {
        match r {
            Ref::Sym(i) => {
                let id = self.objs[obj as usize].global(i);
                if id != NONE {
                    self.mark_sym(id, f);
                }
            }
            Ref::Atom { atom, .. } => self.mark_atom(obj, atom, f),
            _ => {}
        }
    }

    fn visit(&self, oi: u32, ai: u32, f: &mut Found) {
        let obj = &self.objs[oi as usize];
        let a = &obj.atoms[ai as usize];
        let sec = &obj.sections[a.sec as usize];
        if a.flags & ATOM_FDE != 0 {
            // Kept for its function: the CIE and LSDA come with it; its own relocations
            // (the function, the LSDA) are rewritten, not followed.
            let fde = &obj.fdes[a.aux as usize];
            self.mark_atom(oi, obj.cies[fde.cie as usize].atom, f);
            self.mark_ref(oi, fde.lsda, f);
            return;
        }
        if sec.is_code() {
            for e in obj.cu_for(ai) {
                self.mark_ref(oi, e.personality, f);
                self.mark_ref(oi, e.lsda, f);
                // `__unwind_info` names personality routines by their GOT slots.
                if let Ref::Sym(i) = e.personality
                    && !super::unwind::is_dwarf(self.arch, e.encoding)
                {
                    let id = obj.global(i);
                    if id != NONE {
                        let arm64e = self.arch == super::config::Arch::Arm64e;
                        self.symtab
                            .get(id)
                            .set(if arm64e { NEEDS_AUTH_GOT } else { NEEDS_GOT });
                    }
                }
            }
            for &(_, off, fde) in obj.fdes_of(ai) {
                if obj.needs_fde(ai, off) {
                    self.mark_atom(oi, obj.fdes[fde as usize].atom, f);
                }
            }
        }
        if sec.kind == SecKind::NonLazyPointers {
            let slot = sec.reserved1 as usize + (a.off / 8) as usize;
            if let Some(idx) = obj
                .indirect
                .get(slot * 4..slot * 4 + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                && idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0
            {
                let (r, add) = obj.sym_ref(idx, 0);
                self.mark_ref(oi, r, f);
                self.note_pointer(oi, ai, 0, r, add, sec, 0, f);
            }
        }
        let arch = self.arch;
        let mut addend = 0i64;
        let mut i = a.rel_lo as usize;
        let hi = a.rel_hi as usize;
        while i < hi {
            let r = raw_reloc(sec.relocs, i);
            i += 1;
            let k = arch::kind(arch, r.ty);
            if k == Kind::Addend {
                addend = ((r.sym << 8) as i32 >> 8) as i64;
                continue;
            }
            let field = r.addr as usize;
            let target = if r.ext {
                let emb = arch::embedded_addend(arch, k, sec.data, field, r.len);
                obj.sym_ref(r.sym, emb + addend)
            } else {
                let emb = arch::embedded_addend(arch, k, sec.data, field, r.len);
                let at = arch::section_target(arch, k, sec.addr + field as u64, emb, r.pcrel);
                (obj.section_ref(r.sym, at), 0)
            };
            addend = 0;
            self.mark_ref(oi, target.0, f);
            if k == Kind::Subtractor {
                // The minuend follows; the pair computes a difference, never a pointer.
                if i < hi {
                    let m = raw_reloc(sec.relocs, i);
                    i += 1;
                    let mt = if m.ext {
                        obj.sym_ref(m.sym, 0).0
                    } else {
                        let emb =
                            arch::embedded_addend(arch, Kind::Unsigned, sec.data, field, m.len);
                        obj.section_ref(m.sym, emb as u64)
                    };
                    self.mark_ref(oi, mt, f);
                }
                continue;
            }
            self.classify(oi, ai, a, sec, r, k, target.0, target.1, f);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn classify(
        &self,
        oi: u32,
        ai: u32,
        a: &Atom,
        sec: &Section,
        r: RawReloc,
        k: Kind,
        t: Ref,
        addend: i64,
        f: &mut Found,
    ) {
        let obj = &self.objs[oi as usize];
        let sym = match t {
            Ref::Sym(i) => {
                let id = obj.global(i);
                (id != NONE).then(|| (id, self.symtab.get(id)))
            }
            _ => None,
        };
        let imported = sym.is_some_and(|(_, s)| self.needs_binding(s));
        match k {
            Kind::Branch => {
                if let Some((_, s)) = sym
                    && imported
                {
                    // arm64e stubs jump through `__auth_got` slots of their own.
                    s.set(if self.arch == super::config::Arch::Arm64e {
                        NEEDS_STUB | NEEDS_AUTH_GOT
                    } else {
                        NEEDS_STUB | NEEDS_GOT
                    });
                }
            }
            Kind::GotPage | Kind::GotPageOff | Kind::GotLoad => {
                if let Some((_, s)) = sym
                    && imported
                {
                    s.set(NEEDS_GOT);
                }
            }
            Kind::PointerToGot => {
                if let Some((_, s)) = sym {
                    s.set(NEEDS_GOT);
                }
            }
            Kind::TlvPage | Kind::TlvPageOff | Kind::Tlv => {
                if let Some((_, s)) = sym
                    && imported
                {
                    s.set(NEEDS_TLVP);
                }
            }
            Kind::Unsigned | Kind::AuthPointer if r.len == 3 => {
                let off = r.addr - a.off;
                let schema = if k == Kind::AuthPointer {
                    let v = u64le(sec.data, r.addr as usize);
                    auth((v >> 49) & 3, (v >> 48) & 1 != 0, (v >> 32) & 0xffff)
                } else if self.arch == super::config::Arch::Arm64e
                    && sec.kind == SecKind::ThreadVars
                    && off.is_multiple_of(24)
                {
                    // The TLV thunk is called with `blraaz`: ld64 signs it with IA, no diversity.
                    auth(0, false, 0)
                } else {
                    0
                };
                self.note_pointer(oi, ai, off, t, addend, sec, schema, f);
            }
            _ => {}
        }
    }

    /// A pointer-sized absolute reference at `off` in an atom: a rebase or a bind.
    #[allow(clippy::too_many_arguments)]
    fn note_pointer(
        &self,
        oi: u32,
        ai: u32,
        off: u32,
        t: Ref,
        addend: i64,
        sec: &Section,
        auth: u32,
        f: &mut Found,
    ) {
        let obj = &self.objs[oi as usize];
        if sec.kind == SecKind::ThreadVars && off % 24 == 16 {
            // A TLV descriptor's offset into the thread-local template: fixed by the linker.
            if !matches!(t, Ref::Sym(i) if self.symtab.get(obj.global(i)).def.is_imported()) {
                return;
            }
        }
        let bind = match t {
            Ref::Abs(_) | Ref::None => return,
            Ref::Sym(i) => {
                let id = obj.global(i);
                if id == NONE {
                    return;
                }
                let s = self.symtab.get(id);
                if matches!(s.def, Def::Absolute { .. }) {
                    return;
                }
                if self.is_preemptible(s) || self.needs_weak_bind(s) {
                    id
                } else {
                    NONE
                }
            }
            Ref::Atom { .. } => NONE,
        };
        if !self.writable_segment(sec) {
            f.text_relocs.push(format!(
                "{}: absolute pointer in {},{} needs a {} at runtime, but the section is read-only",
                obj.name,
                String::from_utf8_lossy(sec.segname),
                String::from_utf8_lossy(sec.sectname),
                if bind == NONE { "rebase" } else { "bind" }
            ));
            return;
        }
        f.sites.push(Site {
            obj: oi,
            atom: ai,
            off,
            bind,
            addend: if bind == NONE { 0 } else { addend },
            auth,
        });
    }

    /// Bound by dyld: imported from a dylib or looked up dynamically.
    pub fn is_preemptible(&self, s: &super::symtab::Symbol) -> bool {
        match s.def {
            Def::Dylib { .. } | Def::DynamicLookup => true,
            Def::Defined { .. } if self.cfg.interposable => !s.private_extern,
            _ => false,
        }
    }

    /// Reached through a stub or GOT slot dyld fills: imported, or coalesced as a weak definition.
    pub fn needs_binding(&self, s: &super::symtab::Symbol) -> bool {
        self.is_preemptible(s) || self.needs_weak_bind(s)
    }

    /// Weak definitions this image exports are coalesced by dyld with other images' copies.
    pub fn needs_weak_bind(&self, s: &super::symtab::Symbol) -> bool {
        s.weak_def
            && !s.private_extern
            && matches!(s.def, Def::Defined { .. })
            && self.is_exported_name(s.name)
    }

    /// Whether the output section an input section lands in is in a writable segment.
    pub fn writable_segment(&self, sec: &Section) -> bool {
        let (seg, _) = super::layout::output_name(&self.cfg, sec);
        seg != b"__TEXT"
    }
}
