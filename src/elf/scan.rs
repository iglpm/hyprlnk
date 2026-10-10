//! Relocation scanning: what each relocation needs (a GOT entry, a PLT entry, a copy
//! relocation, a dynamic relocation), decided once per relocation of every live section, in
//! parallel. Then slots are numbered in symbol-id order, which is the same on every run.

use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;

use super::object::{FL_WRITE, Object, SecKind};
use super::resolve::Ctx;
use super::symbols::*;
use super::target::{Rel, Target};
use super::*;
use crate::diag::{Result, Timer};

/// Dynamic relocations one section needs: relative ones and the rest.
#[derive(Default, Clone, Copy)]
pub struct ScanState {
    pub nrel: u32,
    pub nsym: u32,
}

/// What a relocation's symbol is, as far as code generation cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKind {
    /// An absolute value (SHN_ABS, or an undefined weak symbol that resolves to 0).
    Abs,
    /// Defined in the output and bound to it.
    Local,
    /// Defined here as an IFUNC: its address is its PLT entry.
    Ifunc,
    /// From a shared object, or interposable: data.
    ImportedData,
    /// From a shared object, or interposable: a function.
    ImportedFunc,
}

/// A symbol a slot belongs to: a global symbol, or a local of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymRef {
    /// Object index for a local symbol, NONE for a global.
    pub obj: u32,
    /// The local's index, or the global's id.
    pub idx: u32,
}

impl SymRef {
    pub fn global(id: SymId) -> SymRef {
        SymRef { obj: NONE, idx: id }
    }
}

/// Per-symbol slots, by `Symbol::aux` (or a local's entry in `local_aux`).
#[derive(Debug, Clone, Copy)]
pub struct Aux {
    pub got: u32,
    pub gottp: u32,
    pub tlsgd: u32,
    pub tlsdesc: u32,
    pub plt: u32,
    pub dynsym: u32,
    pub copy: u32,
}

impl Default for Aux {
    fn default() -> Self {
        Aux {
            got: NONE,
            gottp: NONE,
            tlsgd: NONE,
            tlsdesc: NONE,
            plt: NONE,
            dynsym: NONE,
            copy: NONE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotKind {
    Addr,
    TpOff,
    TlsGd,
    TlsDesc,
    TlsLd,
}

#[derive(Debug, Clone, Copy)]
pub struct GotEnt {
    pub kind: GotKind,
    pub sym: SymRef,
    /// Word index in `.got`.
    pub word: u32,
}

#[derive(Default)]
pub struct ScanResult {
    pub aux: Vec<Aux>,
    /// Per object: (local index, aux index), sorted.
    pub local_aux: Vec<Vec<(u32, u32)>>,
    pub got: Vec<GotEnt>,
    pub got_words: u64,
    /// `.got` words before the first entry (`_DYNAMIC` on some machines).
    pub got_header: u64,
    pub tlsld: Option<u32>,
    pub plt: Vec<SymRef>,
    /// PLT entries for IFUNCs defined here (IRELATIVE slots), after `plt`.
    pub iplt: Vec<SymRef>,
    pub dynsyms: Vec<SymId>,
    pub copyrels: Vec<(SymId, u64)>,
    pub copy_size: u64,
    pub copy_align: u64,
    pub needs_tlsld: AtomicBool,
    pub textrel: AtomicBool,
    pub static_tls: AtomicBool,
    /// Dynamic relocations from GOT entries: relative, other.
    pub got_rel: u64,
    pub got_sym: u64,
    /// Per object: where its sections' dynamic relocations start (relative, other).
    pub obj_rel: Vec<u64>,
    pub obj_sym: Vec<u64>,
    pub nrelative: u64,
    pub nsymbolic: u64,
}

impl ScanResult {
    pub fn rela_dyn_count(&self) -> u64 {
        self.nrelative + self.nsymbolic
    }
}

impl<'a, T: Target> Ctx<'a, T> {
    /// The kind of symbol `idx` of `o` is, for relocation purposes.
    #[inline]
    pub fn sym_kind(&self, o: &Object<'a>, idx: u32) -> (SymRef, SymKind) {
        if idx < o.first_global {
            let s = o.sym::<T>(idx);
            let k = if s.is_abs() {
                SymKind::Abs
            } else if s.ty() == STT_GNU_IFUNC {
                SymKind::Ifunc
            } else {
                SymKind::Local
            };
            return (
                SymRef {
                    obj: self.obj_index(o),
                    idx,
                },
                k,
            );
        }
        let id = o.global_id(idx);
        let r = SymRef::global(id);
        if id == NONE {
            return (r, SymKind::Abs);
        }
        let sym = self.syms.get(id);
        let f = sym.flags();
        let k = if f & (IMPORTED | PREEMPTIBLE) != 0 {
            if f & IS_FUNC != 0 || f & IMPORTED != 0 && o.sym::<T>(idx).ty() == STT_FUNC {
                SymKind::ImportedFunc
            } else {
                SymKind::ImportedData
            }
        } else if sym.def() == UNDEF || f & IS_ABS != 0 {
            SymKind::Abs
        } else if f & IS_IFUNC != 0 {
            SymKind::Ifunc
        } else {
            SymKind::Local
        };
        (r, k)
    }

    /// A live relocation references symbol `idx` of `o` (for `.symtab`).
    #[inline]
    pub fn note_use(&self, o: &Object<'a>, idx: u32) {
        if idx >= o.first_global {
            let id = o.global_id(idx);
            if id != NONE {
                self.syms.get(id).set(USED);
            }
        }
    }

    /// Record that a symbol needs slots (`NEEDS_*` flags).
    #[inline]
    pub fn need(&self, o: &Object<'a>, r: SymRef, f: u32) {
        if r.obj == NONE {
            if r.idx != NONE {
                self.syms.get(r.idx).set(f);
            }
        } else {
            o.local_needs.lock().unwrap().push((r.idx, f));
        }
    }

    fn reloc_error(&self, o: &Object<'a>, si: u32, r: &Rel, what: &str) {
        let name = if r.sym < o.first_global {
            let s = o.sym::<T>(r.sym);
            if s.ty() == STT_SECTION {
                String::from_utf8_lossy(o.sec_name::<T>(s.shndx)).into_owned()
            } else {
                o.display_sym::<T>(r.sym)
            }
        } else {
            o.display_sym::<T>(r.sym)
        };
        self.error(format!(
            "{}: {what} against `{name}` in section {} (relocation type {})",
            o.name,
            String::from_utf8_lossy(o.sec_name::<T>(si)),
            r.ty
        ));
    }

    /// A dynamic relocation is needed at a site in section `si`.
    fn dynrel_site(&self, o: &Object<'a>, si: u32, r: &Rel) -> bool {
        if o.secs[si as usize].fl & FL_WRITE == 0 {
            if self.cfg.z_text {
                self.reloc_error(
                    o,
                    si,
                    r,
                    "relocation in a read-only section needs a dynamic relocation; recompile with -fPIC or link with -z notext",
                );
                return false;
            }
            self.scan.textrel.store(true, Ordering::Relaxed);
        }
        true
    }

    /// An absolute address the size of a pointer.
    pub fn scan_abs_word(&self, o: &Object<'a>, si: u32, r: &Rel, st: &mut ScanState) {
        let (sr, k) = self.sym_kind(o, r.sym);
        let pic = self.cfg.pic();
        match k {
            SymKind::Abs => {}
            SymKind::Local => {
                if pic && self.dynrel_site(o, si, r) {
                    st.nrel += 1;
                }
            }
            SymKind::Ifunc => {
                self.need(o, sr, NEEDS_PLT);
                if pic && self.dynrel_site(o, si, r) {
                    st.nrel += 1;
                }
            }
            SymKind::ImportedData | SymKind::ImportedFunc => {
                let writable = o.secs[si as usize].fl & FL_WRITE != 0;
                if !pic && k == SymKind::ImportedData && !self.cfg.z_nocopyreloc {
                    self.need(o, sr, NEEDS_COPY | NEEDS_DYNSYM);
                } else if !self.cfg.shared && k == SymKind::ImportedFunc && (!pic || !writable) {
                    self.need(o, sr, NEEDS_CPLT | NEEDS_PLT | NEEDS_DYNSYM);
                } else if self.dynrel_site(o, si, r) {
                    self.need(o, sr, NEEDS_DYNSYM);
                    st.nsym += 1;
                }
            }
        }
    }

    /// An absolute address narrower than a pointer: only works if it's link-time constant.
    pub fn scan_abs_narrow(&self, o: &Object<'a>, si: u32, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        match k {
            SymKind::Abs => {}
            SymKind::Local | SymKind::Ifunc => {
                if k == SymKind::Ifunc {
                    self.need(o, sr, NEEDS_PLT);
                }
                if self.cfg.pic() {
                    self.reloc_error(o, si, r, "absolute relocation cannot be used in a position-independent output; recompile with -fPIC");
                }
            }
            SymKind::ImportedData => {
                if self.cfg.pic() {
                    self.reloc_error(o, si, r, "absolute relocation cannot be used against a symbol from a shared object; recompile with -fPIC");
                } else {
                    self.need(o, sr, NEEDS_COPY | NEEDS_DYNSYM);
                }
            }
            SymKind::ImportedFunc => {
                if self.cfg.pic() {
                    self.reloc_error(o, si, r, "absolute relocation cannot be used against a symbol from a shared object; recompile with -fPIC");
                } else {
                    self.need(o, sr, NEEDS_CPLT | NEEDS_PLT | NEEDS_DYNSYM);
                }
            }
        }
    }

    /// A PC-relative reference that is not a call.
    pub fn scan_pcrel(&self, o: &Object<'a>, si: u32, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        match k {
            SymKind::Abs | SymKind::Local => {}
            SymKind::Ifunc => self.need(o, sr, NEEDS_PLT),
            SymKind::ImportedData => {
                if self.cfg.shared {
                    self.reloc_error(o, si, r, "PC-relative relocation cannot be used against a symbol from another module when making a shared object; recompile with -fPIC");
                } else {
                    self.need(o, sr, NEEDS_COPY | NEEDS_DYNSYM);
                }
            }
            SymKind::ImportedFunc => {
                if self.cfg.shared {
                    self.reloc_error(o, si, r, "PC-relative relocation cannot be used against a symbol from another module when making a shared object; recompile with -fPIC");
                } else {
                    self.need(o, sr, NEEDS_CPLT | NEEDS_PLT | NEEDS_DYNSYM);
                }
            }
        }
    }

    /// A call or jump: through the PLT when the target is in another module.
    pub fn scan_call(&self, o: &Object<'a>, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        match k {
            SymKind::ImportedData | SymKind::ImportedFunc => {
                self.need(o, sr, NEEDS_PLT | NEEDS_DYNSYM)
            }
            SymKind::Ifunc => self.need(o, sr, NEEDS_PLT),
            _ => {}
        }
    }

    /// A GOT entry holding the symbol's address.
    pub fn scan_got(&self, o: &Object<'a>, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        let mut f = NEEDS_GOT;
        match k {
            SymKind::ImportedData | SymKind::ImportedFunc => f |= NEEDS_DYNSYM,
            SymKind::Ifunc => f |= NEEDS_PLT,
            _ => {}
        }
        self.need(o, sr, f);
    }

    /// TLS initial-exec: a GOT entry with the TP offset.
    pub fn scan_gottp(&self, o: &Object<'a>, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        let mut f = NEEDS_GOTTP;
        if matches!(k, SymKind::ImportedData | SymKind::ImportedFunc) {
            f |= NEEDS_DYNSYM;
        }
        if self.cfg.shared {
            self.scan.static_tls.store(true, Ordering::Relaxed);
        }
        self.need(o, sr, f);
    }

    /// TLS general dynamic: relaxed to IE or LE when linking an executable.
    pub fn scan_tlsgd(&self, o: &Object<'a>, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        let imported = matches!(k, SymKind::ImportedData | SymKind::ImportedFunc);
        if !self.cfg.shared && T::RELAX_TLS && self.cfg.relax {
            if imported {
                self.need(o, sr, NEEDS_GOTTP | NEEDS_DYNSYM);
            }
        } else {
            self.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
        }
    }

    /// TLS descriptors: relaxed like general dynamic.
    pub fn scan_tlsdesc(&self, o: &Object<'a>, r: &Rel) {
        let (sr, k) = self.sym_kind(o, r.sym);
        let imported = matches!(k, SymKind::ImportedData | SymKind::ImportedFunc);
        if !self.cfg.shared && self.cfg.relax {
            if imported {
                self.need(o, sr, NEEDS_GOTTP | NEEDS_DYNSYM);
            }
        } else {
            self.need(
                o,
                sr,
                NEEDS_TLSDESC | if imported { NEEDS_DYNSYM } else { 0 },
            );
        }
    }

    /// TLS local exec: only in executables.
    pub fn scan_tpoff(&self, o: &Object<'a>, si: u32, r: &Rel) {
        if self.cfg.shared {
            self.reloc_error(
                o,
                si,
                r,
                "TLS local-exec relocation cannot be used in a shared object; recompile with -fPIC",
            );
        }
    }

    /// Whether TLS GD/LD/desc sequences are relaxed (executables, relaxation on).
    pub fn relax_tls(&self) -> bool {
        !self.cfg.shared && self.cfg.relax
    }

    pub fn scan(&mut self, timer: &mut Timer) -> Result<()> {
        // With `--gc-sections`, marking scanned every live section it walked; what is left is
        // `.ARM.exidx`, which lives with its code without being walked.
        let gc = self.cfg.gc_sections;
        let counts: Vec<Vec<(u32, ScanState)>> = self
            .objs
            .par_iter()
            .map(|o| {
                let mut out: Vec<(u32, ScanState)> =
                    std::mem::take(&mut *o.scanned.lock().unwrap())
                        .into_iter()
                        .map(|(si, nrel, nsym)| (si, ScanState { nrel, nsym }))
                        .collect();
                if !o.alive.load(Ordering::Relaxed) {
                    return out;
                }
                for (si, s) in o.secs.iter().enumerate() {
                    let walked = gc && matches!(s.kind, SecKind::Alloc | SecKind::Merge);
                    if walked
                        || !s.is_live()
                        || s.rel_len == 0
                        || !matches!(s.kind, SecKind::Alloc | SecKind::Merge | SecKind::Exidx)
                    {
                        continue;
                    }
                    let mut st = ScanState::default();
                    T::scan(self, o, si as u32, &mut st);
                    if st.nrel != 0 || st.nsym != 0 {
                        out.push((si as u32, st));
                    }
                }
                out
            })
            .collect();
        self.objs
            .par_iter_mut()
            .zip(counts.into_par_iter())
            .for_each(|(o, c)| {
                for (si, st) in c {
                    let s = &mut o.secs[si as usize];
                    s.nrel = st.nrel;
                    s.nsym = st.nsym;
                }
            });
        self.check_errors()?;
        self.finalize_thunks();
        timer.phase("scan relocations");
        self.assign_slots();
        timer.phase("GOT, PLT, dynamic symbols");
        Ok(())
    }

    fn assign_slots(&mut self) {
        let shared = self.cfg.shared;
        let pic = self.cfg.pic();
        let has_dynamic = self.has_dynamic;
        // Globals needing slots, in id order.
        let mut need: Vec<Vec<(SymId, u32)>> = self
            .syms
            .shards
            .par_iter()
            .enumerate()
            .map(|(s, v)| {
                v.iter()
                    .enumerate()
                    .filter_map(|(i, sym)| {
                        let f = sym.flags();
                        let id = ((s as u32) << 24) | i as u32;
                        let dynsym = has_dynamic
                            && (f & (NEEDS_DYNSYM | NEEDS_COPY | NEEDS_CPLT) != 0
                                || f & EXPORTED != 0 && sym.def() != UNDEF);
                        let any = f & (ANY_GOT | NEEDS_PLT | NEEDS_COPY) != 0 || dynsym;
                        any.then_some((id, f | if dynsym { NEEDS_DYNSYM } else { 0 }))
                    })
                    .collect()
            })
            .collect();
        let need: Vec<(SymId, u32)> = need.drain(..).flatten().collect();
        let mut aux: Vec<Aux> = Vec::with_capacity(need.len());
        let mut got: Vec<GotEnt> = Vec::new();
        let header = if T::GOT0_DYNAMIC { 1 } else { 0 };
        let mut words = header as u32;
        let mut plt = Vec::new();
        let mut iplt = Vec::new();
        let mut copyrels = Vec::new();
        let mut copy_size = 0u64;
        let mut copy_align = 1u64;
        let mut dyn_undef = Vec::new();
        let mut dyn_def = Vec::new();
        let mut add_got = |sr: SymRef, f: u32, a: &mut Aux, got: &mut Vec<GotEnt>| {
            if f & NEEDS_GOT != 0 {
                a.got = words;
                got.push(GotEnt {
                    kind: GotKind::Addr,
                    sym: sr,
                    word: words,
                });
                words += 1;
            }
            if f & NEEDS_GOTTP != 0 {
                a.gottp = words;
                got.push(GotEnt {
                    kind: GotKind::TpOff,
                    sym: sr,
                    word: words,
                });
                words += 1;
            }
            if f & NEEDS_TLSGD != 0 {
                a.tlsgd = words;
                got.push(GotEnt {
                    kind: GotKind::TlsGd,
                    sym: sr,
                    word: words,
                });
                words += 2;
            }
            if f & NEEDS_TLSDESC != 0 {
                a.tlsdesc = words;
                got.push(GotEnt {
                    kind: GotKind::TlsDesc,
                    sym: sr,
                    word: words,
                });
                words += 2;
            }
        };
        for &(id, f) in &need {
            let sym = self.syms.get(id);
            let mut a = Aux::default();
            let sr = SymRef::global(id);
            add_got(sr, f, &mut a, &mut got);
            if f & NEEDS_PLT != 0 {
                if f & IMPORTED != 0 || f & PREEMPTIBLE != 0 {
                    a.plt = plt.len() as u32;
                    plt.push(sr);
                } else if f & IS_IFUNC != 0 {
                    a.plt = NONE - 1 - iplt.len() as u32;
                    iplt.push(sr);
                }
            }
            if f & NEEDS_COPY != 0 && f & IMPORTED != 0 {
                let (size, align) = self.copy_size_align(id);
                copy_size = align_up(copy_size, align);
                a.copy = copyrels.len() as u32;
                copyrels.push((id, copy_size));
                copy_size += size.max(1);
                copy_align = copy_align.max(align);
            }
            if f & NEEDS_DYNSYM != 0 {
                let defined = f & IMPORTED == 0 && sym.def() != UNDEF
                    || f & NEEDS_COPY != 0
                    || f & NEEDS_CPLT != 0;
                if defined {
                    dyn_def.push(id);
                } else {
                    dyn_undef.push(id);
                }
            }
            sym.aux.store(aux.len() as u32, Ordering::Relaxed);
            aux.push(a);
        }
        // Locals: in object order, then symbol order.
        let mut local_aux = Vec::with_capacity(self.objs.len());
        for (oi, o) in self.objs.iter().enumerate() {
            let mut v = std::mem::take(&mut *o.local_needs.lock().unwrap());
            if v.is_empty() {
                local_aux.push(Vec::new());
                continue;
            }
            v.sort_unstable();
            let mut merged: Vec<(u32, u32)> = Vec::new();
            for (i, f) in v {
                match merged.last_mut() {
                    Some((j, g)) if *j == i => *g |= f,
                    _ => merged.push((i, f)),
                }
            }
            let mut mine = Vec::with_capacity(merged.len());
            for (i, f) in merged {
                let mut a = Aux::default();
                let sr = SymRef {
                    obj: oi as u32,
                    idx: i,
                };
                add_got(sr, f, &mut a, &mut got);
                if f & NEEDS_PLT != 0 {
                    a.plt = NONE - 1 - iplt.len() as u32;
                    iplt.push(sr);
                }
                mine.push((i, aux.len() as u32));
                aux.push(a);
            }
            local_aux.push(mine);
        }
        let tlsld = if self.scan.needs_tlsld.load(Ordering::Relaxed) {
            let w = words;
            got.push(GotEnt {
                kind: GotKind::TlsLd,
                sym: SymRef::global(NONE),
                word: w,
            });
            words += 2;
            Some(w)
        } else {
            None
        };
        // iplt entries follow plt entries: turn the placeholders into indices.
        let nplt = plt.len() as u32;
        for a in &mut aux {
            if a.plt != NONE && a.plt >= NONE - 1 - iplt.len() as u32 {
                a.plt = nplt + (NONE - 1 - a.plt);
            }
        }
        // Dynamic symbols: undefined first, then defined (sorted for .gnu.hash later).
        let mut dynsyms = dyn_undef;
        dynsyms.extend(dyn_def);
        if has_dynamic {
            for (k, &id) in dynsyms.iter().enumerate() {
                let ai = self.syms.get(id).aux() as usize;
                aux[ai].dynsym = k as u32 + 1;
            }
        } else {
            dynsyms.clear();
        }

        // Dynamic relocations of GOT entries.
        let (mut got_rel, mut got_sym) = (0u64, 0u64);
        for e in &got {
            let (rel, sym) = self.got_dynrels(e, shared, pic);
            got_rel += rel;
            got_sym += sym;
        }
        let mut obj_rel = Vec::with_capacity(self.objs.len());
        let mut obj_sym = Vec::with_capacity(self.objs.len());
        let mut nrel = got_rel;
        let mut nsym = got_sym + copyrels.len() as u64;
        for o in &self.objs {
            obj_rel.push(nrel);
            obj_sym.push(nsym);
            if !o.alive.load(Ordering::Relaxed) {
                continue;
            }
            for s in &o.secs {
                nrel += s.nrel as u64;
                nsym += s.nsym as u64;
            }
        }
        let sc = &mut self.scan;
        sc.aux = aux;
        sc.local_aux = local_aux;
        sc.got = got;
        sc.got_words = words as u64;
        sc.got_header = header;
        sc.tlsld = tlsld;
        sc.plt = plt;
        sc.iplt = iplt;
        sc.dynsyms = dynsyms;
        sc.copyrels = copyrels;
        sc.copy_size = copy_size;
        sc.copy_align = copy_align;
        sc.got_rel = got_rel;
        sc.got_sym = got_sym;
        sc.obj_rel = obj_rel;
        sc.obj_sym = obj_sym;
        sc.nrelative = nrel;
        sc.nsymbolic = nsym;
    }

    /// Dynamic relocations a GOT entry needs: (relative, other).
    pub fn got_dynrels(&self, e: &GotEnt, shared: bool, pic: bool) -> (u64, u64) {
        let imported = self.slot_imported(e.sym);
        let abs = self.slot_abs(e.sym);
        match e.kind {
            GotKind::Addr => {
                if imported {
                    (0, 1)
                } else if pic && !abs {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            GotKind::TpOff => {
                if imported || shared {
                    (0, 1)
                } else {
                    (0, 0)
                }
            }
            GotKind::TlsGd => {
                if imported {
                    (0, 2)
                } else if shared {
                    (0, 1)
                } else {
                    (0, 0)
                }
            }
            GotKind::TlsDesc => {
                if imported || shared || self.has_dynamic {
                    (0, 1)
                } else {
                    (0, 0)
                }
            }
            GotKind::TlsLd => {
                if shared {
                    (0, 1)
                } else {
                    (0, 0)
                }
            }
        }
    }

    pub fn slot_imported(&self, r: SymRef) -> bool {
        r.obj == NONE && r.idx != NONE && self.syms.get(r.idx).has(IMPORTED | PREEMPTIBLE)
    }

    /// The slot holds a link-time constant (absolute symbol or unresolved weak).
    pub fn slot_abs(&self, r: SymRef) -> bool {
        if r.obj != NONE {
            return self.objs[r.obj as usize].sym::<T>(r.idx).is_abs();
        }
        if r.idx == NONE {
            return true;
        }
        let s = self.syms.get(r.idx);
        s.has(IS_ABS) || s.def() == UNDEF && !s.has(IMPORTED)
    }

    fn copy_size_align(&self, id: SymId) -> (u64, u64) {
        let d = self.syms.get(id).def();
        if let super::resolve::FileRef::Dso(k) = self.file(def_prio(d)) {
            let dso = &self.dsos[k as usize];
            let s = &dso.syms[def_index(d) as usize];
            let align = if s.value == 0 {
                16
            } else {
                (1u64 << s.value.trailing_zeros().min(6)).max(1)
            };
            return (s.size, align.max(word::<T>()));
        }
        (word::<T>(), word::<T>())
    }

    /// The aux slots of a relocation's symbol.
    #[inline]
    pub fn aux_of(&self, r: SymRef) -> Option<&Aux> {
        if r.obj == NONE {
            if r.idx == NONE {
                return None;
            }
            let a = self.syms.get(r.idx).aux();
            return self.scan.aux.get(a as usize);
        }
        let v = &self.scan.local_aux[r.obj as usize];
        let i = v.binary_search_by_key(&r.idx, |e| e.0).ok()?;
        self.scan.aux.get(v[i].1 as usize)
    }
}

use super::target::word;
