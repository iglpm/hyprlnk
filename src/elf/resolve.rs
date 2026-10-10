//! The link context and symbol resolution.
//!
//! Every input (and every archive member) is parsed up front, in parallel. Each symbol keeps
//! its best definition as one packed rank (`symbols::pack`) updated with `fetch_min`; lower
//! wins: strong < weak < common < linker-defined < shared object, then the earlier file.
//! Archive members load in waves like GNU ld's archive search: a member is loaded when a
//! loaded file references a symbol whose best definition is in it. Each wave's set of members
//! depends only on the previous waves, so the result is the same on every run.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use super::config::{Bsymbolic, Config, DefsymExpr, Unresolved};
use super::input::{self, Kind};
use super::object::{Dso, Object, SecKind, Sym};
use super::script::{self, Patterns, VersionScript};
use super::symbols::*;
use super::target::Target;
use super::*;
use crate::diag::{self, Result, Timer};
use crate::fileio::Arena;
use crate::{bail, err};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRef {
    Obj(u32),
    Dso(u32),
    Internal,
}

/// A symbol the linker defines when something references it.
#[derive(Debug, Clone)]
pub enum Synth {
    GotBase,
    Dynamic,
    EhdrStart,
    End,
    Etext,
    Edata,
    BssStart,
    InitArrayStart,
    InitArrayEnd,
    FiniArrayStart,
    FiniArrayEnd,
    PreinitArrayStart,
    PreinitArrayEnd,
    RelaIpltStart,
    RelaIpltEnd,
    EhFrameHdr,
    TlsModuleBase,
    ExidxStart,
    ExidxEnd,
    GlobalPointer,
    Toc,
    DsoHandle,
    /// `__start_<section>` / `__stop_<section>`.
    Start(Vec<u8>),
    Stop(Vec<u8>),
    Defsym(DefsymExpr),
}

pub struct InternalSym {
    pub id: SymId,
    pub kind: Synth,
    pub hidden: bool,
}

pub struct Ctx<'a, T: Target> {
    pub cfg: Config,
    pub arena: &'a Arena,
    pub objs: Vec<Object<'a>>,
    pub dsos: Vec<Dso<'a>>,
    pub files: Vec<FileRef>,
    pub syms: SymbolTable<'a>,
    pub internal: Vec<InternalSym>,
    pub internal_prio: u32,
    /// Archive waves and discarded COMDAT sections, for `--time`.
    waves: usize,
    discarded: usize,
    pub entry: Option<SymId>,
    /// `-u`, `--require-defined`, the entry point, `-init`/`-fini`: kept by `--gc-sections`.
    pub roots: Vec<SymId>,
    pub version_script: Option<VersionScript>,
    pub dyn_patterns: Patterns,
    pub has_dynamic: bool,
    pub interp: Option<String>,
    pub errors: Mutex<Vec<String>>,
    pub paths: Vec<std::path::PathBuf>,
    pub loaded: Option<input::Loaded<'a>>,
    pub scan: super::scan::ScanResult,
    pub merged: Vec<super::merge::MergedSec<'a>>,
    pub ehframe: super::ehframe::EhFrameInfo,
    pub exec_stack: bool,
    /// The PLT's address, once laid out.
    pub plt_base: AtomicU64,
    /// Hashes of the output's pieces, for the build ID.
    pub bid: super::write::BuildIdSlots,
    pub thunks: super::thunks::ThunkTable,
    /// ARM: per object, (code section, its `.ARM.exidx` section), sorted.
    pub arm_exidx: Vec<Vec<(u32, u32)>>,
    pub _t: PhantomData<T>,
}

const LINKER_SYMBOLS: &[(&str, Synth, bool)] = &[
    ("_GLOBAL_OFFSET_TABLE_", Synth::GotBase, true),
    ("_DYNAMIC", Synth::Dynamic, true),
    ("__ehdr_start", Synth::EhdrStart, true),
    ("__executable_start", Synth::EhdrStart, true),
    ("_end", Synth::End, false),
    ("end", Synth::End, false),
    ("_etext", Synth::Etext, false),
    ("etext", Synth::Etext, false),
    ("__etext", Synth::Etext, false),
    ("_edata", Synth::Edata, false),
    ("edata", Synth::Edata, false),
    ("__bss_start", Synth::BssStart, false),
    ("__init_array_start", Synth::InitArrayStart, true),
    ("__init_array_end", Synth::InitArrayEnd, true),
    ("__fini_array_start", Synth::FiniArrayStart, true),
    ("__fini_array_end", Synth::FiniArrayEnd, true),
    ("__preinit_array_start", Synth::PreinitArrayStart, true),
    ("__preinit_array_end", Synth::PreinitArrayEnd, true),
    ("__rela_iplt_start", Synth::RelaIpltStart, true),
    ("__rela_iplt_end", Synth::RelaIpltEnd, true),
    ("__rel_iplt_start", Synth::RelaIpltStart, true),
    ("__rel_iplt_end", Synth::RelaIpltEnd, true),
    ("__GNU_EH_FRAME_HDR", Synth::EhFrameHdr, true),
    ("_TLS_MODULE_BASE_", Synth::TlsModuleBase, true),
    ("__exidx_start", Synth::ExidxStart, true),
    ("__exidx_end", Synth::ExidxEnd, true),
    ("__global_pointer$", Synth::GlobalPointer, false),
    (".TOC.", Synth::Toc, true),
    ("__dso_handle", Synth::DsoHandle, true),
];

fn is_c_ident(s: &[u8]) -> bool {
    !s.is_empty()
        && !s[0].is_ascii_digit()
        && s.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
}

/// A compressed section to decompress: where it is and how big it gets.
pub struct Compressed<'a> {
    pub obj: u32,
    pub sec: u32,
    pub src: &'a [u8],
    pub size: usize,
    pub zstd: bool,
}

/// Decompress sections on all threads: (object, section, contents or None if corrupt), in
/// the order given (object, then section).
pub fn inflate<'a>(
    work: &[Compressed<'a>],
    arena: &'a crate::fileio::Arena,
) -> Vec<(u32, u32, Option<&'a [u8]>)> {
    work.par_iter()
        .map(|c| {
            let out = if c.zstd {
                zstd::bulk::decompress(c.src, c.size).ok()
            } else {
                miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(c.src, c.size).ok()
            };
            let data = out.filter(|d| d.len() == c.size).map(|d| arena.alloc(d));
            (c.obj, c.sec, data)
        })
        .collect()
}

/// A defined global's rank class: an unloaded archive member's is lazy.
fn rank_class(s: &Sym, lazy: bool) -> u64 {
    if lazy {
        CLASS_LAZY
    } else if s.is_common() {
        CLASS_COMMON
    } else if s.bind() == STB_WEAK || s.bind() == STB_GNU_UNIQUE {
        CLASS_WEAK
    } else {
        CLASS_STRONG
    }
}

impl<'a, T: Target> Ctx<'a, T> {
    pub fn new(cfg: Config, arena: &'a Arena, loaded: input::Loaded<'a>) -> Result<Ctx<'a, T>> {
        let mut version_script = None;
        for p in &cfg.version_scripts {
            let text = std::fs::read_to_string(p)
                .map_err(|e| err!("cannot read version script {}: {e}", p.display()))?;
            let vs = script::parse_version_script(&text, &p.display().to_string())?;
            let merged: &mut VersionScript =
                version_script.get_or_insert_with(VersionScript::default);
            merged.nodes.extend(vs.nodes);
        }
        let mut dyn_patterns = Patterns::default();
        for p in &cfg.dynamic_lists {
            let text = std::fs::read_to_string(p)
                .map_err(|e| err!("cannot read dynamic list {}: {e}", p.display()))?;
            script::parse_dynamic_list(&text, &p.display().to_string(), &mut dyn_patterns)?;
        }
        for s in &cfg.export_dynamic_symbols {
            dyn_patterns.insert(s);
        }
        Ok(Ctx {
            cfg,
            arena,
            objs: Vec::new(),
            dsos: Vec::new(),
            files: Vec::new(),
            syms: SymbolTable::intern(&[]),
            internal: Vec::new(),
            internal_prio: 0,
            waves: 0,
            discarded: 0,
            entry: None,
            roots: Vec::new(),
            version_script,
            dyn_patterns,
            has_dynamic: false,
            interp: None,
            errors: Mutex::new(Vec::new()),
            paths: Vec::new(),
            loaded: Some(loaded),
            scan: Default::default(),
            merged: Vec::new(),
            ehframe: Default::default(),
            exec_stack: false,
            plt_base: AtomicU64::new(0),
            bid: Default::default(),
            thunks: Default::default(),
            arm_exidx: Vec::new(),
            _t: PhantomData,
        })
    }

    pub fn error(&self, msg: String) {
        self.errors.lock().unwrap().push(msg);
    }

    /// Fail with every error collected so far (sorted: threads report in any order).
    pub fn check_errors(&self) -> Result<()> {
        let mut errs = std::mem::take(&mut *self.errors.lock().unwrap());
        if errs.is_empty() {
            return Ok(());
        }
        errs.sort();
        errs.dedup();
        let n = errs.len();
        for e in errs.iter().take(n.saturating_sub(1)).take(49) {
            diag::error(e);
        }
        if n > 50 {
            diag::error(format!("... and {} more errors", n - 50));
        }
        Err(diag::Error(errs.pop().unwrap()))
    }

    pub fn file(&self, prio: u32) -> FileRef {
        self.files
            .get(prio as usize)
            .copied()
            .unwrap_or(FileRef::Internal)
    }

    /// Parse every input in parallel and intern their global symbols.
    pub fn parse(&mut self, timer: &mut Timer) -> Result<()> {
        let loaded = self.loaded.take().unwrap();
        self.paths = loaded.paths;
        // Short-lived, and an object is the common case: not worth a box (an object is bigger
        // where mutexes are, on macOS).
        #[allow(clippy::large_enum_variant)]
        enum Parsed<'a> {
            Obj(Object<'a>),
            Dso(Dso<'a>),
        }
        // Big files get a task each and start first, so none is left to parse at the end on
        // its own; the many small ones go in the usual batches beside them.
        let parse = |(prio, f): (usize, input::File<'a>)| -> (usize, Result<Parsed<'a>>) {
            let r = (|| {
                Ok(match f.kind {
                    Kind::Object { member, .. } => {
                        Parsed::Obj(Object::parse::<T>(f.name, f.data, prio as u32, member)?)
                    }
                    Kind::Dso { as_needed } => {
                        Parsed::Dso(Dso::parse::<T>(f.name, f.data, prio as u32, as_needed)?)
                    }
                })
            })();
            (prio, r)
        };
        let total: usize = loaded.files.iter().map(|f| f.data.len()).sum();
        let big_at = (total / (rayon::current_num_threads() * 8)).max(1 << 20);
        let (mut big, small): (Vec<_>, Vec<_>) = loaded
            .files
            .into_iter()
            .enumerate()
            .partition(|(_, f)| f.data.len() >= big_at);
        big.sort_by_key(|(_, f)| std::cmp::Reverse(f.data.len()));
        let (mut done, rest): (Vec<_>, Vec<_>) = rayon::join(
            || big.into_par_iter().with_max_len(1).map(parse).collect(),
            || small.into_par_iter().map(parse).collect(),
        );
        done.extend(rest);
        done.sort_unstable_by_key(|d| d.0);
        let parsed = done.into_iter().map(|d| d.1);
        for p in parsed {
            match p? {
                Parsed::Obj(o) => {
                    self.files.push(FileRef::Obj(self.objs.len() as u32));
                    self.objs.push(o);
                }
                Parsed::Dso(d) => {
                    self.files.push(FileRef::Dso(self.dsos.len() as u32));
                    self.dsos.push(d);
                }
            }
        }
        self.internal_prio = self.files.len() as u32;
        if self.objs.is_empty() {
            bail!("no input files");
        }
        timer.phase("parse inputs");

        let mut mk = super::prof::Marks::new();
        let wraps: Vec<&[u8]> = self.cfg.wraps.iter().map(|w| w.as_bytes()).collect();
        let arena = self.arena;
        let named =
            |n: &'a [u8], def: u64| (n, if n.is_empty() { [0; 2] } else { hash_name(n) }, def);
        // Per file: each global symbol's name, hash and rank; taken by the interning pass,
        // which also keeps each symbol's best definition (unloaded archive members: lazy).
        type Names<'n> = Option<Vec<Named<'n>>>;
        let mut obj_names: Vec<Names<'a>> = self
            .objs
            .par_iter()
            .map(|o| {
                let lazy = !o.alive.load(Ordering::Relaxed);
                // A big object's symbols are split between threads too.
                let v: Vec<Named<'a>> = (o.first_global..o.nsyms)
                    .into_par_iter()
                    .with_min_len(4096)
                    .map(|i| {
                        let s = o.sym::<T>(i);
                        let def = if s.is_undef() {
                            UNDEF
                        } else {
                            pack(rank_class(&s, lazy), o.prio, i)
                        };
                        let mut n = o.sym_name(&s);
                        if let Some(at) = memchr::memchr(b'@', n) {
                            // `foo@@VER` defines foo; `foo@VER` references bind to foo.
                            if s.is_undef() || n.get(at + 1) == Some(&b'@') {
                                n = &n[..at];
                            }
                        }
                        if s.is_undef() && !wraps.is_empty() {
                            if wraps.contains(&n) {
                                let mut w = b"__wrap_".to_vec();
                                w.extend_from_slice(n);
                                return named(arena.alloc(w), def);
                            }
                            if let Some(real) = n.strip_prefix(b"__real_")
                                && wraps.contains(&real)
                            {
                                return named(real, def);
                            }
                        }
                        named(n, def)
                    })
                    .collect();
                Some(v)
            })
            .collect();
        let mut dso_names: Vec<Names<'a>> = self
            .dsos
            .par_iter()
            .map(|d| {
                Some(
                    d.syms
                        .iter()
                        .enumerate()
                        .map(|(k, s)| match (s.defined, s.hidden) {
                            (true, true) => named(&[][..], UNDEF),
                            (true, false) => named(s.name, pack(CLASS_LAZY, d.prio, k as u32)),
                            (false, _) => named(s.name, UNDEF),
                        })
                        .collect(),
                )
            })
            .collect();
        mk.mark("names and hashes");
        let mut batches = Vec::with_capacity(self.objs.len() + self.dsos.len());
        for f in &self.files {
            match *f {
                FileRef::Obj(i) => batches.push(Batch {
                    names: obj_names[i as usize].take().unwrap(),
                    out: &self.objs[i as usize].sym_ids,
                }),
                FileRef::Dso(i) => batches.push(Batch {
                    names: dso_names[i as usize].take().unwrap(),
                    out: &self.dsos[i as usize].sym_ids,
                }),
                FileRef::Internal => {}
            }
        }
        mk.mark("batches");
        self.syms = SymbolTable::intern(&batches);
        mk.mark("intern");
        drop(batches);
        mk.mark("drop batches");
        timer.phase("intern symbols");
        Ok(())
    }

    fn intern_name(&mut self, name: &str) -> SymId {
        let b = self.arena.alloc(name.as_bytes().to_vec());
        self.syms.insert(b)
    }

    fn define_internal(&mut self) {
        for (name, kind, hidden) in LINKER_SYMBOLS {
            if let Some(id) = self.syms.find(name.as_bytes()) {
                self.internal.push(InternalSym {
                    id,
                    kind: kind.clone(),
                    hidden: *hidden,
                });
            }
        }
        if self.cfg.shared {
            // A shared object's `_end` and friends would interpose the executable's.
            for s in &mut self.internal {
                s.hidden = true;
            }
        }
        // `__start_foo` / `__stop_foo` for sections named like C identifiers: looked for in
        // every name, on all threads.
        let mut wanted: Vec<(SymId, Synth)> = self
            .syms
            .shards
            .par_iter()
            .enumerate()
            .flat_map_iter(|(sh, v)| {
                v.iter().enumerate().filter_map(move |(i, sym)| {
                    let id = ((sh as u32) << 24) | i as u32;
                    let n = sym.name;
                    if !n.starts_with(b"__st") {
                        return None;
                    }
                    if let Some(sec) = n.strip_prefix(b"__start_")
                        && is_c_ident(sec)
                    {
                        Some((id, Synth::Start(sec.to_vec())))
                    } else if let Some(sec) = n.strip_prefix(b"__stop_")
                        && is_c_ident(sec)
                    {
                        Some((id, Synth::Stop(sec.to_vec())))
                    } else {
                        None
                    }
                })
            })
            .collect();
        wanted.sort_by_key(|(id, _)| *id);
        for (id, kind) in wanted {
            self.internal.push(InternalSym {
                id,
                kind,
                hidden: true,
            });
        }
        for (name, expr) in self.cfg.defsyms.clone() {
            let id = self.intern_name(&name);
            if let DefsymExpr::Symbol(target, _) = &expr {
                let t = self.intern_name(target);
                self.roots.push(t);
            }
            self.internal.push(InternalSym {
                id,
                kind: Synth::Defsym(expr),
                hidden: false,
            });
        }
    }

    fn rank_object(&self, o: &Object<'a>, lazy: bool) {
        for i in o.first_global..o.nsyms {
            let s = o.sym::<T>(i);
            if s.is_undef() {
                continue;
            }
            let id = o.global_id(i);
            if id == NONE {
                continue;
            }
            if !lazy
                && s.shndx < SHN_LORESERVE
                && o.secs.get(s.shndx as usize).map(|x| x.kind) == Some(SecKind::Discarded)
            {
                continue;
            }
            self.syms
                .get(id)
                .def
                .fetch_min(pack(rank_class(&s, lazy), o.prio, i), Ordering::Relaxed);
        }
    }

    fn rank_dsos_and_internal(&self) {
        self.rank_dsos();
        self.rank_internal();
    }

    fn rank_dsos(&self) {
        self.dsos.par_iter().for_each(|d| {
            for (k, s) in d.syms.iter().enumerate() {
                if !s.defined || s.hidden {
                    continue;
                }
                let id = d.sym_ids[k].load(Ordering::Relaxed);
                if id != NONE {
                    self.syms
                        .get(id)
                        .def
                        .fetch_min(pack(CLASS_LAZY, d.prio, k as u32), Ordering::Relaxed);
                }
            }
        });
    }

    fn rank_internal(&self) {
        for (k, s) in self.internal.iter().enumerate() {
            self.syms.get(s.id).def.fetch_min(
                pack(CLASS_INTERNAL, self.internal_prio, k as u32),
                Ordering::Relaxed,
            );
        }
    }

    /// Which files are linked (archive waves) and which COMDAT groups are kept; after this
    /// the set of sections that can be linked is fixed. [`Ctx::finish_resolve`] follows.
    pub fn resolve(&mut self, timer: &mut Timer) -> Result<()> {
        self.define_internal();
        let entry_name = self
            .cfg
            .entry
            .clone()
            .or_else(|| (!self.cfg.shared).then(|| "_start".to_string()));
        if let Some(e) = &entry_name {
            let id = self.intern_name(e);
            self.entry = Some(id);
            self.roots.push(id);
        }
        for u in self
            .cfg
            .undefined
            .clone()
            .iter()
            .chain(&self.cfg.require_defined.clone())
        {
            let id = self.intern_name(u);
            self.roots.push(id);
        }
        for f in [self.cfg.init.clone(), self.cfg.fini.clone()] {
            if let Some(id) = self.syms.find(f.as_bytes()) {
                self.roots.push(id);
            }
        }

        let mut mk = super::prof::Marks::new();
        // Archive members, in waves. Interning ranked the files' definitions already.
        self.rank_internal();
        mk.mark("resolve: rank all");
        let mut frontier: Vec<u32> = (0..self.objs.len() as u32)
            .filter(|&i| self.objs[i as usize].alive.load(Ordering::Relaxed))
            .collect();
        let mut waves = 0;
        let mut first = true;
        loop {
            let roots = if first {
                self.roots.clone()
            } else {
                Vec::new()
            };
            first = false;
            let mut fresh: Vec<u32> = frontier
                .par_iter()
                .flat_map_iter(|&oi| {
                    let o = &self.objs[oi as usize];
                    let mut found = Vec::new();
                    for i in o.first_global..o.nsyms {
                        let s = o.sym::<T>(i);
                        if !s.is_undef() || s.bind() == STB_WEAK {
                            continue;
                        }
                        let id = o.global_id(i);
                        if id != NONE {
                            self.wake(id, &mut found);
                        }
                    }
                    found
                })
                .collect();
            for id in roots {
                self.wake(id, &mut fresh);
            }
            if fresh.is_empty() {
                break;
            }
            waves += 1;
            fresh.sort_unstable();
            fresh
                .par_iter()
                .for_each(|&oi| self.rank_object(&self.objs[oi as usize], false));
            frontier = fresh;
        }

        mk.mark("resolve: waves");
        if let Some(o) = self
            .objs
            .iter()
            .find(|o| o.compressed_debug && o.alive.load(Ordering::Relaxed))
        {
            crate::diag::warn(format!(
                "{}: sections compressed in an unknown format are left out",
                o.name
            ));
        }
        // COMDAT groups: the first loaded file's copy wins.
        let mut groups: HashMap<&[u8], u32> = HashMap::new();
        let mut discarded = 0usize;
        for o in &mut self.objs {
            if !o.alive.load(Ordering::Relaxed) {
                continue;
            }
            for g in &o.groups {
                if groups.contains_key(g.signature) {
                    for &m in &g.members {
                        o.secs[m as usize].kind = SecKind::Discarded;
                        discarded += 1;
                    }
                } else {
                    groups.insert(g.signature, o.prio);
                }
            }
        }
        drop(groups);
        mk.mark("resolve: COMDAT groups");
        self.discarded = discarded;
        self.waves = waves;
        timer.phase("load archive members");
        Ok(())
    }

    /// Final resolution among the loaded files, undefined and duplicate symbols, symbol
    /// properties.
    pub fn finish_resolve(&mut self, timer: &mut Timer) -> Result<()> {
        let mut mk = super::prof::Marks::new();
        let (waves, discarded) = (self.waves, self.discarded);
        // Final resolution among loaded files.
        self.syms
            .par_for_each(|_, s| s.def.store(UNDEF, Ordering::Relaxed));
        self.objs.par_iter().for_each(|o| {
            if o.alive.load(Ordering::Relaxed) {
                self.rank_and_note(o);
            }
        });
        self.rank_dsos_and_internal();
        self.note_references();
        mk.mark("resolve: final ranks and references");
        if timer.enabled() {
            let live = self
                .objs
                .iter()
                .filter(|o| o.alive.load(Ordering::Relaxed))
                .count();
            timer.detail(format!(
                "{} objects ({} loaded), {} shared objects, {} symbols, {} archive waves, {} COMDAT sections discarded",
                self.objs.len(),
                live,
                self.dsos.len(),
                self.syms.len(),
                waves,
                discarded
            ));
        }
        self.check_undefined_and_duplicates()?;
        mk.mark("resolve: undefined and duplicates");
        self.compute_properties();
        mk.mark("resolve: properties");
        timer.phase("resolve symbols");
        Ok(())
    }

    /// The compressed sections (`-gz`) of the files that are linked, to decompress; stripped
    /// debug sections stay as they are. Borrows only the inputs, so it can run beside phases
    /// that change the context.
    pub fn compressed_sections(&self) -> Vec<Compressed<'a>> {
        let strip_debug = self.cfg.strip != super::config::Strip::None;
        let mut v = Vec::new();
        for (oi, o) in self.objs.iter().enumerate() {
            if o.compressed.is_empty() || !o.alive.load(Ordering::Relaxed) {
                continue;
            }
            for &(si, off, len, ty) in &o.compressed {
                if strip_debug && o.sec_name::<T>(si).starts_with(b".debug") {
                    continue;
                }
                v.push(Compressed {
                    obj: oi as u32,
                    sec: si,
                    src: &o.data[off as usize..(off + len) as usize],
                    size: o.secs[si as usize].size as usize,
                    zstd: ty != super::object::ELFCOMPRESS_ZLIB,
                });
            }
        }
        v
    }

    /// Hand each object its decompressed sections.
    pub fn set_inflated(&mut self, done: Vec<(u32, u32, Option<&'a [u8]>)>) -> Result<()> {
        for (oi, si, data) in done {
            let o = &mut self.objs[oi as usize];
            let Some(data) = data else {
                bail!(
                    "{}: cannot decompress section {}",
                    o.name,
                    String::from_utf8_lossy(o.sec_name::<T>(si))
                );
            };
            o.inflated.push((si, data));
        }
        Ok(())
    }

    /// `id` is referenced: if its best definition is an unloaded archive member, load it.
    fn wake(&self, id: SymId, found: &mut Vec<u32>) {
        let d = self.syms.get(id).def();
        if d == UNDEF || def_class(d) != CLASS_LAZY {
            return;
        }
        if let FileRef::Obj(j) = self.file(def_prio(d)) {
            let m = &self.objs[j as usize];
            if !m.alive.load(Ordering::Relaxed) && !m.alive.swap(true, Ordering::Relaxed) {
                found.push(j);
            }
        }
    }

    /// A loaded file's part of the final resolution, in one walk over its symbols: its
    /// definitions' ranks (not those in discarded COMDAT groups), and for every symbol the most
    /// restrictive visibility, the first file referencing it and how.
    fn rank_and_note(&self, o: &Object<'a>) {
        for i in o.first_global..o.nsyms {
            let s = o.sym::<T>(i);
            let id = o.global_id(i);
            if id == NONE {
                continue;
            }
            let sym = self.syms.get(id);
            let vis = match s.vis() {
                STV_DEFAULT => 0,
                STV_PROTECTED => 1,
                _ => 2,
            };
            if vis > 0 && sym.vis.load(Ordering::Relaxed) < vis {
                sym.vis.fetch_max(vis, Ordering::Relaxed);
            }
            if s.is_undef() {
                if sym.first_ref.load(Ordering::Relaxed) > o.prio {
                    sym.first_ref.fetch_min(o.prio, Ordering::Relaxed);
                }
                let mut f = REFERENCED;
                if s.bind() != STB_WEAK {
                    f |= STRONG_REF;
                }
                sym.set(f);
            } else if !(s.shndx < SHN_LORESERVE
                && o.secs.get(s.shndx as usize).map(|x| x.kind) == Some(SecKind::Discarded))
            {
                sym.def
                    .fetch_min(pack(rank_class(&s, false), o.prio, i), Ordering::Relaxed);
            }
        }
    }

    /// References from outside the files: roots, and shared objects' undefined symbols.
    fn note_references(&self) {
        for &r in &self.roots {
            let s = self.syms.get(r);
            s.set(REFERENCED | STRONG_REF);
            s.first_ref.fetch_min(self.internal_prio, Ordering::Relaxed);
        }
        self.dsos.par_iter().for_each(|d| {
            for (k, s) in d.syms.iter().enumerate() {
                if s.defined {
                    continue;
                }
                let id = d.sym_ids[k].load(Ordering::Relaxed);
                if id != NONE {
                    self.syms.get(id).set(REF_BY_DSO);
                }
            }
        });
    }

    fn check_undefined_and_duplicates(&self) -> Result<()> {
        let shared_ok = self.cfg.shared && !self.cfg.no_undefined;
        let policy = self.cfg.unresolved_objects;
        let undefined: Mutex<Vec<(Vec<u8>, String)>> = Mutex::new(Vec::new());
        let duplicates: Mutex<Vec<(Vec<u8>, String, String)>> = Mutex::new(Vec::new());
        self.objs.par_iter().for_each(|o| {
            if !o.alive.load(Ordering::Relaxed) {
                return;
            }
            for i in o.first_global..o.nsyms {
                let s = o.sym::<T>(i);
                let id = o.global_id(i);
                if id == NONE {
                    continue;
                }
                let sym = self.syms.get(id);
                let d = sym.def();
                if s.is_undef() {
                    // An as-needed shared object is needed if it defines what is referenced.
                    if d != UNDEF
                        && def_class(d) == CLASS_LAZY
                        && s.bind() != STB_WEAK
                        && let FileRef::Dso(k) = self.file(def_prio(d))
                    {
                        self.dsos[k as usize].used.store(true, Ordering::Relaxed);
                    }
                    // A hidden symbol must be defined here; others may come from elsewhere at
                    // run time when linking a shared object.
                    let hidden = sym.vis.load(Ordering::Relaxed) == 2;
                    if d == UNDEF
                        && s.bind() != STB_WEAK
                        && (hidden || !shared_ok && policy != Unresolved::Ignore)
                    {
                        undefined
                            .lock()
                            .unwrap()
                            .push((sym.name.to_vec(), o.name.clone()));
                    }
                } else if !self.cfg.allow_multiple_definition
                    && s.bind() == STB_GLOBAL
                    && !s.is_common()
                    && s.shndx < SHN_LORESERVE
                    && o.secs.get(s.shndx as usize).map(|x| x.kind) != Some(SecKind::Discarded)
                    && d != pack(CLASS_STRONG, o.prio, i)
                    && def_class(d) == CLASS_STRONG
                {
                    let other = match self.file(def_prio(d)) {
                        FileRef::Obj(j) => self.objs[j as usize].name.clone(),
                        _ => "<linker>".to_string(),
                    };
                    duplicates
                        .lock()
                        .unwrap()
                        .push((sym.name.to_vec(), other, o.name.clone()));
                }
            }
        });
        for &r in &self.roots {
            let s = self.syms.get(r);
            if s.def() == UNDEF
                && self
                    .cfg
                    .require_defined
                    .iter()
                    .any(|n| n.as_bytes() == s.name)
            {
                undefined
                    .lock()
                    .unwrap()
                    .push((s.name.to_vec(), "--require-defined".into()));
            }
        }
        let mut errs = Vec::new();
        let mut undefined = undefined.into_inner().unwrap();
        undefined.sort();
        let mut by_sym: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
        for (n, f) in undefined {
            match by_sym.last_mut() {
                Some((last, files)) if *last == n => files.push(f),
                _ => by_sym.push((n, vec![f])),
            }
        }
        for (n, files) in &by_sym {
            let mut msg = format!("undefined symbol: {}", diag::symbol(n));
            for f in files.iter().take(3) {
                msg.push_str(&format!("\n>>> referenced by {f}"));
            }
            if files.len() > 3 {
                msg.push_str(&format!("\n>>> referenced {} more times", files.len() - 3));
            }
            errs.push(msg);
        }
        let mut dups = duplicates.into_inner().unwrap();
        dups.sort();
        dups.dedup_by(|a, b| a.0 == b.0);
        for (n, a, b) in &dups {
            errs.push(format!(
                "duplicate symbol: {}\n>>> defined in {a}\n>>> defined in {b}",
                diag::symbol(n)
            ));
        }
        if errs.is_empty() {
            return Ok(());
        }
        if policy == Unresolved::Warn && dups.is_empty() {
            for e in &errs {
                diag::warn(e);
            }
            return Ok(());
        }
        let last = errs.pop().unwrap();
        for e in errs.iter().take(50) {
            diag::error(e);
        }
        Err(diag::Error(last))
    }

    /// Whether `name` is exported by `--dynamic-list`, `--export-dynamic-symbol` or `-E`.
    fn dyn_listed(&self, name: &[u8]) -> bool {
        !self.dyn_patterns.is_empty() && self.dyn_patterns.matches(name)
    }

    /// Per-symbol properties used by everything after: imported, exported, preemptible, type.
    fn compute_properties(&mut self) {
        self.has_dynamic = self.cfg.pic()
            || self
                .dsos
                .iter()
                .any(|d| !d.as_needed || d.used.load(Ordering::Relaxed));
        if self.has_dynamic
            && !self.cfg.shared
            && !self.cfg.no_dynamic_linker
            && !(self.cfg.static_ && self.dsos.is_empty())
        {
            self.interp = self.cfg.dynamic_linker.clone();
        }
        let shared = self.cfg.shared;
        let has_dynamic = self.has_dynamic;
        let export_all = self.cfg.export_dynamic;
        let vs = self.version_script.as_ref();
        let named_versions = vs.is_some_and(|v| !v.is_anonymous());
        self.syms.par_for_each(|_, sym| {
            let d = sym.def();
            let vis = sym.vis.load(Ordering::Relaxed);
            let mut f = 0;
            if d == UNDEF {
                if shared && vis == 0 && sym.has(REFERENCED) {
                    f |= IMPORTED | PREEMPTIBLE;
                }
                sym.set(f);
                return;
            }
            match def_class(d) {
                CLASS_LAZY => {
                    if let FileRef::Dso(k) = self.file(def_prio(d)) {
                        let ds = &self.dsos[k as usize].syms[def_index(d) as usize];
                        f |= IMPORTED | PREEMPTIBLE;
                        match ds.ty() {
                            STT_FUNC | STT_GNU_IFUNC => f |= IS_FUNC,
                            STT_TLS => f |= IS_TLS,
                            _ => {}
                        }
                        sym.ver.store(ds.ver as u32, Ordering::Relaxed);
                    }
                }
                CLASS_INTERNAL => {
                    f |= LINKER_DEFINED;
                    let k = def_index(d) as usize;
                    if self.internal[k].hidden {
                        f |= LOCALIZED;
                    } else if shared || export_all {
                        f |= EXPORTED;
                    }
                    if matches!(self.internal[k].kind, Synth::Defsym(DefsymExpr::Value(_))) {
                        f |= IS_ABS;
                    }
                }
                _ => {
                    let FileRef::Obj(oi) = self.file(def_prio(d)) else {
                        return;
                    };
                    let o = &self.objs[oi as usize];
                    let s = o.sym::<T>(def_index(d));
                    match s.ty() {
                        STT_FUNC => f |= IS_FUNC,
                        STT_GNU_IFUNC => f |= IS_FUNC | IS_IFUNC,
                        STT_TLS => f |= IS_TLS,
                        _ => {}
                    }
                    if s.is_abs() {
                        f |= IS_ABS;
                    }
                    // Exported: in `.dynsym`. Localized: hidden, or made local by a version
                    // script or `--exclude-libs` — a local symbol in `.symtab` too. A symbol an
                    // executable simply doesn't export stays global there.
                    let mut localized = vis == 2;
                    let mut exported = !localized
                        && (shared
                            || has_dynamic
                                && (export_all
                                    || sym.has(REF_BY_DSO)
                                    || self.dyn_listed(sym.name)));
                    let mut ver = VER_NDX_GLOBAL as u32;
                    if exported && let Some(vs) = vs {
                        match vs.assign(sym.name) {
                            Some(None) => {
                                exported = sym.has(REF_BY_DSO) && !shared;
                                localized = !exported;
                            }
                            Some(Some(i)) if named_versions => ver = i as u32 + 2,
                            Some(Some(_)) | None => {}
                        }
                    }
                    if exported && !self.cfg.exclude_libs.is_empty() && o.member {
                        let lib = o.name.split('(').next().unwrap_or("");
                        let base = std::path::Path::new(lib)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if self
                            .cfg
                            .exclude_libs
                            .iter()
                            .any(|l| l == "ALL" || *l == base)
                        {
                            exported = false;
                            localized = true;
                        }
                    }
                    sym.ver.store(ver, Ordering::Relaxed);
                    if exported {
                        f |= EXPORTED;
                        let symbolic = match self.cfg.bsymbolic {
                            Bsymbolic::All => true,
                            Bsymbolic::Functions => f & IS_FUNC != 0,
                            Bsymbolic::NonWeakFunctions => f & IS_FUNC != 0 && s.bind() != STB_WEAK,
                            Bsymbolic::NonWeak => s.bind() != STB_WEAK,
                            Bsymbolic::None => false,
                        };
                        let listed_only = shared
                            && !self.cfg.dynamic_lists.is_empty()
                            && !self.dyn_listed(sym.name);
                        if shared && vis == 0 && !symbolic && !listed_only {
                            f |= PREEMPTIBLE;
                        }
                    } else if localized {
                        f |= LOCALIZED;
                    }
                }
            }
            sym.set(f);
        });
        let mut exec_stack = self.cfg.z_execstack;
        for o in &self.objs {
            if o.alive.load(Ordering::Relaxed) && o.exec_stack {
                exec_stack = true;
            }
        }
        self.exec_stack = exec_stack && !self.cfg.shared || self.cfg.z_execstack;
    }

    /// Where a global symbol is defined: (object, symbol index) if in a loaded object.
    #[inline]
    pub fn def_obj(&self, id: SymId) -> Option<(&Object<'a>, u32)> {
        let d = self.syms.get(id).def();
        if d == UNDEF || def_class(d) > CLASS_COMMON {
            return None;
        }
        match self.file(def_prio(d)) {
            FileRef::Obj(i) => Some((&self.objs[i as usize], def_index(d))),
            _ => None,
        }
    }
}
