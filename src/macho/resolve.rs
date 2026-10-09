//! Inputs and symbol resolution: parallel parsing in waves, merged in a fixed order for determinism.
//!
//! Precedence follows ld64.lld: definitions in objects beat dylib exports; between an archive
//! and a dylib offering the same symbol, the one earlier on the command line wins; strong
//! definitions beat weak ones, and among weak ones the first wins.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use super::config::{Arch, Config, InputKind, LoadFlags, OutputKind, Undefined};
use super::object::{ExtKind, FileKind, NONE, ObjFile, fat_slice, identify};
use super::sdk::SearchPaths;
use super::symtab::{Def, SymId, SymbolTable, Synthetic, hash_name};
use super::tbd::{self, Interface};
use super::*;
use crate::archive::{Archive, ArchiveSymbol};
use crate::diag::{self, Result, Timer};
use crate::fileio::{self, Arena};
use crate::{bail, err};

pub struct ArchiveFile<'a> {
    pub path: String,
    pub ar: Archive<'a>,
}

pub struct DylibFile {
    pub install_name: String,
    pub current_version: u32,
    pub compat_version: u32,
    pub path: String,
    pub flags: LoadFlags,
    /// Linked by name on the command line (or by a `$ld$previous$` move): gets a load command.
    pub explicit: bool,
    /// Pulled in by an object's `LC_LINKER_OPTION`: a load command only when used.
    pub auto_linked: bool,
    pub used: AtomicBool,
    pub ordinal: u32,
}

enum Pending<'a> {
    Object {
        data: &'a [u8],
        name: String,
        mtime: u64,
    },
    Member {
        archive: u32,
        offset: u32,
    },
}

enum Loaded<'a> {
    Object(&'a [u8]),
    Archive(Archive<'a>, Vec<u64>),
    Dylib(Vec<Interface<'a>>, Vec<String>),
}

struct LoadedFile<'a> {
    path: PathBuf,
    flags: LoadFlags,
    key: (u64, u64),
    mtime: u64,
    what: Loaded<'a>,
}

#[derive(Default)]
struct RunStats {
    waves: usize,
    parse: Duration,
    merge: Duration,
}

pub struct Linker<'a> {
    pub cfg: Config,
    pub arch: Arch,
    pub arena: &'a Arena,
    pub search: SearchPaths,
    pub objs: Vec<ObjFile<'a>>,
    pub archives: Vec<ArchiveFile<'a>>,
    pub dylibs: Vec<DylibFile>,
    pub symtab: SymbolTable<'a>,
    pub entry: Option<SymId>,
    pub roots: Vec<SymId>,
    /// Section boundary symbols by (segment, section) name, resolved after layout.
    pub boundaries: Vec<(Vec<u8>, Vec<u8>)>,
    pub header_syms: Vec<SymId>,
    pub zero_mtime: bool,
    /// Rebases and binds found while marking, and pointers in read-only sections.
    pub sites: Vec<super::gc::Site>,
    pub text_relocs: Vec<String>,
    pub got: Vec<SymId>,
    pub stubs: Vec<SymId>,
    pub tlvps: Vec<SymId>,
    pub auth_got: Vec<SymId>,
    /// Deduplicated literals: the (object, atom) written for each.
    pub lits: Vec<(u32, u32)>,
    pub commons: Vec<(SymId, u64)>,
    pub commons_size: u64,
    pub commons_align: u8,
    /// `_objc_msgSend$<selector>` stubs: (symbol, selector), and `_objc_msgSend` itself.
    pub objc_stubs: Vec<(SymId, &'a [u8])>,
    pub objc_msgsend: Option<SymId>,

    pending: Vec<Pending<'a>>,
    fetched: HashSet<(u32, u32)>,
    visited: HashSet<(u64, u64)>,
    dylib_by_name: HashMap<String, u32>,
    auto_link_pending: Vec<String>,
    auto_link_seen: HashSet<String>,
    aliases: Vec<(SymId, SymId)>,
    errors: usize,
}

impl<'a> Linker<'a> {
    pub fn new(cfg: Config, arena: &'a Arena) -> Result<Linker<'a>> {
        let arch = match cfg.arch {
            Some(a) => a,
            None => detect_arch(&cfg)?,
        };
        let search = SearchPaths::new(&cfg);
        Ok(Linker {
            arch,
            search,
            arena,
            objs: Vec::new(),
            archives: Vec::new(),
            dylibs: Vec::new(),
            symtab: SymbolTable::with_capacity(1 << 16),
            entry: None,
            roots: Vec::new(),
            boundaries: Vec::new(),
            header_syms: Vec::new(),
            zero_mtime: std::env::var_os("ZERO_AR_DATE").is_some(),
            sites: Vec::new(),
            text_relocs: Vec::new(),
            got: Vec::new(),
            stubs: Vec::new(),
            tlvps: Vec::new(),
            auth_got: Vec::new(),
            lits: Vec::new(),
            commons: Vec::new(),
            commons_size: 0,
            commons_align: 0,
            objc_stubs: Vec::new(),
            objc_msgsend: None,
            pending: Vec::new(),
            fetched: HashSet::new(),
            visited: HashSet::new(),
            dylib_by_name: HashMap::new(),
            auto_link_pending: Vec::new(),
            auto_link_seen: HashSet::new(),
            aliases: Vec::new(),
            errors: 0,
            cfg,
        })
    }

    fn bytes(&self, s: &[u8]) -> &'a [u8] {
        let arena: &'a Arena = self.arena;
        arena.alloc(s.to_vec())
    }

    fn intern_str(&mut self, name: &str) -> SymId {
        let b = self.bytes(name.as_bytes());
        self.symtab.intern(b, hash_name(b), NONE).0
    }

    pub fn tbd_target(&self) -> tbd::Target {
        tbd::Target {
            arch: self.arch,
            platform: self.cfg.platform,
            min_version: self.cfg.min_version,
        }
    }

    pub fn resolve(&mut self, timer: &mut Timer) -> Result<()> {
        self.define_synthetic();
        for name in self.cfg.forced_undefined.clone() {
            let id = self.intern_str(&name);
            self.roots.push(id);
            let s = self.symtab.get_mut(id);
            s.strong_ref = true;
        }
        if self.cfg.kind == OutputKind::Execute {
            let name = self
                .cfg
                .entry
                .clone()
                .unwrap_or_else(|| "_main".to_string());
            let id = self.intern_str(&name);
            self.symtab.get_mut(id).strong_ref = true;
            self.entry = Some(id);
            self.roots.push(id);
        }

        self.load_inputs()?;
        timer.phase("open inputs");

        for name in self.cfg.forced_undefined.clone() {
            if let Some(id) = self.symtab.find(name.as_bytes()) {
                self.reference(id);
            }
        }
        if let Some(e) = self.entry {
            self.reference(e);
        }

        let mut stats = RunStats::default();
        loop {
            self.run(&mut stats)?;
            if self.objc_msgsend.is_none() && self.wants_objc_stubs() {
                // Selector stubs call `_objc_msgSend`, which may come from an archive.
                let id = self.intern_str("_objc_msgSend");
                self.symtab.get_mut(id).strong_ref = true;
                self.objc_msgsend = Some(id);
                self.reference(id);
                continue;
            }
            if !self.auto_link()? && self.pending.is_empty() {
                break;
            }
        }
        self.resolve_remaining()?;
        if timer.enabled() {
            let atoms: usize = self.objs.iter().map(|o| o.atoms.len()).sum();
            timer.detail(format!(
                "{} objects, {} archives, {} dylibs, {} atoms, {} symbols",
                self.objs.len(),
                self.archives.len(),
                self.dylibs.len(),
                atoms,
                self.symtab.len()
            ));
            timer.detail(format!(
                "{} waves: parsing {:.2} ms, merging {:.2} ms",
                stats.waves,
                stats.parse.as_secs_f64() * 1e3,
                stats.merge.as_secs_f64() * 1e3,
            ));
        }
        timer.phase("resolve symbols");
        Ok(())
    }

    fn define_synthetic(&mut self) {
        let header = match self.cfg.kind {
            OutputKind::Execute => "__mh_execute_header",
            OutputKind::Dylib => "__mh_dylib_header",
            OutputKind::Bundle => "__mh_bundle_header",
        };
        for name in [header, "___dso_handle"] {
            let id = self.intern_str(name);
            let s = self.symtab.get_mut(id);
            s.def = Def::Synthetic(Synthetic::Header);
            s.private_extern = name != "__mh_execute_header";
            if name == "__mh_execute_header" {
                s.referenced_dynamically = true;
                s.no_dead_strip = true;
            }
            self.header_syms.push(id);
        }
    }

    fn run(&mut self, stats: &mut RunStats) -> Result<()> {
        while !self.pending.is_empty() {
            stats.waves += 1;
            let t = Instant::now();
            let wave = std::mem::take(&mut self.pending);
            let this = &*self;
            let parsed: Vec<Result<Option<ObjFile<'a>>>> =
                wave.par_iter().map(|p| this.parse_pending(p)).collect();
            stats.parse += t.elapsed();
            let t = Instant::now();
            for p in parsed {
                if let Some(obj) = p? {
                    self.add_object(obj)?;
                }
            }
            stats.merge += t.elapsed();
        }
        Ok(())
    }

    fn parse_pending(&self, p: &Pending<'a>) -> Result<Option<ObjFile<'a>>> {
        let (data, name, member, mtime) = match p {
            Pending::Object { data, name, mtime } => (*data, name.clone(), false, *mtime),
            Pending::Member { archive, offset } => {
                let a = &self.archives[*archive as usize];
                let m =
                    a.ar.member_at(*offset)
                        .map_err(|e| err!("{}: {e}", a.path))?;
                (m.data, format!("{}({})", a.path, m.name), true, 0)
            }
        };
        let data = match identify(data) {
            FileKind::Fat => fat_slice(data, self.arch).map_err(|e| err!("{name}: {e}"))?,
            _ => data,
        };
        match identify(data) {
            FileKind::Object => {
                let mut obj = ObjFile::parse(data, name, member)?;
                obj.mtime = if self.zero_mtime { 0 } else { mtime };
                for ext in &mut obj.externals {
                    ext.id = self.symtab.find_hashed(ext.name, ext.hash).unwrap_or(NONE);
                }
                Ok(Some(obj))
            }
            FileKind::Bitcode => bail!(
                "{name}: LLVM bitcode (linker-plugin LTO) is not supported; build without `-C linker-plugin-lto`"
            ),
            _ if member => Ok(None),
            k => bail!("{name}: {}", unsupported(k)),
        }
    }

    fn reference(&mut self, id: SymId) {
        if let Def::Lazy { archive, offset } = self.symtab.get(id).def {
            self.fetch(archive, offset);
        }
    }

    fn fetch(&mut self, archive: u32, offset: u32) {
        if self.fetched.insert((archive, offset)) {
            self.pending.push(Pending::Member { archive, offset });
        }
    }

    fn file_of(&self, def: Def) -> String {
        match def {
            Def::Defined { obj, .. } | Def::Common { obj, .. } => {
                self.objs[obj as usize].name.clone()
            }
            Def::Dylib { dylib } => self.dylibs[dylib as usize].path.clone(),
            _ => "<internal>".to_string(),
        }
    }

    fn duplicate(&mut self, id: SymId, existing: Def, file: &str) {
        diag::error(format!(
            "duplicate symbol: {}\n>>> defined in {}\n>>> defined in {file}",
            diag::symbol(self.symtab.get(id).name),
            self.file_of(existing)
        ));
        self.errors += 1;
    }

    fn add_object(&mut self, mut obj: ObjFile<'a>) -> Result<()> {
        let oarch = obj.arch.unwrap();
        if oarch.cputype() != self.arch.cputype() {
            bail!(
                "{}: is built for {}, but the link is for {}",
                obj.name,
                oarch.name(),
                self.arch.name()
            );
        }
        if let Some((platform, _)) = obj.platform
            && platform != self.cfg.platform
            && !(platform == PLATFORM_MACOS && self.cfg.platform == PLATFORM_MACCATALYST)
            && !self.cfg.suppress_warnings
        {
            diag::warn(format!(
                "{}: was built for {}, but the link is for {}",
                obj.name,
                platform_name(platform),
                platform_name(self.cfg.platform)
            ));
        }
        let oi = self.objs.len() as u32;
        if self.cfg.trace {
            diag::note(obj.name.clone());
        }
        let externals = std::mem::take(&mut obj.externals);
        for ext in &externals {
            let (id, _) = if ext.id != NONE {
                (ext.id, false)
            } else {
                self.symtab.intern(ext.name, ext.hash, oi)
            };
            obj.sym_ids[ext.index as usize] = id;
            let weak_def = ext.desc & N_WEAK_DEF != 0;
            // `.weak_def_can_be_hidden` (both weak bits on a definition): hidden in the output
            // unless another copy is plainly visible.
            let autohide = ext.desc & (N_WEAK_DEF | N_WEAK_REF) == N_WEAK_DEF | N_WEAK_REF;
            let pext = ext.private_extern || autohide;
            match ext.kind {
                ExtKind::Defined { atom, off } => {
                    let def = Def::Defined { obj: oi, atom, off };
                    let tlv = obj.sections[obj.atoms[atom as usize].sec as usize].kind
                        == super::object::SecKind::ThreadVars;
                    if !self.define(id, def, weak_def, pext, tlv, ext.desc, &obj.name) && weak_def {
                        // Another copy of this weak definition won: this one is never kept.
                        obj.atoms[atom as usize].flags |= super::gc::ATOM_COALESCED;
                    }
                }
                ExtKind::Absolute { value } => {
                    self.define(
                        id,
                        Def::Absolute { value },
                        weak_def,
                        ext.private_extern,
                        false,
                        ext.desc,
                        &obj.name,
                    );
                }
                ExtKind::Undefined => {
                    let s = self.symtab.get_mut(id);
                    if ext.desc & N_WEAK_REF != 0 {
                        s.weak_ref = true;
                    } else {
                        s.strong_ref = true;
                    }
                    if s.first_ref == NONE {
                        s.first_ref = oi;
                    }
                    self.reference(id);
                }
                ExtKind::Common { size, align } => {
                    let s = self.symtab.get_mut(id);
                    match s.def {
                        Def::Undefined
                        | Def::Lazy { .. }
                        | Def::Dylib { .. }
                        | Def::DynamicLookup => {
                            s.def = Def::Common {
                                obj: oi,
                                size,
                                align,
                            };
                            s.private_extern = ext.private_extern;
                        }
                        Def::Common { size: old, .. } if size > old => {
                            s.def = Def::Common {
                                obj: oi,
                                size,
                                align,
                            };
                        }
                        _ => {}
                    }
                }
                ExtKind::Indirect { target } => {
                    let tname = cstr(obj.strtab, target as usize);
                    let (tid, _) = self.symtab.intern(tname, hash_name(tname), oi);
                    self.reference(tid);
                    self.aliases.push((id, tid));
                }
            }
        }
        let options = std::mem::take(&mut obj.linker_options);
        self.objs.push(obj);
        for opts in options {
            self.queue_linker_option(&opts);
        }
        Ok(())
    }

    /// Offer a definition; returns whether it is now the symbol's definition.
    #[allow(clippy::too_many_arguments)]
    fn define(
        &mut self,
        id: SymId,
        def: Def,
        weak: bool,
        pext: bool,
        tlv: bool,
        desc: u16,
        file: &str,
    ) -> bool {
        let s = self.symtab.get_mut(id);
        if matches!(s.def, Def::Dylib { .. }) && s.weak_def && !weak {
            s.overrides_weak = true;
        }
        let replace = match s.def {
            Def::Undefined
            | Def::Lazy { .. }
            | Def::Dylib { .. }
            | Def::DynamicLookup
            | Def::Common { .. } => true,
            Def::Synthetic(_) => false,
            existing if existing == def => false,
            Def::Defined { obj, atom, .. } if s.weak_def && !weak => {
                // A strong definition replaces a weak one, whose copy is dropped.
                self.objs[obj as usize].atoms[atom as usize].flags |= super::gc::ATOM_COALESCED;
                true
            }
            _ if s.weak_def && !weak => true,
            _ if weak => {
                // Coalesced: the symbol stays visible if any copy is.
                s.private_extern &= pext;
                false
            }
            existing => {
                self.duplicate(id, existing, file);
                return false;
            }
        };
        let s = self.symtab.get_mut(id);
        if replace {
            s.def = def;
            s.weak_def = weak;
            s.private_extern = pext;
            s.tlv = tlv;
        }
        s.no_dead_strip |= desc & N_NO_DEAD_STRIP != 0;
        s.referenced_dynamically |= desc & REFERENCED_DYNAMICALLY != 0;
        replace
    }

    /// Resolve every input on the command line: map files in parallel, then register in order.
    fn load_inputs(&mut self) -> Result<()> {
        let mut files: Vec<(PathBuf, LoadFlags)> = Vec::with_capacity(self.cfg.inputs.len());
        for input in &self.cfg.inputs {
            let path = match &input.kind {
                InputKind::File(p) => PathBuf::from(p),
                InputKind::Library(name) => self.search.find_library(name).ok_or_else(|| {
                    err!(
                        "library not found for -l{name} (searched {})",
                        self.search.describe()
                    )
                })?,
                InputKind::Framework(name) => {
                    self.search.find_framework(name).ok_or_else(|| {
                        err!(
                            "framework not found for -framework {name} (searched {})",
                            self.search.describe()
                        )
                    })?
                }
            };
            let mut flags = input.flags;
            if self.cfg.all_load {
                flags.force_load = true;
            }
            files.push((path, flags));
        }
        let loaded = self.load_files(files)?;
        self.register(loaded)
    }

    fn load_files(&self, files: Vec<(PathBuf, LoadFlags)>) -> Result<Vec<LoadedFile<'a>>> {
        let arena: &'a Arena = self.arena;
        let target = self.tbd_target();
        let arch = self.arch;
        files
            .into_par_iter()
            .map(|(path, flags)| -> Result<LoadedFile<'a>> {
                let (bytes, meta) =
                    fileio::load_with_metadata(&path).map_err(|e| err!("cannot open {}: {e}", path.display()))?;
                let key = file_key(&meta);
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                let mut data = arena.keep(bytes);
                let name = path.display().to_string();
                if identify(data) == FileKind::Fat {
                    data = fat_slice(data, arch).map_err(|e| err!("{name}: {e}"))?;
                }
                let what = match identify(data) {
                    FileKind::Object => Loaded::Object(data),
                    FileKind::Archive => {
                        let ar = Archive::parse(data).map_err(|e| err!("{name}: {e}"))?;
                        let hashes = ar.symbols.iter().map(|s| hash_name(s.name)).collect();
                        Loaded::Archive(ar, hashes)
                    }
                    FileKind::Tbd => {
                        let docs = tbd::parse(data, &target).map_err(|e| err!("{name}: {e}"))?;
                        Loaded::Dylib(docs, Vec::new())
                    }
                    FileKind::Dylib => {
                        let (iface, rpaths) = super::dylib::parse(data, &name)?;
                        Loaded::Dylib(vec![iface], rpaths)
                    }
                    FileKind::ThinArchive => bail!("{name}: thin archives are not supported"),
                    FileKind::Bitcode => bail!(
                        "{name}: LLVM bitcode (linker-plugin LTO) is not supported; build without `-C linker-plugin-lto`"
                    ),
                    k => bail!("{name}: {}", unsupported(k)),
                };
                Ok(LoadedFile { path, flags, key, mtime, what })
            })
            .collect()
    }

    fn register(&mut self, loaded: Vec<LoadedFile<'a>>) -> Result<()> {
        for f in loaded {
            if !self.visited.insert(f.key) {
                continue;
            }
            let name = f.path.display().to_string();
            match f.what {
                Loaded::Object(data) => self.pending.push(Pending::Object {
                    data,
                    name,
                    mtime: f.mtime,
                }),
                Loaded::Archive(ar, hashes) => self.add_archive(ar, hashes, name, f.flags)?,
                Loaded::Dylib(docs, rpaths) => {
                    self.add_dylib(docs, rpaths, &name, f.flags, true, false)?;
                }
            }
        }
        Ok(())
    }

    fn add_archive(
        &mut self,
        mut ar: Archive<'a>,
        mut hashes: Vec<u64>,
        name: String,
        flags: LoadFlags,
    ) -> Result<()> {
        if self.cfg.trace {
            diag::note(name.clone());
        }
        let idx = self.archives.len() as u32;
        if flags.force_load {
            let members = ar.members().map_err(|e| err!("{name}: {e}"))?;
            for m in members {
                self.fetch(idx, m.offset);
            }
            self.archives.push(ArchiveFile { path: name, ar });
            return Ok(());
        }
        if !ar.has_symbol_table {
            // ld64 needs ranlib's table; build one from the members' external definitions.
            for m in ar.members().map_err(|e| err!("{name}: {e}"))? {
                let data = match identify(m.data) {
                    FileKind::Fat => match fat_slice(m.data, self.arch) {
                        Ok(d) => d,
                        Err(_) => continue,
                    },
                    _ => m.data,
                };
                if identify(data) != FileKind::Object {
                    continue;
                }
                if let Ok(obj) = ObjFile::parse(data, String::new(), true) {
                    for e in &obj.externals {
                        if matches!(
                            e.kind,
                            ExtKind::Defined { .. }
                                | ExtKind::Absolute { .. }
                                | ExtKind::Common { .. }
                        ) {
                            ar.symbols.push(ArchiveSymbol {
                                name: e.name,
                                offset: m.offset,
                            });
                            hashes.push(e.hash);
                        }
                    }
                }
            }
        }
        let symbols = std::mem::take(&mut ar.symbols);
        let objc = self.cfg.objc;
        self.archives.push(ArchiveFile { path: name, ar });
        for (s, hash) in symbols.into_iter().zip(hashes) {
            if objc
                && (s.name.starts_with(b"_OBJC_CLASS_$_")
                    || s.name.starts_with(b"_OBJC_METACLASS_$_"))
            {
                self.fetch(idx, s.offset);
            }
            let (id, new) = self.symtab.intern(s.name, hash, NONE);
            let sym = self.symtab.get_mut(id);
            if new {
                sym.def = Def::Lazy {
                    archive: idx,
                    offset: s.offset,
                };
            } else if sym.def.is_undefined() {
                self.fetch(idx, s.offset);
            }
        }
        Ok(())
    }

    /// A dylib and everything it re-exports: their exports become this dylib's symbols.
    fn add_dylib(
        &mut self,
        docs: Vec<Interface<'a>>,
        rpaths: Vec<String>,
        path: &str,
        flags: LoadFlags,
        explicit: bool,
        auto_linked: bool,
    ) -> Result<Option<u32>> {
        let mut docs = docs.into_iter();
        let Some(main) = docs.next() else {
            return Ok(None);
        };
        if let Some(&existing) = self.dylib_by_name.get(&main.install_name) {
            let d = &mut self.dylibs[existing as usize];
            d.explicit |= explicit;
            d.auto_linked &= auto_linked;
            d.flags.weak &= flags.weak;
            d.flags.reexport |= flags.reexport;
            d.flags.needed |= flags.needed;
            return Ok(Some(existing));
        }
        if self.cfg.trace {
            diag::note(path.to_string());
        }
        let idx = self.dylibs.len() as u32;
        self.dylib_by_name.insert(main.install_name.clone(), idx);
        self.dylibs.push(DylibFile {
            install_name: main.install_name.clone(),
            current_version: main.current_version,
            compat_version: main.compat_version,
            path: path.to_string(),
            flags,
            explicit,
            auto_linked,
            used: AtomicBool::new(false),
            ordinal: 0,
        });
        let inline: Vec<Interface<'a>> = docs.collect();
        let mut queue = vec![main];
        let mut seen: HashSet<String> = HashSet::new();
        let dir = Path::new(path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        while let Some(iface) = queue.pop() {
            if !seen.insert(iface.install_name.clone()) {
                continue;
            }
            for (install, compat, sym) in &iface.previous {
                let prev = self.previous_dylib(install, *compat);
                let name = self.cow_bytes(sym);
                self.add_dylib_symbol(name, prev, false, false);
            }
            for e in &iface.exports {
                let name = self.cow_bytes(&e.name);
                self.add_dylib_symbol(name, idx, e.weak, e.tlv);
            }
            for r in &iface.reexports {
                if seen.contains(r) {
                    continue;
                }
                if let Some(doc) = inline.iter().find(|d| &d.install_name == r) {
                    queue.push(Interface {
                        install_name: doc.install_name.clone(),
                        current_version: doc.current_version,
                        compat_version: doc.compat_version,
                        reexports: doc.reexports.clone(),
                        exports: doc.exports.clone(),
                        previous: doc.previous.clone(),
                    });
                    continue;
                }
                match self.find_reexport(r, &dir, &rpaths) {
                    Some(p) => {
                        let docs = self.load_dylib_file(&p)?;
                        let mut it = docs.into_iter();
                        if let Some(first) = it.next() {
                            queue.push(first);
                        }
                    }
                    None => {
                        if !self.cfg.suppress_warnings {
                            diag::warn(format!("{path}: cannot find re-exported library {r}"));
                        }
                    }
                }
            }
        }
        Ok(Some(idx))
    }

    fn cow_bytes(&self, c: &std::borrow::Cow<'a, [u8]>) -> &'a [u8] {
        match c {
            std::borrow::Cow::Borrowed(b) => b,
            std::borrow::Cow::Owned(o) => self.bytes(o),
        }
    }

    fn add_dylib_symbol(&mut self, name: &'a [u8], dylib: u32, weak: bool, tlv: bool) {
        let (id, _) = self.symtab.intern(name, hash_name(name), NONE);
        let s = self.symtab.get_mut(id);
        let take = match s.def {
            Def::Undefined | Def::DynamicLookup => true,
            Def::Dylib { .. } => s.weak_def && !weak,
            Def::Defined { .. } | Def::Absolute { .. } => {
                if weak && !s.weak_def {
                    s.overrides_weak = true;
                }
                false
            }
            _ => false,
        };
        if take {
            s.def = Def::Dylib { dylib };
            s.weak_def = weak;
            s.tlv = tlv;
        }
    }

    /// The dylib a `$ld$previous$` entry moves a symbol to, for older deployment targets.
    fn previous_dylib(&mut self, install: &str, compat: u32) -> u32 {
        if let Some(&i) = self.dylib_by_name.get(install) {
            return i;
        }
        let idx = self.dylibs.len() as u32;
        self.dylib_by_name.insert(install.to_string(), idx);
        self.dylibs.push(DylibFile {
            install_name: install.to_string(),
            current_version: compat.max(0x1_0000),
            compat_version: compat.max(0x1_0000),
            path: install.to_string(),
            flags: LoadFlags::default(),
            explicit: false,
            auto_linked: true,
            used: AtomicBool::new(false),
            ordinal: 0,
        });
        idx
    }

    fn find_reexport(&self, install: &str, dir: &Path, rpaths: &[String]) -> Option<PathBuf> {
        if let Some(rest) = install.strip_prefix("@loader_path/") {
            let p = dir.join(rest);
            return p.is_file().then_some(p);
        }
        if let Some(rest) = install.strip_prefix("@rpath/") {
            for rp in rpaths {
                let base = match rp.strip_prefix("@loader_path") {
                    Some(r) => dir.join(r.trim_start_matches('/')),
                    None => PathBuf::from(rp),
                };
                let p = base.join(rest);
                if p.is_file() {
                    return Some(p);
                }
            }
            return None;
        }
        self.search.find_install_name(install)
    }

    fn load_dylib_file(&self, path: &Path) -> Result<Vec<Interface<'a>>> {
        let name = path.display().to_string();
        let bytes = fileio::load(path).map_err(|e| err!("cannot open {name}: {e}"))?;
        let mut data = self.arena.keep(bytes);
        if identify(data) == FileKind::Fat {
            data = fat_slice(data, self.arch).map_err(|e| err!("{name}: {e}"))?;
        }
        match identify(data) {
            FileKind::Tbd => tbd::parse(data, &self.tbd_target()).map_err(|e| err!("{name}: {e}")),
            FileKind::Dylib => Ok(vec![super::dylib::parse(data, &name)?.0]),
            k => bail!("{name}: {}", unsupported(k)),
        }
    }

    fn queue_linker_option(&mut self, opts: &[String]) {
        let mut i = 0;
        while i < opts.len() {
            let key = if let Some(lib) = opts[i].strip_prefix("-l") {
                Some(format!("-l{lib}"))
            } else if opts[i] == "-framework" && i + 1 < opts.len() {
                i += 1;
                Some(format!("-framework {}", opts[i]))
            } else {
                None
            };
            if let Some(k) = key
                && self.auto_link_seen.insert(k.clone())
            {
                self.auto_link_pending.push(k);
            }
            i += 1;
        }
    }

    /// Libraries named by `LC_LINKER_OPTION`s, loaded once all else is: they fill gaps only.
    fn auto_link(&mut self) -> Result<bool> {
        if self.auto_link_pending.is_empty() {
            return Ok(false);
        }
        let mut names = std::mem::take(&mut self.auto_link_pending);
        names.sort();
        let mut files = Vec::new();
        for n in &names {
            let path = match n.strip_prefix("-l") {
                Some(lib) => self.search.find_library(lib),
                None => self
                    .search
                    .find_framework(n.trim_start_matches("-framework ")),
            };
            match path {
                Some(p) => files.push((p, LoadFlags::default())),
                None => {
                    if !self.cfg.suppress_warnings {
                        diag::warn(format!("auto-linked library not found for {n}"));
                    }
                }
            }
        }
        let loaded = self.load_files(files)?;
        let mut added = false;
        for f in loaded {
            if !self.visited.insert(f.key) {
                continue;
            }
            let name = f.path.display().to_string();
            match f.what {
                Loaded::Archive(ar, hashes) => {
                    self.add_archive(ar, hashes, name, f.flags)?;
                    added = true;
                }
                Loaded::Dylib(docs, rpaths) => {
                    self.add_dylib(docs, rpaths, &name, f.flags, false, true)?;
                    added = true;
                }
                Loaded::Object(data) => {
                    self.pending.push(Pending::Object {
                        data,
                        name,
                        mtime: f.mtime,
                    });
                    added = true;
                }
            }
        }
        // Symbols still undefined may now be lazily available.
        if added {
            for id in 0..self.symtab.len() as SymId {
                let s = self.symtab.get(id);
                if s.def.is_lazy() && (s.strong_ref || s.weak_ref) {
                    self.reference(id);
                }
            }
        }
        Ok(added)
    }

    fn resolve_remaining(&mut self) -> Result<()> {
        for (alias, target) in std::mem::take(&mut self.aliases) {
            let t = self.symtab.get(target);
            let (def, weak, pext) = (t.def, t.weak_def, t.private_extern);
            let a = self.symtab.get_mut(alias);
            if !a.def.is_resolved() || matches!(a.def, Def::Dylib { .. }) {
                a.def = def;
                a.weak_def = weak;
                a.private_extern = pext;
            }
        }
        for (from, to) in self.cfg.aliases.clone() {
            let f = self.intern_str(&from);
            let t = self.intern_str(&to);
            let (def, weak) = (self.symtab.get(f).def, self.symtab.get(f).weak_def);
            let s = self.symtab.get_mut(t);
            s.def = def;
            s.weak_def = weak;
        }
        for name in self.cfg.dynamic_lookup.clone() {
            let id = self.intern_str(&name);
            if !self.symtab.get(id).def.is_resolved() {
                self.symtab.get_mut(id).def = Def::DynamicLookup;
            }
        }
        if self.objc_msgsend.is_some() {
            for id in 0..self.symtab.len() as SymId {
                let s = self.symtab.get(id);
                if s.def.is_resolved() || !(s.strong_ref || s.weak_ref) {
                    continue;
                }
                if let Some(sel) = s.name.strip_prefix(b"_objc_msgSend$") {
                    let i = self.objc_stubs.len() as u32;
                    self.objc_stubs.push((id, sel));
                    self.symtab.get_mut(id).def = Def::Synthetic(Synthetic::ObjcStub(i));
                }
            }
        }
        // section$start$SEG$sect and friends.
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            if s.def.is_resolved() || !(s.strong_ref || s.weak_ref) {
                continue;
            }
            let name = s.name;
            let parse = |prefix: &[u8], two: bool| -> Option<(Vec<u8>, Vec<u8>)> {
                let rest = name.strip_prefix(prefix)?;
                if two {
                    let p = rest.iter().position(|&c| c == b'$')?;
                    Some((rest[..p].to_vec(), rest[p + 1..].to_vec()))
                } else {
                    Some((rest.to_vec(), Vec::new()))
                }
            };
            let found = [
                (&b"section$start$"[..], true, 0u8),
                (b"section$end$", true, 1),
                (b"segment$start$", false, 2),
                (b"segment$end$", false, 3),
            ]
            .into_iter()
            .find_map(|(p, two, k)| parse(p, two).map(|v| (v, k)));
            if let Some(((seg, sect), k)) = found {
                let i = match self
                    .boundaries
                    .iter()
                    .position(|b| b.0 == seg && b.1 == sect)
                {
                    Some(i) => i,
                    None => {
                        self.boundaries.push((seg, sect));
                        self.boundaries.len() - 1
                    }
                } as u32;
                self.symtab.get_mut(id).def = Def::Synthetic(match k {
                    0 => Synthetic::SectionStart(i),
                    1 => Synthetic::SectionEnd(i),
                    2 => Synthetic::SegmentStart(i),
                    _ => Synthetic::SegmentEnd(i),
                });
            }
        }

        let mut undefined = Vec::new();
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            if s.def.is_resolved() || !(s.strong_ref || s.weak_ref) {
                continue;
            }
            undefined.push(id);
        }
        let treat = self.cfg.undefined;
        if treat != Undefined::Error {
            for &id in &undefined {
                if treat == Undefined::Warning && !self.cfg.suppress_warnings {
                    diag::warn(format!(
                        "undefined symbol: {}",
                        diag::symbol(self.symtab.get(id).name)
                    ));
                }
                self.symtab.get_mut(id).def = Def::DynamicLookup;
            }
            undefined.clear();
        }
        for (i, &id) in undefined.iter().enumerate() {
            if i == 20 {
                diag::error(format!(
                    "too many undefined symbols ({} in total)",
                    undefined.len()
                ));
                break;
            }
            let s = self.symtab.get(id);
            let referrer = if s.first_ref == NONE {
                "the command line".to_string()
            } else {
                self.objs[s.first_ref as usize].name.clone()
            };
            diag::error(format!(
                "undefined symbol: {}\n>>> referenced by {referrer}",
                diag::symbol(s.name)
            ));
        }
        self.errors += undefined.len();
        if let Some(e) = self.entry
            && !self.symtab.get(e).def.is_resolved()
            && !undefined.contains(&e)
        {
            diag::error(format!(
                "entry point {} is undefined",
                diag::symbol(self.symtab.get(e).name)
            ));
            self.errors += 1;
        }
        if self.errors > 0 {
            bail!("link failed with {} error(s)", self.errors);
        }
        Ok(())
    }

    fn wants_objc_stubs(&self) -> bool {
        self.symtab.syms.iter().any(|s| {
            !s.def.is_resolved()
                && s.name.starts_with(b"_objc_msgSend$")
                && (s.strong_ref || s.weak_ref)
        })
    }

    pub fn output_path(&self) -> &Path {
        &self.cfg.output
    }
}

fn file_key(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let _ = meta;
        (0, NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// The architecture of the first object (or archive member) on the command line.
pub fn detect_arch(cfg: &Config) -> Result<Arch> {
    for input in &cfg.inputs {
        let InputKind::File(p) = &input.kind else {
            continue;
        };
        let Ok(bytes) = fileio::load(Path::new(p)) else {
            continue;
        };
        let arena = Arena::new();
        let d = arena.keep(bytes);
        let d = match identify(d) {
            FileKind::Archive => {
                let Ok(ar) = Archive::parse(d) else { continue };
                let Ok(members) = ar.members() else { continue };
                match members
                    .into_iter()
                    .find(|m| identify(m.data) == FileKind::Object)
                {
                    Some(m) => m.data,
                    None => continue,
                }
            }
            _ => d,
        };
        if identify(d) == FileKind::Object
            && let Some(a) = Arch::from_cpu(u32le(d, 4), u32le(d, 8))
        {
            return Ok(a);
        }
    }
    if cfg!(target_arch = "x86_64") {
        Ok(Arch::X86_64)
    } else {
        Ok(Arch::Arm64)
    }
}

fn unsupported(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Bitcode => "LLVM bitcode (linker-plugin LTO) is not supported",
        FileKind::ThinArchive => "thin archives are not supported",
        FileKind::OtherMachO => {
            "this Mach-O file can't be linked (32-bit or not an object, archive or dylib)"
        }
        FileKind::Unknown => "unknown file type",
        _ => "can't be linked here",
    }
}
