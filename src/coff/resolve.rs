//! Inputs and symbol resolution: parallel parsing in waves, merged in a fixed order for determinism.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use super::arch::Machine;
use super::config::{Config, Subsystem, lib_key, parse_assignment};
use super::def::{ExportSpec, parse_export};
use super::import::ShortImport;
use super::object::{ExtKind, ExternalSym, FileKind, NONE, ObjFile, identify};
use super::symtab::{Def, SymId, SymbolTable, WeakAlias, hash_name};
use super::synth::{DllImports, Edata, SynthChunk};
use super::*;
use crate::archive::{Archive, ArchiveSymbol};
use crate::diag::{self, Result, Timer};
use crate::fileio::{self, Arena};
use crate::{bail, err};

/// Symbols the MSVC CRT's load configuration needs; the linker defines them as zero.
const LINKER_DEFAULTS: &[&str] = &[
    "__guard_fids_count",
    "__guard_fids_table",
    "__guard_flags",
    "__guard_iat_count",
    "__guard_iat_table",
    "__guard_longjmp_count",
    "__guard_longjmp_table",
    "__guard_eh_cont_count",
    "__guard_eh_cont_table",
    "__enclave_config",
];

pub struct ArchiveFile<'a> {
    pub path: String,
    pub ar: Archive<'a>,
}

pub struct Import<'a> {
    pub dll: &'a [u8],
    pub kind: u8,
    pub name: Option<&'a [u8]>,
    pub ordinal_or_hint: u16,
    pub live: AtomicBool,
    pub thunk_live: AtomicBool,
    pub iat_off: u32,
    pub hint_off: u32,
    pub thunk_off: u32,
}

pub struct Export {
    pub name: String,
    pub sym: SymId,
    pub ordinal: u16,
    pub noname: bool,
    pub data: bool,
    pub constant: bool,
    pub private: bool,
}

type Loaded<'a> = (&'a [u8], Option<Archive<'a>>, Vec<u64>);

#[derive(Default)]
struct RunStats {
    waves: usize,
    parse: Duration,
    merge: Duration,
    libs: Duration,
}

struct Accumulate<'t>(&'t mut Duration, Instant);

impl Drop for Accumulate<'_> {
    fn drop(&mut self) {
        *self.0 += self.1.elapsed();
    }
}

enum Pending<'a> {
    Object { data: &'a [u8], name: String },
    Member { archive: u32, offset: u32 },
}

enum Parsed<'a> {
    Object(ObjFile<'a>),
    Import(ShortImport<'a>, String),
    Skip,
}

pub struct Linker<'a> {
    pub cfg: Config,
    pub arena: &'a Arena,
    pub objs: Vec<ObjFile<'a>>,
    pub archives: Vec<ArchiveFile<'a>>,
    pub imports: Vec<Import<'a>>,
    pub symtab: SymbolTable<'a>,
    pub exports: Vec<Export>,
    pub local_imports: Vec<SymId>,
    pub gc_roots: Vec<SymId>,
    pub merges: BTreeMap<String, String>,
    pub entry: Option<SymId>,
    pub subsystem: Option<Subsystem>,
    pub machine: Machine,
    pub image_base: u64,
    pub synth: Vec<SynthChunk>,
    pub dlls: Vec<DllImports<'a>>,
    pub edata: Option<Edata>,
    pub out_rvas: Vec<u32>,
    pub tls_align: u32,
    pub seh_handlers: Vec<(u32, u32, u32)>,
    pub resources: Vec<(String, &'a [u8])>,
    pub rsrc: Option<super::rsrc::Rsrc>,
    pub pdb: Option<super::pdb::PdbPlan>,

    pending: Vec<Pending<'a>>,
    pending_libs: Vec<String>,
    visited_libs: HashSet<String>,
    visited_files: HashSet<String>,
    fetched: HashSet<(u32, u32)>,
    search_paths: Vec<PathBuf>,
    alternate_names: Vec<(String, String)>,
    entry_name: Option<String>,
    no_default_all: bool,
    no_default_libs: HashSet<String>,
    failifmismatch: HashMap<String, (String, String)>,
    errors: usize,
    entry_inferred: bool,
    load_config_rooted: bool,
}

impl<'a> Linker<'a> {
    pub fn new(cfg: Config, arena: &'a Arena) -> Linker<'a> {
        let machine = cfg.machine.unwrap_or_else(|| detect_machine(&cfg));
        let image_base = cfg
            .image_base
            .unwrap_or_else(|| machine.default_image_base(cfg.dll));
        let mut merges = BTreeMap::new();
        for (from, to) in &cfg.merges {
            merges.insert(from.clone(), to.clone());
        }
        for (from, to) in [
            (".idata", ".rdata"),
            (".didat", ".rdata"),
            (".edata", ".rdata"),
            (".xdata", ".rdata"),
            (".00cfg", ".rdata"),
            (".bss", ".data"),
        ] {
            merges
                .entry(from.to_string())
                .or_insert_with(|| to.to_string());
        }
        if cfg.mingw {
            for (from, to) in [
                (".ctors", ".rdata"),
                (".dtors", ".rdata"),
                (".CRT", ".rdata"),
            ] {
                merges
                    .entry(from.to_string())
                    .or_insert_with(|| to.to_string());
            }
        }
        Linker {
            search_paths: winsdk::search_paths(&cfg.lib_paths, machine),
            machine,
            no_default_all: cfg.no_default_lib_all,
            no_default_libs: cfg.no_default_libs.iter().cloned().collect(),
            alternate_names: cfg.alternate_names.clone(),
            subsystem: cfg.subsystem,
            entry_name: cfg.entry.clone(),
            arena,
            objs: Vec::new(),
            archives: Vec::new(),
            imports: Vec::new(),
            symtab: SymbolTable::with_capacity(1 << 16),
            exports: Vec::new(),
            local_imports: Vec::new(),
            gc_roots: Vec::new(),
            merges,
            entry: None,
            image_base,
            synth: Vec::new(),
            dlls: Vec::new(),
            edata: None,
            out_rvas: Vec::new(),
            tls_align: 0,
            seh_handlers: Vec::new(),
            resources: Vec::new(),
            rsrc: None,
            pdb: None,
            pending: Vec::new(),
            pending_libs: Vec::new(),
            visited_libs: HashSet::new(),
            visited_files: HashSet::new(),
            fetched: HashSet::new(),
            failifmismatch: HashMap::new(),
            errors: 0,
            entry_inferred: false,
            load_config_rooted: false,
            cfg,
        }
    }

    fn bytes(&self, s: &[u8]) -> &'a [u8] {
        let arena: &'a Arena = self.arena;
        arena.alloc(s.to_vec())
    }

    pub fn resolve(&mut self, timer: &mut Timer) -> Result<()> {
        let image_base = self.bytes(self.machine.mangle("__ImageBase").as_bytes());
        let (ib, _) = self.symtab.intern(image_base, hash_name(image_base), NONE);
        self.symtab.get_mut(ib).def = Def::ImageBase;
        let mut defaults: Vec<&str> = LINKER_DEFAULTS.to_vec();
        if self.machine == Machine::X86 {
            defaults.extend(["__safe_se_handler_table", "__safe_se_handler_count"]);
        }
        for name in defaults {
            let name = self.bytes(self.machine.mangle(name).as_bytes());
            let (id, _) = self.symtab.intern(name, hash_name(name), NONE);
            let s = self.symtab.get_mut(id);
            s.def = Def::Absolute { va: 0 };
            s.replaceable = true;
        }

        for name in self.cfg.includes.clone() {
            self.add_root(&name);
        }
        if let Some(entry) = self.entry_name.clone() {
            self.entry = Some(self.add_root(&self.machine.mangle(&entry)));
        }
        for spec in self.cfg.exports.clone() {
            self.add_export(spec);
        }

        self.load_command_line()?;
        for lib in self.cfg.default_libs.clone() {
            self.queue_default_lib(&lib);
        }
        timer.phase("open inputs");

        let mut stats = RunStats::default();
        loop {
            self.run(&mut stats)?;
            self.after_run();
            if self.pending.is_empty() && self.pending_libs.is_empty() {
                break;
            }
        }
        self.resolve_remaining()?;
        if timer.enabled() {
            let sections: usize = self.objs.iter().map(|o| o.sections.len()).sum();
            timer.detail(format!(
                "{} objects, {} archives, {} imports, {} sections, {} symbols",
                self.objs.len(),
                self.archives.len(),
                self.imports.len(),
                sections,
                self.symtab.len()
            ));
            timer.detail(format!(
                "{} waves: parsing {:.2} ms, merging {:.2} ms, libraries {:.2} ms",
                stats.waves,
                stats.parse.as_secs_f64() * 1e3,
                stats.merge.as_secs_f64() * 1e3,
                stats.libs.as_secs_f64() * 1e3
            ));
        }
        timer.phase("resolve symbols");
        Ok(())
    }

    fn run(&mut self, stats: &mut RunStats) -> Result<()> {
        loop {
            if !self.pending_libs.is_empty() {
                let t = Instant::now();
                let libs = std::mem::take(&mut self.pending_libs);
                self.load_libraries(libs)?;
                stats.libs += t.elapsed();
                continue;
            }
            if self.pending.is_empty() {
                return Ok(());
            }
            stats.waves += 1;
            let t = Instant::now();
            let wave = std::mem::take(&mut self.pending);
            let this = &*self;
            let parsed: Vec<Result<Parsed<'a>>> =
                wave.par_iter().map(|p| this.parse_pending(p)).collect();
            stats.parse += t.elapsed();
            let _merge = Accumulate(&mut stats.merge, Instant::now());
            for p in parsed {
                match p? {
                    Parsed::Object(obj) => self.add_object(obj)?,
                    Parsed::Import(imp, name) => self.add_import(imp, &name)?,
                    Parsed::Skip => {}
                }
            }
        }
    }

    fn after_run(&mut self) {
        if !self.entry_inferred {
            self.entry_inferred = true;
            if self.subsystem.is_none() {
                self.subsystem = Some(self.infer_subsystem());
            }
            if self.entry_name.is_none()
                && !self.cfg.no_entry
                && let Some(name) = self.infer_entry()
            {
                self.entry = Some(self.add_root(&name));
                self.entry_name = Some(name);
            }
        }
        // The CRT's `_load_config_used` is linked whenever a library offers it, as link.exe does.
        let load_config = self.machine.mangle("_load_config_used");
        if !self.load_config_rooted && self.symtab.find(load_config.as_bytes()).is_some() {
            self.load_config_rooted = true;
            self.add_root(&load_config);
        }
        for (from, to) in self.alternate_names.clone() {
            let Some(id) = self.symtab.find(from.as_bytes()) else {
                continue;
            };
            let s = self.symtab.get(id);
            if s.def.is_undefined() && s.weak_alias.is_none() {
                let target = self.add_reference(&to);
                self.symtab.get_mut(id).weak_alias = Some(WeakAlias::Global(target));
            }
        }
    }

    fn has(&self, name: &str) -> bool {
        let mangled = self.machine.mangle(name);
        let defined = |id: SymId| !self.symtab.get(id).def.is_undefined();
        if self.symtab.find(mangled.as_bytes()).is_some_and(defined) {
            return true;
        }
        self.machine == Machine::X86
            && self
                .find_decorated(&format!("{mangled}@"))
                .is_some_and(defined)
    }

    fn find_decorated(&self, prefix: &str) -> Option<SymId> {
        self.symtab
            .syms
            .iter()
            .position(|s| s.name.starts_with(prefix.as_bytes()) && s.def.is_defined())
            .map(|i| i as SymId)
    }

    pub fn special(&self, name: &str) -> Option<SymId> {
        self.symtab.find(self.machine.mangle(name).as_bytes())
    }

    fn infer_subsystem(&self) -> Subsystem {
        if self.cfg.dll || self.has("WinMain") || self.has("wWinMain") {
            if !self.cfg.dll && (self.has("main") || self.has("wmain")) {
                return Subsystem::Console;
            }
            Subsystem::Windows
        } else {
            Subsystem::Console
        }
    }

    fn infer_entry(&self) -> Option<String> {
        let m = self.machine;
        if self.cfg.dll {
            return Some(if m == Machine::X86 {
                "__DllMainCRTStartup@12".to_string()
            } else {
                "_DllMainCRTStartup".to_string()
            });
        }
        let name = if self.subsystem == Some(Subsystem::Windows) && self.has("wWinMain") {
            "wWinMainCRTStartup"
        } else if self.subsystem == Some(Subsystem::Windows) && self.has("WinMain") {
            "WinMainCRTStartup"
        } else if self.has("wmain") {
            "wmainCRTStartup"
        } else if self.has("main") {
            "mainCRTStartup"
        } else {
            return None;
        };
        Some(m.mangle(name))
    }

    fn find_file(&self, name: &str) -> Option<PathBuf> {
        let p = Path::new(name);
        if p.is_absolute() {
            return p.is_file().then(|| p.to_path_buf());
        }
        self.search_paths
            .iter()
            .map(|dir| dir.join(name))
            .find(|c| c.is_file())
    }

    fn find_lib(&self, name: &str) -> Option<PathBuf> {
        self.find_file(name).or_else(|| {
            let has_ext = Path::new(name).extension().is_some();
            (!has_ext)
                .then(|| self.find_file(&format!("{name}.lib")))
                .flatten()
        })
    }

    fn load_command_line(&mut self) -> Result<()> {
        let mut files = Vec::new();
        for input in self.cfg.inputs.clone() {
            let path = self
                .find_file(&input.path)
                .or_else(|| {
                    let has_ext = Path::new(&input.path).extension().is_some();
                    (!has_ext)
                        .then(|| self.find_file(&format!("{}.obj", input.path)))
                        .flatten()
                })
                .ok_or_else(|| err!("cannot open input file '{}'", input.path))?;
            if !self
                .visited_files
                .insert(path.to_string_lossy().to_lowercase())
            {
                continue;
            }
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lib"))
            {
                self.visited_libs.insert(lib_key(&input.path));
            }
            files.push((path, input.whole_archive || self.cfg.whole_archive_all));
        }
        self.load_files(files)
    }

    fn load_libraries(&mut self, names: Vec<String>) -> Result<()> {
        let mut files = Vec::new();
        for name in names {
            let path = self.find_lib(&name).ok_or_else(|| {
                err!(
                    "cannot open library '{name}' (searched {})",
                    self.searched()
                )
            })?;
            if self
                .visited_files
                .insert(path.to_string_lossy().to_lowercase())
            {
                files.push((path, self.cfg.whole_archive_all));
            }
        }
        self.load_files(files)
    }

    fn searched(&self) -> String {
        let dirs: Vec<String> = self
            .search_paths
            .iter()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    ".".to_string()
                } else {
                    p.display().to_string()
                }
            })
            .collect();
        dirs.join(", ")
    }

    fn load_files(&mut self, files: Vec<(PathBuf, bool)>) -> Result<()> {
        let arena: &'a Arena = self.arena;
        let loaded: Vec<Result<Loaded<'a>>> = files
            .par_iter()
            .map(|(path, _)| {
                let bytes = fileio::load(path)
                    .map_err(|e| err!("cannot open '{}': {e}", path.display()))?;
                let data = arena.keep(bytes);
                if identify(data) != FileKind::Archive {
                    return Ok((data, None, Vec::new()));
                }
                let ar = Archive::parse(data).map_err(|e| err!("{}: {e}", path.display()))?;
                let hashes = ar.symbols.iter().map(|s| hash_name(s.name)).collect();
                Ok((data, Some(ar), hashes))
            })
            .collect();
        for ((path, whole), r) in files.into_iter().zip(loaded) {
            let (data, ar, hashes) = r?;
            let name = path.display().to_string();
            if self.cfg.verbose {
                diag::note(format!("reading {name}"));
            }
            match ar {
                Some(ar) => self.add_archive(ar, hashes, name, whole)?,
                None => self.add_file(data, name)?,
            }
        }
        Ok(())
    }

    fn add_file(&mut self, data: &'a [u8], name: String) -> Result<()> {
        match identify(data) {
            FileKind::Object | FileKind::BigObject | FileKind::ShortImport => {
                self.pending.push(Pending::Object { data, name });
                Ok(())
            }
            FileKind::Resource => {
                self.resources.push((name, data));
                Ok(())
            }
            kind => bail!("{name}: {}", unsupported(kind)),
        }
    }

    fn add_archive(
        &mut self,
        mut ar: Archive<'a>,
        mut hashes: Vec<u64>,
        name: String,
        whole: bool,
    ) -> Result<()> {
        let idx = self.archives.len() as u32;
        if whole {
            let members = ar.members().map_err(|e| err!("{name}: {e}"))?;
            for m in members {
                self.fetch(idx, m.offset);
            }
            self.archives.push(ArchiveFile { path: name, ar });
            return Ok(());
        }
        if !ar.has_symbol_table {
            for m in ar.members().map_err(|e| err!("{name}: {e}"))? {
                if matches!(identify(m.data), FileKind::Object | FileKind::BigObject)
                    && let Ok(obj) = ObjFile::parse(m.data, String::new())
                {
                    for e in &obj.externals {
                        if matches!(e.kind, ExtKind::Defined { .. } | ExtKind::Absolute { .. }) {
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
        self.archives.push(ArchiveFile { path: name, ar });
        for (s, hash) in symbols.into_iter().zip(hashes) {
            let (id, new) = self.symtab.intern(s.name, hash, NONE);
            let sym = self.symtab.get_mut(id);
            if new {
                sym.def = Def::Lazy {
                    archive: idx,
                    offset: s.offset,
                };
            } else if sym.def.is_undefined() && sym.weak_alias.is_none() {
                self.fetch(idx, s.offset);
            }
        }
        Ok(())
    }

    fn fetch(&mut self, archive: u32, offset: u32) {
        if self.fetched.insert((archive, offset)) {
            self.pending.push(Pending::Member { archive, offset });
        }
    }

    fn parse_pending(&self, p: &Pending<'a>) -> Result<Parsed<'a>> {
        let (data, name, member) = match p {
            Pending::Object { data, name } => (*data, name.clone(), false),
            Pending::Member { archive, offset } => {
                let a = &self.archives[*archive as usize];
                let m =
                    a.ar.member_at(*offset)
                        .map_err(|e| err!("{}: {e}", a.path))?;
                (m.data, format!("{}({})", a.path, m.name), true)
            }
        };
        match identify(data) {
            FileKind::Object | FileKind::BigObject => {
                let mut obj = ObjFile::parse(data, name)?;
                for ext in &mut obj.externals {
                    ext.id = self.symtab.find_hashed(ext.name, ext.hash).unwrap_or(NONE);
                }
                Ok(Parsed::Object(obj))
            }
            FileKind::ShortImport => Ok(Parsed::Import(ShortImport::parse(data, &name)?, name)),
            FileKind::Bitcode | FileKind::AnonObject => {
                bail!("{name}: {}", unsupported(identify(data)))
            }
            _ if member => Ok(Parsed::Skip),
            kind => bail!("{name}: {}", unsupported(kind)),
        }
    }

    fn queue_default_lib(&mut self, name: &str) {
        let key = lib_key(name);
        if self.no_default_all || self.no_default_libs.contains(&key) {
            return;
        }
        if self.visited_libs.insert(key) {
            self.pending_libs.push(name.to_string());
        }
    }

    fn add_root(&mut self, name: &str) -> SymId {
        let id = self.add_reference(name);
        self.gc_roots.push(id);
        id
    }

    fn add_reference(&mut self, name: &str) -> SymId {
        let bytes = self.bytes(name.as_bytes());
        let (id, _) = self.symtab.intern(bytes, hash_name(bytes), NONE);
        self.reference(id);
        id
    }

    #[inline]
    fn reference(&mut self, id: SymId) {
        if let Def::Lazy { archive, offset } = self.symtab.get(id).def {
            self.fetch(archive, offset);
        }
    }

    fn add_export(&mut self, spec: ExportSpec) {
        // x86: exports are undecorated like link.exe (`_foo` → `foo`), but `_foo@4` stays.
        let x86 = self.machine == Machine::X86;
        let name = match &spec.export_as {
            Some(n) => n.clone(),
            None if x86 && spec.name.starts_with('_') && !spec.name.contains('@') => {
                spec.name[1..].to_string()
            }
            None => spec.name.clone(),
        };
        if self.exports.iter().any(|e| e.name == name) {
            return;
        }
        let symbol = spec.symbol();
        let sym = if x86 && !symbol.starts_with(['_', '@', '?']) {
            self.add_root(&self.machine.mangle(symbol))
        } else {
            self.add_root(symbol)
        };
        self.exports.push(Export {
            name,
            sym,
            ordinal: spec.ordinal.unwrap_or(0),
            noname: spec.noname,
            data: spec.data,
            constant: spec.constant,
            private: spec.private,
        });
    }

    fn file_of(&self, def: Def) -> String {
        match def {
            Def::Defined { obj, .. } | Def::Common { obj, .. } => {
                self.objs[obj as usize].name.clone()
            }
            Def::Import { imp } | Def::Thunk { imp } => {
                String::from_utf8_lossy(self.imports[imp as usize].dll).into_owned()
            }
            _ => "<internal>".to_string(),
        }
    }

    fn duplicate(&mut self, id: SymId, existing: Def, file: &str) {
        let msg = format!(
            "duplicate symbol: {}\n>>> defined at {}\n>>> defined at {file}",
            diag::symbol(self.symtab.get(id).name),
            self.file_of(existing)
        );
        if self.cfg.force_multiple {
            diag::warn(msg);
        } else {
            diag::error(msg);
            self.errors += 1;
        }
    }

    fn define(&mut self, id: SymId, def: Def, file: &str) {
        let s = self.symtab.get_mut(id);
        match s.def {
            Def::Undefined | Def::Lazy { .. } | Def::Common { .. } => {
                s.def = def;
                s.comdat = false;
            }
            _ if s.replaceable => {
                s.def = def;
                s.replaceable = false;
            }
            existing if existing == def => {}
            existing => self.duplicate(id, existing, file),
        }
    }

    #[inline]
    fn intern_external(&mut self, ext: &ExternalSym<'a>, oi: u32) -> (SymId, bool) {
        if ext.id != NONE {
            (ext.id, false)
        } else {
            self.symtab.intern(ext.name, ext.hash, oi)
        }
    }

    fn select_comdat(
        &mut self,
        id: SymId,
        obj: &ObjFile<'a>,
        oi: u32,
        sec: u32,
        value: u32,
    ) -> bool {
        let section = &obj.sections[sec as usize];
        let selection = section.comdat.map_or(0, |c| c.selection);
        let s = self.symtab.get(id);
        let new = Def::Defined {
            obj: oi,
            sec,
            value,
        };
        match s.def {
            Def::Undefined | Def::Lazy { .. } | Def::Common { .. } => {
                let s = self.symtab.get_mut(id);
                s.def = new;
                s.comdat = true;
                true
            }
            Def::Defined {
                obj: o2, sec: s2, ..
            } if s.comdat => {
                let other = &self.objs[o2 as usize].sections[s2 as usize];
                let other_selection = other.comdat.map_or(0, |c| c.selection);
                if selection == IMAGE_COMDAT_SELECT_NODUPLICATES
                    || other_selection == IMAGE_COMDAT_SELECT_NODUPLICATES
                {
                    self.duplicate(id, s.def, &obj.name);
                    false
                } else if selection == IMAGE_COMDAT_SELECT_LARGEST && section.size > other.size {
                    self.objs[o2 as usize].sections[s2 as usize].discarded = true;
                    self.symtab.get_mut(id).def = new;
                    true
                } else {
                    false
                }
            }
            _ if s.replaceable => {
                let s = self.symtab.get_mut(id);
                s.def = new;
                s.comdat = true;
                s.replaceable = false;
                true
            }
            existing => {
                self.duplicate(id, existing, &obj.name);
                false
            }
        }
    }

    fn add_object(&mut self, mut obj: ObjFile<'a>) -> Result<()> {
        if obj.machine != IMAGE_FILE_MACHINE_UNKNOWN && obj.machine != self.machine.coff() {
            bail!(
                "{}: machine type {} conflicts with {}",
                obj.name,
                machine_name(obj.machine),
                self.machine.name()
            );
        }
        let oi = self.objs.len() as u32;
        if self.cfg.verbose {
            diag::note(format!("loaded {}", obj.name));
        }
        let externals = std::mem::take(&mut obj.externals);

        // COMDAT leaders first: whether this copy of each COMDAT wins decides
        // whether the other symbols in it are definitions or references.
        for ext in &externals {
            let ExtKind::Defined { sec, value } = ext.kind else {
                continue;
            };
            let s = &obj.sections[sec as usize];
            let Some(c) = s.comdat else { continue };
            if c.leader != ext.index
                || c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE
                || s.discarded
            {
                continue;
            }
            let (id, _) = self.intern_external(ext, oi);
            obj.sym_ids[ext.index as usize] = id;
            if self.select_comdat(id, &obj, oi, sec, value) {
                self.symtab.get_mut(id).function = ext.function;
            } else {
                obj.sections[sec as usize].discarded = true;
            }
        }
        obj.propagate_discards();

        let mut weak = Vec::new();
        for ext in &externals {
            let idx = ext.index as usize;
            if obj.sym_ids[idx] != NONE {
                continue;
            }
            let (id, new) = self.intern_external(ext, oi);
            obj.sym_ids[idx] = id;
            match ext.kind {
                ExtKind::Defined { sec, value } => {
                    if obj.sections[sec as usize].discarded {
                        self.reference(id);
                    } else {
                        let def = Def::Defined {
                            obj: oi,
                            sec,
                            value,
                        };
                        self.define(id, def, &obj.name);
                        if self.symtab.get(id).def == def {
                            self.symtab.get_mut(id).function = ext.function;
                        }
                    }
                }
                ExtKind::Absolute { value } => {
                    self.define(id, Def::Absolute { va: value as u64 }, &obj.name)
                }
                ExtKind::Undefined => self.reference(id),
                ExtKind::Common { size } => {
                    let s = self.symtab.get_mut(id);
                    match s.def {
                        Def::Undefined | Def::Lazy { .. } => s.def = Def::Common { obj: oi, size },
                        Def::Common { size: old, .. } if size > old => {
                            s.def = Def::Common { obj: oi, size }
                        }
                        _ => {}
                    }
                }
                ExtKind::Weak { alias } => {
                    let s = self.symtab.get_mut(id);
                    if new || s.def.is_lazy() {
                        s.def = Def::Undefined;
                    }
                    weak.push((id, alias));
                }
            }
        }
        for (id, alias) in weak {
            let target = match obj.sym_ids.get(alias as usize) {
                Some(&g) if g != NONE => Some(WeakAlias::Global(g)),
                _ => obj.raw_sym(alias).and_then(|r| {
                    let sec = (r.section - 1) as u32;
                    (r.section > 0 && !obj.sections[sec as usize].discarded).then_some(
                        WeakAlias::Local {
                            obj: oi,
                            sec,
                            value: r.value,
                        },
                    )
                }),
            };
            let s = self.symtab.get_mut(id);
            if s.def.is_undefined() && s.weak_alias.is_none() {
                s.weak_alias = target;
            }
        }

        let directives = std::mem::take(&mut obj.directives);
        let name = obj.name.clone();
        self.objs.push(obj);
        for d in directives {
            self.process_directives(d, &name)?;
        }
        Ok(())
    }

    fn add_import(&mut self, imp: ShortImport<'a>, file: &str) -> Result<()> {
        if imp.machine != self.machine.coff() && imp.machine != IMAGE_FILE_MACHINE_UNKNOWN {
            bail!(
                "{file}: machine type {} conflicts with {}",
                machine_name(imp.machine),
                self.machine.name()
            );
        }
        let ii = self.imports.len() as u32;
        self.imports.push(Import {
            dll: imp.dll,
            kind: imp.kind,
            name: imp.name,
            ordinal_or_hint: imp.ordinal_or_hint,
            live: AtomicBool::new(false),
            thunk_live: AtomicBool::new(false),
            iat_off: 0,
            hint_off: 0,
            thunk_off: 0,
        });
        let mut imp_name = b"__imp_".to_vec();
        imp_name.extend_from_slice(imp.symbol);
        let imp_name = self.bytes(&imp_name);
        let mut defs = vec![(imp_name, Def::Import { imp: ii })];
        match imp.kind {
            IMPORT_CODE => defs.push((imp.symbol, Def::Thunk { imp: ii })),
            IMPORT_CONST => defs.push((imp.symbol, Def::Import { imp: ii })),
            _ => {}
        }
        for (name, def) in defs {
            let (id, _) = self.symtab.intern(name, hash_name(name), NONE);
            let s = self.symtab.get_mut(id);
            if !s.def.is_defined() || s.replaceable {
                s.def = def;
                s.replaceable = false;
            }
        }
        Ok(())
    }

    fn process_directives(&mut self, text: &[u8], from: &str) -> Result<()> {
        let text = String::from_utf8_lossy(text);
        let mut toks = Vec::new();
        crate::cmdline::tokenize_windows(text.trim_start_matches('\u{feff}'), &mut toks);
        for tok in toks {
            let Some(body) = tok.strip_prefix('/').or_else(|| tok.strip_prefix('-')) else {
                continue;
            };
            let (name, val) = body.split_once(':').unwrap_or((body, ""));
            match name.to_ascii_lowercase().as_str() {
                "defaultlib" if !val.is_empty() => self.queue_default_lib(val),
                "nodefaultlib" => {
                    if val.is_empty() {
                        self.no_default_all = true;
                    } else {
                        self.no_default_libs.insert(lib_key(val));
                    }
                }
                "include" if !val.is_empty() => {
                    self.add_root(val);
                }
                "includeoptional" if !val.is_empty() => {
                    if let Some(id) = self.symtab.find(val.as_bytes())
                        && self.symtab.get(id).def.is_lazy()
                    {
                        self.add_root(val);
                    }
                }
                "alternatename" => {
                    if let Ok(pair) = parse_assignment(val, &tok) {
                        self.alternate_names.push(pair);
                    }
                }
                "export" => {
                    let spec = parse_export(val).map_err(|e| err!("{from}: {e}"))?;
                    self.add_export(spec);
                }
                "merge" => {
                    if let Ok((a, b)) = parse_assignment(val, &tok) {
                        self.merges.entry(a).or_insert(b);
                    }
                }
                "failifmismatch" => {
                    if let Some((k, v)) = val.split_once('=') {
                        match self.failifmismatch.get(k) {
                            Some((v2, f2)) if v2 != v => {
                                diag::error(format!(
                                    "/FAILIFMISMATCH: mismatch detected for '{k}':\n>>> {f2} has value {v2}\n>>> {from} has value {v}"
                                ));
                                self.errors += 1;
                            }
                            Some(_) => {}
                            None => {
                                self.failifmismatch
                                    .insert(k.to_string(), (v.to_string(), from.to_string()));
                            }
                        }
                    }
                }
                "entry" if !val.is_empty() && self.entry_name.is_none() => {
                    self.entry_name = Some(val.to_string());
                    self.entry = Some(self.add_root(&self.machine.mangle(val)));
                }
                "subsystem" if self.subsystem.is_none() => {
                    let sub = val.split(',').next().unwrap_or("");
                    self.subsystem = Subsystem::parse(sub);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resolve_remaining(&mut self) -> Result<()> {
        let n = self.symtab.len();
        for _ in 0..8 {
            let mut changed = false;
            for id in 0..n {
                let s = &self.symtab.syms[id];
                if !s.def.is_undefined() {
                    continue;
                }
                let new = match s.weak_alias {
                    Some(WeakAlias::Global(t)) => {
                        let d = self.symtab.syms[t as usize].def;
                        d.is_defined().then_some(d)
                    }
                    Some(WeakAlias::Local { obj, sec, value }) => {
                        Some(Def::Defined { obj, sec, value })
                    }
                    None => None,
                };
                if let Some(d) = new {
                    self.symtab.syms[id].def = d;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let mut stand_ins = HashSet::new();
        if self.machine == Machine::X86 {
            for i in 0..self.exports.len() {
                let sym = self.exports[i].sym;
                if !self.symtab.get(sym).def.is_undefined() {
                    continue;
                }
                let prefix = format!("{}@", String::from_utf8_lossy(self.symtab.get(sym).name));
                if let Some(real) = self.find_decorated(&prefix) {
                    self.exports[i].sym = real;
                    self.gc_roots.push(real);
                    stand_ins.insert(sym);
                }
            }
        }

        let mut undefined = Vec::new();
        for id in 0..n as SymId {
            if stand_ins.contains(&id) && self.symtab.get(id).first_ref == NONE {
                continue;
            }
            let s = self.symtab.get(id);
            if !s.def.is_undefined() {
                continue;
            }
            if let Some(local) = s.name.strip_prefix(b"__imp_")
                && let Some(t) = self.symtab.find(local)
                && self.symtab.get(t).def.is_defined()
            {
                if self.cfg.verbose {
                    diag::warn(format!(
                        "{}: locally defined symbol imported",
                        diag::symbol(local)
                    ));
                }
                let slot = self.local_imports.len() as u32;
                self.local_imports.push(t);
                self.symtab.get_mut(id).def = Def::LocalImport { slot };
                continue;
            }
            undefined.push(id);
        }

        if self.entry.is_none() && !self.cfg.dll && !self.cfg.no_entry {
            diag::error(
                "entry point must be defined: no main, wmain, WinMain or wWinMain was found, and no /ENTRY was given",
            );
            self.errors += 1;
        }

        for (i, &id) in undefined.iter().enumerate() {
            if i == 20 && !self.cfg.force_unresolved {
                diag::error(format!(
                    "too many undefined symbols ({} in total)",
                    undefined.len()
                ));
                break;
            }
            let s = self.symtab.get(id);
            let referrer = if s.first_ref == NONE {
                "the command line or a linker directive".to_string()
            } else {
                self.objs[s.first_ref as usize].name.clone()
            };
            let msg = format!(
                "undefined symbol: {}\n>>> referenced by {referrer}",
                diag::symbol(s.name)
            );
            if self.cfg.force_unresolved {
                diag::warn(msg);
            } else {
                diag::error(msg);
            }
        }
        if !self.cfg.force_unresolved {
            self.errors += undefined.len();
        }
        if self.errors > 0 {
            bail!("link failed with {} error(s)", self.errors);
        }
        for e in &self.exports {
            if matches!(
                self.symtab.get(e.sym).def,
                Def::Import { .. } | Def::Thunk { .. }
            ) {
                bail!(
                    "cannot export '{}': it is imported from another DLL (forwarders aren't supported yet)",
                    e.name
                );
            }
        }
        Ok(())
    }

    pub fn output_path(&self) -> PathBuf {
        if let Some(out) = &self.cfg.output {
            return out.clone();
        }
        let stem = self
            .cfg
            .inputs
            .first()
            .and_then(|i| Path::new(&i.path).file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "a".to_string());
        PathBuf::from(format!(
            "{stem}.{}",
            if self.cfg.dll { "dll" } else { "exe" }
        ))
    }
}

pub fn detect_machine(cfg: &Config) -> Machine {
    use std::io::Read;
    for input in &cfg.inputs {
        let mut head = [0u8; 64];
        let Ok(mut f) = std::fs::File::open(&input.path) else {
            continue;
        };
        let Ok(n) = f.read(&mut head) else { continue };
        let head = &head[..n];
        let machine = match identify(head) {
            FileKind::Object => u16le(head, 0),
            FileKind::BigObject => u16le(head, 6),
            _ => continue,
        };
        if let Some(m) = Machine::from_coff(machine) {
            return m;
        }
    }
    Machine::X64
}

fn unsupported(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Bitcode => {
            "LLVM bitcode (linker-plugin LTO) is not supported yet; build without `-C linker-plugin-lto`"
        }
        FileKind::AnonObject => "MSVC /GL (link-time code generation) objects are not supported",
        FileKind::ThinArchive => "thin archives are not supported yet",
        FileKind::Elf => "this is an ELF file; hyprlnk links PE/COFF for now",
        FileKind::MachO => "this is a Mach-O file; hyprlnk links PE/COFF for now",
        _ => "unknown file type",
    }
}
