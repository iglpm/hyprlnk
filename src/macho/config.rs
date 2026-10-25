//! `ld64`/`ld64.lld` command lines, and the `cc`-driver lines rustc writes for a linker it doesn't know.

use std::path::PathBuf;

use super::*;
use crate::diag::{self, Result};
use crate::{bail, err};

pub const HELP: &str = "\
hyprlnk: the fastest linker for macOS (ld64 / ld64.lld command line)

USAGE: hyprlnk [-flavor darwin] [options] <inputs...>

Inputs are Mach-O objects, archives (.a, .rlib), dylibs and text stubs
(.tbd), thin or universal. @file reads more arguments from a response file.
Architectures: arm64, arm64e, x86_64, x86_64h.

Output:
  -o <file>                  output file (default: a.out)
  -execute | -dylib | -bundle
  -arch <name>               (default: from the first object)
  -platform_version <platform> <min> <sdk>
  -macos_version_min <v>     also -ios_version_min and friends
  -e <symbol>                entry point (default: _main)
  -install_name <path>  -current_version <v>  -compatibility_version <v>
  -rpath <path>  -headerpad <n>  -headerpad_max_install_names
  -pagezero_size <n>  -stack_size <n>  -image_base <addr>
  -fixup_chains | -no_fixup_chains   (default: chained fixups from macOS 13)
  -adhoc_codesign | -no_adhoc_codesign   -no_uuid  -random_uuid
  -sectcreate <seg> <sect> <file>

Libraries and symbols:
  -l<name>  -framework <name>  -L<dir>  -F<dir>  -Z  -syslibroot <dir>
  -weak-l<name>  -weak_framework <name>  -needed-l<name>  -reexport-l<name>
  -force_load <archive>  -all_load  -ObjC  -search_paths_first
  -dead_strip  -dead_strip_dylibs  -u <sym>  -U <sym>  -alias <from> <to>
  -undefined error|warning|suppress|dynamic_lookup  -flat_namespace
  -exported_symbol(s_list) <..>  -unexported_symbol(s_list) <..>
  -no_exported_symbols  -export_dynamic  -bundle_loader <exe>
  -x (no local symbols)  -S (no debug map)  -oso_prefix <dir>

Diagnostics:
  -print_statistics, --time  print how long each phase took
  -t                         print each file as it is loaded
  -map <file>                write a map file
  --reproduce=<dir>          copy the inputs and a response file repeating
                             the link to <dir> (also HYPRLNK_REPRODUCE)
  --threads=<n>              worker threads (default: all cores)
  -dependency_info <file>  -w  -fatal_warnings  -v  --version

`cc`-style lines (-Wl,…, -isysroot, -mmacosx-version-min=, -dynamiclib)
are understood too, so rustc can run hyprlnk as its linker directly.
Documentation: https://github.com/runepm/hyprlnk/tree/main/docs
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Arm64,
    Arm64e,
    X86_64,
    X86_64h,
}

impl Arch {
    pub fn parse(name: &str) -> Option<Arch> {
        Some(match name {
            "arm64" | "aarch64" => Arch::Arm64,
            "arm64e" => Arch::Arm64e,
            "x86_64" | "amd64" | "x86-64" => Arch::X86_64,
            "x86_64h" => Arch::X86_64h,
            _ => return None,
        })
    }

    pub fn from_cpu(cputype: u32, cpusubtype: u32) -> Option<Arch> {
        match cputype {
            CPU_TYPE_ARM64 if cpusubtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E => {
                Some(Arch::Arm64e)
            }
            CPU_TYPE_ARM64 => Some(Arch::Arm64),
            CPU_TYPE_X86_64 if cpusubtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_X86_64_H => {
                Some(Arch::X86_64h)
            }
            CPU_TYPE_X86_64 => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Arch::Arm64 => "arm64",
            Arch::Arm64e => "arm64e",
            Arch::X86_64 => "x86_64",
            Arch::X86_64h => "x86_64h",
        }
    }

    pub fn cputype(self) -> u32 {
        match self {
            Arch::Arm64 | Arch::Arm64e => CPU_TYPE_ARM64,
            Arch::X86_64 | Arch::X86_64h => CPU_TYPE_X86_64,
        }
    }

    pub fn cpusubtype(self) -> u32 {
        match self {
            Arch::Arm64 => CPU_SUBTYPE_ARM64_ALL,
            // Versioned pointer-authentication ABI, version 1: what ld64 writes for images.
            Arch::Arm64e => CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI | (1 << 24),
            Arch::X86_64 => CPU_SUBTYPE_X86_64_ALL,
            Arch::X86_64h => CPU_SUBTYPE_X86_64_H,
        }
    }

    pub fn is_arm(self) -> bool {
        matches!(self, Arch::Arm64 | Arch::Arm64e)
    }

    pub fn page_size(self) -> u64 {
        if self.is_arm() { 0x4000 } else { 0x1000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    Execute,
    Dylib,
    Bundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undefined {
    Error,
    Warning,
    Suppress,
    DynamicLookup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKind {
    File(String),
    Library(String),
    Framework(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadFlags {
    pub weak: bool,
    pub reexport: bool,
    pub needed: bool,
    pub upward: bool,
    pub force_load: bool,
    pub hidden: bool,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub kind: InputKind,
    pub flags: LoadFlags,
}

/// A symbol name or a glob (`*`, `?`, `[...]`), as in `-exported_symbols_list`.
#[derive(Debug, Clone, Default)]
pub struct SymbolSet {
    pub literals: std::collections::HashSet<Vec<u8>>,
    pub globs: Vec<Vec<u8>>,
}

impl SymbolSet {
    pub fn is_empty(&self) -> bool {
        self.literals.is_empty() && self.globs.is_empty()
    }

    pub fn insert(&mut self, pattern: &str) {
        let p = pattern.trim();
        if p.is_empty() {
            return;
        }
        if p.contains(['*', '?', '[']) {
            self.globs.push(p.as_bytes().to_vec());
        } else {
            self.literals.insert(p.as_bytes().to_vec());
        }
    }

    pub fn contains(&self, name: &[u8]) -> bool {
        self.literals.contains(name) || self.globs.iter().any(|g| glob_match(g, name))
    }

    fn read_list(&mut self, path: &str) -> Result<()> {
        let text = std::fs::read(path).map_err(|e| err!("cannot read '{path}': {e}"))?;
        for line in String::from_utf8_lossy(&text).lines() {
            let line = line.split('#').next().unwrap_or("");
            self.insert(line);
        }
        Ok(())
    }
}

pub fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while i < s.len() {
        if p < pat.len() {
            match pat[p] {
                b'*' => {
                    star = p;
                    mark = i;
                    p += 1;
                    continue;
                }
                b'?' => {
                    p += 1;
                    i += 1;
                    continue;
                }
                b'[' => {
                    if let Some(end) = pat[p + 1..].iter().position(|&c| c == b']') {
                        let class = &pat[p + 1..p + 1 + end];
                        if class_match(class, s[i]) {
                            p += end + 2;
                            i += 1;
                            continue;
                        }
                    } else if s[i] == b'[' {
                        p += 1;
                        i += 1;
                        continue;
                    }
                }
                c if c == s[i] => {
                    p += 1;
                    i += 1;
                    continue;
                }
                _ => {}
            }
        }
        if star == usize::MAX {
            return false;
        }
        p = star + 1;
        mark += 1;
        i = mark;
    }
    pat[p..].iter().all(|&c| c == b'*')
}

fn class_match(class: &[u8], c: u8) -> bool {
    let (negate, class) = match class.first() {
        Some(b'!' | b'^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut i = 0;
    let mut hit = false;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            hit |= (class[i]..=class[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= class[i] == c;
            i += 1;
        }
    }
    hit != negate
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output: PathBuf,
    pub final_output: Option<String>,
    pub arch: Option<Arch>,
    pub platform: u32,
    pub min_version: u32,
    pub sdk_version: u32,
    pub version_given: bool,
    pub syslibroots: Vec<PathBuf>,
    pub lib_paths: Vec<PathBuf>,
    pub framework_paths: Vec<PathBuf>,
    pub no_default_paths: bool,
    pub search_dylibs_first: bool,
    pub inputs: Vec<Input>,
    pub all_load: bool,
    pub objc: bool,
    pub kind: OutputKind,
    pub entry: Option<String>,
    pub dead_strip: bool,
    pub dead_strip_dylibs: bool,
    pub install_name: Option<String>,
    pub current_version: u32,
    pub compat_version: u32,
    pub exported: SymbolSet,
    pub unexported: SymbolSet,
    pub no_exported_symbols: bool,
    pub export_dynamic: bool,
    pub rpaths: Vec<String>,
    pub headerpad: u64,
    pub headerpad_max_install_names: bool,
    pub pagezero_size: Option<u64>,
    pub stack_size: u64,
    pub image_base: Option<u64>,
    pub undefined: Undefined,
    pub flat_namespace: bool,
    pub bundle_loader: Option<String>,
    pub forced_undefined: Vec<String>,
    pub dynamic_lookup: Vec<String>,
    pub aliases: Vec<(String, String)>,
    pub sectcreate: Vec<(String, String, PathBuf)>,
    pub ast_paths: Vec<String>,
    pub order_file: Option<PathBuf>,
    pub map: Option<PathBuf>,
    pub why_live: Vec<String>,
    pub trace: bool,
    pub time: bool,
    pub verbose: bool,
    pub uuid: UuidMode,
    pub adhoc_codesign: Option<bool>,
    pub strip_debug: bool,
    pub strip_locals: bool,
    pub strip_temp_locals: bool,
    pub fatal_warnings: bool,
    pub suppress_warnings: bool,
    pub pie: Option<bool>,
    pub fixup_chains: Option<bool>,
    pub data_const: Option<bool>,
    pub application_extension: bool,
    pub oso_prefix: Option<String>,
    pub source_version: u64,
    pub threads: Option<usize>,
    pub reproduce: Option<PathBuf>,
    pub dependency_info: Option<PathBuf>,
    pub interposable: bool,
    pub umbrella: Option<String>,
    pub allowable_clients: Vec<String>,
    pub print_help: bool,
    pub print_version: bool,
    pub cc_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidMode {
    Content,
    Random,
    None,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            output: PathBuf::from("a.out"),
            final_output: None,
            arch: None,
            platform: PLATFORM_MACOS,
            min_version: 0,
            sdk_version: 0,
            version_given: false,
            syslibroots: Vec::new(),
            lib_paths: Vec::new(),
            framework_paths: Vec::new(),
            no_default_paths: false,
            search_dylibs_first: false,
            inputs: Vec::new(),
            all_load: false,
            objc: false,
            kind: OutputKind::Execute,
            entry: None,
            dead_strip: false,
            dead_strip_dylibs: false,
            install_name: None,
            current_version: 0,
            compat_version: 0,
            exported: SymbolSet::default(),
            unexported: SymbolSet::default(),
            no_exported_symbols: false,
            export_dynamic: false,
            rpaths: Vec::new(),
            headerpad: 32,
            headerpad_max_install_names: false,
            pagezero_size: None,
            stack_size: 0,
            image_base: None,
            undefined: Undefined::Error,
            flat_namespace: false,
            bundle_loader: None,
            forced_undefined: Vec::new(),
            dynamic_lookup: Vec::new(),
            aliases: Vec::new(),
            sectcreate: Vec::new(),
            ast_paths: Vec::new(),
            order_file: None,
            map: None,
            why_live: Vec::new(),
            trace: false,
            time: false,
            verbose: false,
            uuid: UuidMode::Content,
            adhoc_codesign: None,
            strip_debug: false,
            strip_locals: false,
            strip_temp_locals: false,
            fatal_warnings: false,
            suppress_warnings: false,
            pie: None,
            fixup_chains: None,
            data_const: None,
            application_extension: false,
            oso_prefix: None,
            source_version: 0,
            threads: None,
            reproduce: None,
            dependency_info: None,
            interposable: false,
            umbrella: None,
            allowable_clients: Vec::new(),
            print_help: false,
            print_version: false,
            cc_mode: false,
        }
    }
}

/// Expand `@file` response files (GNU quoting, as ld64.lld reads them).
pub fn expand_args(args: Vec<String>) -> Result<Vec<String>> {
    crate::cmdline::expand_gnu_response_files(args)
}

/// Options that take arguments: how many. Everything here is accepted; most are honored.
fn arity(name: &str) -> Option<usize> {
    Some(match name {
        "-o"
        | "-arch"
        | "-e"
        | "-L"
        | "-F"
        | "-framework"
        | "-weak_framework"
        | "-needed_framework"
        | "-reexport_framework"
        | "-lazy_framework"
        | "-upward_framework"
        | "-weak_library"
        | "-needed_library"
        | "-reexport_library"
        | "-lazy_library"
        | "-upward_library"
        | "-force_load"
        | "-load_hidden"
        | "-syslibroot"
        | "-isysroot"
        | "-install_name"
        | "-dylib_install_name"
        | "-current_version"
        | "-dylib_current_version"
        | "-compatibility_version"
        | "-dylib_compatibility_version"
        | "-exported_symbols_list"
        | "-exported_symbol"
        | "-unexported_symbols_list"
        | "-unexported_symbol"
        | "-reexported_symbols_list"
        | "-rpath"
        | "-headerpad"
        | "-pagezero_size"
        | "-stack_size"
        | "-image_base"
        | "-seg1addr"
        | "-undefined"
        | "-bundle_loader"
        | "-u"
        | "-U"
        | "-order_file"
        | "-map"
        | "-why_live"
        | "-filelist"
        | "-macos_version_min"
        | "-macosx_version_min"
        | "-ios_version_min"
        | "-iphoneos_version_min"
        | "-ios_simulator_version_min"
        | "-tvos_version_min"
        | "-watchos_version_min"
        | "-oso_prefix"
        | "-source_version"
        | "-dependency_info"
        | "-final_output"
        | "-lto_library"
        | "-mllvm"
        | "-object_path_lto"
        | "-cache_path_lto"
        | "-pigel_interval_lto"
        | "-pigel_after_lto"
        | "-max_relative_cache_size_lto"
        | "-add_ast_path"
        | "-umbrella"
        | "-allowable_client"
        | "-sub_library"
        | "-sub_umbrella"
        | "-client_name"
        | "-objc_abi_version"
        | "-alias_list"
        | "-dylinker_install_name"
        | "-max_default_common_align"
        | "-sectorder"
        | "-mcpu"
        | "-interposable_list"
        | "-unaliased"
        | "-read_only_relocs"
        | "-multiply_defined"
        | "-multiply_defined_unused"
        | "-max_relative_cache_size"
        | "-iosmac_version_min"
        | "-uikitformac_version_min"
        | "-bitcode_symbol_map"
        | "-order_file_statistics"
        | "-exported_symbols_order"
        | "-dirty_data_list"
        | "-image_suffix"
        | "-threads"
        | "-reproduce"
        | "-thread_count"
        | "-dtrace"
        | "-segaddr_table"
        | "-seg_page_size"
        | "-commons"
        | "-warn_commons"
        | "-weak_reference_mismatches"
        | "-sect_diff_relocs"
        | "-sdk_version"
        | "-objc_stubs_small"
        | "-objc_stubs_fast"
        | "-ld_path"
        | "-flavor" => 1,
        "-platform_version" | "-sectcreate" | "-segcreate" | "-sectalign" | "-segprot" => 3,
        "-alias"
        | "-rename_section"
        | "-rename_segment"
        | "-segaddr"
        | "-sectobjectsymbols"
        | "-exported_symbols_order_file" => 2,
        "-segprot_max" => 3,
        _ => return None,
    })
}

const IGNORED_FLAGS: &[&str] = &[
    "-dynamic",
    "-demangle",
    "-no_demangle",
    "-search_paths_first",
    "-no_deduplicate",
    "-deduplicate",
    "-pie",
    "-no_pie",
    "-twolevel_namespace",
    "-no_compact_unwind",
    "-keep_dwarf_unwind",
    "-no_keep_dwarf_unwind",
    "-no_eh_labels",
    "-warn_compact_unwind",
    "-no_weak_imports",
    "-no_warn_duplicate_libraries",
    "-warn_duplicate_libraries",
    "-no_warn_inits",
    "-warn_unused_dylibs",
    "-no_function_starts",
    "-function_starts",
    "-no_data_in_code_info",
    "-data_in_code_info",
    "-no_version_load_command",
    "-no_source_version",
    "-add_source_version",
    "-no_objc_category_merging",
    "-objc_category_merging",
    "-ld_classic",
    "-ld_new",
    "-ld64",
    "-no_order_inits",
    "-mark_dead_strippable_dylib",
    "-dead_strip_inits_and_terms",
    "-no_dead_strip_inits_and_terms",
    "-bind_at_load",
    "-no_implicit_dylibs",
    "-noall_load",
    "-prebind",
    "-noprebind",
    "-nofixprebinding",
    "-nomultidefs",
    "-no_branch_islands",
    "-single_module",
    "-multi_module",
    "-no_arch_warnings",
    "-arch_errors_fatal",
    "-allow_stack_execute",
    "-allow_heap_execute",
    "-no_zero_fill_sections",
    "-warn_weak_exports",
    "-warn_stabs",
    "-force_flat_namespace",
    "-no_uuid_warning",
    "-no_inits",
    "-no_warn_unused_dylibs",
    "-reexported_symbols_list_ignored",
    "-ignore_optimization_hints",
    "-ignore_auto_link",
    "-no_new_main",
    "-new_main",
    "-noseglinkedit",
    "-seglinkedit",
    "-dylib_file",
    "-no_merge_objc_categories",
    "-merge_zero_fill_sections",
    "-launch_time_profile",
    "-print_text_section_size",
    "-no_application_extension",
    "-debug_variant",
    "-reproducible",
    "-objc_relative_method_lists",
    "-no_objc_relative_method_lists",
    "-validate_linkedit",
    "-nostdlib",
    "-nodefaultlibs",
    "-nostartfiles",
    "-m64",
    "-pthread",
    "-rdynamic_ignored",
    "-fobjc-link-runtime",
    "-static-libgcc",
    "-mno-red-zone",
];

impl Config {
    pub fn parse(args: &[String]) -> Result<Config> {
        let mut cfg = Config::default();
        let args = if looks_like_cc(args) {
            cfg.cc_mode = true;
            translate_cc(args)
        } else {
            args.to_vec()
        };
        let mut i = 0;
        let mut flat_lookups = Vec::new();
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if let Some(rest) = arg.strip_prefix("-Wl,") {
                let inner: Vec<String> = rest.split(',').map(str::to_string).collect();
                let sub = Config::parse_into(&mut cfg, &inner, &mut flat_lookups);
                sub?;
                continue;
            }
            if !arg.starts_with('-') || arg == "-" {
                cfg.inputs.push(Input {
                    kind: InputKind::File(arg.clone()),
                    flags: LoadFlags::default(),
                });
                continue;
            }
            let (name, inline) = split_option(arg);
            let n = arity(name).unwrap_or(0);
            let mut vals: Vec<&str> = Vec::with_capacity(n);
            if let Some(v) = inline {
                vals.push(v);
            }
            while vals.len() < n {
                let Some(v) = args.get(i) else {
                    bail!("{name}: missing argument");
                };
                vals.push(v);
                i += 1;
            }
            cfg.apply(name, &vals, arg, &mut flat_lookups)?;
        }
        cfg.finish(flat_lookups)?;
        Ok(cfg)
    }

    fn parse_into(cfg: &mut Config, args: &[String], flat: &mut Vec<String>) -> Result<()> {
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if !arg.starts_with('-') {
                cfg.inputs.push(Input {
                    kind: InputKind::File(arg.clone()),
                    flags: LoadFlags::default(),
                });
                continue;
            }
            let (name, inline) = split_option(arg);
            let n = arity(name).unwrap_or(0);
            let mut vals: Vec<&str> = Vec::new();
            if let Some(v) = inline {
                vals.push(v);
            }
            while vals.len() < n {
                let Some(v) = args.get(i) else {
                    bail!("{name}: missing argument");
                };
                vals.push(v);
                i += 1;
            }
            cfg.apply(name, &vals, arg, flat)?;
        }
        Ok(())
    }

    fn push(&mut self, kind: InputKind, flags: LoadFlags) {
        self.inputs.push(Input { kind, flags });
    }

    fn apply(&mut self, name: &str, v: &[&str], arg: &str, flat: &mut Vec<String>) -> Result<()> {
        let flags = |f: fn(&mut LoadFlags)| {
            let mut l = LoadFlags::default();
            f(&mut l);
            l
        };
        match name {
            "-o" => self.output = PathBuf::from(v[0]),
            "-final_output" => self.final_output = Some(v[0].to_string()),
            "-arch" => {
                self.arch = Some(
                    Arch::parse(v[0])
                        .ok_or_else(|| err!("unsupported architecture '{}' (hyprlnk links arm64, arm64e, x86_64 and x86_64h)", v[0]))?,
                )
            }
            "-platform_version" => {
                self.platform = parse_platform(v[0])
                    .ok_or_else(|| err!("-platform_version: unknown platform '{}'", v[0]))?;
                self.min_version = parse_version(v[1])
                    .ok_or_else(|| err!("-platform_version: bad version '{}'", v[1]))?;
                self.sdk_version = parse_version(v[2]).unwrap_or(self.min_version);
                self.version_given = true;
            }
            "-macos_version_min" | "-macosx_version_min" => self.set_min(PLATFORM_MACOS, v[0])?,
            "-ios_version_min" | "-iphoneos_version_min" => self.set_min(PLATFORM_IOS, v[0])?,
            "-ios_simulator_version_min" => self.set_min(PLATFORM_IOSSIMULATOR, v[0])?,
            "-tvos_version_min" => self.set_min(PLATFORM_TVOS, v[0])?,
            "-watchos_version_min" => self.set_min(PLATFORM_WATCHOS, v[0])?,
            "-iosmac_version_min" | "-uikitformac_version_min" => {
                self.set_min(PLATFORM_MACCATALYST, v[0])?
            }
            "-sdk_version" => self.sdk_version = parse_version(v[0]).unwrap_or(0),
            "-syslibroot" | "-isysroot" => self.syslibroots.push(PathBuf::from(v[0])),
            "-L" => self.lib_paths.push(PathBuf::from(v[0])),
            "-F" => self.framework_paths.push(PathBuf::from(v[0])),
            "-Z" => self.no_default_paths = true,
            "-search_dylibs_first" => self.search_dylibs_first = true,
            "-framework" => self.push(InputKind::Framework(v[0].to_string()), LoadFlags::default()),
            "-weak_framework" => {
                self.push(InputKind::Framework(v[0].to_string()), flags(|l| l.weak = true))
            }
            "-needed_framework" => {
                self.push(InputKind::Framework(v[0].to_string()), flags(|l| l.needed = true))
            }
            "-reexport_framework" => {
                self.push(InputKind::Framework(v[0].to_string()), flags(|l| l.reexport = true))
            }
            "-upward_framework" => {
                self.push(InputKind::Framework(v[0].to_string()), flags(|l| l.upward = true))
            }
            "-lazy_framework" => self.push(InputKind::Framework(v[0].to_string()), LoadFlags::default()),
            "-weak_library" => self.push(InputKind::File(v[0].to_string()), flags(|l| l.weak = true)),
            "-needed_library" => {
                self.push(InputKind::File(v[0].to_string()), flags(|l| l.needed = true))
            }
            "-reexport_library" => {
                self.push(InputKind::File(v[0].to_string()), flags(|l| l.reexport = true))
            }
            "-upward_library" => {
                self.push(InputKind::File(v[0].to_string()), flags(|l| l.upward = true))
            }
            "-lazy_library" => self.push(InputKind::File(v[0].to_string()), LoadFlags::default()),
            "-force_load" => {
                self.push(InputKind::File(v[0].to_string()), flags(|l| l.force_load = true))
            }
            "-load_hidden" => self.push(InputKind::File(v[0].to_string()), flags(|l| l.hidden = true)),
            "-filelist" => {
                let (file, dir) = match v[0].split_once(',') {
                    Some((f, d)) => (f, Some(d)),
                    None => (v[0], None),
                };
                let text = std::fs::read(file).map_err(|e| err!("cannot read -filelist '{file}': {e}"))?;
                for line in String::from_utf8_lossy(&text).lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let path = match dir {
                        Some(d) => format!("{d}/{line}"),
                        None => line.to_string(),
                    };
                    self.push(InputKind::File(path), LoadFlags::default());
                }
            }
            "-all_load" => self.all_load = true,
            "-ObjC" => self.objc = true,
            "-execute" => self.kind = OutputKind::Execute,
            "-dylib" | "-dynamiclib" | "-shared" => self.kind = OutputKind::Dylib,
            "-bundle" => self.kind = OutputKind::Bundle,
            "-r" => bail!("relocatable output (-r) is not supported"),
            "-static" => bail!("static Mach-O images (-static) are not supported"),
            "-preload" => bail!("-preload images are not supported"),
            "-e" => self.entry = Some(v[0].to_string()),
            "-dead_strip" => self.dead_strip = true,
            "-no_dead_strip" => self.dead_strip = false,
            "-dead_strip_dylibs" => self.dead_strip_dylibs = true,
            "-install_name" | "-dylib_install_name" => self.install_name = Some(v[0].to_string()),
            "-current_version" | "-dylib_current_version" => {
                self.current_version = parse_version(v[0])
                    .ok_or_else(|| err!("{name}: bad version '{}'", v[0]))?
            }
            "-compatibility_version" | "-dylib_compatibility_version" => {
                self.compat_version = parse_version(v[0])
                    .ok_or_else(|| err!("{name}: bad version '{}'", v[0]))?
            }
            "-exported_symbols_list" => self.exported.read_list(v[0])?,
            "-exported_symbol" => self.exported.insert(v[0]),
            "-unexported_symbols_list" => self.unexported.read_list(v[0])?,
            "-unexported_symbol" => self.unexported.insert(v[0]),
            "-no_exported_symbols" => self.no_exported_symbols = true,
            "-export_dynamic" | "-rdynamic" => self.export_dynamic = true,
            "-rpath" => self.rpaths.push(v[0].to_string()),
            "-headerpad" => self.headerpad = parse_number(v[0])?,
            "-headerpad_max_install_names" => self.headerpad_max_install_names = true,
            "-pagezero_size" => self.pagezero_size = Some(parse_number(v[0])?),
            "-stack_size" => self.stack_size = parse_number(v[0])?,
            "-image_base" | "-seg1addr" => self.image_base = Some(parse_number(v[0])?),
            "-undefined" => {
                self.undefined = match v[0] {
                    "error" => Undefined::Error,
                    "warning" => Undefined::Warning,
                    "suppress" => Undefined::Suppress,
                    "dynamic_lookup" => Undefined::DynamicLookup,
                    other => bail!("-undefined: unknown treatment '{other}'"),
                }
            }
            "-flat_namespace" => self.flat_namespace = true,
            "-twolevel_namespace" => self.flat_namespace = false,
            "-bundle_loader" => self.bundle_loader = Some(v[0].to_string()),
            "-u" => self.forced_undefined.push(v[0].to_string()),
            "-U" => flat.push(v[0].to_string()),
            "-alias" => self.aliases.push((v[0].to_string(), v[1].to_string())),
            "-alias_list" => {
                let text = std::fs::read(v[0]).map_err(|e| err!("cannot read '{}': {e}", v[0]))?;
                for line in String::from_utf8_lossy(&text).lines() {
                    let line = line.split('#').next().unwrap_or("");
                    let mut parts = line.split_whitespace();
                    if let (Some(a), Some(b)) = (parts.next(), parts.next()) {
                        self.aliases.push((a.to_string(), b.to_string()));
                    }
                }
            }
            "-sectcreate" | "-segcreate" => {
                self.sectcreate
                    .push((v[0].to_string(), v[1].to_string(), PathBuf::from(v[2])))
            }
            "-add_ast_path" => self.ast_paths.push(v[0].to_string()),
            "-order_file" => self.order_file = Some(PathBuf::from(v[0])),
            "-map" => self.map = Some(PathBuf::from(v[0])),
            "-why_live" => self.why_live.push(v[0].to_string()),
            "-t" => self.trace = true,
            "-print_statistics" | "--time" | "-time" | "--time-trace" => self.time = true,
            "-v" => self.verbose = true,
            "-version_details" | "--version" | "-version" => self.print_version = true,
            "-help" | "--help" | "-h" => self.print_help = true,
            "-no_uuid" => self.uuid = UuidMode::None,
            "-random_uuid" => self.uuid = UuidMode::Random,
            "-adhoc_codesign" => self.adhoc_codesign = Some(true),
            "-no_adhoc_codesign" => self.adhoc_codesign = Some(false),
            "-S" => self.strip_debug = true,
            "-x" => self.strip_locals = true,
            "-X" => self.strip_temp_locals = true,
            "-w" => self.suppress_warnings = true,
            "-fatal_warnings" => self.fatal_warnings = true,
            "-pie" => self.pie = Some(true),
            "-no_pie" => self.pie = Some(false),
            "-fixup_chains" | "-chained_fixups" => self.fixup_chains = Some(true),
            "-no_fixup_chains" | "-no_chained_fixups" => self.fixup_chains = Some(false),
            "-data_const" => self.data_const = Some(true),
            "-no_data_const" => self.data_const = Some(false),
            "-application_extension" => self.application_extension = true,
            "-oso_prefix" => self.oso_prefix = Some(v[0].to_string()),
            "-source_version" => self.source_version = parse_source_version(v[0])?,
            "-dependency_info" => self.dependency_info = Some(PathBuf::from(v[0])),
            "-interposable" => self.interposable = true,
            "-umbrella" => self.umbrella = Some(v[0].to_string()),
            "-allowable_client" => self.allowable_clients.push(v[0].to_string()),
            "--threads" | "-threads" | "-thread_count" => {
                let n: usize = v[0]
                    .parse()
                    .map_err(|_| err!("{name}: expected a number, got '{}'", v[0]))?;
                self.threads = Some(n.max(1));
            }
            "--reproduce" | "-reproduce" => self.reproduce = Some(PathBuf::from(v[0])),
            "-flavor" => {}
            _ if arity(name).is_some() => {}
            _ if IGNORED_FLAGS.contains(&name) => {}
            _ if name.starts_with("-fuse-ld=")
                || name.starts_with("--ld-path=")
                || name.starts_with("-mllvm")
                || name.starts_with("-O")
                || name.starts_with("-g")
                || name.starts_with("-f")
                || name.starts_with("-B")
                || name.starts_with("--no-")
                || name.starts_with("-W") =>
            {
                // Compiler-driver and optimization flags that reach the linker through rustflags.
            }
            _ => return self.apply_prefixed(arg),
        }
        Ok(())
    }

    /// `-l<name>`, `-L<dir>`, `-F<dir>` and the `-weak-l<name>` family.
    fn apply_prefixed(&mut self, arg: &str) -> Result<()> {
        let flags = |f: fn(&mut LoadFlags)| {
            let mut l = LoadFlags::default();
            f(&mut l);
            l
        };
        // -l<name> and its variants carry the name in the same argument.
        for (prefix, f) in [
            (
                "-weak-l",
                (|l: &mut LoadFlags| l.weak = true) as fn(&mut LoadFlags),
            ),
            ("-needed-l", |l| l.needed = true),
            ("-reexport-l", |l| l.reexport = true),
            ("-lazy-l", |_| {}),
            ("-upward-l", |l| l.upward = true),
            ("-hidden-l", |l| l.hidden = true),
        ] {
            if let Some(lib) = arg.strip_prefix(prefix)
                && !lib.is_empty()
            {
                self.push(InputKind::Library(lib.to_string()), flags(f));
                return Ok(());
            }
        }
        if let Some(lib) = arg.strip_prefix("-l")
            && !lib.is_empty()
        {
            self.push(InputKind::Library(lib.to_string()), LoadFlags::default());
            return Ok(());
        }
        if let Some(dir) = arg.strip_prefix("-L")
            && !dir.is_empty()
        {
            self.lib_paths.push(PathBuf::from(dir));
            return Ok(());
        }
        if let Some(dir) = arg.strip_prefix("-F")
            && !dir.is_empty()
        {
            self.framework_paths.push(PathBuf::from(dir));
            return Ok(());
        }
        diag::warn(format!("ignoring unknown option '{arg}'"));
        Ok(())
    }

    fn set_min(&mut self, platform: u32, v: &str) -> Result<()> {
        self.platform = platform;
        self.min_version = parse_version(v).ok_or_else(|| err!("bad version '{v}'"))?;
        self.version_given = true;
        Ok(())
    }

    fn finish(&mut self, flat: Vec<String>) -> Result<()> {
        self.dynamic_lookup = flat;
        if self.min_version == 0 {
            // ld64's defaults for a target without a version: the oldest each architecture runs.
            self.min_version = match self.arch {
                Some(Arch::X86_64 | Arch::X86_64h) => 0x000a_0d00,
                _ => 0x000b_0000,
            };
        }
        if self.sdk_version == 0 {
            self.sdk_version = self.min_version;
        }
        if self.syslibroots.is_empty()
            && let Some(sdk) = std::env::var_os("SDKROOT").filter(|s| !s.is_empty())
            && self.cc_mode
        {
            self.syslibroots.push(PathBuf::from(sdk));
        }
        if self.compat_version != 0 && self.kind != OutputKind::Dylib {
            bail!("-compatibility_version is only valid with -dylib");
        }
        Ok(())
    }

    pub fn is_pie(&self) -> bool {
        self.pie.unwrap_or(true) || self.kind != OutputKind::Execute
    }
}

fn split_option(arg: &str) -> (&str, Option<&str>) {
    if arg.starts_with("--")
        && let Some((n, v)) = arg.split_once('=')
    {
        return (n, Some(v));
    }
    (arg, None)
}

pub fn parse_platform(s: &str) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Some(n);
    }
    Some(match s {
        "macos" | "macosx" | "osx" => PLATFORM_MACOS,
        "ios" | "iphoneos" => PLATFORM_IOS,
        "tvos" => PLATFORM_TVOS,
        "watchos" => PLATFORM_WATCHOS,
        "bridgeos" => PLATFORM_BRIDGEOS,
        "mac-catalyst" | "maccatalyst" | "ios-macabi" => PLATFORM_MACCATALYST,
        "ios-simulator" | "ios-sim" | "iossimulator" | "iossim" => PLATFORM_IOSSIMULATOR,
        "tvos-simulator" | "tvossimulator" => PLATFORM_TVOSSIMULATOR,
        "watchos-simulator" | "watchossimulator" => PLATFORM_WATCHOSSIMULATOR,
        "driverkit" => PLATFORM_DRIVERKIT,
        "xros" | "visionos" => PLATFORM_XROS,
        "xros-simulator" | "visionos-simulator" => PLATFORM_XROS_SIMULATOR,
        _ => return None,
    })
}

pub fn parse_number(s: &str) -> Result<u64> {
    let t = s.trim();
    let r = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        // ld64 reads -headerpad, -pagezero_size and friends as hex even without 0x.
        u64::from_str_radix(t, 16)
    };
    r.map_err(|_| err!("bad number '{s}'"))
}

/// `-source_version A.B.C.D.E`: 24.10.10.10.10 bits.
fn parse_source_version(s: &str) -> Result<u64> {
    let mut v = 0u64;
    let widths = [24u32, 10, 10, 10, 10];
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 5 {
        bail!("bad -source_version '{s}'");
    }
    for (i, w) in widths.iter().enumerate() {
        let n: u64 = match parts.get(i) {
            Some(p) => p.parse().map_err(|_| err!("bad -source_version '{s}'"))?,
            None => 0,
        };
        if n >= 1 << w {
            bail!("bad -source_version '{s}'");
        }
        v = (v << w) | n;
    }
    Ok(v)
}

fn looks_like_cc(args: &[String]) -> bool {
    let ld64 = args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-platform_version"
                | "-syslibroot"
                | "-macos_version_min"
                | "-macosx_version_min"
                | "-dylib"
                | "-flavor"
        )
    });
    let cc = args.iter().any(|a| {
        a.starts_with("-Wl,")
            || a.starts_with("-mmacosx-version-min=")
            || a.starts_with("-mmacos-version-min=")
            || a.starts_with("-mios-version-min=")
            || a.starts_with("--target=")
            || matches!(
                a.as_str(),
                "-nodefaultlibs"
                    | "-nostdlib"
                    | "-dynamiclib"
                    | "-shared"
                    | "-isysroot"
                    | "-target"
            )
    });
    cc && !ld64
}

/// What clang's Darwin driver would hand to ld64 for this command line.
fn translate_cc(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 8);
    let mut default_libs = true;
    let mut min: Option<String> = None;
    let mut platform = "macos".to_string();
    let mut sysroot: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        let mut next = || {
            let v = args.get(i).cloned().unwrap_or_default();
            i += 1;
            v
        };
        if let Some(rest) = a.strip_prefix("-Wl,") {
            out.extend(rest.split(',').map(str::to_string));
        } else if a == "-Xlinker" {
            out.push(next());
        } else if let Some(v) = a
            .strip_prefix("-mmacosx-version-min=")
            .or_else(|| a.strip_prefix("-mmacos-version-min="))
        {
            min = Some(v.to_string());
            platform = "macos".into();
        } else if let Some(v) = a.strip_prefix("-mios-version-min=") {
            min = Some(v.to_string());
            platform = "ios".into();
        } else if a == "-target" || a.starts_with("--target=") {
            let t = match a.strip_prefix("--target=") {
                Some(t) => t.to_string(),
                None => next(),
            };
            let mut parts = t.split('-');
            if let Some(arch) = parts.next() {
                out.push("-arch".into());
                out.push(arch.to_string());
            }
            if let Some(os) = parts.nth(1) {
                let digits = os.trim_start_matches(|c: char| c.is_ascii_alphabetic());
                if !digits.is_empty() {
                    min = Some(digits.to_string());
                }
            }
        } else if a == "-isysroot" {
            sysroot = Some(next());
        } else if let Some(v) = a.strip_prefix("--sysroot=") {
            sysroot = Some(v.to_string());
        } else if a == "-nodefaultlibs" || a == "-nostdlib" {
            default_libs = false;
        } else if a == "-dynamiclib" || a == "-shared" {
            out.push("-dylib".into());
        } else if a == "-rdynamic" {
            out.push("-export_dynamic".into());
        } else if matches!(
            a.as_str(),
            "-o" | "-arch" | "-L" | "-F" | "-framework" | "-e" | "-u"
        ) {
            out.push(a.clone());
            out.push(next());
        } else if a == "-l" {
            out.push(format!("-l{}", next()));
        } else {
            out.push(a.clone());
        }
    }
    let sysroot = sysroot.or_else(|| std::env::var("SDKROOT").ok().filter(|s| !s.is_empty()));
    if let Some(root) = &sysroot {
        out.push("-syslibroot".into());
        out.push(root.clone());
    }
    let min = min
        .or_else(|| std::env::var("MACOSX_DEPLOYMENT_TARGET").ok())
        .unwrap_or_default();
    if !min.is_empty() {
        let sdk = sysroot
            .as_deref()
            .and_then(sdk::sdk_version)
            .unwrap_or_else(|| min.clone());
        out.extend(["-platform_version".into(), platform, min, sdk]);
    }
    if default_libs {
        out.push("-lSystem".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        Config::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn reads_what_rustc_passes() {
        let c = parse(&[
            "-flavor",
            "darwin",
            "/tmp/symbols.o",
            "main.o",
            "libstd.rlib",
            "-lSystem",
            "-lc",
            "-framework",
            "Security",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            "11.0.0",
            "11.0.0",
            "-syslibroot",
            "/sdk",
            "-L",
            "/lib",
            "-o",
            "hello",
            "-dead_strip",
        ]);
        assert_eq!(c.arch, Some(Arch::Arm64));
        assert_eq!(c.platform, PLATFORM_MACOS);
        assert_eq!(c.min_version, 0x000b_0000);
        assert!(c.dead_strip);
        assert_eq!(c.output, PathBuf::from("hello"));
        assert_eq!(c.inputs.len(), 6);
        assert_eq!(c.inputs[3].kind, InputKind::Library("System".into()));
        assert_eq!(c.inputs[5].kind, InputKind::Framework("Security".into()));
        assert_eq!(c.syslibroots, [PathBuf::from("/sdk")]);
        assert!(!c.cc_mode);
    }

    #[test]
    fn translates_cc_lines() {
        let c = parse(&[
            "main.o",
            "-lSystem",
            "-arch",
            "arm64",
            "-mmacosx-version-min=12.3",
            "-isysroot",
            "/nonexistent-sdk",
            "-Wl,-dead_strip,-rpath,@loader_path",
            "-nodefaultlibs",
            "-dynamiclib",
            "-o",
            "libx.dylib",
            "-fuse-ld=lld",
        ]);
        assert!(c.cc_mode);
        assert!(c.dead_strip);
        assert_eq!(c.kind, OutputKind::Dylib);
        assert_eq!(c.rpaths, ["@loader_path"]);
        assert_eq!(c.min_version, 0x000c_0300);
        assert_eq!(c.syslibroots, [PathBuf::from("/nonexistent-sdk")]);
        assert_eq!(
            c.inputs
                .iter()
                .filter(|i| i.kind == InputKind::Library("System".into()))
                .count(),
            1
        );
    }

    #[test]
    fn globs() {
        assert!(glob_match(b"_foo*", b"_foobar"));
        assert!(glob_match(b"*bar", b"_foobar"));
        assert!(glob_match(b"_f?o", b"_foo"));
        assert!(glob_match(b"_[a-c]x", b"_bx"));
        assert!(!glob_match(b"_[!a-c]x", b"_bx"));
        assert!(!glob_match(b"_foo", b"_foobar"));
        assert!(glob_match(b"*", b""));
    }

    #[test]
    fn response_file_quoting() {
        let mut v = Vec::new();
        crate::cmdline::tokenize_gnu("a 'b c' \"d\\\"e\" f\\ g\n", &mut v);
        assert_eq!(v, ["a", "b c", "d\"e", "f g"]);
    }

    #[test]
    fn numbers_are_hex_like_ld64() {
        assert_eq!(parse_number("1000").unwrap(), 0x1000);
        assert_eq!(parse_number("0x4000").unwrap(), 0x4000);
        assert_eq!(parse_source_version("1.2").unwrap(), (1 << 40) | (2 << 30));
    }
}
