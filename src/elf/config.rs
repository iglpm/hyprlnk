//! GNU ld command lines (as `cc`/`collect2`, rustc and build systems write them) → [`Config`].

use std::path::PathBuf;

use super::target::Machine;
use crate::diag::{self, Result};
use crate::{bail, err};

pub const HELP: &str = "\
hyprlnk: a fast linker for Linux (GNU ld / ld.lld command line)

USAGE: hyprlnk [-flavor gnu] [options] <inputs...>
       cc -B<dir containing hyprlnk as `ld`> ...
       hyprlnk <cc arguments>   (runs $HYPRLNK_CC, else cc, with hyprlnk as its ld)

Inputs are ELF objects (debug sections may be zlib- or zstd-compressed),
archives (.a, .rlib, thin archives), shared objects and linker scripts naming
inputs (GROUP, INPUT, AS_NEEDED). @file reads more
arguments from a response file. Machines: x86-64, i386, AArch64, ARM (EABI),
RISC-V (rv64, rv32), ppc64le, ppc64 (ELFv2), s390x, LoongArch64.

Output:
  -o <file>                 output file (default: a.out)
  -shared | -pie | -no-pie | -static | -static-pie
  -m <emulation>            elf_x86_64, elf_i386, aarch64linux, armelf_linux_eabi,
                            elf64lriscv, elf32lriscv, elf64lppc, elf64ppc,
                            elf64_s390, elf64loongarch (default: from the inputs)
  -e <symbol>               entry point (default: _start)
  -soname <name>  -rpath <dir>  -dynamic-linker <path>  --no-dynamic-linker
  --build-id[=fast|sha1|md5|uuid|sha256|0x<hex>|none]
  --hash-style=gnu|sysv|both   --eh-frame-hdr   --enable-new-dtags
  -z now|lazy|relro|norelro|noexecstack|execstack|text|notext|defs|origin
     |nodelete|separate-code|max-page-size=<n>|pack-relative-relocs|...
  -s, --strip-all   -S, --strip-debug   -x, --discard-all   -X, --discard-locals

Libraries and symbols:
  -l<name>  -l:<file>  -L<dir>  --sysroot=<dir>
  -Bstatic | -Bdynamic   --as-needed   --whole-archive   --push-state
  --start-group ... --end-group   (every archive is searched as one group)
  --gc-sections   --print-gc-sections   -u <sym>   --require-defined=<sym>
  -E, --export-dynamic   --export-dynamic-symbol=<glob>   --dynamic-list=<file>
  --version-script=<file>   -Bsymbolic   -Bsymbolic-functions
  --defsym=<sym>=<expr>   --wrap=<sym>   --allow-multiple-definition
  --no-undefined   --unresolved-symbols=<how>   --allow-shlib-undefined

Diagnostics:
  --time                    print how long each phase took
  -t, --trace               print each file as it is loaded
  -Map=<file>  -M           write a map file (-M: to standard output)
  --dependency-file=<file>  write a Makefile rule listing every input
  --reproduce=<dir>         copy the inputs and a response file repeating the
                            link to <dir> (also HYPRLNK_REPRODUCE)
  --threads=<n>             worker threads (default: all cores)
  --fatal-warnings  -v  --version

GCC's -plugin options and LTO settings are accepted and ignored.
Documentation: https://github.com/runepm/hyprlnk/tree/main/docs
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKind {
    /// A path from the command line or a linker script.
    Path(String),
    /// `-l<name>`; `-l:<file>` is stored with the colon.
    Lib(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputFlags {
    pub as_needed: bool,
    pub whole_archive: bool,
    /// `-Bstatic`: `-l` finds only archives.
    pub link_static: bool,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub kind: InputKind,
    pub flags: InputFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildId {
    None,
    /// A hash of the contents, `n` bytes long.
    Hash(usize),
    Uuid,
    Hex(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strip {
    None,
    Debug,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    None,
    Locals,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bsymbolic {
    None,
    All,
    Functions,
    NonWeakFunctions,
    NonWeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    Error,
    Warn,
    Ignore,
}

#[derive(Debug, Clone)]
pub enum DefsymExpr {
    Value(u64),
    /// `sym` or `sym + n`.
    Symbol(String, i64),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output: PathBuf,
    pub machine: Option<Machine>,
    pub inputs: Vec<Input>,
    pub lib_paths: Vec<PathBuf>,
    pub sysroot: Option<PathBuf>,
    pub shared: bool,
    pub pie: bool,
    pub static_: bool,
    pub dynamic_linker: Option<String>,
    pub no_dynamic_linker: bool,
    pub entry: Option<String>,
    pub soname: Option<String>,
    pub rpaths: Vec<String>,
    pub new_dtags: bool,
    pub gc_sections: bool,
    pub print_gc_sections: bool,
    pub eh_frame_hdr: bool,
    pub build_id: BuildId,
    pub hash_gnu: bool,
    pub hash_sysv: bool,
    pub z_now: bool,
    pub z_relro: bool,
    pub z_execstack: bool,
    pub z_text: bool,
    pub z_origin: bool,
    pub z_nodelete: bool,
    pub z_nodlopen: bool,
    pub z_initfirst: bool,
    pub z_interpose: bool,
    pub z_nodefaultlib: bool,
    pub z_separate_code: bool,
    pub z_max_page_size: Option<u64>,
    pub z_pack_relative_relocs: bool,
    pub z_nocopyreloc: bool,
    pub z_dynamic_undefined_weak: Option<bool>,
    pub z_keep_text_section_prefix: bool,
    pub z_rodynamic: bool,
    pub z_stack_size: Option<u64>,
    pub export_dynamic: bool,
    pub export_dynamic_symbols: Vec<String>,
    pub dynamic_lists: Vec<PathBuf>,
    pub version_scripts: Vec<PathBuf>,
    pub bsymbolic: Bsymbolic,
    pub strip: Strip,
    pub discard: Discard,
    pub undefined: Vec<String>,
    pub require_defined: Vec<String>,
    pub unresolved_objects: Unresolved,
    pub unresolved_shlibs: Unresolved,
    pub no_undefined: bool,
    pub allow_multiple_definition: bool,
    pub defsyms: Vec<(String, DefsymExpr)>,
    pub wraps: Vec<String>,
    pub init: String,
    pub fini: String,
    pub image_base: Option<u64>,
    pub relax: bool,
    pub fatal_warnings: bool,
    pub warn_common: bool,
    pub threads: Option<usize>,
    pub time: bool,
    pub trace: bool,
    pub reproduce: Option<PathBuf>,
    pub map: Option<PathBuf>,
    pub dependency_file: Option<PathBuf>,
    pub exclude_libs: Vec<String>,
    pub print_help: bool,
    pub print_version: bool,
    pub verbose: bool,
    /// Link in a child process and return as soon as the output is written.
    pub fork: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            output: PathBuf::from("a.out"),
            machine: None,
            inputs: Vec::new(),
            lib_paths: Vec::new(),
            sysroot: None,
            shared: false,
            pie: false,
            static_: false,
            dynamic_linker: None,
            no_dynamic_linker: false,
            entry: None,
            soname: None,
            rpaths: Vec::new(),
            new_dtags: true,
            gc_sections: false,
            print_gc_sections: false,
            eh_frame_hdr: false,
            build_id: BuildId::None,
            hash_gnu: true,
            hash_sysv: true,
            z_now: false,
            z_relro: true,
            z_execstack: false,
            z_text: true,
            z_origin: false,
            z_nodelete: false,
            z_nodlopen: false,
            z_initfirst: false,
            z_interpose: false,
            z_nodefaultlib: false,
            z_separate_code: false,
            z_max_page_size: None,
            z_pack_relative_relocs: false,
            z_nocopyreloc: false,
            z_dynamic_undefined_weak: None,
            z_keep_text_section_prefix: false,
            z_rodynamic: false,
            z_stack_size: None,
            export_dynamic: false,
            export_dynamic_symbols: Vec::new(),
            dynamic_lists: Vec::new(),
            version_scripts: Vec::new(),
            bsymbolic: Bsymbolic::None,
            strip: Strip::None,
            discard: Discard::None,
            undefined: Vec::new(),
            require_defined: Vec::new(),
            unresolved_objects: Unresolved::Error,
            unresolved_shlibs: Unresolved::Error,
            no_undefined: false,
            allow_multiple_definition: false,
            defsyms: Vec::new(),
            wraps: Vec::new(),
            init: "_init".into(),
            fini: "_fini".into(),
            image_base: None,
            relax: true,
            fatal_warnings: false,
            warn_common: false,
            threads: None,
            time: false,
            trace: false,
            reproduce: None,
            map: None,
            dependency_file: None,
            exclude_libs: Vec::new(),
            print_help: false,
            print_version: false,
            verbose: false,
            fork: true,
        }
    }
}

/// Long options that take a value (`--name value`, `--name=value`, `-name value`).
fn takes_value(name: &str) -> bool {
    matches!(
        name,
        "o" | "output"
            | "e"
            | "entry"
            | "L"
            | "library-path"
            | "l"
            | "library"
            | "u"
            | "undefined"
            | "m"
            | "T"
            | "script"
            | "h"
            | "soname"
            | "R"
            | "rpath"
            | "rpath-link"
            | "dynamic-linker"
            | "I"
            | "sysroot"
            | "version-script"
            | "dynamic-list"
            | "hash-style"
            | "z"
            | "plugin"
            | "plugin-opt"
            | "Map"
            | "y"
            | "trace-symbol"
            | "defsym"
            | "wrap"
            | "init"
            | "fini"
            | "thread-count"
            | "image-base"
            | "Ttext"
            | "Tdata"
            | "Tbss"
            | "Ttext-segment"
            | "section-start"
            | "exclude-libs"
            | "export-dynamic-symbol"
            | "export-dynamic-symbol-list"
            | "require-defined"
            | "unresolved-symbols"
            | "compress-debug-sections"
            | "icf"
            | "sort-section"
            | "reproduce"
            | "dependency-file"
            | "package-metadata"
            | "retain-symbols-file"
            | "f"
            | "auxiliary"
            | "F"
            | "filter"
            | "error-limit"
            | "orphan-handling"
            | "mllvm"
            | "chroot"
            | "undefined-glob"
            | "just-symbols"
            | "Y"
            | "A"
            | "architecture"
            | "b"
            | "format"
            | "a"
            | "c"
            | "mri-script"
            | "G"
            | "gpsize"
            | "P"
            | "depaudit"
            | "audit"
            | "dT"
            | "default-script"
            | "symbol-ordering-file"
            | "call-graph-ordering-file"
            | "lto-O0"
            | "plugin-opt=-pass-through"
            | "build-id-link-dir"
            | "oformat"
            | "target"
            | "emulation"
            | "error-handling-script"
            | "dependent-libraries"
            | "warn-unresolved-symbols-file"
            | "Bno-symbolic-functions-value"
    )
}

/// Single-letter options that take a value attached (`-lfoo`) or separate (`-l foo`).
fn short_with_value(c: u8) -> bool {
    matches!(
        c,
        b'o' | b'e' | b'L' | b'l' | b'u' | b'm' | b'T' | b'h' | b'R' | b'y' | b'z' | b'I' | b'Y'
    )
}

pub fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(k) = s.strip_suffix(['k', 'K']) {
        k.parse::<u64>().ok().map(|v| v * 1024)
    } else if let Some(m) = s.strip_suffix(['m', 'M']) {
        m.parse::<u64>().ok().map(|v| v << 20)
    } else if s.len() > 1 && s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()) {
        u64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_defsym(spec: &str) -> Result<(String, DefsymExpr)> {
    let (name, expr) = spec
        .split_once('=')
        .ok_or_else(|| err!("--defsym: expected <symbol>=<expression>, got '{spec}'"))?;
    let expr = expr.trim();
    let e = if let Some(v) = parse_number(expr) {
        DefsymExpr::Value(v)
    } else if let Some((s, off)) = expr.split_once('+') {
        let off = parse_number(off).ok_or_else(|| err!("--defsym: bad offset in '{spec}'"))?;
        DefsymExpr::Symbol(s.trim().to_string(), off as i64)
    } else if let Some((s, off)) = expr.split_once('-') {
        let off = parse_number(off).ok_or_else(|| err!("--defsym: bad offset in '{spec}'"))?;
        DefsymExpr::Symbol(s.trim().to_string(), -(off as i64))
    } else {
        DefsymExpr::Symbol(expr.to_string(), 0)
    };
    Ok((name.trim().to_string(), e))
}

fn parse_build_id(v: Option<&str>) -> Result<BuildId> {
    Ok(match v {
        None | Some("sha1") | Some("tree") => BuildId::Hash(20),
        Some("fast") | Some("xxhash") => BuildId::Hash(8),
        Some("md5") => BuildId::Hash(16),
        Some("sha256") => BuildId::Hash(32),
        Some("uuid") => BuildId::Uuid,
        Some("none") => BuildId::None,
        Some(h) if h.starts_with("0x") || h.starts_with("0X") => {
            let h = &h[2..];
            if h.len() % 2 != 0 || h.is_empty() {
                bail!("--build-id: odd number of hex digits in '0x{h}'");
            }
            let bytes = (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
                .map_err(|_| err!("--build-id: bad hex string '0x{h}'"))?;
            BuildId::Hex(bytes)
        }
        Some(other) => bail!("--build-id: unknown style '{other}'"),
    })
}

impl Config {
    pub fn parse(args: &[String]) -> Result<Config> {
        let mut c = Config::default();
        let mut flags = InputFlags::default();
        let mut stack: Vec<InputFlags> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            i += 1;
            if arg.is_empty() {
                continue;
            }
            if !arg.starts_with('-') || arg == "-" {
                c.inputs.push(Input {
                    kind: InputKind::Path(arg.to_string()),
                    flags,
                });
                continue;
            }
            // `--name[=value]`, `-name[=value]`, or a short option with an attached value.
            let double = arg.starts_with("--");
            let body = if double { &arg[2..] } else { &arg[1..] };
            let (mut name, mut inline): (&str, Option<String>) = match body.split_once('=') {
                Some((n, v)) if !n.is_empty() => (n, Some(v.to_string())),
                _ => (body, None),
            };
            // `-lfoo`, `-L/dir`, `-zrelro`, `-ofile`: unless the whole word is a long option.
            if !double
                && name.len() > 1
                && short_with_value(name.as_bytes()[0])
                && !is_long_option(name)
            {
                inline = Some(body[1..].to_string());
                name = &body[..1];
            }
            let mut value = |what: &str| -> Result<String> {
                if let Some(v) = inline.take() {
                    return Ok(v);
                }
                let v = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| err!("option '{what}' needs a value"))?;
                i += 1;
                Ok(v)
            };
            match name {
                "o" | "output" => c.output = PathBuf::from(value(arg)?),
                "m" => {
                    let m = value(arg)?;
                    c.machine = Some(
                        Machine::from_emulation(&m)
                            .ok_or_else(|| err!("unknown emulation '{m}' (-m)"))?,
                    );
                }
                "L" | "library-path" => {
                    let d = value(arg)?;
                    c.lib_paths.push(c.sysrooted(&d));
                }
                "l" | "library" => c.inputs.push(Input {
                    kind: InputKind::Lib(value(arg)?),
                    flags,
                }),
                "e" | "entry" => c.entry = Some(value(arg)?),
                "u" | "undefined" => c.undefined.push(value(arg)?),
                "require-defined" => c.require_defined.push(value(arg)?),
                "h" | "soname" => c.soname = Some(value(arg)?),
                "R" | "rpath" => {
                    let v = value(arg)?;
                    // `-R <file>` names a file to take symbols from; only directories are rpaths.
                    if std::path::Path::new(&v).is_file() {
                        bail!("-R <file> (--just-symbols) is not supported");
                    }
                    for p in v.split(':').filter(|p| !p.is_empty()) {
                        if !c.rpaths.iter().any(|r| r == p) {
                            c.rpaths.push(p.to_string());
                        }
                    }
                }
                "rpath-link" => {
                    value(arg)?;
                }
                "dynamic-linker" | "I" => {
                    c.dynamic_linker = Some(value(arg)?);
                    c.no_dynamic_linker = false;
                }
                "no-dynamic-linker" => c.no_dynamic_linker = true,
                "sysroot" => c.sysroot = Some(PathBuf::from(value(arg)?)),
                "shared" | "Bshareable" => c.shared = true,
                "pie" | "pic-executable" => c.pie = true,
                "no-pie" | "no-pic-executable" => c.pie = false,
                // rustc puts `-static` after the inputs; it means no shared objects either way.
                "static" => {
                    c.static_ = true;
                    flags.link_static = true;
                }
                "static-pie" => {
                    c.static_ = true;
                    c.pie = true;
                    c.no_dynamic_linker = true;
                    flags.link_static = true;
                }
                "Bstatic" | "dn" | "non_shared" => flags.link_static = true,
                "Bdynamic" | "dy" | "call_shared" => flags.link_static = false,
                "as-needed" => flags.as_needed = true,
                "no-as-needed" => flags.as_needed = false,
                "whole-archive" => flags.whole_archive = true,
                "no-whole-archive" => flags.whole_archive = false,
                "push-state" => stack.push(flags),
                "pop-state" => {
                    flags = stack
                        .pop()
                        .ok_or_else(|| err!("--pop-state without --push-state"))?
                }
                "start-group" | "(" | "end-group" | ")" => {}
                "gc-sections" => c.gc_sections = true,
                "no-gc-sections" => c.gc_sections = false,
                "print-gc-sections" => c.print_gc_sections = true,
                "no-print-gc-sections" => c.print_gc_sections = false,
                "eh-frame-hdr" => c.eh_frame_hdr = true,
                "no-eh-frame-hdr" => c.eh_frame_hdr = false,
                "build-id" => c.build_id = parse_build_id(inline.as_deref())?,
                "no-build-id" => c.build_id = BuildId::None,
                "hash-style" => {
                    let v = value(arg)?;
                    (c.hash_gnu, c.hash_sysv) = match v.as_str() {
                        "gnu" => (true, false),
                        "sysv" => (false, true),
                        "both" => (true, true),
                        other => bail!("--hash-style: unknown style '{other}'"),
                    };
                }
                "z" => {
                    let v = value(arg)?;
                    c.z_option(&v)?;
                }
                "E" | "export-dynamic" => c.export_dynamic = true,
                "no-export-dynamic" => c.export_dynamic = false,
                "export-dynamic-symbol" => c.export_dynamic_symbols.push(value(arg)?),
                "export-dynamic-symbol-list" | "dynamic-list" => {
                    c.dynamic_lists.push(PathBuf::from(value(arg)?))
                }
                "version-script" => c.version_scripts.push(PathBuf::from(value(arg)?)),
                "Bsymbolic" => c.bsymbolic = Bsymbolic::All,
                "Bsymbolic-functions" => c.bsymbolic = Bsymbolic::Functions,
                "Bsymbolic-non-weak-functions" => c.bsymbolic = Bsymbolic::NonWeakFunctions,
                "Bsymbolic-non-weak" => c.bsymbolic = Bsymbolic::NonWeak,
                "Bno-symbolic" => c.bsymbolic = Bsymbolic::None,
                "s" | "strip-all" => c.strip = Strip::All,
                "S" | "strip-debug" | "strip-dwo" => {
                    if c.strip == Strip::None {
                        c.strip = Strip::Debug
                    }
                }
                "x" | "discard-all" => c.discard = Discard::All,
                "X" | "discard-locals" => c.discard = Discard::Locals,
                "discard-none" => c.discard = Discard::None,
                "no-undefined" => c.no_undefined = true,
                "allow-shlib-undefined" => c.unresolved_shlibs = Unresolved::Ignore,
                "no-allow-shlib-undefined" => c.unresolved_shlibs = Unresolved::Error,
                "unresolved-symbols" => {
                    let v = value(arg)?;
                    (c.unresolved_objects, c.unresolved_shlibs) = match v.as_str() {
                        "ignore-all" => (Unresolved::Ignore, Unresolved::Ignore),
                        "report-all" => (Unresolved::Error, Unresolved::Error),
                        "ignore-in-object-files" => (Unresolved::Ignore, Unresolved::Error),
                        "ignore-in-shared-libs" => (Unresolved::Error, Unresolved::Ignore),
                        other => bail!("--unresolved-symbols: unknown value '{other}'"),
                    };
                }
                "warn-unresolved-symbols" => c.unresolved_objects = Unresolved::Warn,
                "error-unresolved-symbols" => c.unresolved_objects = Unresolved::Error,
                "allow-multiple-definition" => c.allow_multiple_definition = true,
                "no-allow-multiple-definition" => c.allow_multiple_definition = false,
                "defsym" => {
                    let v = value(arg)?;
                    c.defsyms.push(parse_defsym(&v)?);
                }
                "wrap" => c.wraps.push(value(arg)?),
                "init" => c.init = value(arg)?,
                "fini" => c.fini = value(arg)?,
                "image-base" | "Ttext-segment" => {
                    let v = value(arg)?;
                    c.image_base =
                        Some(parse_number(&v).ok_or_else(|| err!("{arg}: bad address '{v}'"))?);
                }
                "enable-new-dtags" => c.new_dtags = true,
                "disable-new-dtags" => c.new_dtags = false,
                "relax" => c.relax = true,
                "no-relax" => c.relax = false,
                "fatal-warnings" => c.fatal_warnings = true,
                "no-fatal-warnings" => c.fatal_warnings = false,
                "warn-common" => c.warn_common = true,
                "threads" => {
                    if let Some(v) = inline.take() {
                        c.threads = Some(
                            v.parse()
                                .ok()
                                .filter(|n| *n > 0)
                                .ok_or_else(|| err!("--threads: bad count '{v}'"))?,
                        );
                    }
                }
                "thread-count" => {
                    let v = value(arg)?;
                    c.threads = v.parse().ok().filter(|n| *n > 0);
                }
                "no-threads" => c.threads = Some(1),
                "time" | "print-stats" | "stats" | "time-trace" => c.time = true,
                "t" | "trace" => c.trace = true,
                "reproduce" => c.reproduce = Some(PathBuf::from(value(arg)?)),
                "Map" => c.map = Some(PathBuf::from(value(arg)?)),
                "M" | "print-map" => c.map = Some(PathBuf::from("-")),
                "dependency-file" => c.dependency_file = Some(PathBuf::from(value(arg)?)),
                "exclude-libs" => {
                    let v = value(arg)?;
                    c.exclude_libs
                        .extend(v.split([',', ':']).map(|s| s.to_string()));
                }
                "v" | "V" | "version" => c.print_version = true,
                "help" => c.print_help = true,
                "verbose" => c.verbose = true,
                "fork" => c.fork = true,
                "no-fork" => c.fork = false,
                "T" | "script" | "default-script" | "dT" => {
                    let v = value(arg)?;
                    // A script that only names inputs (GROUP/INPUT) is an input.
                    c.inputs.push(Input {
                        kind: InputKind::Path(v),
                        flags,
                    });
                }
                "r" | "relocatable" | "i" => {
                    bail!("relocatable output (-r) is not supported")
                }
                "q" | "emit-relocs" => bail!("--emit-relocs (-q) is not supported"),
                "compress-debug-sections" => {
                    let v = value(arg)?;
                    if v != "none" {
                        diag::warn(format!(
                            "--compress-debug-sections={v} is not supported; writing them uncompressed"
                        ));
                    }
                }
                "icf" => {
                    let v = value(arg)?;
                    if v != "none" {
                        diag::warn(format!("--icf={v} is not supported yet; ignored"));
                    }
                }
                "flavor" => {
                    value(arg)?;
                }
                // Accepted and ignored: they don't change what hyprlnk writes.
                n if takes_value(n) => {
                    value(arg)?;
                }
                n if n.starts_with("plugin-opt")
                    || n.starts_with("lto-")
                    || n.starts_with("thinlto-")
                    || n.starts_with("O")
                    || n.starts_with("color-diagnostics")
                    || n.starts_with("no-color-diagnostics")
                    || n.starts_with("check-sections")
                    || n.starts_with("sort-common")
                    || n.starts_with("build-id-") =>
                {
                    inline.take();
                }
                "nostdlib"
                | "no-undefined-version"
                | "undefined-version"
                | "demangle"
                | "no-demangle"
                | "warn-once"
                | "no-warn-mismatch"
                | "warn-shared-textrel"
                | "no-copy-dt-needed-entries"
                | "copy-dt-needed-entries"
                | "cref"
                | "no-keep-memory"
                | "reduce-memory-overheads"
                | "rosegment"
                | "no-rosegment"
                | "nmagic"
                | "n"
                | "omagic"
                | "N"
                | "no-omagic"
                | "noinhibit-exec"
                | "fix-cortex-a53-843419"
                | "fix-cortex-a53-835769"
                | "no-fix-cortex-a53-843419"
                | "be8"
                | "long-plt"
                | "no-warn-rwx-segments"
                | "warn-rwx-segments"
                | "warn-execstack"
                | "no-warn-execstack"
                | "export-dynamic-symbol-all"
                | "ignore-data-address-equality"
                | "ignore-function-address-equality"
                | "allow-undefined-version"
                | "enable-non-contiguous-regions"
                | "no-relax-gp"
                | "eh-frame-hdr-sort"
                | "no-mmap-output-file"
                | "mmap-output-file"
                | "pack-dyn-relocs=none"
                | "use-android-relr-tags"
                | "ld-path"
                | "fortran-common"
                | "no-fortran-common"
                | "gdb-index"
                | "no-gdb-index"
                | "print-memory-usage"
                | "apply-dynamic-relocs"
                | "no-apply-dynamic-relocs"
                | "Qy"
                | "Qn"
                | "g"
                | "EL"
                | "EB"
                | "d"
                | "dc"
                | "dp"
                | "sort-section"
                | "relax-gp"
                | "no-call-graph-profile-sort"
                | "call-graph-profile-sort"
                | "nostdinc"
                | "accept-unknown-input-arch"
                | "no-accept-unknown-input-arch"
                | "allow-shlib-undefined-version"
                | "dynamic-list-data"
                | "dynamic-list-cpp-new"
                | "dynamic-list-cpp-typeinfo"
                | "no-print-map-discarded"
                | "print-map-discarded"
                | "error-unresolved"
                | "fatal-errors"
                | "Bgroup"
                | "no-validate-sections" => {}
                _ => {
                    diag::warn(format!("ignoring unknown option '{arg}'"));
                    // A value we can't tell from an input: leave it, it'll be an input or fail there.
                }
            }
        }
        if c.static_ && c.shared {
            c.static_ = false;
        }
        if c.shared {
            c.pie = false;
        }
        Ok(c)
    }

    fn z_option(&mut self, v: &str) -> Result<()> {
        let (k, val) = match v.split_once('=') {
            Some((k, val)) => (k, Some(val)),
            None => (v, None),
        };
        let num = |what: &str| -> Result<u64> {
            val.and_then(parse_number)
                .ok_or_else(|| err!("-z {what}: bad number '{}'", val.unwrap_or("")))
        };
        match k {
            "now" => self.z_now = true,
            "lazy" => self.z_now = false,
            "relro" => self.z_relro = true,
            "norelro" => self.z_relro = false,
            "execstack" => self.z_execstack = true,
            "noexecstack" => self.z_execstack = false,
            "text" => self.z_text = true,
            "notext" | "textoff" => self.z_text = false,
            "defs" => self.no_undefined = true,
            "undefs" => self.no_undefined = false,
            "origin" => self.z_origin = true,
            "nodelete" => self.z_nodelete = true,
            "nodlopen" => self.z_nodlopen = true,
            "initfirst" => self.z_initfirst = true,
            "interpose" => self.z_interpose = true,
            "nodefaultlib" => self.z_nodefaultlib = true,
            "muldefs" => self.allow_multiple_definition = true,
            "nocopyreloc" => self.z_nocopyreloc = true,
            "separate-code" | "separate-loadable-segments" => self.z_separate_code = true,
            "noseparate-code" => self.z_separate_code = false,
            "max-page-size" => {
                let n = num(k)?;
                if !n.is_power_of_two() {
                    bail!("-z max-page-size: {n:#x} is not a power of two");
                }
                self.z_max_page_size = Some(n);
            }
            "common-page-size" => {
                num(k)?;
            }
            "pack-relative-relocs" => self.z_pack_relative_relocs = true,
            "nopack-relative-relocs" => self.z_pack_relative_relocs = false,
            "dynamic-undefined-weak" => self.z_dynamic_undefined_weak = Some(true),
            "nodynamic-undefined-weak" => self.z_dynamic_undefined_weak = Some(false),
            "keep-text-section-prefix" => self.z_keep_text_section_prefix = true,
            "nokeep-text-section-prefix" => self.z_keep_text_section_prefix = false,
            "rodynamic" => self.z_rodynamic = true,
            "stack-size" => self.z_stack_size = Some(num(k)?),
            "combreloc"
            | "nocombreloc"
            | "global"
            | "ibt"
            | "shstk"
            | "ibtplt"
            | "force-bti"
            | "pac-plt"
            | "bti-report"
            | "cet-report"
            | "force-ibt"
            | "start-stop-gc"
            | "nostart-stop-gc"
            | "start-stop-visibility"
            | "rel"
            | "rela"
            | "hazardplt"
            | "ifunc-noplt"
            | "report-relative-reloc"
            | "dead-reloc-in-nonalloc"
            | "x86-64-baseline"
            | "x86-64-v2"
            | "x86-64-v3"
            | "x86-64-v4"
            | "mark-plt"
            | "nomark-plt"
            | "gcs"
            | "gcs-report"
            | "memory-seal"
            | "nomemory-seal"
            | "noextern-protected-data"
            | "unique-symbol"
            | "nognustack"
            | "lrodata-after-bss"
            | "nolrodata-after-bss"
            | "zicfilp"
            | "zicfiss"
            | "zicfilp-report"
            | "zicfiss-report"
            | "execute-only-report"
            | "pauth-report"
            | "noseparate-loadable-segments"
            | "sectionheader"
            | "nosectionheader"
            | "unique"
            | "nounique"
            | "common"
            | "nocommon"
            | "noreloc-overflow"
            | "isa-level-report"
            | "indirect-extern-access"
            | "noindirect-extern-access"
            | "plt"
            | "noplt" => {}
            _ => diag::warn(format!("ignoring unknown -z option '{v}'")),
        }
        Ok(())
    }

    /// `-L=/usr/lib` and `-L$SYSROOT/...`: relative to the sysroot.
    fn sysrooted(&self, d: &str) -> PathBuf {
        if let Some(rest) = d.strip_prefix('=').or_else(|| d.strip_prefix("$SYSROOT"))
            && let Some(root) = &self.sysroot
        {
            return root.join(rest.trim_start_matches('/'));
        }
        PathBuf::from(d.strip_prefix('=').unwrap_or(d))
    }

    /// The output has a dynamic section: a shared object, a PIE (also static-pie), or an
    /// executable that links shared objects (decided after loading).
    pub fn pic(&self) -> bool {
        self.shared || self.pie
    }
}

/// Every option name that is longer than one letter and starts like a short option with a
/// value: `-shared` is not `-s hared`... but `-lfoo` is `-l foo`.
fn is_long_option(name: &str) -> bool {
    takes_value(name)
        || matches!(
            name,
            "export-dynamic"
                | "eh-frame-hdr"
                | "entry"
                | "emit-relocs"
                | "end-group"
                | "enable-new-dtags"
                | "error-unresolved-symbols"
                | "error-limit"
                | "omagic"
                | "output"
                | "undefined"
                | "undefined-version"
                | "unresolved-symbols"
                | "use-android-relr-tags"
                | "unique"
                | "library"
                | "library-path"
                | "long-plt"
                | "lto-O0"
                | "Map"
                | "mmap-output-file"
                | "mllvm"
                | "mri-script"
                | "Tbss"
                | "Tdata"
                | "Ttext"
                | "Ttext-segment"
                | "help"
                | "hash-style"
                | "rpath"
                | "rpath-link"
                | "relax"
                | "relocatable"
                | "reproduce"
                | "retain-symbols-file"
                | "require-defined"
                | "rosegment"
                | "reduce-memory-overheads"
                | "relax-gp"
                | "y"
                | "zmuldefs"
                | "init"
                | "image-base"
                | "ignore-data-address-equality"
                | "ignore-function-address-equality"
                | "EL"
                | "EB"
        )
        || name.starts_with("lto-")
        || name.starts_with("thinlto-")
        || name.starts_with("error-")
        || name.starts_with("export-dynamic")
        || name.starts_with("eh-frame")
        || name.starts_with("plugin")
        || name.starts_with("hash-")
        || name.starts_with("mllvm")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Config {
        Config::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn a_collect2_command_line() {
        let c = parse(&[
            "-plugin",
            "/usr/lib/gcc/x86_64-pc-linux-gnu/16/liblto_plugin.so",
            "-plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/16/lto-wrapper",
            "-plugin-opt=-fresolution=/tmp/cc.res",
            "--build-id",
            "--eh-frame-hdr",
            "--hash-style=gnu",
            "-m",
            "elf_x86_64",
            "-dynamic-linker",
            "/lib64/ld-linux-x86-64.so.2",
            "-pie",
            "-o",
            "out",
            "/usr/lib/Scrt1.o",
            "-L/usr/lib",
            "a.o",
            "--as-needed",
            "-Bstatic",
            "libstd.rlib",
            "-Bdynamic",
            "-lgcc_s",
            "-lc",
            "--gc-sections",
            "-z",
            "relro",
            "-z",
            "now",
            "-znoexecstack",
        ]);
        assert_eq!(c.machine, Some(Machine::X86_64));
        assert!(c.pie && !c.shared && !c.static_);
        assert_eq!(c.output, PathBuf::from("out"));
        assert_eq!(
            c.dynamic_linker.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(c.build_id, BuildId::Hash(20));
        assert!(c.hash_gnu && !c.hash_sysv);
        assert!(c.gc_sections && c.eh_frame_hdr && c.z_now && c.z_relro && !c.z_execstack);
        assert_eq!(c.lib_paths, vec![PathBuf::from("/usr/lib")]);
        assert_eq!(c.inputs.len(), 5);
        assert_eq!(c.inputs[2].kind, InputKind::Path("libstd.rlib".into()));
        assert!(c.inputs[2].flags.link_static && c.inputs[2].flags.as_needed);
        assert_eq!(c.inputs[3].kind, InputKind::Lib("gcc_s".into()));
        assert!(!c.inputs[3].flags.link_static);
    }

    #[test]
    fn short_and_long_options() {
        let c = parse(&[
            "-shared",
            "-soname",
            "libx.so.1",
            "-lfoo",
            "-l:libbar.a",
            "-ofile",
            "--version-script=v.map",
            "-Bsymbolic",
            "-rpath=/a:/b",
            "--build-id=0xdeadbeef",
            "-static-pie",
        ]);
        assert!(c.shared && !c.pie);
        assert_eq!(c.soname.as_deref(), Some("libx.so.1"));
        assert_eq!(c.inputs[0].kind, InputKind::Lib("foo".into()));
        assert_eq!(c.inputs[1].kind, InputKind::Lib(":libbar.a".into()));
        assert_eq!(c.output, PathBuf::from("file"));
        assert_eq!(c.version_scripts, vec![PathBuf::from("v.map")]);
        assert_eq!(c.bsymbolic, Bsymbolic::All);
        assert_eq!(c.rpaths, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(c.build_id, BuildId::Hex(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn static_and_states() {
        let c = parse(&[
            "-static",
            "-pie",
            "--no-dynamic-linker",
            "a.o",
            "--push-state",
            "--whole-archive",
            "x.a",
            "--pop-state",
            "y.a",
        ]);
        assert!(c.static_ && c.pie && c.no_dynamic_linker);
        assert!(c.inputs[1].flags.whole_archive);
        assert!(!c.inputs[2].flags.whole_archive);
        assert!(c.inputs[2].flags.link_static);
    }

    #[test]
    fn defsym_and_numbers() {
        assert_eq!(parse_number("0x1000"), Some(4096));
        assert_eq!(parse_number("64k"), Some(65536));
        assert_eq!(parse_number("010"), Some(8));
        let c = parse(&["--defsym=a=0x10", "--defsym", "b=c+4"]);
        assert!(matches!(c.defsyms[0].1, DefsymExpr::Value(16)));
        assert!(matches!(&c.defsyms[1].1, DefsymExpr::Symbol(s, 4) if s == "c"));
    }
}
