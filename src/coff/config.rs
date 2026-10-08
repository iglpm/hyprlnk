//! `link.exe`/`lld-link` command lines.

use std::path::{Path, PathBuf};

use super::def::{ExportSpec, parse_export};
use crate::diag::{self, Result};
use crate::{bail, err};

pub const HELP: &str = "\
hyprlnk: the fastest linker for Windows (link.exe / lld-link command line)

USAGE: hyprlnk [options] <inputs...>

Inputs are COFF objects (.obj, .o), archives (.lib, .rlib, .a), import
libraries and resource files (.res). @file reads more arguments from a
response file. Machines: x64, ARM64, x86.

Output:
  /OUT:<file>              output image
  /DLL                     build a DLL
  /ENTRY:<symbol>          entry point (default: from main/WinMain/DllMain)
  /SUBSYSTEM:<name>[,v]    console, windows, native, efi_application, ...
  /MACHINE:<x64|arm64|x86> (default: from the first object)
  /BASE:<addr>  /STACK:<reserve>[,<commit>]  /HEAP:<reserve>[,<commit>]
  /DYNAMICBASE[:NO]  /NXCOMPAT[:NO]  /HIGHENTROPYVA[:NO]  /LARGEADDRESSAWARE[:NO]
  /FIXED  /TSAWARE[:NO]  /SAFESEH[:NO]  /TIMESTAMP:<n>  /RELEASE (checksum)

Libraries and symbols:
  /LIBPATH:<dir>           library search directory (then %LIB%)
  /DEFAULTLIB:<lib>        link a library    /NODEFAULTLIB[:<lib>]
  /WHOLEARCHIVE[:<lib>]    load every member of an archive
  /INCLUDE:<symbol>        force a symbol in
  /ALTERNATENAME:<a>=<b>   use b where a is undefined
  /MERGE:<from>=<to>       merge output sections
  /EXPORT:<spec>  /DEF:<file>  /IMPLIB:<file>  /NOIMPLIB
  /FORCE[:UNRESOLVED|MULTIPLE]

Optimization and debug info:
  /OPT:REF|NOREF           drop unreferenced COMDATs (default: REF without /DEBUG)
  /OPT:ICF|NOICF           fold identical code (default: ICF with REF, no /DEBUG)
  /DEBUG[:NONE]            write a PDB
  /PDB:<file>  /PDBALTPATH:<path>  /NATVIS:<file>

Diagnostics:
  /TIME                    print how long each phase took
  /VERBOSE                 explain what is loaded and folded
  /MAP[:<file>]            write a map file (sections, symbols by address)
  /REPRODUCE:<dir>         copy the inputs and a response file repeating
                           the link to <dir> (also HYPRLNK_REPRODUCE)
  /THREADS:<n>             worker threads (default: all cores)
  --version                print the version

Accepted for compatibility and ignored: /NOLOGO /INCREMENTAL /MANIFEST*
/GUARD /ERRORREPORT /IGNORE /WX /BREPRO /LTCG and others.
Documentation: https://github.com/runepm/hyprlnk/tree/main/docs
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    Native = 1,
    Windows = 2,
    Console = 3,
    Posix = 7,
    WindowsCe = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    BootApplication = 16,
}

impl Subsystem {
    pub fn parse(name: &str) -> Option<Subsystem> {
        Some(match name.to_ascii_lowercase().as_str() {
            "native" => Subsystem::Native,
            "windows" => Subsystem::Windows,
            "console" => Subsystem::Console,
            "posix" => Subsystem::Posix,
            "windowsce" => Subsystem::WindowsCe,
            "efi_application" => Subsystem::EfiApplication,
            "efi_boot_service_driver" => Subsystem::EfiBootServiceDriver,
            "efi_runtime_driver" => Subsystem::EfiRuntimeDriver,
            "efi_rom" => Subsystem::EfiRom,
            "boot_application" => Subsystem::BootApplication,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InputSpec {
    pub path: String,
    pub whole_archive: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output: Option<PathBuf>,
    pub inputs: Vec<InputSpec>,
    pub lib_paths: Vec<PathBuf>,
    pub default_libs: Vec<String>,
    pub no_default_lib_all: bool,
    pub no_default_libs: Vec<String>,
    pub whole_archive_all: bool,
    pub entry: Option<String>,
    pub no_entry: bool,
    pub dll: bool,
    pub subsystem: Option<Subsystem>,
    pub subsystem_version: Option<(u16, u16)>,
    pub os_version: Option<(u16, u16)>,
    pub image_version: (u16, u16),
    pub image_base: Option<u64>,
    pub stack: (u64, u64),
    pub heap: (u64, u64),
    pub dynamic_base: bool,
    pub nx_compat: bool,
    pub large_address_aware: Option<bool>,
    pub machine: Option<super::arch::Machine>,
    pub safeseh: Option<bool>,
    pub high_entropy_va: bool,
    pub terminal_server_aware: Option<bool>,
    pub fixed: bool,
    pub appcontainer: bool,
    pub cet_compat: bool,
    pub integrity_check: bool,
    pub gc: Option<bool>,
    pub icf: Option<bool>,
    pub debug: bool,
    pub pdb: Option<PathBuf>,
    pub pdb_alt_path: Option<String>,
    pub natvis: Vec<PathBuf>,
    pub map: Option<Option<PathBuf>>,
    pub includes: Vec<String>,
    pub alternate_names: Vec<(String, String)>,
    pub merges: Vec<(String, String)>,
    pub exports: Vec<ExportSpec>,
    pub def_file: Option<PathBuf>,
    pub implib: Option<PathBuf>,
    pub no_implib: bool,
    pub force_unresolved: bool,
    pub force_multiple: bool,
    pub time: bool,
    pub verbose: bool,
    pub threads: Option<usize>,
    pub timestamp: Option<u32>,
    pub file_align: u32,
    pub section_align: u32,
    pub release_checksum: bool,
    pub print_version: bool,
    pub print_help: bool,
    pub mingw: bool,
    pub reproduce: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            output: None,
            inputs: Vec::new(),
            lib_paths: Vec::new(),
            default_libs: Vec::new(),
            no_default_lib_all: false,
            no_default_libs: Vec::new(),
            whole_archive_all: false,
            entry: None,
            no_entry: false,
            dll: false,
            subsystem: None,
            subsystem_version: None,
            os_version: None,
            image_version: (0, 0),
            image_base: None,
            stack: (1024 * 1024, 4096),
            heap: (1024 * 1024, 4096),
            dynamic_base: true,
            nx_compat: true,
            large_address_aware: None,
            machine: None,
            safeseh: None,
            high_entropy_va: true,
            terminal_server_aware: None,
            fixed: false,
            appcontainer: false,
            cet_compat: false,
            integrity_check: false,
            gc: None,
            icf: None,
            debug: false,
            pdb: None,
            pdb_alt_path: None,
            natvis: Vec::new(),
            map: None,
            includes: Vec::new(),
            alternate_names: Vec::new(),
            merges: Vec::new(),
            exports: Vec::new(),
            def_file: None,
            implib: None,
            no_implib: false,
            force_unresolved: false,
            force_multiple: false,
            time: false,
            verbose: false,
            threads: None,
            timestamp: None,
            file_align: 512,
            section_align: 4096,
            release_checksum: false,
            print_version: false,
            print_help: false,
            mingw: false,
            reproduce: None,
        }
    }
}

/// Every known option, so a Unix path like `/home/me/a.obj` is an input, not an unknown option.
const KNOWN: &[&str] = &[
    "align",
    "aligncomm",
    "allowbind",
    "allowisolation",
    "alternatename",
    "appcontainer",
    "base",
    "brepro",
    "cetcompat",
    "debug",
    "debugtype",
    "def",
    "defaultlib",
    "delayload",
    "demangle",
    "dependentloadflag",
    "dll",
    "driver",
    "dynamicbase",
    "editandcontinue",
    "emittoolversioninfo",
    "entry",
    "errorlimit",
    "errorreport",
    "export",
    "failifmismatch",
    "filealign",
    "fixed",
    "force",
    "functionpadmin",
    "guard",
    "heap",
    "help",
    "highentropyva",
    "ignore",
    "ignoreidl",
    "implib",
    "include",
    "includeoptional",
    "incremental",
    "integritycheck",
    "kill-at",
    "largeaddressaware",
    "libpath",
    "lldignoreenv",
    "lldltocache",
    "lldmap",
    "lldmingw",
    "ltcg",
    "machine",
    "manifest",
    "manifestdependency",
    "manifestfile",
    "manifestinput",
    "manifestuac",
    "map",
    "mapinfo",
    "merge",
    "natvis",
    "noentry",
    "nodefaultlib",
    "noimplib",
    "nologo",
    "nxcompat",
    "opt",
    "order",
    "osversion",
    "out",
    "pdb",
    "pdbaltpath",
    "pdbpagesize",
    "profile",
    "release",
    "reproduce",
    "safeseh",
    "section",
    "stack",
    "stub",
    "subsystem",
    "swaprun",
    "threads",
    "time",
    "time+",
    "timestamp",
    "tsaware",
    "verbose",
    "version",
    "wholearchive",
    "winsysroot",
    "wx",
    "?",
    "flavor",
    "lto-pgo-warn-mismatch",
    "pdbstripped",
    "throwingnew",
    "guardsym",
    "disallowlib",
    "inferasanlibs",
    "exclude-symbols",
    "nocoffgrpinfo",
    "nodbgdirmerge",
    "ilk",
    "idlout",
    "tlbout",
    "tlbid",
    "midl",
    "winmd",
    "winmdfile",
    "winmdkeyfile",
    "assemblydebug",
    "clrimagetype",
    "clrthreadattribute",
    "fastfail",
    "sourcelink",
    "hybridpatchable",
    "arm64xsame",
];

impl Config {
    pub fn parse(args: &[String]) -> Result<Config> {
        let mut c = Config::default();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if arg == "-flavor" {
                i += 1;
                continue;
            }
            match option(arg) {
                Some((name, value)) => c.apply(&name, value, arg)?,
                None => c.inputs.push(InputSpec {
                    path: arg.clone(),
                    whole_archive: false,
                }),
            }
        }
        if let Some(def) = &c.def_file {
            let text =
                std::fs::read(def).map_err(|e| err!("cannot read '{}': {e}", def.display()))?;
            let def = super::def::parse_def(&crate::cmdline::decode_text(&text))?;
            if let Some(name) = def.name
                && c.output.is_none()
            {
                c.output = Some(PathBuf::from(name));
            }
            if let Some(base) = def.base
                && c.image_base.is_none()
            {
                c.image_base = Some(base);
            }
            if let Some(stack) = def.stack {
                c.stack = stack;
            }
            if let Some(heap) = def.heap {
                c.heap = heap;
            }
            if let Some(v) = def.version {
                c.image_version = v;
            }
            c.exports.extend(def.exports);
        }
        Ok(c)
    }

    fn apply(&mut self, name: &str, value: Option<&str>, arg: &str) -> Result<()> {
        let v = || value.unwrap_or("");
        let need = || -> Result<&str> {
            match value {
                Some(v) if !v.is_empty() => Ok(v),
                _ => bail!("missing value for '{arg}'"),
            }
        };
        let yes = || !value.is_some_and(|v| v.eq_ignore_ascii_case("no"));
        match name {
            "out" => self.output = Some(PathBuf::from(need()?)),
            "libpath" => self.lib_paths.push(PathBuf::from(need()?)),
            "defaultlib" => self.default_libs.push(need()?.to_string()),
            "nodefaultlib" => match value {
                Some(v) if !v.is_empty() => self.no_default_libs.push(lib_key(v)),
                _ => self.no_default_lib_all = true,
            },
            "wholearchive" => match value {
                Some(v) if !v.is_empty() => self.inputs.push(InputSpec {
                    path: v.to_string(),
                    whole_archive: true,
                }),
                _ => self.whole_archive_all = true,
            },
            "entry" => self.entry = Some(need()?.to_string()),
            "noentry" => self.no_entry = true,
            "dll" => self.dll = true,
            "subsystem" => {
                let (sub, ver) = match need()?.split_once(',') {
                    Some((s, v)) => (s, Some(v)),
                    None => (v(), None),
                };
                self.subsystem =
                    Some(Subsystem::parse(sub).ok_or_else(|| err!("unknown subsystem '{sub}'"))?);
                if let Some(ver) = ver {
                    self.subsystem_version = Some(parse_version(ver)?);
                }
            }
            "osversion" => self.os_version = Some(parse_version(need()?)?),
            "version" => {
                if value.is_none() {
                    self.print_version = true;
                } else {
                    self.image_version = parse_version(need()?)?;
                }
            }
            "base" => self.image_base = Some(parse_number(need()?)?),
            "stack" => self.stack = parse_pair(need()?, self.stack)?,
            "heap" => self.heap = parse_pair(need()?, self.heap)?,
            "dynamicbase" => self.dynamic_base = yes(),
            "nxcompat" => self.nx_compat = yes(),
            "largeaddressaware" => self.large_address_aware = Some(yes()),
            "safeseh" => self.safeseh = Some(yes()),
            "highentropyva" => self.high_entropy_va = yes(),
            "tsaware" => self.terminal_server_aware = Some(yes()),
            "fixed" => self.fixed = yes(),
            "appcontainer" => self.appcontainer = yes(),
            "cetcompat" => self.cet_compat = yes(),
            "integritycheck" => self.integrity_check = yes(),
            "opt" => {
                for part in v().split(',') {
                    match part.to_ascii_lowercase().as_str() {
                        "ref" => self.gc = Some(true),
                        "noref" => self.gc = Some(false),
                        "icf" | "safeicf" => self.icf = Some(true),
                        "noicf" => self.icf = Some(false),
                        "lbr" | "nolbr" => {}
                        p if p.starts_with("icf=") || p.starts_with("lld") => {}
                        "" => {}
                        p => diag::warn(format!("ignoring unknown /OPT argument '{p}'")),
                    }
                }
            }
            "debug" => {
                self.debug = !value.is_some_and(|v| v.eq_ignore_ascii_case("none"));
            }
            "pdb" => self.pdb = Some(PathBuf::from(need()?)),
            "natvis" => self.natvis.push(PathBuf::from(need()?)),
            "pdbaltpath" => self.pdb_alt_path = Some(need()?.to_string()),
            "include" => self.includes.push(need()?.to_string()),
            "alternatename" => self.alternate_names.push(parse_assignment(need()?, arg)?),
            "merge" => self.merges.push(parse_assignment(need()?, arg)?),
            "export" => self.exports.push(parse_export(need()?)?),
            "def" => self.def_file = Some(PathBuf::from(need()?)),
            "implib" => self.implib = Some(PathBuf::from(need()?)),
            "noimplib" => self.no_implib = true,
            "force" => match value.map(|v| v.to_ascii_lowercase()) {
                None => {
                    self.force_unresolved = true;
                    self.force_multiple = true;
                }
                Some(v) if v == "unresolved" => self.force_unresolved = true,
                Some(v) if v == "multiple" => self.force_multiple = true,
                Some(v) => diag::warn(format!("ignoring unknown /FORCE argument '{v}'")),
            },
            "time" | "time+" => self.time = true,
            "verbose" => self.verbose = true,
            "threads" => {
                let n: usize = need()?
                    .parse()
                    .map_err(|_| err!("/THREADS expects a number, got '{}'", v()))?;
                self.threads = Some(n.max(1));
            }
            "timestamp" => {
                self.timestamp = Some(
                    parse_number(need()?)?
                        .try_into()
                        .map_err(|_| err!("/TIMESTAMP is out of range"))?,
                )
            }
            "filealign" => self.file_align = parse_alignment(need()?, arg)?,
            "align" => self.section_align = parse_alignment(need()?, arg)?,
            "release" => self.release_checksum = true,
            "machine" => {
                let m = need()?;
                self.machine = Some(super::arch::Machine::parse(m).ok_or_else(|| {
                    err!("/MACHINE:{m} is not supported: hyprlnk links x64, ARM64 and x86 images")
                })?);
            }
            "lldmingw" => self.mingw = true,
            "reproduce" => self.reproduce = Some(PathBuf::from(need()?)),
            "help" | "?" => self.print_help = true,
            "delayload" => diag::warn(format!(
                "delay-loading is not supported yet: '{}' is imported normally",
                v()
            )),
            "ltcg" => {}
            "map" => self.map = Some(value.filter(|v| !v.is_empty()).map(PathBuf::from)),
            "order" | "lldmap" => {
                diag::warn(format!("'{arg}' is not supported yet and is ignored"))
            }
            "driver" | "profile" | "swaprun" | "stub" | "section" | "functionpadmin" => {
                diag::warn(format!("'{arg}' is not supported yet and is ignored"))
            }
            // Accepted and ignored.
            "nologo"
            | "incremental"
            | "manifest"
            | "manifestuac"
            | "manifestfile"
            | "manifestinput"
            | "manifestdependency"
            | "guard"
            | "errorreport"
            | "ignore"
            | "wx"
            | "brepro"
            | "demangle"
            | "errorlimit"
            | "debugtype"
            | "failifmismatch"
            | "allowbind"
            | "allowisolation"
            | "dependentloadflag"
            | "emittoolversioninfo"
            | "kill-at"
            | "lldltocache"
            | "lto-pgo-warn-mismatch"
            | "pdbpagesize"
            | "pdbstripped"
            | "winsysroot"
            | "lldignoreenv"
            | "editandcontinue"
            | "throwingnew"
            | "guardsym"
            | "disallowlib"
            | "inferasanlibs"
            | "exclude-symbols"
            | "nocoffgrpinfo"
            | "nodbgdirmerge"
            | "ilk"
            | "mapinfo"
            | "idlout"
            | "tlbout"
            | "tlbid"
            | "midl"
            | "ignoreidl"
            | "winmd"
            | "winmdfile"
            | "winmdkeyfile"
            | "assemblydebug"
            | "clrimagetype"
            | "clrthreadattribute"
            | "fastfail"
            | "sourcelink"
            | "hybridpatchable"
            | "arm64xsame"
            | "aligncomm"
            | "includeoptional" => {}
            _ => diag::warn(format!("ignoring unknown argument '{arg}'")),
        }
        Ok(())
    }
}

fn option(arg: &str) -> Option<(String, Option<&str>)> {
    let body = if let Some(rest) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) {
        rest
    } else {
        let rest = arg.strip_prefix('/')?;
        let name = rest.split(':').next().unwrap_or("").to_ascii_lowercase();
        if !cfg!(windows) && !KNOWN.contains(&name.as_str()) && Path::new(arg).exists() {
            return None;
        }
        rest
    };
    if body.is_empty() {
        return None;
    }
    let (name, value) = match body.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (body, None),
    };
    Some((name.to_ascii_lowercase(), value))
}

pub fn lib_key(name: &str) -> String {
    // Both separators on every host: Windows paths reach Unix hosts in
    // cross links.
    let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut key = file.to_ascii_lowercase();
    if !key.contains('.') {
        key.push_str(".lib");
    }
    key
}

pub fn parse_number(s: &str) -> Result<u64> {
    let s = s.trim();
    let r = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8)
    } else {
        s.parse()
    };
    r.map_err(|_| err!("invalid number '{s}'"))
}

fn parse_pair(s: &str, current: (u64, u64)) -> Result<(u64, u64)> {
    Ok(match s.split_once(',') {
        Some((a, b)) => (parse_number(a)?, parse_number(b)?),
        None => (parse_number(s)?, current.1),
    })
}

fn parse_version(s: &str) -> Result<(u16, u16)> {
    let (major, minor) = s.split_once('.').unwrap_or((s, "0"));
    let parse = |p: &str| {
        p.trim()
            .parse::<u16>()
            .map_err(|_| err!("invalid version '{s}'"))
    };
    Ok((parse(major)?, parse(minor)?))
}

fn parse_alignment(s: &str, arg: &str) -> Result<u32> {
    let n = parse_number(s)?;
    if !n.is_power_of_two() || n > 1 << 28 {
        bail!("'{arg}': alignment must be a power of two");
    }
    Ok(n as u32)
}

pub fn parse_assignment(s: &str, arg: &str) -> Result<(String, String)> {
    match s.split_once('=') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => Ok((a.to_string(), b.to_string())),
        _ => bail!("'{arg}': expected <from>=<to>"),
    }
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
            "/NOLOGO",
            "symbols.o",
            "main.o",
            "libstd.rlib",
            "kernel32.lib",
            "/defaultlib:msvcrt",
            "/NXCOMPAT",
            "/OUT:hello.exe",
            "/OPT:REF,NOICF",
            "/DEBUG",
            "/PDBALTPATH:%_PDB%",
            "/NATVIS:C:\\x\\core.natvis",
            "/LIBPATH:C:\\sysroot\\lib",
        ]);
        assert_eq!(c.output.as_deref(), Some(Path::new("hello.exe")));
        assert_eq!(c.inputs.len(), 4);
        assert_eq!(c.default_libs, ["msvcrt"]);
        assert_eq!(c.gc, Some(true));
        assert!(c.debug);
        assert_eq!(c.lib_paths, [PathBuf::from("C:\\sysroot\\lib")]);
    }

    #[test]
    fn options_and_values() {
        let c = parse(&[
            "-dll",
            "/SUBSYSTEM:windows,6.2",
            "/STACK:0x200000,4096",
            "/BASE:0x180000000",
            "/DYNAMICBASE:NO",
            "/NODEFAULTLIB:LIBCMT",
            "/WHOLEARCHIVE:foo.lib",
            "/MERGE:.foo=.rdata",
            "/EXPORT:bar=baz,@3,NONAME",
        ]);
        assert!(c.dll);
        assert_eq!(c.subsystem, Some(Subsystem::Windows));
        assert_eq!(c.subsystem_version, Some((6, 2)));
        assert_eq!(c.stack, (0x200000, 4096));
        assert_eq!(c.image_base, Some(0x1_8000_0000));
        assert!(!c.dynamic_base);
        assert_eq!(c.no_default_libs, ["libcmt.lib"]);
        assert!(c.inputs[0].whole_archive);
        assert_eq!(c.merges, [(".foo".to_string(), ".rdata".to_string())]);
        assert_eq!(c.exports[0].name, "bar");
        assert_eq!(c.exports[0].ordinal, Some(3));
        assert!(c.exports[0].noname);
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0x10").unwrap(), 16);
        assert_eq!(parse_number("010").unwrap(), 8);
        assert_eq!(parse_number("10").unwrap(), 10);
        assert!(parse_number("x").is_err());
        assert_eq!(lib_key("C:\\SDK\\Kernel32"), "kernel32.lib");
        assert_eq!(lib_key("msvcrt.lib"), "msvcrt.lib");
    }
}
