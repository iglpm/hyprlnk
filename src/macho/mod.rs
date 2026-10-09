//! The Mach-O backend: macOS executables, dylibs and bundles for arm64, arm64e and x86_64.
//! Phases: config → resolve → gc → scan → layout → write (image, LINKEDIT, signature).

mod arch;
mod config;
mod dwarf;
mod dyldinfo;
mod dylib;
mod fixups;
mod gc;
mod layout;
mod linkedit;
mod object;
mod reproduce;
mod resolve;
mod scan;
mod sdk;
mod symtab;
mod tbd;
mod unwind;
mod write;

pub use config::Config;

use crate::diag::{Result, Timer};
use crate::fileio::Arena;

// CPU types.
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;

// File types and header flags.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
pub const MH_MAGIC: u32 = 0xfeed_face;
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_BUNDLE: u32 = 8;
pub const MH_DYLIB_STUB: u32 = 9;
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_FORCE_FLAT: u32 = 0x100;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
pub const MH_WEAK_DEFINES: u32 = 0x8000;
pub const MH_BINDS_TO_WEAK: u32 = 0x1_0000;
pub const MH_PIE: u32 = 0x20_0000;
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x10_0000;
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x40_0000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
pub const MH_APP_EXTENSION_SAFE: u32 = 0x0200_0000;

// Load commands.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_LINKER_OPTION: u32 = 0x2d;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

// Segment flags and protections.
pub const SG_READ_ONLY: u32 = 0x10;
pub const VM_PROT_READ: u32 = 1;
pub const VM_PROT_WRITE: u32 = 2;
pub const VM_PROT_EXECUTE: u32 = 4;

// Section types and attributes.
pub const SECTION_TYPE: u32 = 0xff;
pub const S_REGULAR: u32 = 0x0;
pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
pub const S_COALESCED: u32 = 0xb;
pub const S_GB_ZEROFILL: u32 = 0xc;
pub const S_INTERPOSING: u32 = 0xd;
pub const S_16BYTE_LITERALS: u32 = 0xe;
pub const S_DTRACE_DOF: u32 = 0xf;
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x400;

// Symbols.
pub const N_STAB: u8 = 0xe0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0e;
pub const N_EXT: u8 = 0x01;
pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_INDR: u8 = 0xa;
pub const N_SECT: u8 = 0xe;
pub const N_NO_DEAD_STRIP: u16 = 0x20;
pub const REFERENCED_DYNAMICALLY: u16 = 0x10;
pub const N_WEAK_REF: u16 = 0x40;
pub const N_WEAK_DEF: u16 = 0x80;
pub const N_REF_TO_WEAK: u16 = 0x80;
pub const N_SYMBOL_RESOLVER: u16 = 0x100;
pub const N_ALT_ENTRY: u16 = 0x200;
pub const N_COLD_FUNC: u16 = 0x400;
pub const N_GSYM: u8 = 0x20;
pub const N_FUN: u8 = 0x24;
pub const N_STSYM: u8 = 0x26;
pub const N_SO: u8 = 0x64;
pub const N_OSO: u8 = 0x66;
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
pub const SELF_LIBRARY_ORDINAL: i32 = 0;
pub const DYNAMIC_LOOKUP_ORDINAL: i32 = 0xfe;
pub const EXECUTABLE_ORDINAL: i32 = 0xff;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i32 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i32 = -3;

// Platforms (LC_BUILD_VERSION).
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_BRIDGEOS: u32 = 5;
pub const PLATFORM_MACCATALYST: u32 = 6;
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
pub const PLATFORM_DRIVERKIT: u32 = 10;
pub const PLATFORM_XROS: u32 = 11;
pub const PLATFORM_XROS_SIMULATOR: u32 = 12;
pub const TOOL_LD: u32 = 3;

pub fn platform_name(p: u32) -> &'static str {
    match p {
        PLATFORM_MACOS => "macOS",
        PLATFORM_IOS => "iOS",
        PLATFORM_TVOS => "tvOS",
        PLATFORM_WATCHOS => "watchOS",
        PLATFORM_BRIDGEOS => "bridgeOS",
        PLATFORM_MACCATALYST => "Mac Catalyst",
        PLATFORM_IOSSIMULATOR => "iOS Simulator",
        PLATFORM_TVOSSIMULATOR => "tvOS Simulator",
        PLATFORM_WATCHOSSIMULATOR => "watchOS Simulator",
        PLATFORM_DRIVERKIT => "DriverKit",
        PLATFORM_XROS => "visionOS",
        PLATFORM_XROS_SIMULATOR => "visionOS Simulator",
        _ => "an unknown platform",
    }
}

#[inline]
pub(crate) fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

#[inline]
pub(crate) fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

#[inline]
pub(crate) fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

#[inline]
pub(crate) fn u32be(d: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(d[o..o + 4].try_into().unwrap())
}

#[inline]
pub(crate) fn put16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn put32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn put64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn align_up(v: u64, a: u64) -> u64 {
    debug_assert!(a.is_power_of_two());
    (v + a - 1) & !(a - 1)
}

/// The NUL-terminated string at `off`, without the NUL (all of the rest if there is none).
#[inline]
pub(crate) fn cstr(d: &[u8], off: usize) -> &[u8] {
    let rest = d.get(off..).unwrap_or(&[]);
    match memchr0(rest) {
        Some(n) => &rest[..n],
        None => rest,
    }
}

#[inline]
pub(crate) fn memchr0(d: &[u8]) -> Option<usize> {
    d.iter().position(|&b| b == 0)
}

/// Fixed-size Mach-O name fields (`segname`, `sectname`).
#[inline]
pub(crate) fn name16(d: &[u8]) -> &[u8] {
    let n = d
        .iter()
        .take(16)
        .position(|&b| b == 0)
        .unwrap_or(16.min(d.len()));
    &d[..n]
}

pub(crate) fn uleb_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

pub(crate) fn push_uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub(crate) fn push_sleb(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0);
        if done {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub(crate) fn read_uleb(d: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *d.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as u64) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
}

pub(crate) fn read_sleb(d: &[u8], pos: &mut usize) -> Option<i64> {
    let mut v = 0i64;
    let mut shift = 0;
    loop {
        let b = *d.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as i64) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                v |= -1i64 << shift;
            }
            return Some(v);
        }
    }
}

/// `X.Y.Z` packed as `xxxx.yy.zz` nibbles, the Mach-O version format.
pub fn parse_version(s: &str) -> Option<u32> {
    let mut parts = s.trim().split('.');
    let major: u32 = parts.next()?.trim().parse().ok()?;
    let minor: u32 = parts.next().map_or(Some(0), |p| p.trim().parse().ok())?;
    let patch: u32 = parts.next().map_or(Some(0), |p| p.trim().parse().ok())?;
    if major > 0xffff || minor > 0xff || patch > 0xff {
        return None;
    }
    Some((major << 16) | (minor << 8) | patch)
}

pub fn format_version(v: u32) -> String {
    let (a, b, c) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if c == 0 {
        format!("{a}.{b}")
    } else {
        format!("{a}.{b}.{c}")
    }
}

pub fn link_main(args: Vec<String>) -> Result<()> {
    let args = config::expand_args(args)?;
    let cfg = Config::parse(&args)?;
    if cfg.print_help {
        print!("{}", config::HELP);
        return Ok(());
    }
    if cfg.print_version {
        println!(
            "hyprlnk {} (compatible with ld64 and ld64.lld)",
            crate::VERSION
        );
        return Ok(());
    }
    let reproduce = cfg
        .reproduce
        .clone()
        .or_else(|| std::env::var_os("HYPRLNK_REPRODUCE").map(std::path::PathBuf::from));
    if let Some(dir) = reproduce {
        reproduce::save(&dir, &args, &cfg)?;
    }
    match cfg.threads {
        Some(n) => rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build()
            .map_err(|e| crate::err!("cannot start {n} threads: {e}"))?
            .install(|| link(cfg)),
        None => link(cfg),
    }
}

pub fn link(cfg: Config) -> Result<()> {
    let arena = Arena::new();
    let mut timer = Timer::new(cfg.time);
    let mut linker = resolve::Linker::new(cfg, &arena)?;
    linker.resolve(&mut timer)?;
    linker.mark_live();
    timer.phase("dead strip");
    linker.scan(&mut timer)?;
    let layout = linker.layout()?;
    timer.phase("layout");
    linker.write(&layout, &mut timer)?;
    if let Some(path) = &linker.cfg.map {
        linker.write_map(&layout, path)?;
        timer.phase("map file");
    }
    if let Some(path) = &linker.cfg.dependency_info {
        linker.write_dependency_info(path)?;
    }
    timer.report();
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        // Leaked on purpose: freeing millions of small allocations costs more than the exit.
        std::mem::forget(layout);
        std::mem::forget(linker);
        std::mem::forget(arena);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_round_trips() {
        for v in [0u64, 1, 127, 128, 300, 1 << 35, u64::MAX] {
            let mut b = Vec::new();
            push_uleb(&mut b, v);
            assert_eq!(b.len(), uleb_len(v));
            let mut p = 0;
            assert_eq!(read_uleb(&b, &mut p), Some(v));
            assert_eq!(p, b.len());
        }
        for v in [0i64, 1, -1, 63, 64, -64, -65, i64::MIN, i64::MAX] {
            let mut b = Vec::new();
            push_sleb(&mut b, v);
            let mut p = 0;
            assert_eq!(read_sleb(&b, &mut p), Some(v));
        }
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("11.0.0"), Some(0x000b_0000));
        assert_eq!(parse_version("10.15"), Some(0x000a_0f00));
        assert_eq!(parse_version("1359"), Some(1359 << 16));
        assert_eq!(parse_version("1.2.3.4"), Some(0x0001_0203));
        assert_eq!(parse_version("x"), None);
        assert_eq!(format_version(0x000b_0000), "11.0");
        assert_eq!(format_version(0x000a_0f01), "10.15.1");
    }
}
