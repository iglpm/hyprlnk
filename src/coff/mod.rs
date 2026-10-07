//! The PE/COFF backend: links x86-64 Windows executables and DLLs from COFF
//! objects, archives (rlibs, static libraries) and import libraries, driven by
//! `link.exe`/`lld-link` command lines.
//!
//! The phases, in order:
//!
//! 1. [`config`]: the command line (and later `.drectve` sections) becomes a
//!    [`Config`].
//! 2. [`resolve`]: inputs are mapped and parsed in parallel waves; symbols are
//!    resolved, pulling archive members in as they are needed.
//! 3. [`gc`]: COMDAT selection and `/OPT:REF` garbage collection decide which
//!    sections are written.
//! 4. [`synth`]: linker-made data (import tables, thunks, exports).
//! 5. [`layout`]: sections are grouped into output sections and given
//!    addresses.
//! 6. [`write`]: sections are copied and relocated in parallel, and the PE
//!    headers, base relocations and exception table are finished.

mod config;
mod def;
mod gc;
mod implib;
mod import;
mod layout;
mod object;
mod reproduce;
mod resolve;
mod symtab;
mod synth;
mod winsdk;
mod write;

pub use config::Config;

use crate::diag::{Result, Timer};
use crate::fileio::Arena;

// Machine types.
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x1c4;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;

// Section characteristics.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F0_0000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// The bits of an input section's characteristics that decide which output
/// section it joins: memory permissions and content type.
pub const OUTPUT_CHARS_MASK: u32 = 0xFE00_0000
    | IMAGE_SCN_CNT_CODE
    | IMAGE_SCN_CNT_INITIALIZED_DATA
    | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

// Symbols.
pub const IMAGE_SYM_UNDEFINED: i32 = 0;
pub const IMAGE_SYM_ABSOLUTE: i32 = -1;
pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const IMAGE_SYM_CLASS_SECTION: u8 = 104;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

// COMDAT selection.
pub const IMAGE_COMDAT_SELECT_NODUPLICATES: u8 = 1;
pub const IMAGE_COMDAT_SELECT_ANY: u8 = 2;
pub const IMAGE_COMDAT_SELECT_SAME_SIZE: u8 = 3;
pub const IMAGE_COMDAT_SELECT_EXACT_MATCH: u8 = 4;
pub const IMAGE_COMDAT_SELECT_ASSOCIATIVE: u8 = 5;
pub const IMAGE_COMDAT_SELECT_LARGEST: u8 = 6;

// x86-64 relocations.
pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0;
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x1;
pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x2;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x3;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x4;
pub const IMAGE_REL_AMD64_REL32_5: u16 = 0x9;
pub const IMAGE_REL_AMD64_SECTION: u16 = 0xA;
pub const IMAGE_REL_AMD64_SECREL: u16 = 0xB;
pub const IMAGE_REL_AMD64_SECREL7: u16 = 0xC;

// Base relocation types.
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

// Short import object types.
pub const IMPORT_CODE: u8 = 0;
pub const IMPORT_DATA: u8 = 1;
pub const IMPORT_CONST: u8 = 2;
pub const IMPORT_ORDINAL: u8 = 0;
pub const IMPORT_NAME: u8 = 1;
pub const IMPORT_NAME_NOPREFIX: u8 = 2;
pub const IMPORT_NAME_UNDECORATE: u8 = 3;
pub const IMPORT_NAME_EXPORTAS: u8 = 4;

pub(crate) fn machine_name(m: u16) -> &'static str {
    match m {
        IMAGE_FILE_MACHINE_UNKNOWN => "unknown",
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_ARM64 => "arm64",
        IMAGE_FILE_MACHINE_ARMNT => "arm",
        IMAGE_FILE_MACHINE_ARM64EC => "arm64ec",
        IMAGE_FILE_MACHINE_ARM64X => "arm64x",
        _ => "an unknown machine",
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

/// Link with a `link.exe`-style command line (without the program name).
pub fn link_main(args: Vec<String>) -> Result<()> {
    let args = crate::cmdline::expand_response_files(args)?;
    let cfg = Config::parse(&args)?;
    if cfg.print_help {
        print!("{}", config::HELP);
        return Ok(());
    }
    if cfg.print_version {
        println!("hyprlnk {} (compatible with lld-link)", crate::VERSION);
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

/// Link with a parsed configuration.
pub fn link(cfg: Config) -> Result<()> {
    let arena = Arena::new();
    let mut timer = Timer::new(cfg.time);
    let mut linker = resolve::Linker::new(cfg, &arena);
    linker.resolve(&mut timer)?;
    linker.mark_live();
    timer.phase("garbage collection");
    linker.create_synthetic()?;
    let layout = linker.layout();
    timer.phase("layout");
    linker.write(&layout, &mut timer)?;
    if let Some(path) = linker.implib_path() {
        linker.write_implib(&path)?;
        timer.phase("import library");
    }
    timer.report();
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        // The process ends right after: let the OS reclaim the inputs'
        // mappings and the millions of small allocations at once, instead
        // of freeing them one by one (a third of the wall time of a large
        // link).
        std::mem::forget(layout);
        std::mem::forget(linker);
        std::mem::forget(arena);
    }
    Ok(())
}
