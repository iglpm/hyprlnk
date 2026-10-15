//! The ELF backend: Linux executables, PIEs and shared objects for x86-64, i386, AArch64, ARM,
//! RISC-V, POWER (ppc64le), s390x and LoongArch.
//! Phases: config → load → resolve → gc + scan → merge → layout → write (sections ∥ synthetic).
//!
//! The linker is monomorphized per machine through [`Target`]: everything a machine decides —
//! relocations, PLT code, TLS models — is in its own module, the rest is shared.

mod aarch64;
mod arm;
mod config;
pub mod driver;
mod dynamic;
mod ehframe;
mod gc;
mod i386;
mod input;
mod layout;
mod loongarch;
mod mapfile;
mod merge;
mod object;
mod ppc64;
pub(crate) mod prof;
mod reproduce;
mod resolve;
mod riscv;
mod s390x;
mod scan;
mod script;
mod symbols;
mod target;
mod thunks;
mod write;
mod x86_64;

pub use config::Config;
pub use target::Machine;

use crate::diag::{Result, Timer};
use crate::fileio::Arena;
use target::Target;

// File types and machines.
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_386: u16 = 3;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;
pub const EM_LOONGARCH: u16 = 258;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

// Section types.
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_RELR: u32 = 19;
pub const SHT_LLVM_ADDRSIG: u32 = 0x6fff_4c03;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub const SHT_ARM_EXIDX: u32 = 0x7000_0001;
pub const SHT_ARM_ATTRIBUTES: u32 = 0x7000_0003;
pub const SHT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;

// Section flags.
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_GNU_RETAIN: u64 = 0x20_0000;
pub const SHF_EXCLUDE: u64 = 0x8000_0000;
pub const GRP_COMDAT: u32 = 1;

// Symbols.
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_GNU_UNIQUE: u8 = 10;
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;
pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;
pub const SHN_UNDEF: u32 = 0;
pub const SHN_LORESERVE: u32 = 0xff00;
pub const SHN_ABS: u32 = 0xfff1;
pub const SHN_COMMON: u32 = 0xfff2;
pub const SHN_XINDEX: u32 = 0xffff;

// Program headers.
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_ARM_EXIDX: u32 = 0x7000_0001;
pub const PT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// Dynamic section tags.
pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_SYMBOLIC: u64 = 16;
pub const DT_REL: u64 = 17;
pub const DT_RELSZ: u64 = 18;
pub const DT_RELENT: u64 = 19;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_PREINIT_ARRAY: u64 = 32;
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
pub const DT_RELRSZ: u64 = 35;
pub const DT_RELR: u64 = 36;
pub const DT_RELRENT: u64 = 37;
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;
pub const DT_VERSYM: u64 = 0x6fff_fff0;
pub const DT_RELACOUNT: u64 = 0x6fff_fff9;
pub const DT_RELCOUNT: u64 = 0x6fff_fffa;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
pub const DT_VERDEF: u64 = 0x6fff_fffc;
pub const DT_VERDEFNUM: u64 = 0x6fff_fffd;
pub const DT_VERNEED: u64 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
pub const DT_PPC64_GLINK: u64 = 0x7000_0000;
pub const DT_PPC64_OPT: u64 = 0x7000_0003;
pub const DF_ORIGIN: u64 = 0x1;
pub const DF_SYMBOLIC: u64 = 0x2;
pub const DF_TEXTREL: u64 = 0x4;
pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_STATIC_TLS: u64 = 0x10;
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_NODELETE: u64 = 0x8;
pub const DF_1_INITFIRST: u64 = 0x20;
pub const DF_1_NOOPEN: u64 = 0x40;
pub const DF_1_ORIGIN: u64 = 0x80;
pub const DF_1_INTERPOSE: u64 = 0x400;
pub const DF_1_NODEFLIB: u64 = 0x800;
pub const DF_1_PIE: u64 = 0x0800_0000;

// Symbol versions.
pub const VER_NDX_LOCAL: u16 = 0;
pub const VER_NDX_GLOBAL: u16 = 1;
pub const VERSYM_HIDDEN: u16 = 0x8000;
pub const VER_FLG_BASE: u16 = 1;

pub const NT_GNU_BUILD_ID: u32 = 3;

/// An index meaning "none" in u32 tables.
pub const NONE: u32 = u32::MAX;

#[inline]
pub(crate) fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 {
        return v;
    }
    debug_assert!(a.is_power_of_two());
    (v + a - 1) & !(a - 1)
}

/// The NUL-terminated string at `off`, without the NUL.
#[inline]
pub(crate) fn cstr(d: &[u8], off: usize) -> &[u8] {
    let rest = d.get(off..).unwrap_or(&[]);
    match memchr::memchr(0, rest) {
        Some(n) => &rest[..n],
        None => rest,
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

/// A mutable byte buffer that threads write disjoint ranges of.
#[derive(Clone, Copy)]
pub(crate) struct OutBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: writers only touch disjoint ranges (each phase partitions the file), and the buffer
// outlives every thread that holds a copy.
unsafe impl Send for OutBuf {}
unsafe impl Sync for OutBuf {}

impl OutBuf {
    pub fn new(b: &mut [u8]) -> OutBuf {
        OutBuf {
            ptr: b.as_mut_ptr(),
            len: b.len(),
        }
    }

    /// The bytes at `[off, off + len)`.
    ///
    /// Callers guarantee no two live slices overlap.
    #[allow(clippy::mut_from_ref)]
    #[inline]
    pub fn slice(&self, off: u64, len: u64) -> &mut [u8] {
        let (off, len) = (off as usize, len as usize);
        assert!(
            off.checked_add(len).is_some_and(|e| e <= self.len),
            "write past the end of the output ({off:#x}+{len:#x} > {:#x})",
            self.len
        );
        // SAFETY: in bounds; disjointness is the caller's contract above.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(off), len) }
    }
}

/// A vector whose distinct elements threads may write at the same time.
pub(crate) struct SyncVec<T> {
    data: Vec<std::cell::UnsafeCell<T>>,
}

// SAFETY: see `set`; reads after the writing phase happen-after through rayon's joins.
unsafe impl<T: Send> Sync for SyncVec<T> {}

impl<T: Clone> SyncVec<T> {
    pub fn new(n: usize, v: T) -> SyncVec<T> {
        SyncVec {
            data: (0..n)
                .map(|_| std::cell::UnsafeCell::new(v.clone()))
                .collect(),
        }
    }
}

impl<T> SyncVec<T> {
    /// Element `i` is written by one thread at a time and not read while it is written.
    #[inline]
    pub fn set(&self, i: usize, v: T) {
        // SAFETY: the caller partitions the indices between threads.
        unsafe { *self.data[i].get() = v }
    }

    pub fn into_vec(self) -> Vec<T> {
        self.data.into_iter().map(|c| c.into_inner()).collect()
    }

    /// All elements, once no thread writes any more.
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `UnsafeCell<T>` has `T`'s layout; no write is in progress (phase ordering).
        unsafe { std::slice::from_raw_parts(self.data.as_ptr().cast::<T>(), self.data.len()) }
    }
}

pub fn link_main(args: Vec<String>) -> Result<()> {
    let t0 = std::time::Instant::now();
    #[cfg(target_os = "linux")]
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        // Transparent huge pages make every first touch of fresh heap memory zero 2 MiB; a
        // linker touches a few kilobytes of most of what it allocates, and pays for it with
        // a third of its run time. This process only links, so it opts out.
        // SAFETY: a plain prctl.
        unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) };
    }
    let args = crate::cmdline::expand_gnu_response_files(args)?;
    let cfg = Config::parse(&args)?;
    if cfg.print_help {
        print!("{}", config::HELP);
        return Ok(());
    }
    if cfg.print_version {
        println!("hyprlnk {} (compatible with GNU linkers)", crate::VERSION);
        if cfg.inputs.is_empty() {
            return Ok(());
        }
    }
    let reproduce = cfg
        .reproduce
        .clone()
        .or_else(|| std::env::var_os("HYPRLNK_REPRODUCE").map(std::path::PathBuf::from));
    if let Some(dir) = reproduce {
        reproduce::save(&dir, &args, &cfg)?;
    }
    if prof::enabled() {
        eprintln!(
            "prof: before linking: {:.2} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
    }
    #[cfg(target_os = "linux")]
    if cfg.fork
        && crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed)
        && std::env::var_os("HYPRLNK_NO_FORK").is_none()
        && single_threaded()
    {
        return forked(move || {
            let r = link_threads(cfg);
            if prof::enabled() {
                eprintln!(
                    "prof: linked after {:.2} ms",
                    t0.elapsed().as_secs_f64() * 1e3
                );
            }
            r
        });
    }
    link_threads(cfg)
}

fn link_threads(cfg: Config) -> Result<()> {
    match cfg.threads {
        Some(n) => rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build()
            .map_err(|e| crate::err!("cannot start {n} threads: {e}"))?
            .install(|| link(cfg)),
        None => link(cfg),
    }
}

/// Forking is only safe (and only useful) at the start of a linker process, before any other
/// thread exists — not, say, inside a test harness that called `main_with_args`.
#[cfg(target_os = "linux")]
fn single_threaded() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .is_some_and(|n| n.trim() == "1")
    })
}

/// Run `f` in a child process and exit this one as soon as the child reports its result: the
/// caller (a compiler driver waiting for the link) doesn't wait for the child to tear down a
/// gigabyte of mappings and allocations. As mold and wild do.
#[cfg(target_os = "linux")]
fn forked(f: impl FnOnce() -> Result<()>) -> Result<()> {
    let mut fds = [0i32; 2];
    // SAFETY: plain system calls; before any thread has started (rayon's pool is lazy).
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return f();
        }
        let pid = libc::fork();
        if pid < 0 {
            libc::close(fds[0]);
            libc::close(fds[1]);
            return f();
        }
        if pid > 0 {
            libc::close(fds[1]);
            let mut b = [0u8; 1];
            let n = libc::read(fds[0], b.as_mut_ptr().cast(), 1);
            if n == 1 {
                libc::_exit(b[0] as i32);
            }
            // The child died without reporting (a crash): report its status.
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                1
            };
            libc::_exit(if code == 0 { 1 } else { code });
        }
        libc::close(fds[0]);
        let code: u8 = match f() {
            Ok(()) => 0,
            Err(e) => {
                crate::diag::error(e);
                1
            }
        };
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        libc::write(fds[1], [code].as_ptr().cast(), 1);
        // Whoever reads our output through a pipe (rustc does) waits for it to close, and the
        // kernel closes files only after unmapping everything: hand them over now.
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
        }
        libc::close(fds[1]);
        libc::_exit(code as i32);
    }
}

/// Link with an explicit configuration; the machine comes from `-m` or the first input.
pub fn link(cfg: Config) -> Result<()> {
    // The output is a new file, renamed over the old one. Writing into the old one instead is
    // only correct with every byte the writers skip zeroed first, which made relinking Rune's
    // 300 MB debug build 20–100 ms slower than writing a new file (tmpfs, ext4).
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        crate::fileio::remove_old_output_in_background(&cfg.output);
    }
    let arena = Arena::new();
    let mut timer = Timer::new(cfg.time);
    let mut loaded = input::load(&cfg, &arena)?;
    timer.phase("open inputs");
    let machine = match cfg.machine {
        Some(m) => m,
        None => loaded.machine.ok_or_else(|| {
            crate::err!("no input files to tell the machine from; pass -m <emulation>")
        })?,
    };
    if let Some(m) = loaded.machine
        && m != machine
    {
        crate::bail!(
            "{} is for {}, but the output is for {} (-m)",
            loaded.machine_source,
            m.name(),
            machine.name()
        );
    }
    loaded.machine = Some(machine);
    let r = match machine {
        Machine::X86_64 => run::<x86_64::X86_64>(cfg, &arena, loaded, timer),
        Machine::I386 => run::<i386::I386>(cfg, &arena, loaded, timer),
        Machine::AArch64 => run::<aarch64::AArch64>(cfg, &arena, loaded, timer),
        Machine::Arm => run::<arm::Arm>(cfg, &arena, loaded, timer),
        Machine::RiscV64 => run::<riscv::RiscV64>(cfg, &arena, loaded, timer),
        Machine::RiscV32 => run::<riscv::RiscV32>(cfg, &arena, loaded, timer),
        Machine::Ppc64le => run::<ppc64::Ppc64le>(cfg, &arena, loaded, timer),
        Machine::Ppc64 => run::<ppc64::Ppc64be>(cfg, &arena, loaded, timer),
        Machine::S390x => run::<s390x::S390x>(cfg, &arena, loaded, timer),
        Machine::LoongArch64 => run::<loongarch::LoongArch64>(cfg, &arena, loaded, timer),
    };
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        // The inputs stay mapped: unmapping a gigabyte only delays the exit.
        std::mem::forget(arena);
    }
    r
}

/// `--dependency-file`: a Makefile rule making the output depend on every input, and an empty
/// rule per input so a deleted one doesn't break the build (as lld writes it).
fn write_dependency_file(
    dep: &std::path::Path,
    output: &std::path::Path,
    inputs: &[std::path::PathBuf],
) -> Result<()> {
    let quote = |p: &std::path::Path| p.display().to_string().replace(' ', "\\ ");
    let mut s = format!("{}:", quote(output));
    for i in inputs {
        s.push_str(&format!(" \\\n  {}", quote(i)));
    }
    s.push('\n');
    for i in inputs {
        s.push_str(&format!("\n{}:\n", quote(i)));
    }
    std::fs::write(dep, s).map_err(|e| crate::err!("cannot write {}: {e}", dep.display()))
}

fn run<'a, T: Target>(
    cfg: Config,
    arena: &'a Arena,
    loaded: input::Loaded<'a>,
    mut timer: Timer,
) -> Result<()> {
    let mut ctx = resolve::Ctx::<T>::new(cfg, arena, loaded)?;
    ctx.parse(&mut timer)?;
    ctx.resolve(&mut timer)?;
    // Mergeable sections that aren't allocated (`.debug_str`, `.comment`) don't depend on
    // symbol resolution's last steps or on what garbage collection keeps: they are decompressed
    // if need be and merged beside those.
    let work = ctx.compressed_sections();
    let mut groups = ctx.merge_groups(false);
    let arena = ctx.arena;
    let mut inflated = Vec::new();
    let mut merged = Vec::new();
    let mut beside = std::time::Duration::ZERO;
    rayon::scope(|s| -> Result<()> {
        let (work, groups) = (&work, &mut groups);
        let (inflated, merged, beside) = (&mut inflated, &mut merged, &mut beside);
        s.spawn(move |_| {
            let t = std::time::Instant::now();
            if !work.is_empty() {
                *inflated = resolve::inflate(work, arena);
                merge::fill_inflated(groups, inflated);
            }
            *merged = std::mem::take(groups)
                .into_iter()
                .map(merge::merge_group)
                .collect();
            *beside = t.elapsed();
        });
        ctx.finish_resolve(&mut timer)?;
        ctx.gc(&mut timer)?;
        ctx.scan(&mut timer)
    })?;
    timer.detail(format!(
        "merged unallocated sections beside resolution, gc and scan in {:.2} ms",
        beside.as_secs_f64() * 1e3
    ));
    ctx.set_inflated(inflated)?;
    ctx.merge(&mut timer, merged);
    let mut layout = ctx.layout(&mut timer)?;
    ctx.write(&mut layout, &mut timer)?;
    if let Some(map) = &ctx.cfg.map {
        ctx.write_map(&layout, map)?;
        timer.phase("map file");
    }
    if let Some(dep) = &ctx.cfg.dependency_file {
        write_dependency_file(dep, &ctx.cfg.output, &ctx.paths)?;
    }
    timer.report();
    if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
        // Leaked on purpose: freeing millions of small allocations costs more than the exit.
        std::mem::forget(layout);
        std::mem::forget(ctx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128() {
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        for (b, v) in [
            (&[0x00][..], 0u64),
            (&[0x7f], 127),
            (&[0x80, 0x01], 128),
            (&[0xac, 0x02], 300),
            (&max, u64::MAX),
        ] {
            let mut p = 0;
            assert_eq!(read_uleb(b, &mut p), Some(v));
            assert_eq!(p, b.len());
        }
        let mut p = 0;
        assert_eq!(read_uleb(&[0x80], &mut p), None);
    }

    #[test]
    fn alignment() {
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(8, 4), 8);
        assert_eq!(align_up(5, 0), 5);
        assert_eq!(align_up(5, 1), 5);
    }
}
