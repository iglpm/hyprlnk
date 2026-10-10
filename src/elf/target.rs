//! What differs between machines: the ELF class and byte order, relocations, PLT code, TLS.
//! Each machine's module implements [`Target`]; the linker is monomorphized per machine.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::ScanState;
use super::write::RelocCtx;
use crate::diag::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    X86_64,
    I386,
    AArch64,
    Arm,
    RiscV64,
    RiscV32,
    Ppc64le,
    Ppc64,
    S390x,
    LoongArch64,
}

impl Machine {
    pub fn name(self) -> &'static str {
        match self {
            Machine::X86_64 => "x86-64",
            Machine::I386 => "i386",
            Machine::AArch64 => "AArch64",
            Machine::Arm => "ARM",
            Machine::RiscV64 => "RISC-V (64-bit)",
            Machine::RiscV32 => "RISC-V (32-bit)",
            Machine::Ppc64le => "POWER (ppc64le)",
            Machine::Ppc64 => "POWER (ppc64, big-endian)",
            Machine::S390x => "s390x",
            Machine::LoongArch64 => "LoongArch (64-bit)",
        }
    }

    /// From an ELF header's `e_machine`, class and byte order.
    pub fn from_header(e_machine: u16, class: u8, data: u8) -> Option<Machine> {
        use super::*;
        let is64 = class == ELFCLASS64;
        let le = data == ELFDATA2LSB;
        Some(match (e_machine, is64, le) {
            (EM_X86_64, true, true) => Machine::X86_64,
            (EM_386, false, true) => Machine::I386,
            (EM_AARCH64, true, true) => Machine::AArch64,
            (EM_ARM, false, true) => Machine::Arm,
            (EM_RISCV, true, true) => Machine::RiscV64,
            (EM_RISCV, false, true) => Machine::RiscV32,
            (EM_PPC64, true, true) => Machine::Ppc64le,
            (EM_PPC64, true, false) => Machine::Ppc64,
            (EM_S390, true, false) => Machine::S390x,
            (EM_LOONGARCH, true, true) => Machine::LoongArch64,
            _ => return None,
        })
    }

    /// From `-m <emulation>`.
    pub fn from_emulation(m: &str) -> Option<Machine> {
        Some(match m {
            "elf_x86_64" | "elf_x86_64_fbsd" | "elf_amd64" => Machine::X86_64,
            "elf_i386" | "elf_i386_fbsd" => Machine::I386,
            "aarch64linux" | "aarch64elf" | "aarch64linuxb" | "aarch64_elf64_le_vec" => {
                Machine::AArch64
            }
            "armelf_linux_eabi" | "armelf" | "armelf_linux" | "armelfb_linux_eabi" => Machine::Arm,
            "elf64lriscv" | "elf64lriscv_lp64" | "elf64lriscv_lp64f" => Machine::RiscV64,
            "elf32lriscv" | "elf32lriscv_ilp32" | "elf32lriscv_ilp32f" => Machine::RiscV32,
            "elf64lppc" | "elf64lppc_fbsd" => Machine::Ppc64le,
            "elf64ppc" | "elf64ppc_fbsd" => Machine::Ppc64,
            "elf64_s390" => Machine::S390x,
            "elf64loongarch" => Machine::LoongArch64,
            _ => return None,
        })
    }

    /// From a target triple's first component, for [`crate::supports_target`].
    pub fn from_triple_arch(arch: &str) -> Option<Machine> {
        Some(match arch {
            "x86_64" => Machine::X86_64,
            "i386" | "i486" | "i586" | "i686" => Machine::I386,
            "aarch64" => Machine::AArch64,
            a if a.starts_with("armv") || a == "arm" || a.starts_with("thumbv") => Machine::Arm,
            "riscv64gc" | "riscv64" | "riscv64a23" => Machine::RiscV64,
            a if a.starts_with("riscv32") => Machine::RiscV32,
            "powerpc64le" => Machine::Ppc64le,
            "powerpc64" => Machine::Ppc64,
            "s390x" => Machine::S390x,
            "loongarch64" => Machine::LoongArch64,
            _ => return None,
        })
    }
}

/// A relocation decoded from REL or RELA. For REL inputs `addend` is filled in from the
/// section contents by the machine.
#[derive(Debug, Clone, Copy)]
pub struct Rel {
    pub offset: u64,
    pub ty: u32,
    pub sym: u32,
    pub addend: i64,
}

/// The machine-specific half of the linker.
pub trait Target: Sized + Send + Sync + 'static {
    const M: Machine;
    const E_MACHINE: u16;
    const IS64: bool;
    const BE: bool;
    /// Dynamic relocations are RELA (else REL, with addends written in place).
    const RELA_DYN: bool = true;
    const MAX_PAGE: u64;
    const PLT0_SIZE: u64;
    const PLT_SIZE: u64;
    /// `.got.plt` slots before the first PLT entry's.
    const GOTPLT_RESERVED: u64 = 3;
    /// Aligns `.plt` and PLT entries.
    const PLT_ALIGN: u64 = 16;
    const R_ABS: u32;
    const R_RELATIVE: u32;
    const R_GLOB_DAT: u32;
    const R_JUMP_SLOT: u32;
    const R_COPY: u32;
    const R_IRELATIVE: u32;
    const R_DTPMOD: u32;
    const R_DTPOFF: u32;
    const R_TPOFF: u32;
    const R_TLSDESC: u32 = 0;
    /// The thread pointer is at the end of the TLS block (x86, s390x) instead of before it.
    const TLS_VARIANT2: bool = false;
    /// Variant 1: bytes between the thread pointer and the TLS block (the TCB).
    const TLS_TCB: u64 = 0;
    /// Added to TP-relative offsets (ppc64's TP is 0x7000 past the block start).
    const TP_BIAS: i64 = 0;
    /// Subtracted from DTP-relative offsets (ppc64 0x8000, RISC-V 0x800).
    const DTP_BIAS: i64 = 0;
    /// Relaxing TLS GD/LD/TLSDESC to IE/LE is possible.
    const RELAX_TLS: bool = true;
    /// `.got[0]` holds `_DYNAMIC` (x86-64, AArch64… as lld does).
    const GOT0_DYNAMIC: bool = false;

    /// The relocations of an input section.
    fn decode_rel(data: &[u8], i: usize, rela: bool) -> Rel {
        if Self::IS64 {
            let sz = if rela { 24 } else { 16 };
            let b = &data[i * sz..];
            let info = rd64::<Self>(b, 8);
            Rel {
                offset: rd64::<Self>(b, 0),
                // ppc64/s390x/... all use the standard r_info split on ELF64.
                ty: (info & 0xffff_ffff) as u32,
                sym: (info >> 32) as u32,
                addend: if rela { rd64::<Self>(b, 16) as i64 } else { 0 },
            }
        } else {
            let sz = if rela { 12 } else { 8 };
            let b = &data[i * sz..];
            let info = rd32::<Self>(b, 4);
            Rel {
                offset: rd32::<Self>(b, 0) as u64,
                ty: info & 0xff,
                sym: info >> 8,
                addend: if rela {
                    rd32::<Self>(b, 8) as i32 as i64
                } else {
                    0
                },
            }
        }
    }

    /// For REL inputs: the addend stored at the relocated location.
    fn implicit_addend(_ty: u32, _loc: &[u8]) -> i64 {
        0
    }

    /// Classify every relocation of live allocated section `si`: GOT, PLT, dynamic relocations.
    fn scan(ctx: &Ctx<'_, Self>, obj: &Object<'_>, si: u32, st: &mut ScanState);

    /// Apply the relocations of an allocated section copied to `out` (at `addr`).
    fn apply_alloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()>;

    /// Apply the relocations of a non-allocated (debug) section.
    fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()>;

    /// The PLT header, at `plt` with `.got.plt` at `gotplt`.
    fn write_plt0(ctx: &Ctx<'_, Self>, buf: &mut [u8], plt: u64, gotplt: u64);

    /// A PLT entry at `ent` jumping through `slot`; `idx` is its index, `plt` the PLT start.
    fn write_plt(ctx: &Ctx<'_, Self>, buf: &mut [u8], ent: u64, slot: u64, idx: u64, plt: u64);

    /// The initial `.got.plt` contents for a lazily bound entry.
    fn gotplt_initial(_plt: u64, ent: u64) -> u64 {
        ent
    }

    /// The output's `e_flags`, from the inputs'.
    fn e_flags(ctx: &Ctx<'_, Self>) -> u32 {
        let _ = ctx;
        0
    }

    /// Code of a thunk of `kind` to `target` placed at `at` (see `thunks.rs`).
    /// `toc` is the TOC base (POWER) or 0.
    fn write_thunk(_buf: &mut [u8], _at: u64, _target: u64, _kind: u8, _toc: u64) {}
    const THUNK_SIZE: u64 = 0;
}

#[inline]
pub fn rd16<T: Target>(d: &[u8], o: usize) -> u16 {
    let b = [d[o], d[o + 1]];
    if T::BE {
        u16::from_be_bytes(b)
    } else {
        u16::from_le_bytes(b)
    }
}

#[inline]
pub fn rd32<T: Target>(d: &[u8], o: usize) -> u32 {
    let b: [u8; 4] = d[o..o + 4].try_into().unwrap();
    if T::BE {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    }
}

#[inline]
pub fn rd64<T: Target>(d: &[u8], o: usize) -> u64 {
    let b: [u8; 8] = d[o..o + 8].try_into().unwrap();
    if T::BE {
        u64::from_be_bytes(b)
    } else {
        u64::from_le_bytes(b)
    }
}

/// An address-sized field.
#[inline]
pub fn rdw<T: Target>(d: &[u8], o: usize) -> u64 {
    if T::IS64 {
        rd64::<T>(d, o)
    } else {
        rd32::<T>(d, o) as u64
    }
}

#[inline]
pub fn wr16<T: Target>(d: &mut [u8], o: usize, v: u16) {
    let b = if T::BE {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    };
    d[o..o + 2].copy_from_slice(&b);
}

#[inline]
pub fn wr32<T: Target>(d: &mut [u8], o: usize, v: u32) {
    let b = if T::BE {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    };
    d[o..o + 4].copy_from_slice(&b);
}

#[inline]
pub fn wr64<T: Target>(d: &mut [u8], o: usize, v: u64) {
    let b = if T::BE {
        v.to_be_bytes()
    } else {
        v.to_le_bytes()
    };
    d[o..o + 8].copy_from_slice(&b);
}

#[inline]
pub fn wrw<T: Target>(d: &mut [u8], o: usize, v: u64) {
    if T::IS64 {
        wr64::<T>(d, o, v)
    } else {
        wr32::<T>(d, o, v as u32)
    }
}

pub fn word<T: Target>() -> u64 {
    if T::IS64 { 8 } else { 4 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn machines_from_headers_and_names() {
        use crate::elf::*;
        assert_eq!(
            Machine::from_header(EM_X86_64, ELFCLASS64, ELFDATA2LSB),
            Some(Machine::X86_64)
        );
        assert_eq!(
            Machine::from_header(EM_S390, ELFCLASS64, ELFDATA2MSB),
            Some(Machine::S390x)
        );
        assert_eq!(
            Machine::from_header(EM_RISCV, ELFCLASS32, ELFDATA2LSB),
            Some(Machine::RiscV32)
        );
        assert_eq!(
            Machine::from_header(EM_X86_64, ELFCLASS32, ELFDATA2LSB),
            None
        );
        assert_eq!(
            Machine::from_emulation("aarch64linux"),
            Some(Machine::AArch64)
        );
        assert_eq!(Machine::from_triple_arch("armv7"), Some(Machine::Arm));
        assert_eq!(Machine::from_triple_arch("thumbv7neon"), Some(Machine::Arm));
        assert_eq!(Machine::from_triple_arch("mips"), None);
    }
}
