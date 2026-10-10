//! RISC-V (RV64 and RV32): relocations — including the HI20/LO12 pairs where the low part
//! names its high part's instruction — and the PLT. Linker relaxation is not performed:
//! `R_RISCV_RELAX` and `R_RISCV_ALIGN` leave the code as the assembler wrote it, which is
//! correct, only not the shortest.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSDESC, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd16, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct RiscV64;
pub struct RiscV32;

const R_NONE: u32 = 0;
const R_32: u32 = 1;
const R_64: u32 = 2;
const R_BRANCH: u32 = 16;
const R_JAL: u32 = 17;
const R_CALL: u32 = 18;
const R_CALL_PLT: u32 = 19;
const R_GOT_HI20: u32 = 20;
const R_TLS_GOT_HI20: u32 = 21;
const R_TLS_GD_HI20: u32 = 22;
const R_PCREL_HI20: u32 = 23;
const R_PCREL_LO12_I: u32 = 24;
const R_PCREL_LO12_S: u32 = 25;
const R_HI20: u32 = 26;
const R_LO12_I: u32 = 27;
const R_LO12_S: u32 = 28;
const R_TPREL_HI20: u32 = 29;
const R_TPREL_LO12_I: u32 = 30;
const R_TPREL_LO12_S: u32 = 31;
const R_TPREL_ADD: u32 = 32;
const R_ADD8: u32 = 33;
const R_ADD16: u32 = 34;
const R_ADD32: u32 = 35;
const R_ADD64: u32 = 36;
const R_SUB8: u32 = 37;
const R_SUB16: u32 = 38;
const R_SUB32: u32 = 39;
const R_SUB64: u32 = 40;
const R_GOT32_PCREL: u32 = 41;
const R_ALIGN: u32 = 43;
const R_RVC_BRANCH: u32 = 44;
const R_RVC_JUMP: u32 = 45;
const R_RELAX: u32 = 51;
const R_SUB6: u32 = 52;
const R_SET6: u32 = 53;
const R_SET8: u32 = 54;
const R_SET16: u32 = 55;
const R_SET32: u32 = 56;
const R_32_PCREL: u32 = 57;
const R_PLT32: u32 = 59;
const R_SET_ULEB128: u32 = 60;
const R_SUB_ULEB128: u32 = 61;
const R_TLSDESC_HI20: u32 = 62;
const R_TLSDESC_LOAD_LO12: u32 = 63;
const R_TLSDESC_ADD_LO12: u32 = 64;
const R_TLSDESC_CALL: u32 = 65;
const R_DTPREL32: u32 = 8;
const R_DTPREL64: u32 = 9;

const EF_RISCV_RVC: u32 = 1;

#[inline]
fn hi20(v: u64) -> u32 {
    (((v as i64 + 0x800) >> 12) as u32) & 0xfffff
}

#[inline]
fn lo12(v: u64) -> u32 {
    (v & 0xfff) as u32
}

#[inline]
fn rd(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

#[inline]
fn wr(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn set_u(d: &mut [u8], o: usize, v: u64) {
    wr(d, o, (rd(d, o) & 0xfff) | (hi20(v) << 12));
}

fn set_i(d: &mut [u8], o: usize, v: u64) {
    wr(d, o, (rd(d, o) & 0x000f_ffff) | (lo12(v) << 20));
}

fn set_s(d: &mut [u8], o: usize, v: u64) {
    let imm = lo12(v);
    let insn = rd(d, o) & 0x01ff_f07f;
    wr(d, o, insn | ((imm >> 5) << 25) | ((imm & 0x1f) << 7));
}

fn set_b(d: &mut [u8], o: usize, v: u64) {
    let v = v as u32;
    let insn = rd(d, o) & 0x01ff_f07f;
    let imm = ((v >> 12) & 1) << 31
        | ((v >> 5) & 0x3f) << 25
        | ((v >> 1) & 0xf) << 8
        | ((v >> 11) & 1) << 7;
    wr(d, o, insn | imm);
}

fn set_j(d: &mut [u8], o: usize, v: u64) {
    let v = v as u32;
    let insn = rd(d, o) & 0xfff;
    let imm = ((v >> 20) & 1) << 31
        | ((v >> 1) & 0x3ff) << 21
        | ((v >> 11) & 1) << 20
        | ((v >> 12) & 0xff) << 12;
    wr(d, o, insn | imm);
}

fn set_cb(d: &mut [u8], o: usize, v: u64) {
    let v = v as u16;
    let insn = u16::from_le_bytes([d[o], d[o + 1]]) & 0xe383;
    let imm = ((v >> 8) & 1) << 12
        | ((v >> 3) & 3) << 10
        | ((v >> 6) & 3) << 5
        | ((v >> 1) & 3) << 3
        | ((v >> 5) & 1) << 2;
    d[o..o + 2].copy_from_slice(&(insn | imm).to_le_bytes());
}

fn set_cj(d: &mut [u8], o: usize, v: u64) {
    let v = v as u16;
    let insn = u16::from_le_bytes([d[o], d[o + 1]]) & 0xe003;
    let imm = ((v >> 11) & 1) << 12
        | ((v >> 4) & 1) << 11
        | ((v >> 8) & 3) << 9
        | ((v >> 10) & 1) << 8
        | ((v >> 6) & 1) << 7
        | ((v >> 7) & 1) << 6
        | ((v >> 1) & 7) << 3
        | ((v >> 5) & 1) << 2;
    d[o..o + 2].copy_from_slice(&(insn | imm).to_le_bytes());
}

/// Overwrite the ULEB128 at `o` with `v`, keeping its length.
fn set_uleb(d: &mut [u8], o: usize, mut v: u64) {
    let mut i = o;
    loop {
        let more = d.get(i).is_some_and(|b| b & 0x80 != 0);
        if more {
            d[i] = 0x80 | (v & 0x7f) as u8;
            v >>= 7;
            i += 1;
        } else {
            if let Some(b) = d.get_mut(i) {
                *b = (v & 0x7f) as u8;
            }
            return;
        }
    }
}

fn read_uleb(d: &[u8], o: usize) -> u64 {
    let mut p = o;
    super::read_uleb(d, &mut p).unwrap_or(0)
}

fn scan<T: Target>(ctx: &Ctx<'_, T>, o: &Object<'_>, si: u32, st: &mut ScanState) {
    let (raw, rela) = o.rel_data::<T>(si);
    let n = o.rel_count::<T>(si);
    for k in 0..n {
        let r = o.rel::<T>(raw, rela, k, si);
        if r.sym >= o.nsyms {
            ctx.error(format!(
                "{}: relocation against an invalid symbol index {}",
                o.name, r.sym
            ));
            continue;
        }
        ctx.note_use(o, r.sym);
        let word = if T::IS64 { R_64 } else { R_32 };
        match r.ty {
            t if t == word => ctx.scan_abs_word(o, si, &r, st),
            R_32 | R_64 => ctx.scan_abs_narrow(o, si, &r),
            R_HI20 | R_LO12_I | R_LO12_S => ctx.scan_abs_narrow(o, si, &r),
            R_PCREL_HI20 | R_32_PCREL => ctx.scan_pcrel(o, si, &r),
            R_BRANCH | R_JAL | R_CALL | R_CALL_PLT | R_RVC_BRANCH | R_RVC_JUMP | R_PLT32 => {
                ctx.scan_call(o, &r)
            }
            R_GOT_HI20 | R_GOT32_PCREL => ctx.scan_got(o, &r),
            R_TLS_GOT_HI20 => ctx.scan_gottp(o, &r),
            R_TLS_GD_HI20 => {
                let (sr, kind) = ctx.sym_kind(o, r.sym);
                let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
            }
            R_TLSDESC_HI20 => {
                let (sr, kind) = ctx.sym_kind(o, r.sym);
                let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                ctx.need(
                    o,
                    sr,
                    NEEDS_TLSDESC | if imported { NEEDS_DYNSYM } else { 0 },
                );
            }
            R_TPREL_HI20 | R_TPREL_LO12_I | R_TPREL_LO12_S => ctx.scan_tpoff(o, si, &r),
            R_NONE
            | R_PCREL_LO12_I
            | R_PCREL_LO12_S
            | R_TPREL_ADD
            | R_ADD8..=R_SUB64
            | R_ALIGN
            | R_RELAX
            | R_SUB6..=R_SET32
            | R_SET_ULEB128
            | R_SUB_ULEB128
            | R_TLSDESC_LOAD_LO12
            | R_TLSDESC_ADD_LO12
            | R_TLSDESC_CALL => {}
            _ => ctx.error(format!(
                "{}: unsupported relocation type {} in section {}",
                o.name,
                r.ty,
                String::from_utf8_lossy(o.sec_name::<T>(si))
            )),
        }
    }
}

/// The value a HI20-type relocation computed, for the LO12 that refers to its instruction.
fn hi_value<T: Target>(rc: &RelocCtx<'_, '_, T>, r: &Rel) -> Option<u64> {
    let p = rc.p(r);
    let a = r.addend as u64;
    Some(match r.ty {
        R_PCREL_HI20 => rc.sa(r).wrapping_sub(p),
        R_GOT_HI20 => rc.got(r.sym).wrapping_add(a).wrapping_sub(p),
        R_TLS_GOT_HI20 => rc.gottp(r.sym).wrapping_add(a).wrapping_sub(p),
        R_TLS_GD_HI20 => rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(p),
        R_TLSDESC_HI20 => rc.tlsdesc(r.sym).wrapping_add(a).wrapping_sub(p),
        _ => return None,
    })
}

fn apply_alloc<T: Target>(rc: &mut RelocCtx<'_, '_, T>, out: &mut [u8]) -> Result<()> {
    let n = rc.len();
    // HI20 relocations by offset, for the PCREL_LO12s pointing at them.
    let mut his: Vec<(u64, u64)> = Vec::new();
    for k in 0..n {
        let r = rc.rel(k);
        if let Some(v) = hi_value(rc, &r) {
            his.push((r.offset, v));
        }
    }
    if !his.is_sorted_by_key(|h| h.0) {
        his.sort_by_key(|h| h.0);
    }
    let word = if T::IS64 { R_64 } else { R_32 };
    let mut k = 0;
    while k < n {
        let r = rc.rel(k);
        k += 1;
        let off = r.offset as usize;
        let p = rc.p(&r);
        match r.ty {
            R_NONE | R_ALIGN | R_RELAX | R_TPREL_ADD | R_TLSDESC_CALL => {}
            t if t == word => {
                let v = rc.abs_word(&r);
                if T::IS64 {
                    wr64::<T>(out, off, v)
                } else {
                    wr32::<T>(out, off, v as u32)
                }
            }
            R_32 => {
                let v = rc.sa(&r);
                rc.check_any(&r, v, 32);
                wr32::<T>(out, off, v as u32);
            }
            R_64 => wr64::<T>(out, off, rc.sa(&r)),
            R_32_PCREL | R_PLT32 => {
                let t = if r.ty == R_PLT32 {
                    rc.call_target(&r)
                } else {
                    rc.sa(&r)
                };
                let v = t.wrapping_sub(p);
                rc.check_signed(&r, v as i64, 32);
                wr32::<T>(out, off, v as u32);
            }
            R_GOT32_PCREL => {
                let v = rc.got(r.sym).wrapping_add(r.addend as u64).wrapping_sub(p);
                wr32::<T>(out, off, v as u32);
            }
            R_BRANCH => {
                let v = rc.call_target(&r).wrapping_sub(p);
                rc.check_signed(&r, v as i64, 13);
                set_b(out, off, v);
            }
            R_JAL => {
                let v = rc.call_target(&r).wrapping_sub(p);
                rc.check_signed(&r, v as i64, 21);
                set_j(out, off, v);
            }
            R_RVC_BRANCH => {
                let v = rc.call_target(&r).wrapping_sub(p);
                rc.check_signed(&r, v as i64, 9);
                set_cb(out, off, v);
            }
            R_RVC_JUMP => {
                let v = rc.call_target(&r).wrapping_sub(p);
                rc.check_signed(&r, v as i64, 12);
                set_cj(out, off, v);
            }
            R_CALL | R_CALL_PLT => {
                let v = rc.call_target(&r).wrapping_sub(p);
                rc.check_signed(&r, v as i64, 32);
                set_u(out, off, v);
                set_i(out, off + 4, v);
            }
            R_PCREL_HI20 | R_GOT_HI20 | R_TLS_GOT_HI20 | R_TLS_GD_HI20 | R_TLSDESC_HI20 => {
                let v = hi_value(rc, &r).unwrap_or(0);
                rc.check_signed(&r, v as i64, 32);
                set_u(out, off, v);
            }
            R_PCREL_LO12_I | R_PCREL_LO12_S | R_TLSDESC_LOAD_LO12 | R_TLSDESC_ADD_LO12 => {
                // The symbol is the label of the AUIPC whose relocation gives the value.
                let label = rc.label_offset(r.sym);
                let v = match his.binary_search_by_key(&label, |h| h.0) {
                    Ok(i) => his[i].1,
                    Err(_) => {
                        rc.error(&r, "no HI20 relocation found for this LO12 relocation");
                        continue;
                    }
                };
                if r.ty == R_PCREL_LO12_S {
                    set_s(out, off, v);
                } else {
                    set_i(out, off, v);
                }
            }
            R_HI20 => set_u(out, off, rc.sa(&r)),
            R_LO12_I => set_i(out, off, rc.sa(&r)),
            R_LO12_S => set_s(out, off, rc.sa(&r)),
            R_TPREL_HI20 => set_u(out, off, rc.tp(rc.sa(&r))),
            R_TPREL_LO12_I => set_i(out, off, rc.tp(rc.sa(&r))),
            R_TPREL_LO12_S => set_s(out, off, rc.tp(rc.sa(&r))),
            _ => apply_data(rc, &r, out),
        }
    }
    Ok(())
}

/// ADD/SUB/SET arithmetic (label differences in `.eh_frame`, `.gcc_except_table`, debug info).
fn apply_data<T: Target>(rc: &mut RelocCtx<'_, '_, T>, r: &Rel, out: &mut [u8]) {
    let off = r.offset as usize;
    let v = rc.sa(r);
    match r.ty {
        R_ADD8 => out[off] = out[off].wrapping_add(v as u8),
        R_ADD16 => wr16::<T>(out, off, rd16::<T>(out, off).wrapping_add(v as u16)),
        R_ADD32 => wr32::<T>(out, off, rd32::<T>(out, off).wrapping_add(v as u32)),
        R_ADD64 => wr64::<T>(
            out,
            off,
            u64::from_le_bytes(out[off..off + 8].try_into().unwrap()).wrapping_add(v),
        ),
        R_SUB8 => out[off] = out[off].wrapping_sub(v as u8),
        R_SUB16 => wr16::<T>(out, off, rd16::<T>(out, off).wrapping_sub(v as u16)),
        R_SUB32 => wr32::<T>(out, off, rd32::<T>(out, off).wrapping_sub(v as u32)),
        R_SUB64 => wr64::<T>(
            out,
            off,
            u64::from_le_bytes(out[off..off + 8].try_into().unwrap()).wrapping_sub(v),
        ),
        R_SUB6 => out[off] = (out[off] & 0xc0) | (out[off].wrapping_sub(v as u8) & 0x3f),
        R_SET6 => out[off] = (out[off] & 0xc0) | (v as u8 & 0x3f),
        R_SET8 => out[off] = v as u8,
        R_SET16 => wr16::<T>(out, off, v as u16),
        R_SET32 => wr32::<T>(out, off, v as u32),
        R_SET_ULEB128 => set_uleb(out, off, v),
        R_SUB_ULEB128 => {
            let cur = read_uleb(out, off);
            set_uleb(out, off, cur.wrapping_sub(v));
        }
        R_32_PCREL => wr32::<T>(out, off, v.wrapping_sub(rc.p(r)) as u32),
        R_DTPREL32 => wr32::<T>(out, off, rc.dtp(v) as u32),
        R_DTPREL64 => wr64::<T>(out, off, rc.dtp(v)),
        _ => rc.error(r, "unsupported relocation"),
    }
}

fn apply_nonalloc<T: Target>(rc: &mut RelocCtx<'_, '_, T>, out: &mut [u8]) -> Result<()> {
    let tomb = rc.tombstone();
    let word = if T::IS64 { R_64 } else { R_32 };
    rc.apply_debug(
        out,
        if T::IS64 { R_64 } else { u32::MAX },
        [R_32, R_32],
        |rc, r, out| {
            let off = r.offset as usize;
            match r.ty {
                R_NONE | R_RELAX | R_ALIGN => {}
                t if t == word && T::IS64 => wr64::<T>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_32 => wr32::<T>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
                R_64 => wr64::<T>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_DTPREL32 => wr32::<T>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v)) as u32),
                R_DTPREL64 => wr64::<T>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v))),
                _ => apply_data(rc, r, out),
            }
        },
    );
    Ok(())
}

const X_T0: u32 = 5;
const X_T1: u32 = 6;
const X_T2: u32 = 7;
const X_T3: u32 = 28;
const AUIPC: u32 = 0x17;
const ADDI: u32 = 0x13;
const JALR: u32 = 0x67;
const LD: u32 = 0x3003;
const LW: u32 = 0x2003;
const SRLI: u32 = 0x5013;
const SUB: u32 = 0x4000_0033;

fn utype(op: u32, rd: u32, imm: u32) -> u32 {
    op | (rd << 7) | (imm << 12)
}
fn itype(op: u32, rd: u32, rs1: u32, imm: u32) -> u32 {
    op | (rd << 7) | (rs1 << 15) | (imm << 20)
}
fn rtype(op: u32, rd: u32, rs1: u32, rs2: u32) -> u32 {
    op | (rd << 7) | (rs1 << 15) | (rs2 << 20)
}

fn write_plt0<T: Target>(b: &mut [u8], plt: u64, gotplt: u64) {
    let off = gotplt.wrapping_sub(plt);
    let load = if T::IS64 { LD } else { LW };
    wr(b, 0, utype(AUIPC, X_T2, hi20(off)));
    wr(b, 4, rtype(SUB, X_T1, X_T1, X_T3));
    wr(b, 8, itype(load, X_T3, X_T2, lo12(off)));
    wr(
        b,
        12,
        itype(
            ADDI,
            X_T1,
            X_T1,
            (-(T::PLT0_SIZE as i32) - 12) as u32 & 0xfff,
        ),
    );
    wr(b, 16, itype(ADDI, X_T0, X_T2, lo12(off)));
    wr(b, 20, itype(SRLI, X_T1, X_T1, if T::IS64 { 1 } else { 2 }));
    wr(b, 24, itype(load, X_T0, X_T0, word::<T>() as u32));
    wr(b, 28, itype(JALR, 0, X_T3, 0));
}

fn write_plt<T: Target>(b: &mut [u8], ent: u64, slot: u64) {
    let off = slot.wrapping_sub(ent);
    wr(b, 0, utype(AUIPC, X_T3, hi20(off)));
    wr(
        b,
        4,
        itype(if T::IS64 { LD } else { LW }, X_T3, X_T3, lo12(off)),
    );
    wr(b, 8, itype(JALR, X_T1, X_T3, 0));
    wr(b, 12, itype(ADDI, 0, 0, 0));
}

fn e_flags<T: Target>(ctx: &Ctx<'_, T>) -> u32 {
    let mut flags = None;
    let mut rvc = false;
    for o in &ctx.objs {
        if o.alive.load(std::sync::atomic::Ordering::Relaxed) {
            flags.get_or_insert(o.e_flags);
            rvc |= o.e_flags & EF_RISCV_RVC != 0;
        }
    }
    flags.unwrap_or(0) | if rvc { EF_RISCV_RVC } else { 0 }
}

use super::target::word;

macro_rules! riscv_target {
    ($ty:ident, $m:expr, $is64:expr) => {
        impl Target for $ty {
            const M: Machine = $m;
            const E_MACHINE: u16 = EM_RISCV;
            const IS64: bool = $is64;
            const BE: bool = false;
            const MAX_PAGE: u64 = 0x1000;
            const PLT0_SIZE: u64 = 32;
            const PLT_SIZE: u64 = 16;
            const R_ABS: u32 = if $is64 { R_64 } else { R_32 };
            const R_RELATIVE: u32 = 3;
            const R_GLOB_DAT: u32 = if $is64 { R_64 } else { R_32 };
            const R_JUMP_SLOT: u32 = 5;
            const R_COPY: u32 = 4;
            const R_IRELATIVE: u32 = 58;
            const R_DTPMOD: u32 = if $is64 { 7 } else { 6 };
            const R_DTPOFF: u32 = if $is64 { 9 } else { 8 };
            const R_TPOFF: u32 = if $is64 { 11 } else { 10 };
            const R_TLSDESC: u32 = 12;
            const DTP_BIAS: i64 = 0x800;
            const RELAX_TLS: bool = false;

            fn scan(ctx: &Ctx<'_, Self>, o: &Object<'_>, si: u32, st: &mut ScanState) {
                scan(ctx, o, si, st)
            }
            fn apply_alloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
                apply_alloc(rc, out)
            }
            fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
                apply_nonalloc(rc, out)
            }
            fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
                write_plt0::<Self>(b, plt, gotplt)
            }
            fn write_plt(
                _ctx: &Ctx<'_, Self>,
                b: &mut [u8],
                ent: u64,
                slot: u64,
                _idx: u64,
                _plt: u64,
            ) {
                write_plt::<Self>(b, ent, slot)
            }
            fn gotplt_initial(plt: u64, _ent: u64) -> u64 {
                plt
            }
            fn e_flags(ctx: &Ctx<'_, Self>) -> u32 {
                e_flags(ctx)
            }
        }
    };
}

riscv_target!(RiscV64, Machine::RiscV64, true);
riscv_target!(RiscV32, Machine::RiscV32, false);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediates() {
        // auipc + addi of 0x12345678: hi20 rounds up for a negative low part.
        assert_eq!(hi20(0x12345678), 0x12345);
        assert_eq!(hi20(0x12345878), 0x12346);
        assert_eq!(lo12(0x12345878) as i32 - 0x1000, -0x788);
        let mut b = 0x0000_0063u32.to_le_bytes().to_vec(); // beq
        set_b(&mut b, 0, (-8i64) as u64);
        let w = rd(&b, 0);
        assert_eq!(w >> 31, 1, "sign bit");
        let mut u = vec![0x80, 0x80, 0x00];
        set_uleb(&mut u, 0, 300);
        assert_eq!(read_uleb(&u, 0), 300);
        assert_eq!(u.len(), 3);
    }
}
