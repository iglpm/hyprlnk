//! LoongArch64: page-relative address sequences (`pcalau12i` + `addi.d`/`ld.d`, optionally
//! `lu32i.d` + `lu52i.d`), branches, TLS, the PLT. Linker relaxation is not performed; the
//! code stays as the assembler wrote it.

use std::cell::Cell;

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{IS_TLS, NEEDS_DYNSYM, NEEDS_TLSDESC, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd16, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct LoongArch64;

const R_NONE: u32 = 0;
const R_32: u32 = 1;
const R_64: u32 = 2;
const R_TLS_DTPREL32: u32 = 8;
const R_TLS_DTPREL64: u32 = 9;
const R_MARK_LA: u32 = 20;
const R_MARK_PCREL: u32 = 21;
const R_ADD8: u32 = 47;
const R_ADD16: u32 = 48;
const R_ADD24: u32 = 49;
const R_ADD32: u32 = 50;
const R_ADD64: u32 = 51;
const R_SUB8: u32 = 52;
const R_SUB16: u32 = 53;
const R_SUB24: u32 = 54;
const R_SUB32: u32 = 55;
const R_SUB64: u32 = 56;
const R_B16: u32 = 64;
const R_B21: u32 = 65;
const R_B26: u32 = 66;
const R_ABS_HI20: u32 = 67;
const R_ABS_LO12: u32 = 68;
const R_ABS64_LO20: u32 = 69;
const R_ABS64_HI12: u32 = 70;
const R_PCALA_HI20: u32 = 71;
const R_PCALA_LO12: u32 = 72;
const R_PCALA64_LO20: u32 = 73;
const R_PCALA64_HI12: u32 = 74;
const R_GOT_PC_HI20: u32 = 75;
const R_GOT_PC_LO12: u32 = 76;
const R_GOT64_PC_LO20: u32 = 77;
const R_GOT64_PC_HI12: u32 = 78;
const R_GOT_HI20: u32 = 79;
const R_GOT_LO12: u32 = 80;
const R_GOT64_LO20: u32 = 81;
const R_GOT64_HI12: u32 = 82;
const R_TLS_LE_HI20: u32 = 83;
const R_TLS_LE_LO12: u32 = 84;
const R_TLS_LE64_LO20: u32 = 85;
const R_TLS_LE64_HI12: u32 = 86;
const R_TLS_IE_PC_HI20: u32 = 87;
const R_TLS_IE_PC_LO12: u32 = 88;
const R_TLS_IE64_PC_LO20: u32 = 89;
const R_TLS_IE64_PC_HI12: u32 = 90;
const R_TLS_IE_HI20: u32 = 91;
const R_TLS_IE_LO12: u32 = 92;
const R_TLS_IE64_LO20: u32 = 93;
const R_TLS_IE64_HI12: u32 = 94;
const R_TLS_LD_PC_HI20: u32 = 95;
const R_TLS_LD_HI20: u32 = 96;
const R_TLS_GD_PC_HI20: u32 = 97;
const R_TLS_GD_HI20: u32 = 98;
const R_32_PCREL: u32 = 99;
const R_RELAX: u32 = 100;
const R_ALIGN: u32 = 102;
const R_PCREL20_S2: u32 = 103;
const R_ADD6: u32 = 105;
const R_SUB6: u32 = 106;
const R_ADD_ULEB128: u32 = 107;
const R_SUB_ULEB128: u32 = 108;
const R_64_PCREL: u32 = 109;
const R_CALL36: u32 = 110;
const R_TLS_DESC_PC_HI20: u32 = 111;
const R_TLS_DESC_PC_LO12: u32 = 112;
const R_TLS_DESC64_PC_LO20: u32 = 113;
const R_TLS_DESC64_PC_HI12: u32 = 114;
const R_TLS_DESC_LD: u32 = 119;
const R_TLS_DESC_CALL: u32 = 120;
const R_TLS_LE_HI20_R: u32 = 121;
const R_TLS_LE_ADD_R: u32 = 122;
const R_TLS_LE_LO12_R: u32 = 123;

fn rd(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

fn wr(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// imm20 in bits 5..24 (`lu12i.w`, `pcalau12i`, `lu32i.d`, `pcaddi`).
fn set_j20(d: &mut [u8], o: usize, v: u64) {
    wr(
        d,
        o,
        (rd(d, o) & 0xfe00_001f) | (((v as u32) & 0xfffff) << 5),
    );
}

/// imm12 in bits 10..21 (`addi.d`, `ld.d`, `ori`, `lu52i.d`).
fn set_k12(d: &mut [u8], o: usize, v: u64) {
    wr(
        d,
        o,
        (rd(d, o) & 0xffc0_03ff) | (((v as u32) & 0xfff) << 10),
    );
}

/// imm16 in bits 10..25 (`jirl`, `beq`).
fn set_k16(d: &mut [u8], o: usize, v: u64) {
    wr(
        d,
        o,
        (rd(d, o) & 0xfc00_03ff) | (((v as u32) & 0xffff) << 10),
    );
}

/// `b`/`bl`: offs[15:0] in bits 10..25, offs[25:16] in bits 0..9.
fn set_d10k16(d: &mut [u8], o: usize, v: u64) {
    let v = v as u32;
    wr(
        d,
        o,
        (rd(d, o) & 0xfc00_0000) | ((v & 0xffff) << 10) | ((v >> 16) & 0x3ff),
    );
}

/// `beqz`/`bnez`: offs[15:0] in bits 10..25, offs[20:16] in bits 0..4.
fn set_d5k16(d: &mut [u8], o: usize, v: u64) {
    let v = v as u32;
    wr(
        d,
        o,
        (rd(d, o) & 0xfc00_03e0) | ((v & 0xffff) << 10) | ((v >> 16) & 0x1f),
    );
}

fn page(v: u64) -> u64 {
    v & !0xfff
}

/// The psABI's page delta for `pcalau12i` (and the `lu32i.d`/`lu52i.d` that follow it at
/// +8/+12, which compensate for the sign extension of the lower parts).
fn page_delta(dest: u64, pc: u64, ty: u32) -> u64 {
    let pc = match ty {
        R_PCALA64_LO20 | R_GOT64_PC_LO20 | R_TLS_IE64_PC_LO20 | R_TLS_DESC64_PC_LO20 => {
            pc.wrapping_sub(8)
        }
        R_PCALA64_HI12 | R_GOT64_PC_HI12 | R_TLS_IE64_PC_HI12 | R_TLS_DESC64_PC_HI12 => {
            pc.wrapping_sub(12)
        }
        _ => pc,
    };
    let mut r = page(dest).wrapping_sub(page(pc));
    if dest & 0x800 != 0 {
        r = r.wrapping_add(0x1000).wrapping_sub(0x1_0000_0000);
    }
    if r & 0x8000_0000 != 0 {
        r = r.wrapping_add(0x1_0000_0000);
    }
    r
}

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

/// A GD/LD pair's low part is a `GOT_PC_LO12` too: which entry it means depends on the
/// high part before it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TlsHi {
    None,
    Gd,
    Ld,
}

impl Target for LoongArch64 {
    const M: Machine = Machine::LoongArch64;
    const E_MACHINE: u16 = EM_LOONGARCH;
    const IS64: bool = true;
    const BE: bool = false;
    const MAX_PAGE: u64 = 0x10000;
    const PLT0_SIZE: u64 = 32;
    const PLT_SIZE: u64 = 16;
    const R_ABS: u32 = R_64;
    const R_RELATIVE: u32 = 3;
    const R_GLOB_DAT: u32 = R_64;
    const R_JUMP_SLOT: u32 = 5;
    const R_COPY: u32 = 4;
    const R_IRELATIVE: u32 = 12;
    const R_DTPMOD: u32 = 7;
    const R_DTPOFF: u32 = 9;
    const R_TPOFF: u32 = 11;
    const R_TLSDESC: u32 = 14;
    const RELAX_TLS: bool = false;

    fn scan(ctx: &Ctx<'_, Self>, o: &Object<'_>, si: u32, st: &mut ScanState) {
        let (raw, rela) = o.rel_data::<Self>(si);
        let n = o.rel_count::<Self>(si);
        let mut hi = TlsHi::None;
        for k in 0..n {
            let r = o.rel::<Self>(raw, rela, k, si);
            if r.sym >= o.nsyms {
                ctx.error(format!(
                    "{}: relocation against an invalid symbol index {}",
                    o.name, r.sym
                ));
                continue;
            }
            ctx.note_use(o, r.sym);
            let (sr, kind) = ctx.sym_kind(o, r.sym);
            let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
            match r.ty {
                R_64 => ctx.scan_abs_word(o, si, &r, st),
                R_32 | R_ABS_HI20 | R_ABS_LO12 | R_ABS64_LO20 | R_ABS64_HI12 => {
                    ctx.scan_abs_narrow(o, si, &r)
                }
                R_PCALA_HI20 | R_PCALA_LO12 | R_PCALA64_LO20 | R_PCALA64_HI12 | R_32_PCREL
                | R_64_PCREL | R_PCREL20_S2 => ctx.scan_pcrel(o, si, &r),
                R_B16 | R_B21 | R_B26 | R_CALL36 => ctx.scan_call(o, &r),
                R_GOT_PC_LO12 if hi != TlsHi::None => {}
                R_GOT_PC_HI20 | R_GOT_PC_LO12 | R_GOT64_PC_LO20 | R_GOT64_PC_HI12 | R_GOT_HI20
                | R_GOT_LO12 | R_GOT64_LO20 | R_GOT64_HI12 => ctx.scan_got(o, &r),
                R_TLS_LE_HI20 | R_TLS_LE_LO12 | R_TLS_LE64_LO20 | R_TLS_LE64_HI12
                | R_TLS_LE_HI20_R | R_TLS_LE_LO12_R => ctx.scan_tpoff(o, si, &r),
                R_TLS_IE_PC_HI20 | R_TLS_IE_PC_LO12 | R_TLS_IE64_PC_LO20 | R_TLS_IE64_PC_HI12
                | R_TLS_IE_HI20 | R_TLS_IE_LO12 | R_TLS_IE64_LO20 | R_TLS_IE64_HI12 => {
                    ctx.scan_gottp(o, &r)
                }
                // LoongArch's local dynamic uses the same per-symbol pair as general dynamic.
                R_TLS_GD_PC_HI20 | R_TLS_GD_HI20 | R_TLS_LD_PC_HI20 | R_TLS_LD_HI20 => {
                    ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
                }
                R_TLS_DESC_PC_HI20 => {
                    ctx.need(
                        o,
                        sr,
                        NEEDS_TLSDESC | if imported { NEEDS_DYNSYM } else { 0 },
                    );
                }
                R_NONE
                | R_MARK_LA
                | R_MARK_PCREL
                | R_RELAX
                | R_ALIGN
                | R_TLS_LE_ADD_R
                | R_TLS_DESC_PC_LO12
                | R_TLS_DESC64_PC_LO20
                | R_TLS_DESC64_PC_HI12
                | R_TLS_DESC_LD
                | R_TLS_DESC_CALL
                | R_ADD8..=R_SUB64
                | R_ADD6
                | R_SUB6
                | R_ADD_ULEB128
                | R_SUB_ULEB128
                | R_TLS_DTPREL32
                | R_TLS_DTPREL64 => {}
                _ => ctx.error(format!(
                    "{}: unsupported relocation type {} in section {}",
                    o.name,
                    r.ty,
                    String::from_utf8_lossy(o.sec_name::<Self>(si))
                )),
            }
            hi = match r.ty {
                R_TLS_GD_PC_HI20 | R_TLS_GD_HI20 => TlsHi::Gd,
                R_TLS_LD_PC_HI20 | R_TLS_LD_HI20 => TlsHi::Ld,
                R_RELAX => hi,
                _ => TlsHi::None,
            };
        }
    }

    fn apply_alloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let hi = Cell::new(TlsHi::None);
        for k in 0..rc.len() {
            let r = rc.rel(k);
            let off = r.offset as usize;
            let p = rc.p(&r);
            let a = r.addend as u64;
            let pd = |dest: u64| page_delta(dest, p, r.ty);
            match r.ty {
                R_NONE | R_MARK_LA | R_MARK_PCREL | R_RELAX | R_ALIGN | R_TLS_LE_ADD_R
                | R_TLS_DESC_CALL => {}
                R_64 => {
                    let v = rc.abs_word(&r);
                    wr64::<Self>(out, off, v);
                }
                R_32 => wr32::<Self>(out, off, rc.sa(&r) as u32),
                R_32_PCREL => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_64_PCREL => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(p)),
                R_B16 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 18);
                    set_k16(out, off, v >> 2);
                }
                R_B21 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 23);
                    set_d5k16(out, off, v >> 2);
                }
                R_B26 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 28);
                    set_d10k16(out, off, v >> 2);
                }
                R_CALL36 => {
                    // pcaddu18i + jirl.
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 38);
                    set_j20(out, off, (v.wrapping_add(0x20000)) >> 18);
                    set_k16(out, off + 4, v >> 2);
                }
                R_PCREL20_S2 => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 22);
                    set_j20(out, off, v >> 2);
                }
                R_ABS_HI20 => set_j20(out, off, rc.sa(&r) >> 12),
                R_ABS_LO12 => set_k12(out, off, rc.sa(&r)),
                R_ABS64_LO20 => set_j20(out, off, rc.sa(&r) >> 32),
                R_ABS64_HI12 => set_k12(out, off, rc.sa(&r) >> 52),
                R_PCALA_HI20 => set_j20(out, off, pd(rc.sa(&r)) >> 12),
                R_PCALA_LO12 => set_k12(out, off, rc.sa(&r)),
                R_PCALA64_LO20 => set_j20(out, off, pd(rc.sa(&r)) >> 32),
                R_PCALA64_HI12 => set_k12(out, off, pd(rc.sa(&r)) >> 52),
                R_GOT_PC_HI20 => set_j20(out, off, pd(rc.got(r.sym).wrapping_add(a)) >> 12),
                R_GOT_PC_LO12 => {
                    let g = match hi.get() {
                        TlsHi::Gd => rc.tlsgd(r.sym),
                        TlsHi::Ld => rc.tlsgd(r.sym),
                        TlsHi::None => rc.got(r.sym),
                    };
                    set_k12(out, off, g.wrapping_add(a));
                }
                R_GOT64_PC_LO20 => set_j20(out, off, pd(rc.got(r.sym).wrapping_add(a)) >> 32),
                R_GOT64_PC_HI12 => set_k12(out, off, pd(rc.got(r.sym).wrapping_add(a)) >> 52),
                R_GOT_HI20 => set_j20(out, off, rc.got(r.sym).wrapping_add(a) >> 12),
                R_GOT_LO12 => set_k12(out, off, rc.got(r.sym).wrapping_add(a)),
                R_GOT64_LO20 => set_j20(out, off, rc.got(r.sym).wrapping_add(a) >> 32),
                R_GOT64_HI12 => set_k12(out, off, rc.got(r.sym).wrapping_add(a) >> 52),
                R_TLS_LE_HI20 => set_j20(out, off, rc.tp(rc.sa(&r)) >> 12),
                R_TLS_LE_LO12 | R_TLS_LE_LO12_R => set_k12(out, off, rc.tp(rc.sa(&r))),
                R_TLS_LE64_LO20 => set_j20(out, off, rc.tp(rc.sa(&r)) >> 32),
                R_TLS_LE64_HI12 => set_k12(out, off, rc.tp(rc.sa(&r)) >> 52),
                R_TLS_LE_HI20_R => set_j20(out, off, rc.tp(rc.sa(&r)).wrapping_add(0x800) >> 12),
                R_TLS_IE_PC_HI20 => set_j20(out, off, pd(rc.gottp(r.sym).wrapping_add(a)) >> 12),
                R_TLS_IE_PC_LO12 => set_k12(out, off, rc.gottp(r.sym).wrapping_add(a)),
                R_TLS_IE64_PC_LO20 => set_j20(out, off, pd(rc.gottp(r.sym).wrapping_add(a)) >> 32),
                R_TLS_IE64_PC_HI12 => set_k12(out, off, pd(rc.gottp(r.sym).wrapping_add(a)) >> 52),
                R_TLS_IE_HI20 => set_j20(out, off, rc.gottp(r.sym).wrapping_add(a) >> 12),
                R_TLS_IE_LO12 => set_k12(out, off, rc.gottp(r.sym).wrapping_add(a)),
                R_TLS_IE64_LO20 => set_j20(out, off, rc.gottp(r.sym).wrapping_add(a) >> 32),
                R_TLS_IE64_HI12 => set_k12(out, off, rc.gottp(r.sym).wrapping_add(a) >> 52),
                R_TLS_GD_PC_HI20 => set_j20(out, off, pd(rc.tlsgd(r.sym).wrapping_add(a)) >> 12),
                R_TLS_GD_HI20 => set_j20(out, off, rc.tlsgd(r.sym).wrapping_add(a) >> 12),
                R_TLS_LD_PC_HI20 => set_j20(out, off, pd(rc.tlsgd(r.sym).wrapping_add(a)) >> 12),
                R_TLS_LD_HI20 => set_j20(out, off, rc.tlsgd(r.sym).wrapping_add(a) >> 12),
                R_TLS_DESC_PC_HI20 => {
                    set_j20(out, off, pd(rc.tlsdesc(r.sym).wrapping_add(a)) >> 12)
                }
                R_TLS_DESC_PC_LO12 => set_k12(out, off, rc.tlsdesc(r.sym).wrapping_add(a)),
                R_TLS_DESC64_PC_LO20 => {
                    set_j20(out, off, pd(rc.tlsdesc(r.sym).wrapping_add(a)) >> 32)
                }
                R_TLS_DESC64_PC_HI12 => {
                    set_k12(out, off, pd(rc.tlsdesc(r.sym).wrapping_add(a)) >> 52)
                }
                R_TLS_DESC_LD => {}
                _ => apply_data(rc, &r, out),
            }
            hi.set(match r.ty {
                R_TLS_GD_PC_HI20 | R_TLS_GD_HI20 => TlsHi::Gd,
                R_TLS_LD_PC_HI20 | R_TLS_LD_HI20 => TlsHi::Ld,
                R_RELAX => hi.get(),
                _ => TlsHi::None,
            });
        }
        Ok(())
    }

    fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let tomb = rc.tombstone();
        rc.apply_debug(out, R_64, [R_32, R_32], |rc, r, out| {
            let off = r.offset as usize;
            match r.ty {
                R_NONE | R_RELAX | R_ALIGN | R_MARK_LA | R_MARK_PCREL => {}
                R_64 => wr64::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_32 => wr32::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
                R_TLS_DTPREL32 => {
                    wr32::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v)) as u32)
                }
                R_TLS_DTPREL64 => wr64::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v))),
                _ => apply_data(rc, r, out),
            }
        });
        Ok(())
    }

    fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
        let off = gotplt.wrapping_sub(plt);
        let h = ((off.wrapping_add(0x800)) >> 12) as u32 & 0xfffff;
        let l = off as u32 & 0xfff;
        let insn = |op: u32, d: u32, j: u32, k: u32| op | d | (j << 5) | (k << 10);
        wr(b, 0, insn(0x1c00_0000, T2, h, 0));
        wr(b, 4, insn(0x0011_8000, T1, T1, T3));
        wr(b, 8, insn(0x28c0_0000, T3, T2, l));
        wr(
            b,
            12,
            insn(
                0x02c0_0000,
                T1,
                T1,
                ((-(Self::PLT0_SIZE as i64) - 12) as u32) & 0xfff,
            ),
        );
        wr(b, 16, insn(0x02c0_0000, T0, T2, l));
        wr(b, 20, insn(0x0045_0000, T1, T1, 1));
        wr(b, 24, insn(0x28c0_0000, T0, T0, 8));
        wr(b, 28, insn(0x4c00_0000, 0, T3, 0));
    }

    fn write_plt(_ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, _idx: u64, _plt: u64) {
        let off = slot.wrapping_sub(ent);
        let h = ((off.wrapping_add(0x800)) >> 12) as u32 & 0xfffff;
        let l = off as u32 & 0xfff;
        let insn = |op: u32, d: u32, j: u32, k: u32| op | d | (j << 5) | (k << 10);
        wr(b, 0, insn(0x1c00_0000, T3, h, 0));
        wr(b, 4, insn(0x28c0_0000, T3, T3, l));
        wr(b, 8, insn(0x4c00_0000, T1, T3, 0));
        wr(b, 12, insn(0x0340_0000, 0, 0, 0));
    }

    fn gotplt_initial(plt: u64, _ent: u64) -> u64 {
        plt
    }

    fn e_flags(ctx: &Ctx<'_, Self>) -> u32 {
        ctx.objs
            .iter()
            .find(|o| o.alive.load(std::sync::atomic::Ordering::Relaxed))
            .map_or(0, |o| o.e_flags)
    }
}

const T0: u32 = 12;
const T1: u32 = 13;
const T2: u32 = 14;
const T3: u32 = 15;

fn apply_data(rc: &mut RelocCtx<'_, '_, LoongArch64>, r: &Rel, out: &mut [u8]) {
    type T = LoongArch64;
    let off = r.offset as usize;
    let v = rc.sa(r);
    match r.ty {
        R_ADD6 => out[off] = (out[off] & 0xc0) | (out[off].wrapping_add(v as u8) & 0x3f),
        R_SUB6 => out[off] = (out[off] & 0xc0) | (out[off].wrapping_sub(v as u8) & 0x3f),
        R_ADD8 => out[off] = out[off].wrapping_add(v as u8),
        R_SUB8 => out[off] = out[off].wrapping_sub(v as u8),
        R_ADD16 => wr16::<T>(out, off, rd16::<T>(out, off).wrapping_add(v as u16)),
        R_SUB16 => wr16::<T>(out, off, rd16::<T>(out, off).wrapping_sub(v as u16)),
        R_ADD24 | R_SUB24 => {
            let cur = u32::from_le_bytes([out[off], out[off + 1], out[off + 2], 0]);
            let n = if r.ty == R_ADD24 {
                cur.wrapping_add(v as u32)
            } else {
                cur.wrapping_sub(v as u32)
            };
            out[off..off + 3].copy_from_slice(&n.to_le_bytes()[..3]);
        }
        R_ADD32 => wr32::<T>(out, off, rd32::<T>(out, off).wrapping_add(v as u32)),
        R_SUB32 => wr32::<T>(out, off, rd32::<T>(out, off).wrapping_sub(v as u32)),
        R_ADD64 => wr64::<T>(
            out,
            off,
            u64::from_le_bytes(out[off..off + 8].try_into().unwrap()).wrapping_add(v),
        ),
        R_SUB64 => wr64::<T>(
            out,
            off,
            u64::from_le_bytes(out[off..off + 8].try_into().unwrap()).wrapping_sub(v),
        ),
        R_ADD_ULEB128 | R_SUB_ULEB128 => {
            let mut p = off;
            let cur = super::read_uleb(out, &mut p).unwrap_or(0);
            let n = if r.ty == R_ADD_ULEB128 {
                cur.wrapping_add(v)
            } else {
                cur.wrapping_sub(v)
            };
            set_uleb(out, off, n);
        }
        R_32_PCREL => wr32::<T>(out, off, v.wrapping_sub(rc.p(r)) as u32),
        R_64_PCREL => wr64::<T>(out, off, v.wrapping_sub(rc.p(r))),
        _ => rc.error(r, "unsupported relocation"),
    }
}

#[allow(dead_code)]
fn _uses() -> u32 {
    IS_TLS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_deltas_follow_the_psabi() {
        // Same page.
        assert_eq!(page_delta(0x1234, 0x1000, R_PCALA_HI20), 0);
        // Low part >= 0x800 is sign-extended by addi.d: the high part compensates.
        let d = page_delta(0x2900, 0x1000, R_PCALA_HI20);
        assert_eq!((d >> 12) & 0xfffff, 2);
    }
}
