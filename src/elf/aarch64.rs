//! AArch64: relocations, TLS descriptor relaxation, the PLT.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct AArch64;

const R_NONE: u32 = 0;
const R_NONE_OLD: u32 = 256;
const R_ABS64: u32 = 257;
const R_ABS32: u32 = 258;
const R_ABS16: u32 = 259;
const R_PREL64: u32 = 260;
const R_PREL32: u32 = 261;
const R_PREL16: u32 = 262;
const R_MOVW_UABS_G0: u32 = 263;
const R_MOVW_UABS_G0_NC: u32 = 264;
const R_MOVW_UABS_G1: u32 = 265;
const R_MOVW_UABS_G1_NC: u32 = 266;
const R_MOVW_UABS_G2: u32 = 267;
const R_MOVW_UABS_G2_NC: u32 = 268;
const R_MOVW_UABS_G3: u32 = 269;
const R_MOVW_SABS_G0: u32 = 270;
const R_MOVW_SABS_G1: u32 = 271;
const R_MOVW_SABS_G2: u32 = 272;
const R_LD_PREL_LO19: u32 = 273;
const R_ADR_PREL_LO21: u32 = 274;
const R_ADR_PREL_PG_HI21: u32 = 275;
const R_ADR_PREL_PG_HI21_NC: u32 = 276;
const R_ADD_ABS_LO12_NC: u32 = 277;
const R_LDST8_ABS_LO12_NC: u32 = 278;
const R_TSTBR14: u32 = 279;
const R_CONDBR19: u32 = 280;
const R_JUMP26: u32 = 282;
const R_CALL26: u32 = 283;
const R_LDST16_ABS_LO12_NC: u32 = 284;
const R_LDST32_ABS_LO12_NC: u32 = 285;
const R_LDST64_ABS_LO12_NC: u32 = 286;
const R_MOVW_PREL_G0: u32 = 287;
const R_MOVW_PREL_G0_NC: u32 = 288;
const R_MOVW_PREL_G1: u32 = 289;
const R_MOVW_PREL_G1_NC: u32 = 290;
const R_MOVW_PREL_G2: u32 = 291;
const R_MOVW_PREL_G2_NC: u32 = 292;
const R_MOVW_PREL_G3: u32 = 293;
const R_LDST128_ABS_LO12_NC: u32 = 299;
const R_ADR_GOT_PAGE: u32 = 311;
const R_LD64_GOT_LO12_NC: u32 = 312;
const R_LD64_GOTPAGE_LO15: u32 = 313;
const R_PLT32: u32 = 314;
const R_GOTPCREL32: u32 = 315;
const R_TLSGD_ADR_PAGE21: u32 = 513;
const R_TLSGD_ADD_LO12_NC: u32 = 514;
const R_TLSLD_ADR_PAGE21: u32 = 518;
const R_TLSLD_ADD_LO12_NC: u32 = 519;
const R_TLSLD_MOVW_DTPREL_G1: u32 = 524;
const R_TLSLD_MOVW_DTPREL_G0_NC: u32 = 527;
const R_TLSLD_ADD_DTPREL_HI12: u32 = 528;
const R_TLSLD_ADD_DTPREL_LO12: u32 = 529;
const R_TLSLD_ADD_DTPREL_LO12_NC: u32 = 530;
const R_TLSLD_LDST8_DTPREL_LO12: u32 = 531;
const R_TLSLD_LDST64_DTPREL_LO12_NC: u32 = 538;
const R_TLSIE_MOVW_GOTTPREL_G1: u32 = 539;
const R_TLSIE_MOVW_GOTTPREL_G0_NC: u32 = 540;
const R_TLSIE_ADR_GOTTPREL_PAGE21: u32 = 541;
const R_TLSIE_LD64_GOTTPREL_LO12_NC: u32 = 542;
const R_TLSIE_LD_GOTTPREL_PREL19: u32 = 543;
const R_TLSLE_MOVW_TPREL_G2: u32 = 544;
const R_TLSLE_MOVW_TPREL_G1: u32 = 545;
const R_TLSLE_MOVW_TPREL_G1_NC: u32 = 546;
const R_TLSLE_MOVW_TPREL_G0: u32 = 547;
const R_TLSLE_MOVW_TPREL_G0_NC: u32 = 548;
const R_TLSLE_ADD_TPREL_HI12: u32 = 549;
const R_TLSLE_ADD_TPREL_LO12: u32 = 550;
const R_TLSLE_ADD_TPREL_LO12_NC: u32 = 551;
const R_TLSLE_LDST8_TPREL_LO12: u32 = 552;
const R_TLSLE_LDST64_TPREL_LO12_NC: u32 = 559;
const R_TLSDESC_LD_PREL19: u32 = 560;
const R_TLSDESC_ADR_PREL21: u32 = 561;
const R_TLSDESC_ADR_PAGE21: u32 = 562;
const R_TLSDESC_LD64_LO12: u32 = 563;
const R_TLSDESC_ADD_LO12: u32 = 564;
const R_TLSDESC_OFF_G1: u32 = 565;
const R_TLSDESC_OFF_G0_NC: u32 = 566;
const R_TLSDESC_LDR: u32 = 567;
const R_TLSDESC_ADD: u32 = 568;
const R_TLSDESC_CALL: u32 = 569;
const R_TLSLE_LDST128_TPREL_LO12: u32 = 570;
const R_TLSLE_LDST128_TPREL_LO12_NC: u32 = 571;
const R_TLSLD_LDST128_DTPREL_LO12: u32 = 572;
const R_TLSLD_LDST128_DTPREL_LO12_NC: u32 = 573;
const R_TLS_DTPREL64: u32 = 1029;

const NOP: u32 = 0xd503_201f;

#[inline]
fn page(v: u64) -> u64 {
    v & !0xfff
}

/// Patch an instruction's bits under `mask` with `v` shifted to `shift`.
#[inline]
fn set_bits(out: &mut [u8], off: usize, v: u64, shift: u32, width: u32) {
    let insn = rd32::<AArch64>(out, off);
    let mask = ((1u32 << width) - 1) << shift;
    let v = ((v as u32) << shift) & mask;
    wr32::<AArch64>(out, off, (insn & !mask) | v);
}

/// ADR/ADRP immediate: 21 bits split into immlo (29..31) and immhi (5..24).
#[inline]
fn set_adr(out: &mut [u8], off: usize, imm: u64) {
    let insn = rd32::<AArch64>(out, off);
    let lo = (imm & 3) as u32;
    let hi = ((imm >> 2) & 0x7ffff) as u32;
    wr32::<AArch64>(out, off, (insn & 0x9f00_001f) | (lo << 29) | (hi << 5));
}

/// The 12-bit field of ADD/LDR/STR immediates, scaled by the access size of a load/store.
#[inline]
fn set_lo12(out: &mut [u8], off: usize, v: u64, scale: u32) {
    set_bits(out, off, (v & 0xfff) >> scale, 10, 12);
}

/// MOVZ/MOVK/MOVN immediate (bits 5..21).
#[inline]
fn set_movw(out: &mut [u8], off: usize, v: u64) {
    set_bits(out, off, v & 0xffff, 5, 16);
}

/// A signed MOVW group: MOVZ for non-negative values, MOVN (inverted) for negative ones.
fn set_movw_signed(out: &mut [u8], off: usize, v: i64, group: u32) {
    let mut insn = rd32::<AArch64>(out, off);
    let shifted = (v >> (16 * group)) as u64;
    if v < 0 {
        insn &= !(1 << 30); // MOVN
        insn = (insn & !(0xffff << 5)) | ((!shifted as u32 & 0xffff) << 5);
    } else {
        insn |= 1 << 30; // MOVZ
        insn = (insn & !(0xffff << 5)) | ((shifted as u32 & 0xffff) << 5);
    }
    wr32::<AArch64>(out, off, insn);
}

fn ldst_scale(ty: u32, insn: u32) -> u32 {
    match ty {
        R_LDST8_ABS_LO12_NC => 0,
        R_LDST16_ABS_LO12_NC => 1,
        R_LDST32_ABS_LO12_NC => 2,
        R_LDST64_ABS_LO12_NC => 3,
        R_LDST128_ABS_LO12_NC => 4,
        // TLS LDST: the size is in the instruction (bits 30..31; 128-bit when V and opc[1]).
        _ => {
            let size = insn >> 30;
            if insn & 0x0480_0000 == 0x0480_0000 && size == 0 {
                4
            } else {
                size
            }
        }
    }
}

impl Target for AArch64 {
    const M: Machine = Machine::AArch64;
    const E_MACHINE: u16 = EM_AARCH64;
    const IS64: bool = true;
    const BE: bool = false;
    const MAX_PAGE: u64 = 0x10000;
    const PLT0_SIZE: u64 = 32;
    const PLT_SIZE: u64 = 16;
    const R_ABS: u32 = R_ABS64;
    const R_RELATIVE: u32 = 1027;
    const R_GLOB_DAT: u32 = 1025;
    const R_JUMP_SLOT: u32 = 1026;
    const R_COPY: u32 = 1024;
    const R_IRELATIVE: u32 = 1032;
    const R_DTPMOD: u32 = 1028;
    const R_DTPOFF: u32 = 1029;
    const R_TPOFF: u32 = 1030;
    const R_TLSDESC: u32 = 1031;
    const TLS_TCB: u64 = 16;

    fn scan(ctx: &Ctx<'_, Self>, o: &Object<'_>, si: u32, st: &mut ScanState) {
        let (raw, rela) = o.rel_data::<Self>(si);
        let n = o.rel_count::<Self>(si);
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
            match r.ty {
                R_NONE | R_NONE_OLD => {}
                R_ABS64 => ctx.scan_abs_word(o, si, &r, st),
                R_ABS32 | R_ABS16 | R_MOVW_UABS_G0..=R_MOVW_SABS_G2 => {
                    ctx.scan_abs_narrow(o, si, &r)
                }
                R_PREL64
                | R_PREL32
                | R_PREL16
                | R_LD_PREL_LO19
                | R_ADR_PREL_LO21
                | R_ADR_PREL_PG_HI21
                | R_ADR_PREL_PG_HI21_NC
                | R_MOVW_PREL_G0..=R_MOVW_PREL_G3 => ctx.scan_pcrel(o, si, &r),
                R_ADD_ABS_LO12_NC
                | R_LDST8_ABS_LO12_NC
                | R_LDST16_ABS_LO12_NC
                | R_LDST32_ABS_LO12_NC
                | R_LDST64_ABS_LO12_NC
                | R_LDST128_ABS_LO12_NC => {}
                R_CALL26 | R_JUMP26 | R_CONDBR19 | R_TSTBR14 | R_PLT32 => ctx.scan_call(o, &r),
                R_ADR_GOT_PAGE | R_LD64_GOT_LO12_NC | R_LD64_GOTPAGE_LO15 | R_GOTPCREL32 => {
                    ctx.scan_got(o, &r)
                }
                R_TLSDESC_ADR_PAGE21 | R_TLSDESC_ADR_PREL21 | R_TLSDESC_LD_PREL19 => {
                    ctx.scan_tlsdesc(o, &r)
                }
                R_TLSDESC_LD64_LO12 | R_TLSDESC_ADD_LO12 | R_TLSDESC_CALL | R_TLSDESC_OFF_G1
                | R_TLSDESC_OFF_G0_NC | R_TLSDESC_LDR | R_TLSDESC_ADD => {}
                R_TLSIE_ADR_GOTTPREL_PAGE21
                | R_TLSIE_LD64_GOTTPREL_LO12_NC
                | R_TLSIE_LD_GOTTPREL_PREL19
                | R_TLSIE_MOVW_GOTTPREL_G1
                | R_TLSIE_MOVW_GOTTPREL_G0_NC => {
                    let local = ctx.sym_kind(o, r.sym).1 == SymKind::Local;
                    let relax = !ctx.cfg.shared
                        && ctx.cfg.relax
                        && local
                        && matches!(
                            r.ty,
                            R_TLSIE_ADR_GOTTPREL_PAGE21 | R_TLSIE_LD64_GOTTPREL_LO12_NC
                        );
                    if !relax {
                        ctx.scan_gottp(o, &r);
                    }
                }
                R_TLSLE_MOVW_TPREL_G2..=R_TLSLE_LDST64_TPREL_LO12_NC
                | R_TLSLE_LDST128_TPREL_LO12
                | R_TLSLE_LDST128_TPREL_LO12_NC => ctx.scan_tpoff(o, si, &r),
                R_TLSGD_ADR_PAGE21 | R_TLSGD_ADD_LO12_NC => {
                    let (sr, kind) = ctx.sym_kind(o, r.sym);
                    let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                    ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
                }
                R_TLSLD_ADR_PAGE21 | R_TLSLD_ADD_LO12_NC => ctx
                    .scan
                    .needs_tlsld
                    .store(true, std::sync::atomic::Ordering::Relaxed),
                R_TLSLD_MOVW_DTPREL_G1..=R_TLSLD_LDST64_DTPREL_LO12_NC
                | R_TLSLD_LDST128_DTPREL_LO12
                | R_TLSLD_LDST128_DTPREL_LO12_NC => {}
                _ => ctx.error(format!(
                    "{}: unsupported relocation type {} in section {}",
                    o.name,
                    r.ty,
                    String::from_utf8_lossy(o.sec_name::<Self>(si))
                )),
            }
        }
    }

    fn apply_alloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let ctx = rc.ctx;
        let relax_tls = ctx.relax_tls();
        for k in 0..rc.len() {
            let r = rc.rel(k);
            let off = r.offset as usize;
            if off + 4 > out.len() && !matches!(r.ty, R_NONE | R_NONE_OLD | R_ABS16 | R_PREL16) {
                rc.error(&r, "relocation past the end of its section");
                continue;
            }
            let p = rc.p(&r);
            let a = r.addend as u64;
            match r.ty {
                R_NONE | R_NONE_OLD => {}
                R_ABS64 => {
                    let v = rc.abs_word(&r);
                    wr64::<Self>(out, off, v);
                }
                R_ABS32 => {
                    let v = rc.sa(&r);
                    rc.check_any(&r, v, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_ABS16 => {
                    let v = rc.sa(&r);
                    rc.check_any(&r, v, 16);
                    wr16::<Self>(out, off, v as u16);
                }
                R_PREL64 => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(p)),
                R_PREL32 | R_PLT32 => {
                    let t = if r.ty == R_PLT32 {
                        rc.call_target(&r)
                    } else {
                        rc.sa(&r)
                    };
                    let v = t.wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_PREL16 => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 16);
                    wr16::<Self>(out, off, v as u16);
                }
                R_MOVW_UABS_G0 | R_MOVW_UABS_G0_NC => set_movw(out, off, rc.sa(&r)),
                R_MOVW_UABS_G1 | R_MOVW_UABS_G1_NC => set_movw(out, off, rc.sa(&r) >> 16),
                R_MOVW_UABS_G2 | R_MOVW_UABS_G2_NC => set_movw(out, off, rc.sa(&r) >> 32),
                R_MOVW_UABS_G3 => set_movw(out, off, rc.sa(&r) >> 48),
                R_MOVW_SABS_G0 => set_movw_signed(out, off, rc.sa(&r) as i64, 0),
                R_MOVW_SABS_G1 => set_movw_signed(out, off, rc.sa(&r) as i64, 1),
                R_MOVW_SABS_G2 => set_movw_signed(out, off, rc.sa(&r) as i64, 2),
                R_MOVW_PREL_G0 | R_MOVW_PREL_G0_NC => {
                    set_movw_signed(out, off, rc.sa(&r).wrapping_sub(p) as i64, 0)
                }
                R_MOVW_PREL_G1 | R_MOVW_PREL_G1_NC => {
                    set_movw_signed(out, off, rc.sa(&r).wrapping_sub(p) as i64, 1)
                }
                R_MOVW_PREL_G2 | R_MOVW_PREL_G2_NC => {
                    set_movw_signed(out, off, rc.sa(&r).wrapping_sub(p) as i64, 2)
                }
                R_MOVW_PREL_G3 => set_movw(out, off, rc.sa(&r).wrapping_sub(p) >> 48),
                R_LD_PREL_LO19 | R_CONDBR19 => {
                    let t = if r.ty == R_CONDBR19 {
                        rc.call_target(&r)
                    } else {
                        rc.sa(&r)
                    };
                    let v = t.wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 21);
                    set_bits(out, off, v >> 2, 5, 19);
                }
                R_TSTBR14 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 16);
                    set_bits(out, off, v >> 2, 5, 14);
                }
                R_ADR_PREL_LO21 => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 21);
                    set_adr(out, off, v);
                }
                R_ADR_PREL_PG_HI21 | R_ADR_PREL_PG_HI21_NC => {
                    let v = page(rc.sa(&r)).wrapping_sub(page(p)) >> 12;
                    if r.ty == R_ADR_PREL_PG_HI21 {
                        rc.check_signed(&r, (page(rc.sa(&r)).wrapping_sub(page(p))) as i64, 33);
                    }
                    set_adr(out, off, v);
                }
                R_ADD_ABS_LO12_NC => set_lo12(out, off, rc.sa(&r), 0),
                R_LDST8_ABS_LO12_NC
                | R_LDST16_ABS_LO12_NC
                | R_LDST32_ABS_LO12_NC
                | R_LDST64_ABS_LO12_NC
                | R_LDST128_ABS_LO12_NC => {
                    let scale = ldst_scale(r.ty, 0);
                    set_lo12(out, off, rc.sa(&r), scale);
                }
                R_CALL26 | R_JUMP26 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    if (v as i64) < -(1 << 27) || (v as i64) >= (1 << 27) {
                        match rc.thunk_for(&r) {
                            Some(t) => set_bits(out, off, t.wrapping_sub(p) >> 2, 0, 26),
                            None => {
                                rc.error(&r, "branch target out of range (more than 128 MiB away)")
                            }
                        }
                    } else {
                        set_bits(out, off, v >> 2, 0, 26);
                    }
                }
                R_ADR_GOT_PAGE => {
                    let g = rc.got(r.sym).wrapping_add(a);
                    set_adr(out, off, page(g).wrapping_sub(page(p)) >> 12);
                }
                R_LD64_GOT_LO12_NC => set_lo12(out, off, rc.got(r.sym).wrapping_add(a), 3),
                R_LD64_GOTPAGE_LO15 => {
                    let v = rc.got(r.sym).wrapping_add(a).wrapping_sub(page(rc.lay.got));
                    set_bits(out, off, (v >> 3) & 0xfff, 10, 12);
                }
                R_GOTPCREL32 => {
                    let v = rc.got(r.sym).wrapping_add(a).wrapping_sub(p);
                    wr32::<Self>(out, off, v as u32);
                }
                // TLS descriptors: relaxed to local exec or initial exec in executables.
                R_TLSDESC_ADR_PAGE21 | R_TLSDESC_LD64_LO12 | R_TLSDESC_ADD_LO12
                | R_TLSDESC_CALL => {
                    if relax_tls {
                        if rc.is_local(r.sym) {
                            let v = rc.tp(rc.sa(&r));
                            match r.ty {
                                R_TLSDESC_ADR_PAGE21 | R_TLSDESC_LD64_LO12 => {
                                    wr32::<Self>(out, off, NOP)
                                }
                                R_TLSDESC_ADD_LO12 => wr32::<Self>(
                                    out,
                                    off,
                                    0xd2a0_0000 | ((((v >> 16) & 0xffff) as u32) << 5),
                                ),
                                _ => wr32::<Self>(
                                    out,
                                    off,
                                    0xf280_0000 | (((v & 0xffff) as u32) << 5),
                                ),
                            }
                            if v >> 32 != 0 {
                                rc.error(&r, "TLS offset too large for local exec");
                            }
                        } else {
                            let g = rc.gottp(r.sym);
                            match r.ty {
                                R_TLSDESC_ADR_PAGE21 => {
                                    wr32::<Self>(out, off, 0x9000_0000);
                                    set_adr(out, off, page(g).wrapping_sub(page(p)) >> 12);
                                }
                                R_TLSDESC_LD64_LO12 => {
                                    wr32::<Self>(out, off, 0xf940_0000);
                                    set_lo12(out, off, g, 3);
                                }
                                _ => wr32::<Self>(out, off, NOP),
                            }
                        }
                    } else {
                        let d = rc.tlsdesc(r.sym).wrapping_add(a);
                        match r.ty {
                            R_TLSDESC_ADR_PAGE21 => {
                                set_adr(out, off, page(d).wrapping_sub(page(p)) >> 12)
                            }
                            R_TLSDESC_LD64_LO12 => set_lo12(out, off, d, 3),
                            R_TLSDESC_ADD_LO12 => set_lo12(out, off, d, 0),
                            _ => {}
                        }
                    }
                }
                R_TLSDESC_ADR_PREL21 => {
                    set_adr(out, off, rc.tlsdesc(r.sym).wrapping_add(a).wrapping_sub(p))
                }
                R_TLSDESC_LD_PREL19 => set_bits(
                    out,
                    off,
                    rc.tlsdesc(r.sym).wrapping_add(a).wrapping_sub(p) >> 2,
                    5,
                    19,
                ),
                R_TLSDESC_OFF_G1 | R_TLSDESC_OFF_G0_NC | R_TLSDESC_LDR | R_TLSDESC_ADD => {}
                R_TLSIE_ADR_GOTTPREL_PAGE21 | R_TLSIE_LD64_GOTTPREL_LO12_NC => {
                    let relax =
                        !ctx.cfg.shared && ctx.cfg.relax && rc.kind(r.sym).1 == SymKind::Local;
                    if relax {
                        let reg = rd32::<Self>(out, off) & 0x1f;
                        let v = rc.tp(rc.sa(&r));
                        if r.ty == R_TLSIE_ADR_GOTTPREL_PAGE21 {
                            wr32::<Self>(
                                out,
                                off,
                                0xd2a0_0000 | reg | ((((v >> 16) & 0xffff) as u32) << 5),
                            );
                        } else {
                            wr32::<Self>(
                                out,
                                off,
                                0xf280_0000 | reg | (((v & 0xffff) as u32) << 5),
                            );
                        }
                    } else {
                        let g = rc.gottp(r.sym).wrapping_add(a);
                        if r.ty == R_TLSIE_ADR_GOTTPREL_PAGE21 {
                            set_adr(out, off, page(g).wrapping_sub(page(p)) >> 12);
                        } else {
                            set_lo12(out, off, g, 3);
                        }
                    }
                }
                R_TLSIE_LD_GOTTPREL_PREL19 => set_bits(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(p) >> 2,
                    5,
                    19,
                ),
                R_TLSIE_MOVW_GOTTPREL_G1 => set_movw(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(rc.lay.got) >> 16,
                ),
                R_TLSIE_MOVW_GOTTPREL_G0_NC => set_movw(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(rc.lay.got),
                ),
                R_TLSLE_MOVW_TPREL_G2 => set_movw_signed(out, off, rc.tp(rc.sa(&r)) as i64, 2),
                R_TLSLE_MOVW_TPREL_G1 => set_movw_signed(out, off, rc.tp(rc.sa(&r)) as i64, 1),
                R_TLSLE_MOVW_TPREL_G1_NC => set_movw(out, off, rc.tp(rc.sa(&r)) >> 16),
                R_TLSLE_MOVW_TPREL_G0 => set_movw_signed(out, off, rc.tp(rc.sa(&r)) as i64, 0),
                R_TLSLE_MOVW_TPREL_G0_NC => set_movw(out, off, rc.tp(rc.sa(&r))),
                R_TLSLE_ADD_TPREL_HI12 => {
                    let v = rc.tp(rc.sa(&r));
                    rc.check_unsigned(&r, v, 24);
                    set_bits(out, off, (v >> 12) & 0xfff, 10, 12);
                }
                R_TLSLE_ADD_TPREL_LO12 | R_TLSLE_ADD_TPREL_LO12_NC => {
                    set_lo12(out, off, rc.tp(rc.sa(&r)), 0)
                }
                R_TLSLE_LDST8_TPREL_LO12..=R_TLSLE_LDST64_TPREL_LO12_NC
                | R_TLSLE_LDST128_TPREL_LO12
                | R_TLSLE_LDST128_TPREL_LO12_NC => {
                    let scale = ldst_scale(r.ty, rd32::<Self>(out, off));
                    set_lo12(out, off, rc.tp(rc.sa(&r)), scale);
                }
                R_TLSGD_ADR_PAGE21 => {
                    let g = rc.tlsgd(r.sym).wrapping_add(a);
                    set_adr(out, off, page(g).wrapping_sub(page(p)) >> 12);
                }
                R_TLSGD_ADD_LO12_NC => set_lo12(out, off, rc.tlsgd(r.sym).wrapping_add(a), 0),
                R_TLSLD_ADR_PAGE21 => {
                    let g = rc.tlsld().wrapping_add(a);
                    set_adr(out, off, page(g).wrapping_sub(page(p)) >> 12);
                }
                R_TLSLD_ADD_LO12_NC => set_lo12(out, off, rc.tlsld().wrapping_add(a), 0),
                R_TLSLD_MOVW_DTPREL_G1 => set_movw_signed(out, off, rc.dtp(rc.sa(&r)) as i64, 1),
                R_TLSLD_MOVW_DTPREL_G0_NC => set_movw(out, off, rc.dtp(rc.sa(&r))),
                R_TLSLD_ADD_DTPREL_HI12 => {
                    set_bits(out, off, (rc.dtp(rc.sa(&r)) >> 12) & 0xfff, 10, 12)
                }
                R_TLSLD_ADD_DTPREL_LO12 | R_TLSLD_ADD_DTPREL_LO12_NC => {
                    set_lo12(out, off, rc.dtp(rc.sa(&r)), 0)
                }
                R_TLSLD_LDST8_DTPREL_LO12..=R_TLSLD_LDST64_DTPREL_LO12_NC
                | R_TLSLD_LDST128_DTPREL_LO12
                | R_TLSLD_LDST128_DTPREL_LO12_NC => {
                    let scale = ldst_scale(r.ty, rd32::<Self>(out, off));
                    set_lo12(out, off, rc.dtp(rc.sa(&r)), scale);
                }
                _ => rc.error(&r, "unsupported relocation"),
            }
        }
        Ok(())
    }

    fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let tomb = rc.tombstone();
        rc.apply_debug(out, R_ABS64, [R_ABS32, R_ABS32], |rc, r, out| {
            let off = r.offset as usize;
            match r.ty {
                R_NONE | R_NONE_OLD => {}
                R_ABS64 => wr64::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_ABS32 => wr32::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
                R_ABS16 => wr16::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u16),
                R_PREL32 => wr32::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r)) as u32),
                R_PREL64 => wr64::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r))),
                R_TLS_DTPREL64 => wr64::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v))),
                _ => rc.error(r, "unsupported relocation in a non-allocated section"),
            }
        });
        Ok(())
    }

    fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
        let insns = [
            0xa9bf_7bf0u32, // stp x16, x30, [sp, #-16]!
            0x9000_0010,    // adrp x16, Page(.got.plt[2])
            0xf940_0211,    // ldr x17, [x16, Offset(.got.plt[2])]
            0x9100_0210,    // add x16, x16, Offset(.got.plt[2])
            0xd61f_0220,    // br x17
            NOP,
            NOP,
            NOP,
        ];
        for (i, w) in insns.iter().enumerate() {
            wr32::<Self>(b, i * 4, *w);
        }
        let slot = gotplt + 16;
        set_adr(b, 4, page(slot).wrapping_sub(page(plt + 4)) >> 12);
        set_lo12(b, 8, slot, 3);
        set_lo12(b, 12, slot, 0);
    }

    fn write_plt(_ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, _idx: u64, _plt: u64) {
        let insns = [
            0x9000_0010u32, // adrp x16, Page(slot)
            0xf940_0211,    // ldr x17, [x16, Offset(slot)]
            0x9100_0210,    // add x16, x16, Offset(slot)
            0xd61f_0220,    // br x17
        ];
        for (i, w) in insns.iter().enumerate() {
            wr32::<Self>(b, i * 4, *w);
        }
        set_adr(b, 0, page(slot).wrapping_sub(page(ent)) >> 12);
        set_lo12(b, 4, slot, 3);
        set_lo12(b, 8, slot, 0);
    }

    fn gotplt_initial(plt: u64, _ent: u64) -> u64 {
        plt
    }

    const THUNK_SIZE: u64 = 16;

    /// `adrp x16, target; add x16, x16, :lo12:target; br x16` (+ padding).
    fn write_thunk(b: &mut [u8], at: u64, target: u64, _kind: u8, _toc: u64) {
        wr32::<Self>(b, 0, 0x9000_0010);
        wr32::<Self>(b, 4, 0x9100_0210);
        wr32::<Self>(b, 8, 0xd61f_0200);
        wr32::<Self>(b, 12, NOP);
        set_adr(b, 0, page(target).wrapping_sub(page(at)) >> 12);
        set_lo12(b, 4, target, 0);
    }
}

#[allow(dead_code)]
fn _check(_: &Rel) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_fields() {
        let mut b = 0x9000_0010u32.to_le_bytes().to_vec();
        set_adr(&mut b, 0, 0x12345);
        let w = u32::from_le_bytes(b[..4].try_into().unwrap());
        assert_eq!((w >> 29) & 3, 0x12345 & 3);
        assert_eq!((w >> 5) & 0x7ffff, 0x12345 >> 2);
        assert_eq!(w & 0x1f, 0x10);
        let mut b = 0xf940_0211u32.to_le_bytes().to_vec();
        set_lo12(&mut b, 0, 0xabc8, 3);
        let w = u32::from_le_bytes(b[..4].try_into().unwrap());
        assert_eq!((w >> 10) & 0xfff, 0xbc8 >> 3);
        let mut b = 0xd280_0000u32.to_le_bytes().to_vec();
        set_movw_signed(&mut b, 0, -2, 0);
        let w = u32::from_le_bytes(b[..4].try_into().unwrap());
        assert_eq!(w & (1 << 30), 0, "MOVN");
        assert_eq!((w >> 5) & 0xffff, 1);
    }
}
