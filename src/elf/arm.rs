//! 32-bit ARM (EABI): ARM and Thumb-2 code side by side — calls between them become BLX,
//! jumps between them go through thunks — REL relocations whose addends are encoded in the
//! instructions, the PLT, and `.ARM.exidx`, the unwind index Rust's panics rely on: sorted
//! by code address and closed by a `EXIDX_CANTUNWIND` sentinel.

use std::sync::atomic::Ordering;

use super::layout::{Layout, Synthetic};
use super::object::{Object, SecKind};
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd32, wr16, wr32};
use super::write::{DynWriter, RelocCtx, Rels};
use super::*;
use crate::diag::Result;

pub struct Arm;

const R_NONE: u32 = 0;
const R_PC24: u32 = 1;
const R_ABS32: u32 = 2;
const R_REL32: u32 = 3;
const R_ABS16: u32 = 5;
const R_ABS8: u32 = 8;
const R_THM_CALL: u32 = 10;
const R_TLS_DESC: u32 = 13;
const R_TLS_DTPMOD32: u32 = 17;
const R_TLS_DTPOFF32: u32 = 18;
const R_TLS_TPOFF32: u32 = 19;
const R_GOTOFF32: u32 = 24;
const R_BASE_PREL: u32 = 25;
const R_GOT_BREL: u32 = 26;
const R_PLT32: u32 = 27;
const R_CALL: u32 = 28;
const R_JUMP24: u32 = 29;
const R_THM_JUMP24: u32 = 30;
const R_TARGET1: u32 = 38;
const R_V4BX: u32 = 40;
const R_TARGET2: u32 = 41;
const R_PREL31: u32 = 42;
const R_MOVW_ABS_NC: u32 = 43;
const R_MOVT_ABS: u32 = 44;
const R_MOVW_PREL_NC: u32 = 45;
const R_MOVT_PREL: u32 = 46;
const R_THM_MOVW_ABS_NC: u32 = 47;
const R_THM_MOVT_ABS: u32 = 48;
const R_THM_MOVW_PREL_NC: u32 = 49;
const R_THM_MOVT_PREL: u32 = 50;
const R_THM_JUMP19: u32 = 51;
const R_GOT_ABS: u32 = 95;
const R_GOT_PREL: u32 = 96;
const R_THM_JUMP11: u32 = 102;
const R_THM_JUMP8: u32 = 103;
const R_TLS_GD32: u32 = 104;
const R_TLS_LDM32: u32 = 105;
const R_TLS_LDO32: u32 = 106;
const R_TLS_IE32: u32 = 107;
const R_TLS_LE32: u32 = 108;

/// Thunk kinds.
const ARM_TO_THUMB: u8 = 0;
const THUMB_TO_ARM: u8 = 1;

fn sext(v: u64, bits: u32) -> i64 {
    let s = 64 - bits;
    ((v << s) as i64) >> s
}

fn rd16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn thumb_bl_imm(d: &[u8], o: usize) -> i64 {
    let (h1, h2) = (rd16(d, o) as u64, rd16(d, o + 2) as u64);
    let s = (h1 >> 10) & 1;
    let j1 = (h2 >> 13) & 1;
    let j2 = (h2 >> 11) & 1;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    let v = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3ff) << 12) | ((h2 & 0x7ff) << 1);
    sext(v, 25)
}

fn set_thumb_bl(d: &mut [u8], o: usize, v: u64) {
    let s = (v >> 24) & 1;
    let i1 = (v >> 23) & 1;
    let i2 = (v >> 22) & 1;
    let j1 = (!i1 ^ s) & 1;
    let j2 = (!i2 ^ s) & 1;
    let h1 = (rd16(d, o) & 0xf800) as u64 | (s << 10) | ((v >> 12) & 0x3ff);
    let h2 = (rd16(d, o + 2) & 0xd000) as u64 | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7ff);
    wr16::<Arm>(d, o, h1 as u16);
    wr16::<Arm>(d, o + 2, h2 as u16);
}

fn thumb_b19_imm(d: &[u8], o: usize) -> i64 {
    let (h1, h2) = (rd16(d, o) as u64, rd16(d, o + 2) as u64);
    let s = (h1 >> 10) & 1;
    let j1 = (h2 >> 13) & 1;
    let j2 = (h2 >> 11) & 1;
    let v = (s << 20) | (j2 << 19) | (j1 << 18) | ((h1 & 0x3f) << 12) | ((h2 & 0x7ff) << 1);
    sext(v, 21)
}

fn set_thumb_b19(d: &mut [u8], o: usize, v: u64) {
    let h1 = (rd16(d, o) & 0xfbc0) as u64 | (((v >> 20) & 1) << 10) | ((v >> 12) & 0x3f);
    let h2 = (rd16(d, o + 2) & 0xd000) as u64
        | (((v >> 18) & 1) << 13)
        | (((v >> 19) & 1) << 11)
        | ((v >> 1) & 0x7ff);
    wr16::<Arm>(d, o, h1 as u16);
    wr16::<Arm>(d, o + 2, h2 as u16);
}

fn movw_imm(insn: u32) -> i64 {
    sext((((insn >> 4) & 0xf000) | (insn & 0xfff)) as u64, 16)
}

fn set_movw(d: &mut [u8], o: usize, imm: u64) {
    let insn = rd32::<Arm>(d, o);
    let imm = imm as u32 & 0xffff;
    wr32::<Arm>(
        d,
        o,
        (insn & 0xfff0_f000) | ((imm & 0xf000) << 4) | (imm & 0xfff),
    );
}

fn thumb_movw_imm(d: &[u8], o: usize) -> i64 {
    let (h1, h2) = (rd16(d, o) as u64, rd16(d, o + 2) as u64);
    let v = ((h1 & 0xf) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xff);
    sext(v, 16)
}

fn set_thumb_movw(d: &mut [u8], o: usize, imm: u64) {
    let imm = imm & 0xffff;
    let h1 = (rd16(d, o) & 0xfbf0) as u64 | ((imm >> 12) & 0xf) | (((imm >> 11) & 1) << 10);
    let h2 = (rd16(d, o + 2) & 0x8f00) as u64 | (((imm >> 8) & 7) << 12) | (imm & 0xff);
    wr16::<Arm>(d, o, h1 as u16);
    wr16::<Arm>(d, o + 2, h2 as u16);
}

impl Arm {
    /// Whether a branch to `sym` lands in Thumb code: `Some(false)` for ARM code (including
    /// PLT entries), `None` when unknown (a section symbol: same state as the caller).
    fn target_thumb(ctx: &Ctx<'_, Self>, o: &Object<'_>, sym: u32) -> Option<bool> {
        let (_, k) = ctx.sym_kind(o, sym);
        if matches!(
            k,
            SymKind::ImportedData | SymKind::ImportedFunc | SymKind::Ifunc
        ) {
            return Some(false);
        }
        let (d, s) = if sym < o.first_global {
            (o, o.sym::<Self>(sym))
        } else {
            let id = o.global_id(sym);
            let (d, i) = ctx.def_obj(id)?;
            (d, d.sym::<Self>(i))
        };
        let _ = d;
        match s.ty() {
            STT_FUNC | STT_GNU_IFUNC => Some(s.value & 1 != 0),
            _ => None,
        }
    }

    fn got_base(rc: &RelocCtx<'_, '_, Self>) -> u64 {
        if rc.lay.gotplt != 0 {
            rc.lay.gotplt
        } else {
            rc.lay.got
        }
    }
}

impl Target for Arm {
    const M: Machine = Machine::Arm;
    const E_MACHINE: u16 = EM_ARM;
    const IS64: bool = false;
    const BE: bool = false;
    const RELA_DYN: bool = false;
    const MAX_PAGE: u64 = 0x10000;
    const PLT0_SIZE: u64 = 32;
    const PLT_SIZE: u64 = 16;
    const R_ABS: u32 = R_ABS32;
    const R_RELATIVE: u32 = 23;
    const R_GLOB_DAT: u32 = 21;
    const R_JUMP_SLOT: u32 = 22;
    const R_COPY: u32 = 20;
    const R_IRELATIVE: u32 = 160;
    const R_DTPMOD: u32 = R_TLS_DTPMOD32;
    const R_DTPOFF: u32 = R_TLS_DTPOFF32;
    const R_TPOFF: u32 = R_TLS_TPOFF32;
    const R_TLSDESC: u32 = R_TLS_DESC;
    const TLS_TCB: u64 = 8;
    const RELAX_TLS: bool = false;
    const THUNK_SIZE: u64 = 16;

    fn implicit_addend(ty: u32, loc: &[u8]) -> i64 {
        if loc.len() < 4 {
            return match ty {
                R_ABS16 if loc.len() >= 2 => rd16(loc, 0) as i16 as i64,
                R_ABS8 if !loc.is_empty() => loc[0] as i8 as i64,
                _ => 0,
            };
        }
        let w = rd32::<Arm>(loc, 0);
        match ty {
            R_NONE | R_V4BX => 0,
            R_ABS16 => rd16(loc, 0) as i16 as i64,
            R_ABS8 => loc[0] as i8 as i64,
            R_PREL31 => sext(w as u64 & 0x7fff_ffff, 31),
            R_PC24 | R_CALL | R_JUMP24 | R_PLT32 => sext(((w & 0x00ff_ffff) << 2) as u64, 26),
            R_THM_CALL | R_THM_JUMP24 => thumb_bl_imm(loc, 0),
            R_THM_JUMP19 => thumb_b19_imm(loc, 0),
            R_MOVW_ABS_NC | R_MOVT_ABS | R_MOVW_PREL_NC | R_MOVT_PREL => movw_imm(w),
            R_THM_MOVW_ABS_NC | R_THM_MOVT_ABS | R_THM_MOVW_PREL_NC | R_THM_MOVT_PREL => {
                thumb_movw_imm(loc, 0)
            }
            R_THM_JUMP11 => sext(((rd16(loc, 0) & 0x7ff) as u64) << 1, 12),
            R_THM_JUMP8 => sext(((rd16(loc, 0) & 0xff) as u64) << 1, 9),
            _ => w as i32 as i64,
        }
    }

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
                R_NONE | R_V4BX | R_GOTOFF32 | R_BASE_PREL | R_TLS_LDO32 => {}
                R_ABS32 | R_TARGET1 => ctx.scan_abs_word(o, si, &r, st),
                R_ABS16 | R_ABS8 | R_MOVW_ABS_NC | R_MOVT_ABS | R_THM_MOVW_ABS_NC
                | R_THM_MOVT_ABS => ctx.scan_abs_narrow(o, si, &r),
                R_REL32 | R_PREL31 | R_MOVW_PREL_NC | R_MOVT_PREL | R_THM_MOVW_PREL_NC
                | R_THM_MOVT_PREL => ctx.scan_pcrel(o, si, &r),
                R_CALL | R_PLT32 | R_THM_CALL | R_THM_JUMP19 | R_THM_JUMP11 | R_THM_JUMP8 => {
                    ctx.scan_call(o, &r)
                }
                R_JUMP24 | R_PC24 => {
                    ctx.scan_call(o, &r);
                    if Self::target_thumb(ctx, o, r.sym) == Some(true) {
                        ctx.need_thunk(ctx.sym_kind(o, r.sym).0, ARM_TO_THUMB);
                    }
                }
                R_THM_JUMP24 => {
                    ctx.scan_call(o, &r);
                    if Self::target_thumb(ctx, o, r.sym) == Some(false) {
                        ctx.need_thunk(ctx.sym_kind(o, r.sym).0, THUMB_TO_ARM);
                    }
                }
                R_TARGET2 | R_GOT_PREL | R_GOT_BREL | R_GOT_ABS => ctx.scan_got(o, &r),
                R_TLS_GD32 => {
                    let (sr, kind) = ctx.sym_kind(o, r.sym);
                    let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                    ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
                }
                R_TLS_LDM32 => ctx.scan.needs_tlsld.store(true, Ordering::Relaxed),
                R_TLS_IE32 => ctx.scan_gottp(o, &r),
                R_TLS_LE32 => ctx.scan_tpoff(o, si, &r),
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
        let gb = Self::got_base(rc);
        for k in 0..rc.len() {
            let r = rc.rel(k);
            let off = r.offset as usize;
            let p = rc.p(&r);
            let a = r.addend as u64;
            match r.ty {
                R_NONE | R_V4BX => {}
                R_ABS32 | R_TARGET1 => {
                    let v = rc.abs_word(&r);
                    wr32::<Self>(out, off, v as u32);
                }
                R_ABS16 => wr16::<Self>(out, off, rc.sa(&r) as u16),
                R_ABS8 => out[off] = rc.sa(&r) as u8,
                R_REL32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u32),
                R_PREL31 => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 31);
                    let w = rd32::<Self>(out, off);
                    wr32::<Self>(out, off, (w & 0x8000_0000) | (v as u32 & 0x7fff_ffff));
                }
                R_TARGET2 | R_GOT_PREL => wr32::<Self>(
                    out,
                    off,
                    rc.got(r.sym).wrapping_add(a).wrapping_sub(p) as u32,
                ),
                R_GOT_BREL => wr32::<Self>(
                    out,
                    off,
                    rc.got(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                ),
                R_GOT_ABS => wr32::<Self>(out, off, rc.got(r.sym).wrapping_add(a) as u32),
                R_GOTOFF32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(gb) as u32),
                R_BASE_PREL => wr32::<Self>(out, off, gb.wrapping_add(a).wrapping_sub(p) as u32),
                R_CALL | R_PLT32 | R_PC24 | R_JUMP24 => {
                    let target = rc.call_target(&r).wrapping_sub(a);
                    // Switch state only when the target's state is known (not for section
                    // symbols, nor undefined weak symbols that are never called).
                    let thumb = Self::target_thumb(ctx, rc.obj, r.sym) == Some(true);
                    let insn = rd32::<Self>(out, off);
                    if r.ty == R_CALL && thumb {
                        // BL to Thumb code → BLX (unconditional; H bit from bit 1).
                        let v = (target & !1).wrapping_add(a).wrapping_sub(p);
                        rc.check_signed(&r, v as i64, 26);
                        wr32::<Self>(
                            out,
                            off,
                            0xfa00_0000
                                | (((v >> 1) & 1) << 24) as u32
                                | ((v >> 2) & 0x00ff_ffff) as u32,
                        );
                    } else if thumb && (r.ty == R_JUMP24 || r.ty == R_PC24) {
                        let sr = rc.kind(r.sym).0;
                        match ctx.thunk_addr(rc.lay, sr, ARM_TO_THUMB) {
                            Some(t) => {
                                let v = t.wrapping_add(a).wrapping_sub(p);
                                wr32::<Self>(
                                    out,
                                    off,
                                    (insn & 0xff00_0000) | ((v >> 2) & 0x00ff_ffff) as u32,
                                );
                            }
                            None => rc.error(&r, "ARM branch to Thumb code without a thunk"),
                        }
                    } else {
                        let v = (target & !1).wrapping_add(a).wrapping_sub(p);
                        rc.check_signed(&r, v as i64, 26);
                        // A BLX to ARM code turns back into BL.
                        let insn = if insn >> 25 == 0x7d {
                            0xeb00_0000
                        } else {
                            insn & 0xff00_0000
                        };
                        wr32::<Self>(out, off, insn | ((v >> 2) & 0x00ff_ffff) as u32);
                    }
                }
                R_THM_CALL | R_THM_JUMP24 => {
                    let target = rc.call_target(&r).wrapping_sub(a);
                    let to_arm = Self::target_thumb(ctx, rc.obj, r.sym) == Some(false);
                    if r.ty == R_THM_CALL {
                        if to_arm {
                            // BLX: from the word-aligned PC; clear H (bit 12 of the second half).
                            let v = target.wrapping_add(a).wrapping_sub(p & !3);
                            rc.check_signed(&r, v as i64, 25);
                            set_thumb_bl(out, off, v);
                            let h2 = rd16(out, off + 2) & !0x1000;
                            wr16::<Self>(out, off + 2, h2);
                        } else {
                            let v = (target & !1).wrapping_add(a).wrapping_sub(p);
                            rc.check_signed(&r, v as i64, 25);
                            set_thumb_bl(out, off, v);
                            let h2 = rd16(out, off + 2) | 0x1000;
                            wr16::<Self>(out, off + 2, h2);
                        }
                    } else if to_arm {
                        let sr = rc.kind(r.sym).0;
                        match ctx.thunk_addr(rc.lay, sr, THUMB_TO_ARM) {
                            Some(t) => set_thumb_bl(out, off, t.wrapping_add(a).wrapping_sub(p)),
                            None => rc.error(&r, "Thumb branch to ARM code without a thunk"),
                        }
                    } else {
                        let v = (target & !1).wrapping_add(a).wrapping_sub(p);
                        rc.check_signed(&r, v as i64, 25);
                        set_thumb_bl(out, off, v);
                    }
                }
                R_THM_JUMP19 => {
                    let v = (rc.call_target(&r).wrapping_sub(a) & !1)
                        .wrapping_add(a)
                        .wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 21);
                    set_thumb_b19(out, off, v);
                }
                R_THM_JUMP11 => {
                    let v = (rc.call_target(&r).wrapping_sub(a) & !1)
                        .wrapping_add(a)
                        .wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 12);
                    let h = (rd16(out, off) & 0xf800) | ((v >> 1) as u16 & 0x7ff);
                    wr16::<Self>(out, off, h);
                }
                R_THM_JUMP8 => {
                    let v = (rc.call_target(&r).wrapping_sub(a) & !1)
                        .wrapping_add(a)
                        .wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 9);
                    let h = (rd16(out, off) & 0xff00) | ((v >> 1) as u16 & 0xff);
                    wr16::<Self>(out, off, h);
                }
                R_MOVW_ABS_NC => set_movw(out, off, rc.sa(&r)),
                R_MOVT_ABS => set_movw(out, off, rc.sa(&r) >> 16),
                R_MOVW_PREL_NC => set_movw(out, off, rc.sa(&r).wrapping_sub(p)),
                R_MOVT_PREL => set_movw(out, off, rc.sa(&r).wrapping_sub(p) >> 16),
                R_THM_MOVW_ABS_NC => set_thumb_movw(out, off, rc.sa(&r)),
                R_THM_MOVT_ABS => set_thumb_movw(out, off, rc.sa(&r) >> 16),
                R_THM_MOVW_PREL_NC => set_thumb_movw(out, off, rc.sa(&r).wrapping_sub(p)),
                R_THM_MOVT_PREL => set_thumb_movw(out, off, rc.sa(&r).wrapping_sub(p) >> 16),
                R_TLS_GD32 => wr32::<Self>(
                    out,
                    off,
                    rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(p) as u32,
                ),
                R_TLS_LDM32 => {
                    wr32::<Self>(out, off, rc.tlsld().wrapping_add(a).wrapping_sub(p) as u32)
                }
                R_TLS_LDO32 => wr32::<Self>(out, off, rc.dtp(rc.sa(&r)) as u32),
                R_TLS_IE32 => wr32::<Self>(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(p) as u32,
                ),
                R_TLS_LE32 => wr32::<Self>(out, off, rc.tp(rc.sa(&r)) as u32),
                _ => rc.error(&r, "unsupported relocation"),
            }
        }
        Ok(())
    }

    fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let tomb = rc.tombstone();
        for k in 0..rc.len() {
            let r = rc.rel(k);
            let off = r.offset as usize;
            match r.ty {
                R_NONE | R_V4BX => {}
                R_ABS32 | R_TARGET1 => {
                    wr32::<Self>(out, off, rc.sa_debug(&r).unwrap_or(tomb) as u32)
                }
                R_ABS16 => wr16::<Self>(out, off, rc.sa_debug(&r).unwrap_or(tomb) as u16),
                R_ABS8 => out[off] = rc.sa_debug(&r).unwrap_or(tomb) as u8,
                R_REL32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(rc.p(&r)) as u32),
                R_TLS_LDO32 | R_TLS_DTPOFF32 => {
                    wr32::<Self>(out, off, rc.sa_debug(&r).map_or(0, |v| rc.dtp(v)) as u32)
                }
                _ => rc.error(&r, "unsupported relocation in a non-allocated section"),
            }
        }
        Ok(())
    }

    fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
        let off = gotplt.wrapping_sub(plt).wrapping_sub(4 + 4) as u32;
        let words = [
            0xe52d_e004u32,                     // str lr, [sp, #-4]!
            0xe28f_e600 | ((off >> 20) & 0xff), // add lr, pc, #0x0NN00000
            0xe28e_ea00 | ((off >> 12) & 0xff), // add lr, lr, #0x000NN000
            0xe5be_f000 | (off & 0xfff),        // ldr pc, [lr, #0x00000NNN]!
            0xd4d4_d4d4,
            0xd4d4_d4d4,
            0xd4d4_d4d4,
            0xd4d4_d4d4,
        ];
        for (i, w) in words.iter().enumerate() {
            wr32::<Self>(b, i * 4, *w);
        }
    }

    fn write_plt(_ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, _idx: u64, _plt: u64) {
        let off = slot.wrapping_sub(ent).wrapping_sub(8) as u32;
        let words = [
            0xe28f_c600 | ((off >> 20) & 0xff), // add ip, pc, #0x0NN00000
            0xe28c_ca00 | ((off >> 12) & 0xff), // add ip, ip, #0x000NN000
            0xe5bc_f000 | (off & 0xfff),        // ldr pc, [ip, #0x00000NNN]!
            0xd4d4_d4d4,
        ];
        for (i, w) in words.iter().enumerate() {
            wr32::<Self>(b, i * 4, *w);
        }
    }

    fn gotplt_initial(plt: u64, _ent: u64) -> u64 {
        plt
    }

    fn e_flags(ctx: &Ctx<'_, Self>) -> u32 {
        ctx.objs
            .iter()
            .find(|o| o.alive.load(Ordering::Relaxed))
            .map_or(0x0500_0000, |o| o.e_flags & 0xff00_0600)
    }

    fn write_thunk(b: &mut [u8], at: u64, target: u64, kind: u8, _toc: u64) {
        if kind == ARM_TO_THUMB {
            // movw ip, :lower16:(S - (P + 16)); movt ip, :upper16:(...); add ip, ip, pc; bx ip
            let v = target.wrapping_sub(at + 16);
            wr32::<Self>(b, 0, 0xe300_c000);
            wr32::<Self>(b, 4, 0xe340_c000);
            set_movw(b, 0, v);
            set_movw(b, 4, v >> 16);
            wr32::<Self>(b, 8, 0xe08c_c00f);
            wr32::<Self>(b, 12, 0xe12f_ff1c);
        } else {
            // Thumb: movw ip, ...; movt ip, ...; add ip, pc; bx ip — to ARM code.
            let v = target.wrapping_sub(at + 12);
            wr16::<Self>(b, 0, 0xf240);
            wr16::<Self>(b, 2, 0x0c00);
            wr16::<Self>(b, 4, 0xf2c0);
            wr16::<Self>(b, 6, 0x0c00);
            set_thumb_movw(b, 0, v);
            set_thumb_movw(b, 4, v >> 16);
            wr16::<Self>(b, 8, 0x44fc);
            wr16::<Self>(b, 10, 0x4760);
            wr32::<Self>(b, 12, 0xd4d4_d4d4);
        }
    }
}

impl<T: Target> Ctx<'_, T> {
    /// `.ARM.exidx` sections kept, each with the address its code section ends up at.
    fn exidx_inputs(&self, lay: Option<&Layout>) -> Vec<(u64, u32, u32)> {
        let mut v = Vec::new();
        for (oi, o) in self.objs.iter().enumerate() {
            if !o.alive.load(Ordering::Relaxed) {
                continue;
            }
            for (si, s) in o.secs.iter().enumerate() {
                if s.kind == SecKind::Exidx && s.is_live() {
                    let link = o.shdr::<T>(si as u32).link as usize;
                    let addr = if lay.is_some() { o.secs[link].addr } else { 0 };
                    v.push((addr, oi as u32, si as u32));
                }
            }
        }
        v
    }

    pub fn exidx_size(&self) -> u64 {
        let v = self.exidx_inputs(None);
        if v.is_empty() {
            return 0;
        }
        v.iter()
            .map(|&(_, oi, si)| self.objs[oi as usize].secs[si as usize].size as u64)
            .sum::<u64>()
            + 8
    }

    /// The index, sorted by the address of the code each entry covers, then a sentinel
    /// marking the end of the last function.
    pub fn write_exidx(&self, lay: &Layout, b: &mut [u8]) {
        let Some(sec) = lay.out(Synthetic::Exidx) else {
            return;
        };
        let mut v = self.exidx_inputs(Some(lay));
        v.sort_by_key(|e| e.0);
        let mut pos = 0usize;
        let mut code_end = 0u64;
        for &(_, oi, si) in &v {
            let o = &self.objs[oi as usize];
            let s = &o.secs[si as usize];
            let size = s.size as usize;
            let buf = &mut b[pos..pos + size];
            buf.copy_from_slice(o.sec_data(si));
            let link = o.shdr::<T>(si).link as usize;
            code_end = code_end.max(o.secs[link].addr + o.secs[link].size as u64);
            if s.rel_len != 0 {
                let (raw, rela) = o.rel_data::<T>(si);
                let n = o.rel_count::<T>(si);
                let mut rc = RelocCtx::new(
                    self,
                    lay,
                    o,
                    si,
                    sec.addr + pos as u64,
                    0,
                    Rels::Raw { data: raw, rela, n },
                    DynWriter::default(),
                );
                if let Err(e) = T::apply_alloc(&mut rc, buf) {
                    self.error(e.0);
                }
            }
            pos += size;
        }
        if pos + 8 <= b.len() {
            let p = sec.addr + pos as u64;
            wr32::<T>(b, pos, (code_end.wrapping_sub(p) as u32) & 0x7fff_ffff);
            wr32::<T>(b, pos + 4, 1); // EXIDX_CANTUNWIND
        }
    }
}

#[allow(dead_code)]
fn _uses(_: &Rel) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_bl_round_trips() {
        let mut d = vec![0x00, 0xf0, 0x00, 0xf8]; // bl 0
        for v in [0i64, 4, -4, 0x12344, -0x200000, 0xfffffe] {
            set_thumb_bl(&mut d, 0, v as u64);
            assert_eq!(thumb_bl_imm(&d, 0), v, "{v:#x}");
        }
        let mut d = vec![0x40, 0xf2, 0x00, 0x0c];
        set_thumb_movw(&mut d, 0, 0xbeef);
        assert_eq!(thumb_movw_imm(&d, 0), 0xbeefu16 as i16 as i64);
        let mut a = 0xe300_c000u32.to_le_bytes().to_vec();
        set_movw(&mut a, 0, 0x1234);
        assert_eq!(movw_imm(rd32::<Arm>(&a, 0)), 0x1234);
    }
}
