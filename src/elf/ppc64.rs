//! POWER, 64-bit ELFv2 (ppc64le, and big-endian ppc64 as musl uses it): TOC-relative
//! addressing, local entry points, calls to other modules through stubs that save the TOC
//! pointer (the `nop` after the call restores it), `.glink` lazy binding, TLS.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct Ppc64le;
pub struct Ppc64be;

const R_NONE: u32 = 0;
const R_ADDR32: u32 = 1;
const R_ADDR24: u32 = 2;
const R_ADDR16: u32 = 3;
const R_ADDR16_LO: u32 = 4;
const R_ADDR16_HI: u32 = 5;
const R_ADDR16_HA: u32 = 6;
const R_ADDR14: u32 = 7;
const R_REL24: u32 = 10;
const R_REL14: u32 = 11;
const R_GOT16: u32 = 14;
const R_GOT16_LO: u32 = 15;
const R_GOT16_HI: u32 = 16;
const R_GOT16_HA: u32 = 17;
const R_REL32: u32 = 26;
const R_ADDR64: u32 = 38;
const R_ADDR16_HIGHER: u32 = 39;
const R_ADDR16_HIGHERA: u32 = 40;
const R_ADDR16_HIGHEST: u32 = 41;
const R_ADDR16_HIGHESTA: u32 = 42;
const R_REL64: u32 = 44;
const R_TOC16: u32 = 47;
const R_TOC16_LO: u32 = 48;
const R_TOC16_HI: u32 = 49;
const R_TOC16_HA: u32 = 50;
const R_TOC: u32 = 51;
const R_ADDR16_DS: u32 = 56;
const R_ADDR16_LO_DS: u32 = 57;
const R_GOT16_DS: u32 = 58;
const R_GOT16_LO_DS: u32 = 59;
const R_TOC16_DS: u32 = 63;
const R_TOC16_LO_DS: u32 = 64;
const R_TLS: u32 = 67;
const R_DTPMOD64: u32 = 68;
const R_TPREL16: u32 = 69;
const R_TPREL16_LO: u32 = 70;
const R_TPREL16_HI: u32 = 71;
const R_TPREL16_HA: u32 = 72;
const R_TPREL64: u32 = 73;
const R_DTPREL16: u32 = 74;
const R_DTPREL16_LO: u32 = 75;
const R_DTPREL16_HI: u32 = 76;
const R_DTPREL16_HA: u32 = 77;
const R_DTPREL64: u32 = 78;
const R_GOT_TLSGD16: u32 = 79;
const R_GOT_TLSGD16_LO: u32 = 80;
const R_GOT_TLSGD16_HI: u32 = 81;
const R_GOT_TLSGD16_HA: u32 = 82;
const R_GOT_TLSLD16: u32 = 83;
const R_GOT_TLSLD16_LO: u32 = 84;
const R_GOT_TLSLD16_HI: u32 = 85;
const R_GOT_TLSLD16_HA: u32 = 86;
const R_GOT_TPREL16_DS: u32 = 87;
const R_GOT_TPREL16_LO_DS: u32 = 88;
const R_GOT_TPREL16_HI: u32 = 89;
const R_GOT_TPREL16_HA: u32 = 90;
/// `R_PPC64_GOT_DTPREL16_DS` to `_HA`: GOT entries holding a DTP offset.
const R_GOT_DTPREL16_DS: u32 = 91;
const R_GOT_DTPREL16_HA: u32 = 94;
const R_TPREL16_DS: u32 = 95;
const R_TPREL16_LO_DS: u32 = 96;
const R_DTPREL16_DS: u32 = 101;
const R_DTPREL16_LO_DS: u32 = 102;
const R_TLSGD: u32 = 107;
const R_TLSLD: u32 = 108;
const R_ADDR16_HIGH: u32 = 110;
const R_ADDR16_HIGHA: u32 = 111;
const R_TPREL16_HIGH: u32 = 112;
const R_TPREL16_HIGHA: u32 = 113;
const R_ADDR64_LOCAL: u32 = 117;
const R_ENTRY: u32 = 118;
const R_REL16: u32 = 249;
const R_REL16_LO: u32 = 250;
const R_REL16_HI: u32 = 251;
const R_REL16_HA: u32 = 252;

const NOP: u32 = 0x6000_0000;
/// `ld r2, 24(r1)`: restore the TOC pointer after a call through a stub.
const LD_R2: u32 = 0xe841_0018;

#[inline]
fn lo(v: u64) -> u16 {
    v as u16
}
#[inline]
fn hi(v: u64) -> u16 {
    (v >> 16) as u16
}
#[inline]
fn ha(v: u64) -> u16 {
    (v.wrapping_add(0x8000) >> 16) as u16
}

/// The offset of a function's local entry point (ELFv2 `st_other` bits 5..7).
fn local_entry(other: u8) -> u64 {
    match other >> 5 {
        v @ 2..=6 => 1 << v,
        _ => 0,
    }
}

fn toc<T: Target>(rc: &RelocCtx<'_, '_, T>) -> u64 {
    rc.lay.got + 0x8000
}

/// The `st_other` of the definition a relocation's symbol resolves to.
fn sym_other<T: Target>(ctx: &Ctx<'_, T>, o: &Object<'_>, sym: u32) -> u8 {
    if sym < o.first_global {
        return o.sym::<T>(sym).other;
    }
    let id = o.global_id(sym);
    match ctx.def_obj(id) {
        Some((d, i)) => d.sym::<T>(i).other,
        None => 0,
    }
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
        let (sr, kind) = ctx.sym_kind(o, r.sym);
        let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
        match r.ty {
            R_NONE
            | R_TLS
            | R_TLSGD
            | R_TLSLD
            | R_ENTRY
            | R_TOC
            | R_TOC16
            | R_TOC16_LO
            | R_TOC16_HI
            | R_TOC16_HA
            | R_TOC16_DS
            | R_TOC16_LO_DS
            | R_DTPREL16..=R_DTPREL16_HA
            | R_DTPREL16_DS
            | R_DTPREL16_LO_DS
            | R_DTPREL64
            | R_DTPMOD64 => {}
            R_ADDR64 | R_ADDR64_LOCAL => ctx.scan_abs_word(o, si, &r, st),
            R_ADDR32
            | R_ADDR24
            | R_ADDR16
            | R_ADDR16_LO
            | R_ADDR16_HI
            | R_ADDR16_HA
            | R_ADDR14
            | R_ADDR16_DS
            | R_ADDR16_LO_DS
            | R_ADDR16_HIGHER..=R_ADDR16_HIGHESTA
            | R_ADDR16_HIGH
            | R_ADDR16_HIGHA => ctx.scan_abs_narrow(o, si, &r),
            R_REL32 | R_REL64 | R_REL16 | R_REL16_LO | R_REL16_HI | R_REL16_HA => {
                ctx.scan_pcrel(o, si, &r)
            }
            R_REL24 | R_REL14 => {
                ctx.scan_call(o, &r);
                if matches!(
                    kind,
                    SymKind::ImportedData | SymKind::ImportedFunc | SymKind::Ifunc
                ) {
                    ctx.need_thunk(sr, 0);
                }
            }
            R_GOT16 | R_GOT16_LO | R_GOT16_HI | R_GOT16_HA | R_GOT16_DS | R_GOT16_LO_DS => {
                ctx.scan_got(o, &r)
            }
            R_GOT_TLSGD16..=R_GOT_TLSGD16_HA => {
                ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
            }
            R_GOT_TLSLD16..=R_GOT_TLSLD16_HA => ctx
                .scan
                .needs_tlsld
                .store(true, std::sync::atomic::Ordering::Relaxed),
            R_GOT_TPREL16_DS | R_GOT_TPREL16_LO_DS | R_GOT_TPREL16_HI | R_GOT_TPREL16_HA => {
                ctx.scan_gottp(o, &r)
            }
            R_GOT_DTPREL16_DS..=R_GOT_DTPREL16_HA => ctx.error(format!(
                "{}: GOT DTPREL relocations are not supported (type {})",
                o.name, r.ty
            )),
            R_TPREL16..=R_TPREL16_HA
            | R_TPREL16_DS
            | R_TPREL16_LO_DS
            | R_TPREL16_HIGH
            | R_TPREL16_HIGHA
            | R_TPREL64 => ctx.scan_tpoff(o, si, &r),
            _ => ctx.error(format!(
                "{}: unsupported relocation type {} in section {}",
                o.name,
                r.ty,
                String::from_utf8_lossy(o.sec_name::<T>(si))
            )),
        }
    }
}

fn write16<T: Target>(out: &mut [u8], off: usize, v: u16) {
    wr16::<T>(out, off, v);
}

/// A DS-form field: the low two bits belong to the instruction.
fn write16ds<T: Target>(rc: &RelocCtx<'_, '_, T>, r: &Rel, out: &mut [u8], off: usize, v: u16) {
    if v & 3 != 0 {
        rc.error(r, "misaligned DS-form offset");
    }
    let old = u16::from_le_bytes(if T::BE {
        [out[off + 1], out[off]]
    } else {
        [out[off], out[off + 1]]
    });
    wr16::<T>(out, off, (old & 3) | (v & !3));
}

fn apply_alloc<T: Target>(rc: &mut RelocCtx<'_, '_, T>, out: &mut [u8]) -> Result<()> {
    let ctx = rc.ctx;
    let tocb = toc(rc);
    for k in 0..rc.len() {
        let r = rc.rel(k);
        let off = r.offset as usize;
        let p = rc.p(&r);
        let a = r.addend as u64;
        match r.ty {
            R_NONE | R_TLS | R_TLSGD | R_TLSLD | R_ENTRY => {}
            R_ADDR64 => {
                let v = rc.abs_word(&r);
                wr64::<T>(out, off, v);
            }
            R_ADDR64_LOCAL => {
                let v = rc
                    .sa(&r)
                    .wrapping_add(local_entry(sym_other(ctx, rc.obj, r.sym)));
                wr64::<T>(out, off, v);
            }
            R_ADDR32 => wr32::<T>(out, off, rc.sa(&r) as u32),
            R_ADDR16 | R_ADDR16_LO => write16::<T>(out, off, lo(rc.sa(&r))),
            R_ADDR16_HI | R_ADDR16_HIGH => write16::<T>(out, off, hi(rc.sa(&r))),
            R_ADDR16_HA | R_ADDR16_HIGHA => write16::<T>(out, off, ha(rc.sa(&r))),
            R_ADDR16_HIGHER => write16::<T>(out, off, (rc.sa(&r) >> 32) as u16),
            R_ADDR16_HIGHERA => {
                write16::<T>(out, off, (rc.sa(&r).wrapping_add(0x8000) >> 32) as u16)
            }
            R_ADDR16_HIGHEST => write16::<T>(out, off, (rc.sa(&r) >> 48) as u16),
            R_ADDR16_HIGHESTA => {
                write16::<T>(out, off, (rc.sa(&r).wrapping_add(0x8000) >> 48) as u16)
            }
            R_ADDR16_DS | R_ADDR16_LO_DS => write16ds(rc, &r, out, off, lo(rc.sa(&r))),
            R_REL32 => wr32::<T>(out, off, rc.sa(&r).wrapping_sub(p) as u32),
            R_REL64 => wr64::<T>(out, off, rc.sa(&r).wrapping_sub(p)),
            R_REL16 | R_REL16_LO => write16::<T>(out, off, lo(rc.sa(&r).wrapping_sub(p))),
            R_REL16_HI => write16::<T>(out, off, hi(rc.sa(&r).wrapping_sub(p))),
            R_REL16_HA => write16::<T>(out, off, ha(rc.sa(&r).wrapping_sub(p))),
            R_TOC => wr64::<T>(out, off, tocb),
            R_TOC16 | R_TOC16_LO => write16::<T>(out, off, lo(rc.sa(&r).wrapping_sub(tocb))),
            R_TOC16_HI => write16::<T>(out, off, hi(rc.sa(&r).wrapping_sub(tocb))),
            R_TOC16_HA => write16::<T>(out, off, ha(rc.sa(&r).wrapping_sub(tocb))),
            R_TOC16_DS | R_TOC16_LO_DS => {
                write16ds(rc, &r, out, off, lo(rc.sa(&r).wrapping_sub(tocb)))
            }
            R_GOT16 | R_GOT16_LO => write16::<T>(
                out,
                off,
                lo(rc.got(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT16_HI => write16::<T>(
                out,
                off,
                hi(rc.got(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT16_HA => write16::<T>(
                out,
                off,
                ha(rc.got(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT16_DS | R_GOT16_LO_DS => write16ds(
                rc,
                &r,
                out,
                off,
                lo(rc.got(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_REL24 | R_REL14 => {
                let (sr, kind) = rc.kind(r.sym);
                let via_stub = matches!(
                    kind,
                    SymKind::ImportedData | SymKind::ImportedFunc | SymKind::Ifunc
                );
                let target = if via_stub {
                    match ctx.thunk_addr(rc.lay, sr, 0) {
                        Some(t) => t.wrapping_add(a),
                        None => {
                            rc.error(&r, "call to another module without a call stub");
                            continue;
                        }
                    }
                } else if rc.is_undef_weak(r.sym) {
                    rc.call_target(&r)
                } else {
                    // Calls within the module go to the local entry point (TOC already set).
                    rc.sa(&r)
                        .wrapping_add(local_entry(sym_other(ctx, rc.obj, r.sym)))
                };
                let v = target.wrapping_sub(p);
                let insn = rd32::<T>(out, off);
                if r.ty == R_REL24 {
                    rc.check_signed(&r, v as i64, 26);
                    wr32::<T>(out, off, (insn & 0xfc00_0003) | (v as u32 & 0x03ff_fffc));
                } else {
                    rc.check_signed(&r, v as i64, 16);
                    wr32::<T>(out, off, (insn & 0xffff_0003) | (v as u32 & 0xfffc));
                }
                if via_stub && off + 8 <= out.len() && rd32::<T>(out, off + 4) == NOP {
                    wr32::<T>(out, off + 4, LD_R2);
                }
            }
            R_ADDR24 => {
                let insn = rd32::<T>(out, off);
                wr32::<T>(
                    out,
                    off,
                    (insn & 0xfc00_0003) | (rc.sa(&r) as u32 & 0x03ff_fffc),
                );
            }
            R_ADDR14 => {
                let insn = rd32::<T>(out, off);
                wr32::<T>(out, off, (insn & 0xffff_0003) | (rc.sa(&r) as u32 & 0xfffc));
            }
            R_GOT_TLSGD16 | R_GOT_TLSGD16_LO => write16::<T>(
                out,
                off,
                lo(rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT_TLSGD16_HI => write16::<T>(
                out,
                off,
                hi(rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT_TLSGD16_HA => write16::<T>(
                out,
                off,
                ha(rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT_TLSLD16 | R_GOT_TLSLD16_LO => {
                write16::<T>(out, off, lo(rc.tlsld().wrapping_add(a).wrapping_sub(tocb)))
            }
            R_GOT_TLSLD16_HI => {
                write16::<T>(out, off, hi(rc.tlsld().wrapping_add(a).wrapping_sub(tocb)))
            }
            R_GOT_TLSLD16_HA => {
                write16::<T>(out, off, ha(rc.tlsld().wrapping_add(a).wrapping_sub(tocb)))
            }
            R_GOT_TPREL16_DS | R_GOT_TPREL16_LO_DS => write16ds(
                rc,
                &r,
                out,
                off,
                lo(rc.gottp(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT_TPREL16_HI => write16::<T>(
                out,
                off,
                hi(rc.gottp(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_GOT_TPREL16_HA => write16::<T>(
                out,
                off,
                ha(rc.gottp(r.sym).wrapping_add(a).wrapping_sub(tocb)),
            ),
            R_TPREL16 | R_TPREL16_LO => write16::<T>(out, off, lo(rc.tp(rc.sa(&r)))),
            R_TPREL16_HI | R_TPREL16_HIGH => write16::<T>(out, off, hi(rc.tp(rc.sa(&r)))),
            R_TPREL16_HA | R_TPREL16_HIGHA => write16::<T>(out, off, ha(rc.tp(rc.sa(&r)))),
            R_TPREL16_DS | R_TPREL16_LO_DS => write16ds(rc, &r, out, off, lo(rc.tp(rc.sa(&r)))),
            R_TPREL64 => wr64::<T>(out, off, rc.tp(rc.sa(&r))),
            R_DTPREL16 | R_DTPREL16_LO => write16::<T>(out, off, lo(rc.dtp(rc.sa(&r)))),
            R_DTPREL16_HI => write16::<T>(out, off, hi(rc.dtp(rc.sa(&r)))),
            R_DTPREL16_HA => write16::<T>(out, off, ha(rc.dtp(rc.sa(&r)))),
            R_DTPREL16_DS | R_DTPREL16_LO_DS => write16ds(rc, &r, out, off, lo(rc.dtp(rc.sa(&r)))),
            R_DTPREL64 => wr64::<T>(out, off, rc.dtp(rc.sa(&r))),
            _ => rc.error(&r, "unsupported relocation"),
        }
    }
    Ok(())
}

fn apply_nonalloc<T: Target>(rc: &mut RelocCtx<'_, '_, T>, out: &mut [u8]) -> Result<()> {
    let tomb = rc.tombstone();
    rc.apply_debug(out, R_ADDR64, [R_ADDR32, R_ADDR32], |rc, r, out| {
        let off = r.offset as usize;
        match r.ty {
            R_NONE => {}
            R_ADDR64 => wr64::<T>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
            R_ADDR32 => wr32::<T>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
            R_REL32 => wr32::<T>(out, off, rc.sa(r).wrapping_sub(rc.p(r)) as u32),
            R_REL64 => wr64::<T>(out, off, rc.sa(r).wrapping_sub(rc.p(r))),
            R_DTPREL64 => wr64::<T>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v))),
            _ => rc.error(r, "unsupported relocation in a non-allocated section"),
        }
    });
    Ok(())
}

/// `.glink`'s resolver: works out the PLT index from the entry it was entered from.
fn write_plt0<T: Target>(b: &mut [u8], plt: u64, gotplt: u64) {
    let words = [
        0x7c08_02a6u32, // mflr r0
        0x429f_0005,    // bcl 20,31,.+4
        0x7d68_02a6,    // mflr r11
        0x7c08_03a6,    // mtlr r0
        0x7d8b_6050,    // subf r12, r11, r12
        0x380c_ffcc,    // subi r0, r12, 52
        0x7800_f082,    // srdi r0, r0, 2
        0xe98b_002c,    // ld r12, 44(r11)
        0x7d6c_5a14,    // add r11, r12, r11
        0xe98b_0000,    // ld r12, 0(r11)
        0xe96b_0008,    // ld r11, 8(r11)
        0x7d89_03a6,    // mtctr r12
        0x4e80_0420,    // bctr
    ];
    for (i, w) in words.iter().enumerate() {
        wr32::<T>(b, i * 4, *w);
    }
    wr64::<T>(b, 52, gotplt.wrapping_sub(plt + 8));
}

fn write_plt<T: Target>(b: &mut [u8], ent: u64, plt: u64) {
    // b <resolver>
    let off = plt.wrapping_sub(ent) as u32;
    wr32::<T>(b, 0, 0x4800_0000 | (off & 0x03ff_fffc));
}

/// A call stub to another module: save the TOC pointer, load the target from its slot.
fn write_stub<T: Target>(b: &mut [u8], slot: u64, toc: u64) {
    let v = slot.wrapping_sub(toc);
    let words = [
        0xf841_0018u32,                    // std r2, 24(r1)
        0x3d82_0000 | ha(v) as u32,        // addis r12, r2, v@ha
        0xe98c_0000 | (lo(v) as u32 & !3), // ld r12, v@l(r12)
        0x7d89_03a6,                       // mtctr r12
        0x4e80_0420,                       // bctr
        NOP,
        NOP,
        NOP,
    ];
    for (i, w) in words.iter().enumerate() {
        wr32::<T>(b, i * 4, *w);
    }
}

macro_rules! ppc64_target {
    ($ty:ident, $m:expr, $be:expr) => {
        impl Target for $ty {
            const M: Machine = $m;
            const E_MACHINE: u16 = EM_PPC64;
            const IS64: bool = true;
            const BE: bool = $be;
            const MAX_PAGE: u64 = 0x10000;
            const PLT0_SIZE: u64 = 60;
            const PLT_SIZE: u64 = 4;
            const PLT_ALIGN: u64 = 4;
            const GOTPLT_RESERVED: u64 = 2;
            const GOT0_DYNAMIC: bool = true;
            const R_ABS: u32 = R_ADDR64;
            const R_RELATIVE: u32 = 22;
            const R_GLOB_DAT: u32 = 20;
            const R_JUMP_SLOT: u32 = 21;
            const R_COPY: u32 = 19;
            const R_IRELATIVE: u32 = 248;
            const R_DTPMOD: u32 = R_DTPMOD64;
            const R_DTPOFF: u32 = R_DTPREL64;
            const R_TPOFF: u32 = R_TPREL64;
            const TP_BIAS: i64 = -0x7000;
            const DTP_BIAS: i64 = 0x8000;
            const RELAX_TLS: bool = false;
            const THUNK_SIZE: u64 = 32;

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
                _slot: u64,
                _idx: u64,
                plt: u64,
            ) {
                write_plt::<Self>(b, ent, plt)
            }
            fn gotplt_initial(_plt: u64, ent: u64) -> u64 {
                ent
            }
            fn e_flags(_ctx: &Ctx<'_, Self>) -> u32 {
                2 // ELFv2
            }
            fn write_thunk(b: &mut [u8], _at: u64, target: u64, _kind: u8, toc: u64) {
                write_stub::<Self>(b, target, toc)
            }
        }
    };
}

ppc64_target!(Ppc64le, Machine::Ppc64le, false);
ppc64_target!(Ppc64be, Machine::Ppc64, true);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halves_and_entries() {
        assert_eq!(ha(0x1234_8000), 0x1235);
        assert_eq!(lo(0x1234_8000), 0x8000);
        assert_eq!(local_entry(3 << 5), 8);
        assert_eq!(local_entry(1 << 5), 0);
    }
}
