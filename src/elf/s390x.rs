//! s390x (big-endian): halfword-scaled PC-relative relocations, GOT and PLT addressing, TLS
//! with `__tls_get_offset` (relaxed in executables), the PLT.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct S390x;

const R_NONE: u32 = 0;
const R_8: u32 = 1;
const R_12: u32 = 2;
const R_16: u32 = 3;
const R_32: u32 = 4;
const R_PC32: u32 = 5;
const R_GOT12: u32 = 6;
const R_GOT32: u32 = 7;
const R_PLT32: u32 = 8;
const R_GOTOFF32: u32 = 13;
const R_GOTPC: u32 = 14;
const R_GOT16: u32 = 15;
const R_PC16: u32 = 16;
const R_PC16DBL: u32 = 17;
const R_PLT16DBL: u32 = 18;
const R_PC32DBL: u32 = 19;
const R_PLT32DBL: u32 = 20;
const R_GOTPCDBL: u32 = 21;
const R_64: u32 = 22;
const R_PC64: u32 = 23;
const R_GOT64: u32 = 24;
const R_PLT64: u32 = 25;
const R_GOTENT: u32 = 26;
const R_GOTOFF16: u32 = 27;
const R_GOTOFF64: u32 = 28;
const R_GOTPLT12: u32 = 29;
const R_GOTPLT16: u32 = 30;
const R_GOTPLT32: u32 = 31;
const R_GOTPLT64: u32 = 32;
const R_GOTPLTENT: u32 = 33;
const R_PLTOFF16: u32 = 34;
const R_PLTOFF32: u32 = 35;
const R_PLTOFF64: u32 = 36;
const R_TLS_LOAD: u32 = 37;
const R_TLS_GDCALL: u32 = 38;
const R_TLS_LDCALL: u32 = 39;
const R_TLS_GD32: u32 = 40;
const R_TLS_GD64: u32 = 41;
const R_TLS_GOTIE12: u32 = 42;
const R_TLS_GOTIE32: u32 = 43;
const R_TLS_GOTIE64: u32 = 44;
const R_TLS_LDM32: u32 = 45;
const R_TLS_LDM64: u32 = 46;
const R_TLS_IE32: u32 = 47;
const R_TLS_IE64: u32 = 48;
const R_TLS_IEENT: u32 = 49;
const R_TLS_LE32: u32 = 50;
const R_TLS_LE64: u32 = 51;
const R_TLS_LDO32: u32 = 52;
const R_TLS_LDO64: u32 = 53;
const R_TLS_DTPOFF: u32 = 55;
const R_20: u32 = 57;
const R_GOT20: u32 = 58;
const R_GOTPLT20: u32 = 59;
const R_TLS_GOTIE20: u32 = 60;
const R_PC12DBL: u32 = 62;
const R_PLT12DBL: u32 = 63;
const R_PC24DBL: u32 = 64;
const R_PLT24DBL: u32 = 65;

fn set_20(d: &mut [u8], o: usize, v: u64) {
    // DL (12 bits) at bits 4..15 of the field, DH (8 bits) after it.
    let w = rd32::<S390x>(d, o);
    let v = v as u32;
    wr32::<S390x>(
        d,
        o,
        (w & 0xf000_00ff) | ((v & 0xfff) << 16) | ((v & 0xff000) >> 4),
    );
}

fn set_12(d: &mut [u8], o: usize, v: u64) {
    let h = u16::from_be_bytes([d[o], d[o + 1]]);
    wr16::<S390x>(d, o, (h & 0xf000) | (v as u16 & 0xfff));
}

impl S390x {
    fn got_base(rc: &RelocCtx<'_, '_, Self>) -> u64 {
        if rc.lay.gotplt != 0 {
            rc.lay.gotplt
        } else {
            rc.lay.got
        }
    }
}

impl Target for S390x {
    const M: Machine = Machine::S390x;
    const E_MACHINE: u16 = EM_S390;
    const IS64: bool = true;
    const BE: bool = true;
    const MAX_PAGE: u64 = 0x1000;
    const PLT0_SIZE: u64 = 32;
    const PLT_SIZE: u64 = 32;
    const R_ABS: u32 = R_64;
    const R_RELATIVE: u32 = 12;
    const R_GLOB_DAT: u32 = 10;
    const R_JUMP_SLOT: u32 = 11;
    const R_COPY: u32 = 9;
    const R_IRELATIVE: u32 = 61;
    const R_DTPMOD: u32 = 54;
    const R_DTPOFF: u32 = R_TLS_DTPOFF;
    const R_TPOFF: u32 = 56;
    const TLS_VARIANT2: bool = true;

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
            let (sr, kind) = ctx.sym_kind(o, r.sym);
            let imported = matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
            match r.ty {
                R_NONE | R_GOTOFF32 | R_GOTOFF16 | R_GOTOFF64 | R_GOTPC | R_GOTPCDBL
                | R_TLS_LOAD | R_TLS_LDO32 | R_TLS_LDO64 => {}
                R_64 => ctx.scan_abs_word(o, si, &r, st),
                R_8 | R_12 | R_16 | R_20 | R_32 => ctx.scan_abs_narrow(o, si, &r),
                R_PC16 | R_PC32 | R_PC64 | R_PC12DBL | R_PC16DBL | R_PC24DBL | R_PC32DBL => {
                    ctx.scan_pcrel(o, si, &r)
                }
                R_PLT32 | R_PLT64 | R_PLT12DBL | R_PLT16DBL | R_PLT24DBL | R_PLT32DBL
                | R_PLTOFF16 | R_PLTOFF32 | R_PLTOFF64 => ctx.scan_call(o, &r),
                R_GOT12 | R_GOT16 | R_GOT20 | R_GOT32 | R_GOT64 | R_GOTENT | R_GOTPLT12
                | R_GOTPLT16 | R_GOTPLT20 | R_GOTPLT32 | R_GOTPLT64 | R_GOTPLTENT => {
                    ctx.scan_got(o, &r)
                }
                R_TLS_GD32 | R_TLS_GD64 => {
                    if ctx.relax_tls() {
                        ctx.scan_tlsgd(o, &r);
                    } else {
                        ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
                    }
                }
                R_TLS_GDCALL | R_TLS_LDCALL => {}
                R_TLS_LDM32 | R_TLS_LDM64 => {
                    if !ctx.relax_tls() {
                        ctx.scan
                            .needs_tlsld
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                R_TLS_GOTIE12 | R_TLS_GOTIE20 | R_TLS_GOTIE32 | R_TLS_GOTIE64 | R_TLS_IE32
                | R_TLS_IE64 | R_TLS_IEENT => ctx.scan_gottp(o, &r),
                R_TLS_LE32 | R_TLS_LE64 => ctx.scan_tpoff(o, si, &r),
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
        let relax = ctx.relax_tls();
        for k in 0..rc.len() {
            let r = rc.rel(k);
            let off = r.offset as usize;
            let p = rc.p(&r);
            let a = r.addend as u64;
            let dbl = |v: u64| (v as i64 >> 1) as u64;
            match r.ty {
                R_NONE | R_TLS_LOAD => {}
                R_64 => {
                    let v = rc.abs_word(&r);
                    wr64::<Self>(out, off, v);
                }
                R_32 => wr32::<Self>(out, off, rc.sa(&r) as u32),
                R_16 => wr16::<Self>(out, off, rc.sa(&r) as u16),
                R_12 => set_12(out, off, rc.sa(&r)),
                R_20 => set_20(out, off, rc.sa(&r)),
                R_8 => out[off] = rc.sa(&r) as u8,
                R_PC16 => wr16::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u16),
                R_PC32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u32),
                R_PC64 => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(p)),
                R_PC16DBL => wr16::<Self>(out, off, dbl(rc.sa(&r).wrapping_sub(p)) as u16),
                R_PC32DBL => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 33);
                    wr32::<Self>(out, off, dbl(v) as u32);
                }
                R_PC12DBL | R_PLT12DBL => set_12(out, off, dbl(rc.call_target(&r).wrapping_sub(p))),
                R_PC24DBL | R_PLT24DBL => {
                    let v = dbl(rc.call_target(&r).wrapping_sub(p)) as u32 & 0xff_ffff;
                    let w = rd32::<Self>(out, off);
                    wr32::<Self>(out, off, (w & 0xff00_0000) | v);
                }
                R_PLT16DBL => {
                    wr16::<Self>(out, off, dbl(rc.call_target(&r).wrapping_sub(p)) as u16)
                }
                R_PLT32DBL => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 33);
                    wr32::<Self>(out, off, dbl(v) as u32);
                }
                R_PLT32 => wr32::<Self>(out, off, rc.call_target(&r).wrapping_sub(p) as u32),
                R_PLT64 => wr64::<Self>(out, off, rc.call_target(&r).wrapping_sub(p)),
                R_PLTOFF16 => wr16::<Self>(out, off, rc.call_target(&r).wrapping_sub(gb) as u16),
                R_PLTOFF32 => wr32::<Self>(out, off, rc.call_target(&r).wrapping_sub(gb) as u32),
                R_PLTOFF64 => wr64::<Self>(out, off, rc.call_target(&r).wrapping_sub(gb)),
                R_GOTOFF16 => wr16::<Self>(out, off, rc.sa(&r).wrapping_sub(gb) as u16),
                R_GOTOFF32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(gb) as u32),
                R_GOTOFF64 => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(gb)),
                R_GOTPC => wr32::<Self>(out, off, gb.wrapping_add(a).wrapping_sub(p) as u32),
                R_GOTPCDBL => {
                    wr32::<Self>(out, off, dbl(gb.wrapping_add(a).wrapping_sub(p)) as u32)
                }
                R_GOT12 | R_GOTPLT12 => {
                    set_12(out, off, rc.got(r.sym).wrapping_add(a).wrapping_sub(gb))
                }
                R_GOT16 | R_GOTPLT16 => wr16::<Self>(
                    out,
                    off,
                    rc.got(r.sym).wrapping_add(a).wrapping_sub(gb) as u16,
                ),
                R_GOT20 | R_GOTPLT20 => {
                    set_20(out, off, rc.got(r.sym).wrapping_add(a).wrapping_sub(gb))
                }
                R_GOT32 | R_GOTPLT32 => wr32::<Self>(
                    out,
                    off,
                    rc.got(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                ),
                R_GOT64 | R_GOTPLT64 => {
                    wr64::<Self>(out, off, rc.got(r.sym).wrapping_add(a).wrapping_sub(gb))
                }
                R_GOTENT | R_GOTPLTENT => wr32::<Self>(
                    out,
                    off,
                    dbl(rc.got(r.sym).wrapping_add(a).wrapping_sub(p)) as u32,
                ),
                // General dynamic: a literal with the GOT offset of the pair, and a marked call
                // to __tls_get_offset (which returns a TP-relative offset).
                R_TLS_GD32 | R_TLS_GD64 => {
                    let v = if relax {
                        if rc.is_local(r.sym) {
                            rc.tp(rc.sa(&r))
                        } else {
                            rc.gottp(r.sym).wrapping_sub(gb)
                        }
                    } else {
                        rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(gb)
                    };
                    if r.ty == R_TLS_GD64 {
                        wr64::<Self>(out, off, v);
                    } else {
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TLS_GDCALL => {
                    if relax && off + 6 <= out.len() {
                        if rc.is_local(r.sym) {
                            // brasl → brcl 0,. (a 6-byte nop)
                            out[off..off + 6].copy_from_slice(&[0xc0, 0x04, 0, 0, 0, 0]);
                        } else {
                            // brasl → lg %r2,0(%r2,%r12)
                            out[off..off + 6]
                                .copy_from_slice(&[0xe3, 0x22, 0xc0, 0x00, 0x00, 0x04]);
                        }
                    }
                }
                R_TLS_LDM32 | R_TLS_LDM64 => {
                    let v = if relax {
                        0
                    } else {
                        rc.tlsld().wrapping_add(a).wrapping_sub(gb)
                    };
                    if r.ty == R_TLS_LDM64 {
                        wr64::<Self>(out, off, v);
                    } else {
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TLS_LDCALL => {
                    if relax && off + 6 <= out.len() {
                        out[off..off + 6].copy_from_slice(&[0xc0, 0x04, 0, 0, 0, 0]);
                    }
                }
                R_TLS_LDO32 | R_TLS_LDO64 => {
                    let v = if relax {
                        rc.tp(rc.sa(&r))
                    } else {
                        rc.dtp(rc.sa(&r))
                    };
                    if r.ty == R_TLS_LDO64 {
                        wr64::<Self>(out, off, v);
                    } else {
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TLS_GOTIE12 => set_12(out, off, rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb)),
                R_TLS_GOTIE20 => set_20(out, off, rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb)),
                R_TLS_GOTIE32 => wr32::<Self>(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                ),
                R_TLS_GOTIE64 => {
                    wr64::<Self>(out, off, rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb))
                }
                R_TLS_IE32 => wr32::<Self>(out, off, rc.gottp(r.sym).wrapping_add(a) as u32),
                R_TLS_IE64 => wr64::<Self>(out, off, rc.gottp(r.sym).wrapping_add(a)),
                R_TLS_IEENT => wr32::<Self>(
                    out,
                    off,
                    dbl(rc.gottp(r.sym).wrapping_add(a).wrapping_sub(p)) as u32,
                ),
                R_TLS_LE32 => wr32::<Self>(out, off, rc.tp(rc.sa(&r)) as u32),
                R_TLS_LE64 => wr64::<Self>(out, off, rc.tp(rc.sa(&r))),
                _ => rc.error(&r, "unsupported relocation"),
            }
        }
        Ok(())
    }

    fn apply_nonalloc(rc: &mut RelocCtx<'_, '_, Self>, out: &mut [u8]) -> Result<()> {
        let tomb = rc.tombstone();
        rc.apply_debug(out, R_64, [R_32, R_32], |rc, r, out| {
            let off = r.offset as usize;
            match r.ty {
                R_NONE => {}
                R_64 => wr64::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_32 => wr32::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
                R_16 => wr16::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u16),
                R_8 => out[off] = rc.sa_debug(r).unwrap_or(tomb) as u8,
                R_PC32 => wr32::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r)) as u32),
                R_PC64 => wr64::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r))),
                R_TLS_LDO32 => {
                    wr32::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v)) as u32)
                }
                R_TLS_LDO64 | R_TLS_DTPOFF => {
                    wr64::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v)))
                }
                _ => rc.error(r, "unsupported relocation in a non-allocated section"),
            }
        });
        Ok(())
    }

    fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
        b[..32].copy_from_slice(&[
            0xe3, 0x10, 0xf0, 0x38, 0x00, 0x24, // stg %r1,56(%r15)
            0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, // larl %r1,_GLOBAL_OFFSET_TABLE_
            0xd2, 0x07, 0xf0, 0x30, 0x10, 0x08, // mvc 48(8,%r15),8(%r1)
            0xe3, 0x10, 0x10, 0x10, 0x00, 0x04, // lg %r1,16(%r1)
            0x07, 0xf1, // br %r1
            0x07, 0x00, 0x07, 0x00, 0x07, 0x00, // nopr
        ]);
        wr32::<Self>(b, 8, (gotplt.wrapping_sub(plt + 6) >> 1) as u32);
    }

    fn write_plt(_ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, idx: u64, plt: u64) {
        b[..32].copy_from_slice(&[
            0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, // larl %r1,<slot>
            0xe3, 0x10, 0x10, 0x00, 0x00, 0x04, // lg %r1,0(%r1)
            0x07, 0xf1, // br %r1
            0x0d, 0x10, // basr %r1,%r0
            0xe3, 0x10, 0x10, 0x0c, 0x00, 0x14, // lgf %r1,12(%r1)
            0xc0, 0xf4, 0x00, 0x00, 0x00, 0x00, // jg <PLT0>
            0x00, 0x00, 0x00, 0x00, // offset of the relocation in .rela.plt
        ]);
        wr32::<Self>(b, 2, (slot.wrapping_sub(ent) >> 1) as u32);
        wr32::<Self>(b, 24, (plt.wrapping_sub(ent + 22) >> 1) as u32);
        wr32::<Self>(b, 28, (idx * 24) as u32);
    }

    fn gotplt_initial(_plt: u64, ent: u64) -> u64 {
        ent + 14
    }
}

#[allow(dead_code)]
fn _uses(_: &Rel) {}
