//! i386: REL relocations (addends in the code), %ebx-relative PIC, both PLT forms, TLS relaxation.

use super::object::Object;
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::symbols::{NEEDS_DYNSYM, NEEDS_TLSGD};
use super::target::{Machine, Rel, Target, rd16, rd32, wr16, wr32};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct I386;

const R_NONE: u32 = 0;
const R_32: u32 = 1;
const R_PC32: u32 = 2;
const R_GOT32: u32 = 3;
const R_PLT32: u32 = 4;
const R_GOTOFF: u32 = 9;
const R_GOTPC: u32 = 10;
const R_TLS_TPOFF: u32 = 14;
const R_TLS_IE: u32 = 15;
const R_TLS_GOTIE: u32 = 16;
const R_TLS_LE: u32 = 17;
const R_TLS_GD: u32 = 18;
const R_TLS_LDM: u32 = 19;
const R_16: u32 = 20;
const R_PC16: u32 = 21;
const R_8: u32 = 22;
const R_PC8: u32 = 23;
const R_TLS_LDO_32: u32 = 32;
const R_TLS_IE_32: u32 = 33;
const R_TLS_LE_32: u32 = 34;
const R_TLS_DTPMOD32: u32 = 35;
const R_TLS_DTPOFF32: u32 = 36;
const R_SIZE32: u32 = 38;
const R_TLS_GOTDESC: u32 = 39;
const R_TLS_DESC_CALL: u32 = 40;
const R_GOT32X: u32 = 43;

impl I386 {
    /// `leal x@tlsgd(...), %eax` followed by a call to `___tls_get_addr` we can rewrite.
    /// Either `leal x@tlsgd(,%ebx,1),%eax` (8d 04 1d) + `call ___tls_get_addr@PLT`, or
    /// `leal x@tlsgd(%ebx),%eax` (8d 83) + `call *___tls_get_addr@GOT(%ebx)`: 12 bytes both.
    fn gd_call_ok(d: &[u8], off: usize) -> bool {
        if off < 3 || off + 8 > d.len() {
            return false;
        }
        let sib =
            d[off - 3] == 0x8d && d[off - 2] == 0x04 && d[off - 1] == 0x1d && d[off + 4] == 0xe8;
        let base =
            d[off - 2] == 0x8d && d[off - 1] == 0x83 && d[off + 4] == 0xff && d[off + 5] == 0x93;
        sib || base
    }

    fn ldm_call_ok(d: &[u8], off: usize) -> bool {
        off >= 2
            && off + 9 <= d.len()
            && d[off - 2] == 0x8d
            && (d[off + 4] == 0xe8 || d[off + 4] == 0xff)
    }

    /// `movl/addl x@gotntpoff(%reg), %reg`.
    fn ie_relaxable(d: &[u8], off: usize) -> bool {
        off >= 2
            && off + 4 <= d.len()
            && matches!(d[off - 2], 0x8b | 0x03)
            && d[off - 1] & 0xc0 == 0x80
    }

    fn got_base(rc: &RelocCtx<'_, '_, Self>) -> u64 {
        if rc.lay.gotplt != 0 {
            rc.lay.gotplt
        } else {
            rc.lay.got
        }
    }
}

impl Target for I386 {
    const M: Machine = Machine::I386;
    const E_MACHINE: u16 = EM_386;
    const IS64: bool = false;
    const BE: bool = false;
    const RELA_DYN: bool = false;
    const MAX_PAGE: u64 = 0x1000;
    const PLT0_SIZE: u64 = 16;
    const PLT_SIZE: u64 = 16;
    const R_ABS: u32 = R_32;
    const R_RELATIVE: u32 = 8;
    const R_GLOB_DAT: u32 = 6;
    const R_JUMP_SLOT: u32 = 7;
    const R_COPY: u32 = 5;
    const R_IRELATIVE: u32 = 42;
    const R_DTPMOD: u32 = R_TLS_DTPMOD32;
    const R_DTPOFF: u32 = R_TLS_DTPOFF32;
    const R_TPOFF: u32 = R_TLS_TPOFF;
    const R_TLSDESC: u32 = 41;
    const TLS_VARIANT2: bool = true;

    fn implicit_addend(ty: u32, loc: &[u8]) -> i64 {
        match ty {
            R_16 | R_PC16 if loc.len() >= 2 => i16::from_le_bytes([loc[0], loc[1]]) as i64,
            R_8 | R_PC8 if !loc.is_empty() => loc[0] as i8 as i64,
            R_NONE | R_TLS_DESC_CALL => 0,
            _ if loc.len() >= 4 => i32::from_le_bytes(loc[..4].try_into().unwrap()) as i64,
            _ => 0,
        }
    }

    fn scan(ctx: &Ctx<'_, Self>, o: &Object<'_>, si: u32, st: &mut ScanState) {
        let (raw, rela) = o.rel_data::<Self>(si);
        let n = o.rel_count::<Self>(si);
        let data = o.sec_data(si);
        let mut k = 0;
        while k < n {
            let r = o.rel::<Self>(raw, rela, k, si);
            k += 1;
            if r.sym >= o.nsyms {
                ctx.error(format!(
                    "{}: relocation against an invalid symbol index {}",
                    o.name, r.sym
                ));
                continue;
            }
            ctx.note_use(o, r.sym);
            let off = r.offset as usize;
            match r.ty {
                R_NONE | R_SIZE32 | R_TLS_DESC_CALL | R_GOTOFF | R_GOTPC | R_TLS_LDO_32 => {}
                R_32 => ctx.scan_abs_word(o, si, &r, st),
                R_16 | R_8 => ctx.scan_abs_narrow(o, si, &r),
                R_PC32 | R_PC16 | R_PC8 => ctx.scan_pcrel(o, si, &r),
                R_PLT32 => ctx.scan_call(o, &r),
                R_GOT32 | R_GOT32X => ctx.scan_got(o, &r),
                R_TLS_GD => {
                    if ctx.relax_tls() && Self::gd_call_ok(data, off) {
                        ctx.scan_tlsgd(o, &r);
                        k += 1;
                    } else {
                        let (sr, kind) = ctx.sym_kind(o, r.sym);
                        let imported =
                            matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                        ctx.need(o, sr, NEEDS_TLSGD | if imported { NEEDS_DYNSYM } else { 0 });
                    }
                }
                R_TLS_LDM => {
                    if ctx.relax_tls() && Self::ldm_call_ok(data, off) {
                        k += 1;
                    } else {
                        ctx.scan
                            .needs_tlsld
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                R_TLS_IE | R_TLS_GOTIE | R_TLS_IE_32 => {
                    let local = ctx.sym_kind(o, r.sym).1 == SymKind::Local;
                    let relax = ctx.relax_tls()
                        && local
                        && r.ty == R_TLS_GOTIE
                        && Self::ie_relaxable(data, off);
                    if !relax {
                        ctx.scan_gottp(o, &r);
                    }
                }
                R_TLS_LE | R_TLS_LE_32 => ctx.scan_tpoff(o, si, &r),
                R_TLS_GOTDESC => ctx.scan_tlsdesc(o, &r),
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
        let n = rc.len();
        let mut k = 0;
        while k < n {
            let r = rc.rel(k);
            k += 1;
            let off = r.offset as usize;
            let p = rc.p(&r);
            let a = r.addend as u64;
            match r.ty {
                R_NONE => {}
                R_32 => {
                    let v = rc.abs_word(&r);
                    wr32::<Self>(out, off, v as u32);
                }
                R_16 => wr16::<Self>(out, off, rc.sa(&r) as u16),
                R_8 => out[off] = rc.sa(&r) as u8,
                R_PC32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u32),
                R_PC16 => wr16::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u16),
                R_PC8 => out[off] = rc.sa(&r).wrapping_sub(p) as u8,
                R_PLT32 => wr32::<Self>(out, off, rc.call_target(&r).wrapping_sub(p) as u32),
                R_GOTOFF => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(gb) as u32),
                R_GOTPC => wr32::<Self>(out, off, gb.wrapping_add(a).wrapping_sub(p) as u32),
                R_GOT32 | R_GOT32X => {
                    // Without a base register (`mov foo@GOT, %reg`) the GOT entry's address is
                    // absolute; otherwise it is relative to the GOT base in %ebx.
                    let absolute = r.ty == R_GOT32X && off >= 1 && out[off - 1] & 0xc7 == 0x05;
                    let g = rc.got(r.sym).wrapping_add(a);
                    wr32::<Self>(
                        out,
                        off,
                        if absolute { g } else { g.wrapping_sub(gb) } as u32,
                    );
                }
                R_SIZE32 => wr32::<Self>(out, off, rc.size_of(r.sym).wrapping_add(a) as u32),
                R_TLS_GD => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    if ctx.relax_tls() && Self::gd_call_ok(data, in_off) {
                        k += 1;
                        let w = if out[off - 2] == 0x04 {
                            off - 3
                        } else {
                            off - 2
                        };
                        if rc.is_local(r.sym) {
                            // movl %gs:0, %eax; subl $x@tpoff, %eax
                            out[w..w + 12]
                                .copy_from_slice(&[0x65, 0xa1, 0, 0, 0, 0, 0x81, 0xe8, 0, 0, 0, 0]);
                            let v = rc.tp(rc.s(r.sym));
                            wr32::<Self>(out, w + 8, (v as u32).wrapping_neg());
                        } else {
                            // movl %gs:0, %eax; addl x@gotntpoff(%ebx), %eax
                            out[w..w + 12]
                                .copy_from_slice(&[0x65, 0xa1, 0, 0, 0, 0, 0x03, 0x83, 0, 0, 0, 0]);
                            wr32::<Self>(out, w + 8, rc.gottp(r.sym).wrapping_sub(gb) as u32);
                        }
                    } else {
                        wr32::<Self>(
                            out,
                            off,
                            rc.tlsgd(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                        );
                    }
                }
                R_TLS_LDM => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    if ctx.relax_tls() && Self::ldm_call_ok(data, in_off) {
                        k += 1;
                        if out[off + 4] == 0xe8 {
                            // movl %gs:0,%eax; nop; leal 0(%esi,1),%esi
                            out[off - 2..off + 9].copy_from_slice(&[
                                0x65, 0xa1, 0, 0, 0, 0, 0x90, 0x8d, 0x74, 0x26, 0,
                            ]);
                        } else {
                            // call *___tls_get_addr@GOT(%ebx) is one byte longer.
                            out[off - 2..off + 10]
                                .copy_from_slice(&[0x65, 0xa1, 0, 0, 0, 0, 0x8d, 0xb6, 0, 0, 0, 0]);
                        }
                    } else {
                        wr32::<Self>(out, off, rc.tlsld().wrapping_add(a).wrapping_sub(gb) as u32);
                    }
                }
                R_TLS_LDO_32 => {
                    let v = if ctx.relax_tls() {
                        rc.tp(rc.sa(&r))
                    } else {
                        rc.dtp(rc.sa(&r))
                    };
                    wr32::<Self>(out, off, v as u32);
                }
                R_TLS_IE => wr32::<Self>(out, off, rc.gottp(r.sym).wrapping_add(a) as u32),
                R_TLS_IE_32 => wr32::<Self>(
                    out,
                    off,
                    rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                ),
                R_TLS_GOTIE => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    let relax = ctx.relax_tls()
                        && rc.kind(r.sym).1 == SymKind::Local
                        && Self::ie_relaxable(data, in_off);
                    if relax {
                        let reg = (out[off - 1] >> 3) & 7;
                        out[off - 2] = if out[off - 2] == 0x8b { 0xc7 } else { 0x81 };
                        out[off - 1] = 0xc0 | reg;
                        wr32::<Self>(out, off, rc.tp(rc.sa(&r)) as u32);
                    } else {
                        wr32::<Self>(
                            out,
                            off,
                            rc.gottp(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                        );
                    }
                }
                R_TLS_LE => wr32::<Self>(out, off, rc.tp(rc.sa(&r)) as u32),
                R_TLS_LE_32 => wr32::<Self>(out, off, (rc.tp(rc.sa(&r)) as u32).wrapping_neg()),
                R_TLS_GOTDESC => {
                    if ctx.relax_tls() && off >= 2 {
                        if rc.is_local(r.sym) {
                            // leal x@tlsdesc(%ebx), %eax → leal x@ntpoff, %eax
                            out[off - 1] = 0x05;
                            wr32::<Self>(out, off, rc.tp(rc.sa(&r)) as u32);
                        } else {
                            // → movl x@gotntpoff(%ebx), %eax
                            out[off - 2] = 0x8b;
                            wr32::<Self>(out, off, rc.gottp(r.sym).wrapping_sub(gb) as u32);
                        }
                    } else {
                        wr32::<Self>(
                            out,
                            off,
                            rc.tlsdesc(r.sym).wrapping_add(a).wrapping_sub(gb) as u32,
                        );
                    }
                }
                R_TLS_DESC_CALL => {
                    if ctx.relax_tls() {
                        // call *(%eax) → xchg %ax,%ax
                        out[off] = 0x66;
                        out[off + 1] = 0x90;
                    }
                }
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
                R_NONE => {}
                R_32 => wr32::<Self>(out, off, rc.sa_debug(&r).unwrap_or(tomb) as u32),
                R_16 => wr16::<Self>(out, off, rc.sa_debug(&r).unwrap_or(tomb) as u16),
                R_8 => out[off] = rc.sa_debug(&r).unwrap_or(tomb) as u8,
                R_PC32 => wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(rc.p(&r)) as u32),
                R_TLS_LDO_32 | R_TLS_DTPOFF32 => {
                    wr32::<Self>(out, off, rc.sa_debug(&r).map_or(0, |v| rc.dtp(v)) as u32)
                }
                R_GOTOFF => {
                    wr32::<Self>(out, off, rc.sa(&r).wrapping_sub(Self::got_base(rc)) as u32)
                }
                _ => rc.error(&r, "unsupported relocation in a non-allocated section"),
            }
        }
        Ok(())
    }

    fn write_plt0(ctx: &Ctx<'_, Self>, b: &mut [u8], _plt: u64, gotplt: u64) {
        if ctx.cfg.pic() {
            b[..16].copy_from_slice(&[
                0xff, 0xb3, 4, 0, 0, 0, 0xff, 0xa3, 8, 0, 0, 0, 0x90, 0x90, 0x90, 0x90,
            ]);
        } else {
            b[..16].copy_from_slice(&[
                0xff, 0x35, 0, 0, 0, 0, 0xff, 0x25, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90,
            ]);
            wr32::<Self>(b, 2, (gotplt + 4) as u32);
            wr32::<Self>(b, 8, (gotplt + 8) as u32);
        }
    }

    fn write_plt(ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, idx: u64, plt: u64) {
        if ctx.cfg.pic() {
            let gotplt = slot - (Self::GOTPLT_RESERVED + idx) * 4;
            b[..16].copy_from_slice(&[0xff, 0xa3, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
            wr32::<Self>(b, 2, slot.wrapping_sub(gotplt) as u32);
        } else {
            b[..16].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
            wr32::<Self>(b, 2, slot as u32);
        }
        // Lazy binding pushes the relocation's offset in .rel.plt.
        wr32::<Self>(b, 7, (idx * 8) as u32);
        wr32::<Self>(b, 12, plt.wrapping_sub(ent + 16) as u32);
    }

    fn gotplt_initial(_plt: u64, ent: u64) -> u64 {
        ent + 6
    }
}

#[allow(dead_code)]
fn _uses(d: &[u8], r: &Rel) -> u32 {
    rd16::<I386>(d, 0) as u32 + rd32::<I386>(d, 0) + r.ty
}
