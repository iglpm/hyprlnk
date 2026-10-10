//! x86-64: relocations, relaxations (GOT loads to address computations, TLS models), the PLT.

use super::object::{FL_EXEC, Object};
use super::resolve::Ctx;
use super::scan::{ScanState, SymKind};
use super::target::{Machine, Rel, Target, rd32, wr16, wr32, wr64};
use super::write::RelocCtx;
use super::*;
use crate::diag::Result;

pub struct X86_64;

const R_NONE: u32 = 0;
const R_64: u32 = 1;
const R_PC32: u32 = 2;
const R_GOT32: u32 = 3;
const R_PLT32: u32 = 4;
const R_GOTPCREL: u32 = 9;
const R_32: u32 = 10;
const R_32S: u32 = 11;
const R_16: u32 = 12;
const R_PC16: u32 = 13;
const R_8: u32 = 14;
const R_PC8: u32 = 15;
const R_DTPMOD64: u32 = 16;
const R_DTPOFF64: u32 = 17;
const R_TPOFF64: u32 = 18;
const R_TLSGD: u32 = 19;
const R_TLSLD: u32 = 20;
const R_DTPOFF32: u32 = 21;
const R_GOTTPOFF: u32 = 22;
const R_TPOFF32: u32 = 23;
const R_PC64: u32 = 24;
const R_GOTOFF64: u32 = 25;
const R_GOTPC32: u32 = 26;
const R_GOT64: u32 = 27;
const R_GOTPCREL64: u32 = 28;
const R_GOTPC64: u32 = 29;
const R_GOTPLT64: u32 = 30;
const R_PLTOFF64: u32 = 31;
const R_SIZE32: u32 = 32;
const R_SIZE64: u32 = 33;
const R_GOTPC32_TLSDESC: u32 = 34;
const R_TLSDESC_CALL: u32 = 35;
const R_GOTPCRELX: u32 = 41;
const R_REX_GOTPCRELX: u32 = 42;
const R_CODE_4_GOTPCRELX: u32 = 43;
const R_CODE_4_GOTTPOFF: u32 = 44;
const R_CODE_4_GOTPC32_TLSDESC: u32 = 45;

/// How a GOT load can be rewritten when the symbol is in this module.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GotRelax {
    None,
    /// `mov foo@GOTPCREL(%rip), %reg` → `lea foo(%rip), %reg`
    MovToLea,
    /// `call *foo@GOTPCREL(%rip)` → `addr32 call foo`
    Call,
    /// `jmp *foo@GOTPCREL(%rip)` → `jmp foo; nop`
    Jmp,
}

fn got_relax_kind(data: &[u8], off: usize) -> GotRelax {
    if off < 2 || off + 4 > data.len() {
        return GotRelax::None;
    }
    let (op, modrm) = (data[off - 2], data[off - 1]);
    match (op, modrm) {
        (0x8b, m) if m & 0xc7 == 0x05 => GotRelax::MovToLea,
        (0xff, 0x15) => GotRelax::Call,
        (0xff, 0x25) => GotRelax::Jmp,
        _ => GotRelax::None,
    }
}

impl X86_64 {
    /// Whether a GOT-relative load of `r` is rewritten to use the address directly.
    fn relax_got<'a>(ctx: &Ctx<'a, Self>, o: &Object<'a>, si: u32, r: &Rel) -> GotRelax {
        if !ctx.cfg.relax || r.addend != -4 {
            return GotRelax::None;
        }
        if !matches!(r.ty, R_GOTPCREL | R_GOTPCRELX | R_REX_GOTPCRELX) {
            return GotRelax::None;
        }
        if o.secs[si as usize].fl & FL_EXEC == 0 {
            return GotRelax::None;
        }
        if ctx.sym_kind(o, r.sym).1 != SymKind::Local {
            return GotRelax::None;
        }
        got_relax_kind(o.sec_data(si), r.offset as usize)
    }

    /// `movq foo@GOTTPOFF(%rip), %reg` / `addq ..., %reg` → immediate forms.
    fn relax_ie(data: &[u8], off: usize) -> bool {
        if off < 3 || off + 4 > data.len() {
            return false;
        }
        let (rex, op, modrm) = (data[off - 3], data[off - 2], data[off - 1]);
        (rex == 0x48 || rex == 0x4c) && (op == 0x8b || op == 0x03) && modrm & 0xc7 == 0x05
    }

    /// The instruction after a TLS GD/LD `lea`: is it a call to __tls_get_addr we recognize?
    fn tls_call_ok(data: &[u8], off: usize, ld: bool) -> bool {
        if ld {
            if off < 3 || off + 6 > data.len() {
                return false;
            }
            data[off - 3..off] == [0x48, 0x8d, 0x3d]
                && (data[off + 4] == 0xe8 || data[off + 4..off + 6] == [0xff, 0x15])
        } else {
            if off < 4 || off + 12 > data.len() {
                return false;
            }
            data[off - 4..off] == [0x66, 0x48, 0x8d, 0x3d]
                && (data[off + 4..off + 8] == [0x66, 0x66, 0x48, 0xe8]
                    || data[off + 4..off + 8] == [0x66, 0x48, 0xff, 0x15])
        }
    }
}

impl Target for X86_64 {
    const M: Machine = Machine::X86_64;
    const E_MACHINE: u16 = EM_X86_64;
    const IS64: bool = true;
    const BE: bool = false;
    const MAX_PAGE: u64 = 0x1000;
    const PLT0_SIZE: u64 = 16;
    const PLT_SIZE: u64 = 16;
    const R_ABS: u32 = R_64;
    const R_RELATIVE: u32 = 8;
    const R_GLOB_DAT: u32 = 6;
    const R_JUMP_SLOT: u32 = 7;
    const R_COPY: u32 = 5;
    const R_IRELATIVE: u32 = 37;
    const R_DTPMOD: u32 = R_DTPMOD64;
    const R_DTPOFF: u32 = R_DTPOFF64;
    const R_TPOFF: u32 = R_TPOFF64;
    const R_TLSDESC: u32 = 36;
    const TLS_VARIANT2: bool = true;

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
            match r.ty {
                R_NONE | R_SIZE32 | R_SIZE64 | R_TLSDESC_CALL => {}
                R_64 => ctx.scan_abs_word(o, si, &r, st),
                R_32 | R_32S | R_16 | R_8 => ctx.scan_abs_narrow(o, si, &r),
                R_PC32 | R_PC16 | R_PC8 | R_PC64 => ctx.scan_pcrel(o, si, &r),
                R_PLT32 | R_PLTOFF64 => ctx.scan_call(o, &r),
                R_GOTPCREL | R_GOTPCRELX | R_REX_GOTPCRELX | R_CODE_4_GOTPCRELX => {
                    if Self::relax_got(ctx, o, si, &r) == GotRelax::None {
                        ctx.scan_got(o, &r);
                    }
                }
                R_GOT32 | R_GOT64 | R_GOTPCREL64 | R_GOTPLT64 => ctx.scan_got(o, &r),
                R_GOTOFF64 | R_GOTPC32 | R_GOTPC64 => {}
                R_TLSGD => {
                    if ctx.relax_tls() && Self::tls_call_ok(data, r.offset as usize, false) {
                        ctx.scan_tlsgd(o, &r);
                        k += 1; // the call to __tls_get_addr goes away
                    } else {
                        let (sr, kind) = ctx.sym_kind(o, r.sym);
                        let imported =
                            matches!(kind, SymKind::ImportedData | SymKind::ImportedFunc);
                        ctx.need(
                            o,
                            sr,
                            symbols::NEEDS_TLSGD | if imported { symbols::NEEDS_DYNSYM } else { 0 },
                        );
                    }
                }
                R_TLSLD => {
                    if ctx.relax_tls() && Self::tls_call_ok(data, r.offset as usize, true) {
                        k += 1;
                    } else {
                        ctx.scan
                            .needs_tlsld
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                R_DTPOFF32 | R_DTPOFF64 => {}
                R_GOTTPOFF | R_CODE_4_GOTTPOFF => {
                    let local = ctx.sym_kind(o, r.sym).1 == SymKind::Local;
                    let relax = !ctx.cfg.shared
                        && ctx.cfg.relax
                        && local
                        && r.ty == R_GOTTPOFF
                        && Self::relax_ie(data, r.offset as usize);
                    if !relax {
                        ctx.scan_gottp(o, &r);
                    }
                }
                R_TPOFF32 | R_TPOFF64 => ctx.scan_tpoff(o, si, &r),
                R_GOTPC32_TLSDESC | R_CODE_4_GOTPC32_TLSDESC => ctx.scan_tlsdesc(o, &r),
                R_DTPMOD64 => {}
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
        let n = rc.len();
        let got_base = if rc.lay.gotplt != 0 {
            rc.lay.gotplt
        } else {
            rc.lay.got
        };
        let mut k = 0;
        while k < n {
            let r = rc.rel(k);
            k += 1;
            let off = r.offset as usize;
            if off >= out.len() && r.ty != R_NONE {
                rc.error(&r, "relocation past the end of its section");
                continue;
            }
            let p = rc.p(&r);
            match r.ty {
                R_NONE => {}
                R_64 => {
                    let v = rc.abs_word(&r);
                    wr64::<Self>(out, off, v);
                }
                R_32 => {
                    let v = rc.sa(&r);
                    rc.check_unsigned(&r, v, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_32S => {
                    let v = rc.sa(&r);
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_16 => wr16::<Self>(out, off, rc.sa(&r) as u16),
                R_8 => out[off] = rc.sa(&r) as u8,
                R_PC32 => {
                    let v = rc.sa(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_PC64 => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(p)),
                R_PC16 => wr16::<Self>(out, off, rc.sa(&r).wrapping_sub(p) as u16),
                R_PC8 => out[off] = rc.sa(&r).wrapping_sub(p) as u8,
                R_PLT32 => {
                    let v = rc.call_target(&r).wrapping_sub(p);
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_GOTPCREL | R_GOTPCRELX | R_REX_GOTPCRELX | R_CODE_4_GOTPCRELX => {
                    let relax = Self::relax_got(
                        ctx,
                        rc.obj,
                        rc.sec,
                        &Rel {
                            offset: r.offset + rc.base,
                            ..r
                        },
                    );
                    match relax {
                        GotRelax::None => {
                            let v = rc.got(r.sym).wrapping_add(r.addend as u64).wrapping_sub(p);
                            rc.check_signed(&r, v as i64, 32);
                            wr32::<Self>(out, off, v as u32);
                        }
                        GotRelax::MovToLea => {
                            out[off - 2] = 0x8d;
                            let v = rc.sa(&r).wrapping_sub(p);
                            rc.check_signed(&r, v as i64, 32);
                            wr32::<Self>(out, off, v as u32);
                        }
                        GotRelax::Call | GotRelax::Jmp => {
                            let v = rc.sa(&r).wrapping_sub(p).wrapping_add(1);
                            if relax == GotRelax::Call {
                                out[off - 2] = 0x67; // addr32 prefix
                                out[off - 1] = 0xe8;
                            } else {
                                out[off - 2] = 0xe9;
                                out[off + 3] = 0x90;
                            }
                            let v = if relax == GotRelax::Jmp {
                                v
                            } else {
                                v.wrapping_sub(1)
                            };
                            let at = if relax == GotRelax::Jmp { off - 1 } else { off };
                            rc.check_signed(&r, v as i64, 32);
                            wr32::<Self>(out, at, v as u32);
                        }
                    }
                }
                R_GOTPCREL64 => wr64::<Self>(
                    out,
                    off,
                    rc.got(r.sym).wrapping_add(r.addend as u64).wrapping_sub(p),
                ),
                R_GOT32 => wr32::<Self>(
                    out,
                    off,
                    rc.got(r.sym)
                        .wrapping_sub(got_base)
                        .wrapping_add(r.addend as u64) as u32,
                ),
                R_GOT64 | R_GOTPLT64 => wr64::<Self>(
                    out,
                    off,
                    rc.got(r.sym)
                        .wrapping_sub(got_base)
                        .wrapping_add(r.addend as u64),
                ),
                R_GOTOFF64 => wr64::<Self>(out, off, rc.sa(&r).wrapping_sub(got_base)),
                R_GOTPC32 => wr32::<Self>(
                    out,
                    off,
                    got_base.wrapping_add(r.addend as u64).wrapping_sub(p) as u32,
                ),
                R_GOTPC64 => wr64::<Self>(
                    out,
                    off,
                    got_base.wrapping_add(r.addend as u64).wrapping_sub(p),
                ),
                R_PLTOFF64 => wr64::<Self>(out, off, rc.call_target(&r).wrapping_sub(got_base)),
                R_SIZE32 => wr32::<Self>(
                    out,
                    off,
                    rc.size_of(r.sym).wrapping_add(r.addend as u64) as u32,
                ),
                R_SIZE64 => wr64::<Self>(out, off, rc.size_of(r.sym).wrapping_add(r.addend as u64)),
                R_TLSGD => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    if ctx.relax_tls() && Self::tls_call_ok(data, in_off, false) {
                        k += 1;
                        let s = rc.s(r.sym);
                        if rc.is_local(r.sym) {
                            // mov %fs:0,%rax; lea x@tpoff(%rax),%rax
                            out[off - 4..off + 12].copy_from_slice(&[
                                0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0, 0,
                                0, 0,
                            ]);
                            let v = rc.tp(s.wrapping_add(r.addend as u64).wrapping_add(4));
                            wr32::<Self>(out, off + 8, v as u32);
                        } else {
                            // mov %fs:0,%rax; add x@gottpoff(%rip),%rax
                            out[off - 4..off + 12].copy_from_slice(&[
                                0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x03, 0x05, 0, 0,
                                0, 0,
                            ]);
                            let v = rc.gottp(r.sym).wrapping_sub(p + 12);
                            wr32::<Self>(out, off + 8, v as u32);
                        }
                    } else {
                        let v = rc
                            .tlsgd(r.sym)
                            .wrapping_add(r.addend as u64)
                            .wrapping_sub(p);
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TLSLD => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    if ctx.relax_tls() && Self::tls_call_ok(data, in_off, true) {
                        k += 1;
                        if data[in_off + 4] == 0xe8 {
                            out[off - 3..off + 9].copy_from_slice(&[
                                0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                            ]);
                        } else {
                            out[off - 3..off + 10].copy_from_slice(&[
                                0x66, 0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                            ]);
                        }
                    } else {
                        let v = rc.tlsld().wrapping_add(r.addend as u64).wrapping_sub(p);
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_DTPOFF32 => {
                    let a = rc.sa(&r);
                    let v = if ctx.relax_tls() { rc.tp(a) } else { rc.dtp(a) };
                    wr32::<Self>(out, off, v as u32);
                }
                R_DTPOFF64 => {
                    let a = rc.sa(&r);
                    let v = if ctx.relax_tls() { rc.tp(a) } else { rc.dtp(a) };
                    wr64::<Self>(out, off, v);
                }
                R_GOTTPOFF | R_CODE_4_GOTTPOFF => {
                    let data = rc.obj.sec_data(rc.sec);
                    let in_off = (r.offset + rc.base) as usize;
                    let relax = !ctx.cfg.shared
                        && ctx.cfg.relax
                        && r.ty == R_GOTTPOFF
                        && rc.kind(r.sym).1 == SymKind::Local
                        && Self::relax_ie(data, in_off);
                    if relax {
                        let rex = out[off - 3];
                        let op = out[off - 2];
                        let reg = (out[off - 1] >> 3) & 7;
                        out[off - 3] = if rex == 0x4c { 0x49 } else { 0x48 };
                        out[off - 2] = if op == 0x8b { 0xc7 } else { 0x81 };
                        out[off - 1] = 0xc0 | reg;
                        let v = rc.tp(rc.s(r.sym).wrapping_add(r.addend as u64).wrapping_add(4));
                        wr32::<Self>(out, off, v as u32);
                    } else {
                        let v = rc
                            .gottp(r.sym)
                            .wrapping_add(r.addend as u64)
                            .wrapping_sub(p);
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TPOFF32 => {
                    let v = rc.tp(rc.sa(&r));
                    rc.check_signed(&r, v as i64, 32);
                    wr32::<Self>(out, off, v as u32);
                }
                R_TPOFF64 => wr64::<Self>(out, off, rc.tp(rc.sa(&r))),
                R_GOTPC32_TLSDESC | R_CODE_4_GOTPC32_TLSDESC => {
                    if ctx.relax_tls() && r.ty == R_GOTPC32_TLSDESC && off >= 3 {
                        if rc.is_local(r.sym) {
                            // lea x@tlsdesc(%rip),%rax → mov $x@tpoff,%rax
                            out[off - 3] = 0x48 | ((out[off - 3] >> 2) & 1);
                            out[off - 2] = 0xc7;
                            out[off - 1] = 0xc0 | ((out[off - 1] >> 3) & 7);
                            let v =
                                rc.tp(rc.s(r.sym).wrapping_add(r.addend as u64).wrapping_add(4));
                            wr32::<Self>(out, off, v as u32);
                        } else {
                            // → mov x@gottpoff(%rip),%rax
                            out[off - 2] = 0x8b;
                            let v = rc
                                .gottp(r.sym)
                                .wrapping_add(r.addend as u64)
                                .wrapping_sub(p);
                            wr32::<Self>(out, off, v as u32);
                        }
                    } else {
                        let v = rc
                            .tlsdesc(r.sym)
                            .wrapping_add(r.addend as u64)
                            .wrapping_sub(p);
                        wr32::<Self>(out, off, v as u32);
                    }
                }
                R_TLSDESC_CALL => {
                    if ctx.relax_tls() && off + 2 <= out.len() {
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
        rc.apply_debug(out, R_64, [R_32, R_32S], |rc, r, out| {
            let off = r.offset as usize;
            match r.ty {
                R_NONE => {}
                R_64 => wr64::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb)),
                R_32 | R_32S => wr32::<Self>(out, off, rc.sa_debug(r).unwrap_or(tomb) as u32),
                R_DTPOFF32 => {
                    wr32::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v)) as u32)
                }
                R_DTPOFF64 => wr64::<Self>(out, off, rc.sa_debug(r).map_or(0, |v| rc.dtp(v))),
                R_PC32 => wr32::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r)) as u32),
                R_PC64 => wr64::<Self>(out, off, rc.sa(r).wrapping_sub(rc.p(r))),
                R_SIZE32 => wr32::<Self>(
                    out,
                    off,
                    rc.size_of(r.sym).wrapping_add(r.addend as u64) as u32,
                ),
                R_SIZE64 => wr64::<Self>(out, off, rc.size_of(r.sym).wrapping_add(r.addend as u64)),
                R_16 => wr16::<Self>(out, off, rc.sa(r) as u16),
                R_8 => out[off] = rc.sa(r) as u8,
                _ => rc.error(r, "unsupported relocation in a non-allocated section"),
            }
        });
        Ok(())
    }

    fn write_plt0(_ctx: &Ctx<'_, Self>, b: &mut [u8], plt: u64, gotplt: u64) {
        b[..16].copy_from_slice(&[
            0xff, 0x35, 0, 0, 0, 0, // pushq GOTPLT+8(%rip)
            0xff, 0x25, 0, 0, 0, 0, // jmp *GOTPLT+16(%rip)
            0x0f, 0x1f, 0x40, 0x00, // nopl 0(%rax)
        ]);
        wr32::<Self>(b, 2, (gotplt + 8).wrapping_sub(plt + 6) as u32);
        wr32::<Self>(b, 8, (gotplt + 16).wrapping_sub(plt + 12) as u32);
    }

    fn write_plt(_ctx: &Ctx<'_, Self>, b: &mut [u8], ent: u64, slot: u64, idx: u64, plt: u64) {
        b[..16].copy_from_slice(&[
            0xff, 0x25, 0, 0, 0, 0, // jmp *slot(%rip)
            0x68, 0, 0, 0, 0, // pushq $idx
            0xe9, 0, 0, 0, 0, // jmp PLT0
        ]);
        wr32::<Self>(b, 2, slot.wrapping_sub(ent + 6) as u32);
        wr32::<Self>(b, 7, idx as u32);
        wr32::<Self>(b, 12, plt.wrapping_sub(ent + 16) as u32);
    }

    fn gotplt_initial(_plt: u64, ent: u64) -> u64 {
        ent + 6
    }
}

#[allow(dead_code)]
fn _uses(d: &[u8]) -> u32 {
    rd32::<X86_64>(d, 0)
}
