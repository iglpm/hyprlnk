//! Writing the output: every input section copied and relocated in parallel, the linker's
//! own sections alongside, then the build ID over the finished image.

use std::sync::atomic::Ordering;

use rayon::prelude::*;

use super::config::{BuildId, Discard, Strip};
use super::layout::{Layout, OutSec, Synthetic};
use super::object::{FL_NOBITS, Object, SecKind, Sym};
use super::resolve::Ctx;
use super::scan::{GotKind, SymKind, SymRef};
use super::symbols::*;
use super::target::{Rel, Target, word, wr16, wr32, wr64, wrw};
use super::*;
use crate::diag::{Result, Timer};
use crate::fileio::OutputFile;
use crate::{bail, err};

struct Defer<F: FnMut()>(F);
impl<F: FnMut()> Drop for Defer<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

/// The build ID is a hash of hashes: each writer hashes what it just wrote (still in cache)
/// into its own slot, in an order fixed by the inputs; the linker's small sections and the
/// headers are hashed at the end. No pass re-reads the whole output.
#[derive(Default)]
pub struct BuildIdSlots {
    pub on: bool,
    pub sec_base: Vec<u32>,
    pub merged_base: Vec<u32>,
    pub sym_base: u32,
    pub eh_base: u32,
    pub slots: Option<SyncVec<u64>>,
}

impl BuildIdSlots {
    #[inline]
    pub fn put(&self, slot: usize, data: &[u8], seed: u64) {
        if self.on
            && let Some(s) = &self.slots
        {
            s.set(slot, xxhash_rust::xxh3::xxh3_64_with_seed(data, seed));
        }
    }

    #[inline]
    pub fn put_hash(&self, slot: usize, h: u64) {
        if self.on
            && let Some(s) = &self.slots
        {
            s.set(slot, h);
        }
    }
}

/// A debug relocation's symbol, resolved.
#[derive(Clone, Copy)]
pub enum DebugTarget<'c> {
    Dead,
    Plain(u64),
    Merged {
        base: u64,
        member: &'c super::merge::Member,
        value: u64,
        section: bool,
    },
}

impl DebugTarget<'_> {
    /// S + A, or None for a dropped target (the caller writes the tombstone).
    #[inline]
    pub fn value(&self, addend: i64) -> Option<u64> {
        let a = addend as u64;
        match *self {
            DebugTarget::Dead => None,
            DebugTarget::Plain(v) => Some(v.wrapping_add(a)),
            DebugTarget::Merged {
                base,
                member,
                value,
                section,
            } => {
                if section {
                    Some(base + member.lookup(value.wrapping_add(a))?)
                } else {
                    Some((base + member.lookup(value)?).wrapping_add(a))
                }
            }
        }
    }
}

/// Where a section's relocations come from: the raw table, or decoded records.
pub enum Rels<'r> {
    Raw {
        data: &'r [u8],
        rela: bool,
        n: usize,
    },
    Slice(&'r [Rel]),
}

/// A cursor into `.rela.dyn` for one section's dynamic relocations.
#[derive(Clone, Copy, Default)]
pub struct DynWriter {
    pub buf: Option<OutBuf>,
    pub off: u64,
    pub rel: u64,
    pub sym: u64,
}

impl DynWriter {
    #[inline]
    fn put<T: Target>(&self, idx: u64, offset: u64, sym: u32, ty: u32, addend: i64) {
        let Some(buf) = self.buf else {
            return;
        };
        let w = word::<T>();
        let sz = if T::RELA_DYN { 3 * w } else { 2 * w };
        let e = buf.slice(self.off + idx * sz, sz);
        write_rel::<T>(e, offset, sym, ty, addend);
    }
}

pub fn write_rel<T: Target>(e: &mut [u8], offset: u64, sym: u32, ty: u32, addend: i64) {
    if T::IS64 {
        wr64::<T>(e, 0, offset);
        wr64::<T>(e, 8, ((sym as u64) << 32) | ty as u64);
        if T::RELA_DYN {
            wr64::<T>(e, 16, addend as u64);
        }
    } else {
        wr32::<T>(e, 0, offset as u32);
        wr32::<T>(e, 4, (sym << 8) | (ty & 0xff));
        if T::RELA_DYN {
            wr32::<T>(e, 8, addend as u32);
        }
    }
}

/// Everything a machine needs to relocate one section (or `.eh_frame` record).
pub struct RelocCtx<'c, 'a, T: Target> {
    pub ctx: &'c Ctx<'a, T>,
    pub lay: &'c Layout,
    pub obj: &'c Object<'a>,
    pub sec: u32,
    /// Output address of `out[0]`.
    pub addr: u64,
    /// Input offset of `out[0]`.
    pub base: u64,
    rels: Rels<'c>,
    pub dw: DynWriter,
}

impl<'c, 'a, T: Target> RelocCtx<'c, 'a, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: &'c Ctx<'a, T>,
        lay: &'c Layout,
        obj: &'c Object<'a>,
        sec: u32,
        addr: u64,
        base: u64,
        rels: Rels<'c>,
        dw: DynWriter,
    ) -> Self {
        RelocCtx {
            ctx,
            lay,
            obj,
            sec,
            addr,
            base,
            rels,
            dw,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.rels {
            Rels::Raw { n, .. } => *n,
            Rels::Slice(s) => s.len(),
        }
    }

    /// Relocation `k`, its offset relative to the output buffer.
    #[inline]
    pub fn rel(&self, k: usize) -> Rel {
        let mut r = match &self.rels {
            Rels::Raw { data, rela, .. } => self.obj.rel::<T>(data, *rela, k, self.sec),
            Rels::Slice(s) => s[k],
        };
        r.offset = r.offset.wrapping_sub(self.base);
        r
    }

    /// The place being relocated.
    #[inline]
    pub fn p(&self, r: &Rel) -> u64 {
        self.addr.wrapping_add(r.offset)
    }

    #[inline]
    pub fn kind(&self, sym: u32) -> (SymRef, SymKind) {
        self.ctx.sym_kind(self.obj, sym)
    }

    /// The symbol's address.
    #[inline]
    pub fn s(&self, sym: u32) -> u64 {
        let o = self.obj;
        if sym < o.first_global {
            return self.ctx.local_addr(o, sym);
        }
        let id = o.global_id(sym);
        if id == NONE {
            return 0;
        }
        self.ctx.syms.get(id).addr()
    }

    /// S + A, with references into merged sections mapped.
    #[inline]
    pub fn sa(&self, r: &Rel) -> u64 {
        let o = self.obj;
        if r.sym < o.first_global && r.sym != 0 {
            let s = o.sym::<T>(r.sym);
            if s.shndx < SHN_LORESERVE
                && let Some(sec) = o.secs.get(s.shndx as usize)
            {
                if sec.kind == SecKind::Merge {
                    if s.ty() == STT_SECTION {
                        return self
                            .ctx
                            .merged_addr(o, s.shndx, s.value.wrapping_add(r.addend as u64))
                            .unwrap_or(0);
                    }
                    return self
                        .ctx
                        .merged_addr(o, s.shndx, s.value)
                        .unwrap_or(0)
                        .wrapping_add(r.addend as u64);
                }
                if sec.kind == SecKind::EhFrame {
                    // Rebuilt from its records, not laid out as a section.
                    return if s.ty() == STT_SECTION {
                        self.ctx
                            .eh_frame_addr(o, s.shndx, s.value.wrapping_add(r.addend as u64))
                    } else {
                        self.ctx
                            .eh_frame_addr(o, s.shndx, s.value)
                            .wrapping_add(r.addend as u64)
                    };
                }
                return sec.addr.wrapping_add(s.value).wrapping_add(r.addend as u64);
            }
        }
        self.s(r.sym).wrapping_add(r.addend as u64)
    }

    /// The raw RELA records, when this context reads them straight from an input.
    #[inline]
    pub fn raw_rela(&self) -> Option<&'c [u8]> {
        match &self.rels {
            Rels::Raw {
                data,
                rela: true,
                n,
            } => Some(&data[..*n * if T::IS64 { 24 } else { 12 }]),
            _ => None,
        }
    }

    /// What a debug relocation's symbol resolves to, decided once per symbol.
    #[inline]
    pub fn debug_target(&self, sym: u32) -> DebugTarget<'c> {
        let o = self.obj;
        if sym >= o.first_global {
            return DebugTarget::Plain(self.s(sym));
        }
        if sym == 0 {
            return DebugTarget::Plain(0);
        }
        let s = o.sym::<T>(sym);
        if s.shndx == SHN_UNDEF || s.shndx >= SHN_LORESERVE {
            return DebugTarget::Plain(s.value);
        }
        let Some(sec) = o.secs.get(s.shndx as usize) else {
            return DebugTarget::Dead;
        };
        match sec.kind {
            SecKind::Discarded | SecKind::Ignore => DebugTarget::Dead,
            SecKind::Merge => match self.ctx.merged_member(o, s.shndx) {
                Some((m, mb)) => DebugTarget::Merged {
                    base: m.addr,
                    member: mb,
                    value: s.value,
                    section: s.ty() == STT_SECTION,
                },
                None => DebugTarget::Dead,
            },
            SecKind::EhFrame => DebugTarget::Plain(self.ctx.eh_frame_addr(o, s.shndx, s.value)),
            _ if !sec.is_live() => DebugTarget::Dead,
            _ => DebugTarget::Plain(sec.addr.wrapping_add(s.value)),
        }
    }

    /// Apply a debug section's relocations: pointer-sized (`abs64`) and 32-bit absolute ones
    /// (`abs32`) inline, with the target of the previous symbol cached — consecutive
    /// relocations nearly always use the same one (`.debug_str`) — the rest through `slow`.
    #[inline]
    pub fn apply_debug(
        &mut self,
        out: &mut [u8],
        abs64: u32,
        abs32: [u32; 2],
        mut slow: impl FnMut(&mut Self, &Rel, &mut [u8]),
    ) {
        let tomb = self.tombstone();
        let Some(raw) = self.raw_rela().filter(|_| T::IS64 && !T::BE) else {
            for k in 0..self.len() {
                let r = self.rel(k);
                slow(self, &r, out);
            }
            return;
        };
        let mut last = u32::MAX;
        let mut target = DebugTarget::Dead;
        for rec in raw.as_chunks::<24>().0 {
            let off = u64::from_le_bytes(rec[0..8].try_into().unwrap());
            let info = u64::from_le_bytes(rec[8..16].try_into().unwrap());
            let addend = i64::from_le_bytes(rec[16..24].try_into().unwrap());
            let (ty, sym) = (info as u32, (info >> 32) as u32);
            let off = off.wrapping_sub(self.base);
            let size = if ty == abs64 {
                8
            } else if ty == abs32[0] || ty == abs32[1] {
                4
            } else {
                slow(
                    self,
                    &Rel {
                        offset: off,
                        ty,
                        sym,
                        addend,
                    },
                    out,
                );
                continue;
            };
            if sym != last {
                last = sym;
                target = self.debug_target(sym);
            }
            let v = target.value(addend).unwrap_or(tomb);
            let at = off as usize;
            if size == 8 {
                if let Some(b) = out.get_mut(at..at + 8) {
                    b.copy_from_slice(&v.to_le_bytes());
                }
            } else if let Some(b) = out.get_mut(at..at + 4) {
                b.copy_from_slice(&(v as u32).to_le_bytes());
            }
        }
    }

    /// S + A for a debug section, or None if the symbol's section was dropped (the caller
    /// writes a tombstone). One read of the symbol.
    #[inline]
    pub fn sa_debug(&self, r: &Rel) -> Option<u64> {
        let o = self.obj;
        let a = r.addend as u64;
        if r.sym >= o.first_global {
            return Some(self.s(r.sym).wrapping_add(a));
        }
        if r.sym == 0 {
            return Some(a);
        }
        let s = o.sym::<T>(r.sym);
        if s.shndx == SHN_UNDEF || s.shndx >= SHN_LORESERVE {
            return Some(s.value.wrapping_add(a));
        }
        let sec = o.secs.get(s.shndx as usize)?;
        match sec.kind {
            SecKind::Discarded | SecKind::Ignore => None,
            SecKind::Merge => {
                if s.ty() == STT_SECTION {
                    self.ctx.merged_addr(o, s.shndx, s.value.wrapping_add(a))
                } else {
                    Some(self.ctx.merged_addr(o, s.shndx, s.value)?.wrapping_add(a))
                }
            }
            SecKind::EhFrame if s.ty() == STT_SECTION => {
                Some(self.ctx.eh_frame_addr(o, s.shndx, s.value.wrapping_add(a)))
            }
            SecKind::EhFrame => Some(self.ctx.eh_frame_addr(o, s.shndx, s.value).wrapping_add(a)),
            _ if !sec.is_live() => None,
            _ => Some(sec.addr.wrapping_add(s.value).wrapping_add(a)),
        }
    }

    #[inline]
    fn aux(&self, sym: u32) -> Option<&'c super::scan::Aux> {
        let (sr, _) = self.kind(sym);
        self.ctx.aux_of(sr)
    }

    #[inline]
    pub fn got(&self, sym: u32) -> u64 {
        let a = self.aux(sym).map_or(NONE, |a| a.got);
        self.lay.got + a as u64 * word::<T>()
    }

    #[inline]
    pub fn gottp(&self, sym: u32) -> u64 {
        let a = self.aux(sym).map_or(NONE, |a| a.gottp);
        self.lay.got + a as u64 * word::<T>()
    }

    #[inline]
    pub fn tlsgd(&self, sym: u32) -> u64 {
        let a = self.aux(sym).map_or(NONE, |a| a.tlsgd);
        self.lay.got + a as u64 * word::<T>()
    }

    #[inline]
    pub fn tlsdesc(&self, sym: u32) -> u64 {
        let a = self.aux(sym).map_or(NONE, |a| a.tlsdesc);
        self.lay.got + a as u64 * word::<T>()
    }

    #[inline]
    pub fn tlsld(&self) -> u64 {
        self.lay.got + self.ctx.scan.tlsld.unwrap_or(0) as u64 * word::<T>()
    }

    /// The PLT entry of the symbol, if it has one.
    #[inline]
    pub fn plt(&self, sym: u32) -> Option<u64> {
        let a = self.aux(sym)?;
        (a.plt != NONE).then(|| self.lay.plt + T::PLT0_SIZE + a.plt as u64 * T::PLT_SIZE)
    }

    /// The offset (relative to the output buffer) of a local label in this section.
    #[inline]
    pub fn label_offset(&self, sym: u32) -> u64 {
        self.obj.sym::<T>(sym).value.wrapping_sub(self.base)
    }

    /// A range-extension thunk reaching the target of branch `r` from here, if one was made.
    #[inline]
    pub fn thunk_for(&self, r: &Rel) -> Option<u64> {
        self.ctx.thunk_addr(self.lay, self.kind(r.sym).0, 0)
    }

    /// Where a call to `sym` goes: its PLT entry if it has one, else the symbol.
    #[inline]
    pub fn call_target(&self, r: &Rel) -> u64 {
        let (_, k) = self.kind(r.sym);
        // A branch to an undefined weak symbol (never taken: callers check the address) goes
        // to the next instruction (ARM, AArch64) or to itself, as lld does: address 0 may be
        // out of the branch's range.
        if self.is_undef_weak(r.sym) && !matches!(T::M, Machine::X86_64 | Machine::I386) {
            let next = if matches!(T::M, Machine::Arm | Machine::AArch64) {
                4
            } else {
                0
            };
            return self.p(r).wrapping_add(next).wrapping_add(r.addend as u64);
        }
        if matches!(
            k,
            SymKind::ImportedData | SymKind::ImportedFunc | SymKind::Ifunc
        ) && let Some(p) = self.plt(r.sym)
        {
            return p.wrapping_add(r.addend as u64);
        }
        self.sa(r)
    }

    /// A global that stayed undefined (weak) and resolves to 0.
    #[inline]
    pub fn is_undef_weak(&self, sym: u32) -> bool {
        let (sr, k) = self.kind(sym);
        k == SymKind::Abs
            && sr.obj == NONE
            && sr.idx != NONE
            && self.ctx.syms.get(sr.idx).def() == UNDEF
    }

    /// The TP-relative offset of a TLS address.
    #[inline]
    pub fn tp(&self, addr: u64) -> u64 {
        self.ctx.tp_offset(self.lay, addr)
    }

    /// The DTP-relative offset of a TLS address.
    #[inline]
    pub fn dtp(&self, addr: u64) -> u64 {
        self.ctx.dtp_offset(self.lay, addr)
    }

    /// Whether `sym` is bound in this module (relaxations allowed).
    #[inline]
    pub fn is_local(&self, sym: u32) -> bool {
        matches!(self.kind(sym).1, SymKind::Local | SymKind::Abs)
    }

    pub fn error(&self, r: &Rel, msg: &str) {
        let name = if r.sym < self.obj.first_global {
            let s = self.obj.sym::<T>(r.sym);
            if s.ty() == STT_SECTION {
                String::from_utf8_lossy(self.obj.sec_name::<T>(s.shndx)).into_owned()
            } else {
                self.obj.display_sym::<T>(r.sym)
            }
        } else {
            self.obj.display_sym::<T>(r.sym)
        };
        self.ctx.error(format!(
            "{}:({}+{:#x}): {msg}; relocation type {} against {name}",
            self.obj.name,
            String::from_utf8_lossy(self.obj.sec_name::<T>(self.sec)),
            r.offset + self.base,
            r.ty
        ));
    }

    /// Check that `v` fits in a signed field of `bits` bits.
    #[inline]
    pub fn check_signed(&self, r: &Rel, v: i64, bits: u32) {
        if bits < 64 && (v < -(1i64 << (bits - 1)) || v >= (1i64 << (bits - 1))) {
            self.error(
                r,
                &format!("value {v:#x} out of range for a {bits}-bit signed field"),
            );
        }
    }

    #[inline]
    pub fn check_unsigned(&self, r: &Rel, v: u64, bits: u32) {
        if bits < 64 && v >> bits != 0 {
            self.error(
                r,
                &format!("value {v:#x} out of range for a {bits}-bit field"),
            );
        }
    }

    /// A field that may be read as either signed or unsigned.
    #[inline]
    pub fn check_any(&self, r: &Rel, v: u64, bits: u32) {
        let s = v as i64;
        if bits < 64 && (s < -(1i64 << (bits - 1)) || s >= (1i64 << bits)) {
            self.error(
                r,
                &format!("value {v:#x} out of range for a {bits}-bit field"),
            );
        }
    }

    /// The size of the symbol (`R_*_SIZE*`).
    pub fn size_of(&self, sym: u32) -> u64 {
        let o = self.obj;
        if sym < o.first_global {
            return o.sym::<T>(sym).size;
        }
        let id = o.global_id(sym);
        if id == NONE { 0 } else { self.ctx.sym_size(id) }
    }

    /// The value a debug section gets for a reference to discarded code: 1 in the range and
    /// location lists (0 would end the list), 0 elsewhere.
    pub fn tombstone(&self) -> u64 {
        let n = self.obj.sec_name::<T>(self.sec);
        if n == b".debug_loc" || n == b".debug_ranges" {
            1
        } else {
            0
        }
    }

    /// Whether a symbol is in a section that didn't make it into the output.
    /// A pointer-sized absolute relocation in an allocated section, with whatever dynamic
    /// relocation the scan decided on. Returns the value to store at the location.
    pub fn abs_word(&mut self, r: &Rel) -> u64 {
        let ctx = self.ctx;
        let (sr, k) = self.kind(r.sym);
        let pic = ctx.cfg.pic();
        let p = self.p(r);
        let ro = self.obj.secs[self.sec as usize].fl & super::object::FL_WRITE == 0;
        let textrel_ok = !ro || !ctx.cfg.z_text;
        match k {
            SymKind::Abs => self.sa(r),
            SymKind::Local | SymKind::Ifunc => {
                let v = self.sa(r);
                if pic && textrel_ok {
                    self.dw.put::<T>(self.dw.rel, p, 0, T::R_RELATIVE, v as i64);
                    self.dw.rel += 1;
                }
                v
            }
            SymKind::ImportedData | SymKind::ImportedFunc => {
                let sym = ctx.syms.get(sr.idx);
                let f = sym.flags();
                if f & (NEEDS_COPY | NEEDS_CPLT) != 0
                    && f & IMPORTED != 0
                    && (!pic || f & NEEDS_CPLT != 0 && k == SymKind::ImportedFunc && (ro || !pic))
                {
                    return self.sa(r);
                }
                if !textrel_ok {
                    return 0;
                }
                let dynsym = ctx.aux_of(sr).map_or(0, |a| a.dynsym);
                self.dw.put::<T>(self.dw.sym, p, dynsym, T::R_ABS, r.addend);
                self.dw.sym += 1;
                if T::RELA_DYN { 0 } else { r.addend as u64 }
            }
        }
    }
}

#[derive(Default)]
pub struct SymtabPlan {
    pub nsyms: u64,
    pub first_global: u64,
    pub strsize: u64,
    /// Per object: (first local, first global, first string byte).
    pub obj: Vec<(u64, u64, u64)>,
    pub shstrtab: Vec<u8>,
    pub shname: Vec<u32>,
    /// Per object, the lengths of the local names it writes, in order.
    pub local_lens: Vec<Vec<u32>>,
}

/// What one object contributes to `.symtab`.
#[derive(Default, Clone, Copy)]
struct SymCount {
    locals: u64,
    globals: u64,
    strs: u64,
}

impl<'a, T: Target> Ctx<'a, T> {
    /// A local symbol's address.
    #[inline]
    pub fn local_addr(&self, o: &Object<'a>, i: u32) -> u64 {
        let s = o.sym::<T>(i);
        if s.ty() == STT_GNU_IFUNC
            && let Some(a) = self.aux_of(SymRef {
                obj: self.obj_index(o),
                idx: i,
            })
            && a.plt != NONE
        {
            return self.plt_entry_addr(a.plt);
        }
        self.local_value(i, o)
    }

    pub fn plt_entry_addr(&self, idx: u32) -> u64 {
        // Valid once laid out; the layout keeps the PLT's address in each symbol's value.
        self.plt_base.load(Ordering::Relaxed) + T::PLT0_SIZE + idx as u64 * T::PLT_SIZE
    }

    pub fn tp_offset(&self, lay: &Layout, addr: u64) -> u64 {
        let Some((start, _, memsz, align)) = lay.tls else {
            return addr;
        };
        if T::TLS_VARIANT2 {
            addr.wrapping_sub(start)
                .wrapping_sub(align_up(memsz, align))
        } else {
            addr.wrapping_sub(start)
                .wrapping_add(align_up(T::TLS_TCB, align))
                .wrapping_add(T::TP_BIAS as u64)
        }
    }

    pub fn dtp_offset(&self, lay: &Layout, addr: u64) -> u64 {
        let start = lay.tls.map_or(0, |t| t.0);
        addr.wrapping_sub(start).wrapping_sub(T::DTP_BIAS as u64)
    }

    /// Whether local symbol `i` of `o` goes to `.symtab`.
    fn keep_local(&self, o: &Object<'a>, i: u32, s: &Sym) -> bool {
        if i == 0 || self.cfg.discard == Discard::All {
            return false;
        }
        match s.ty() {
            STT_SECTION => return false,
            STT_FILE => return self.cfg.discard == Discard::None,
            _ => {}
        }
        // The name's start is enough here: no need to find its end.
        let name = o.strtab.get(s.name as usize..).unwrap_or(&[]);
        if name.first().is_none_or(|&c| c == 0) {
            return false;
        }
        if s.shndx != SHN_ABS {
            let Some(sec) = o.secs.get(s.shndx as usize) else {
                return false;
            };
            if !sec.is_live()
                || sec.kind == SecKind::Discarded
                || sec.kind == SecKind::Ignore
                || sec.kind == SecKind::EhFrame
            {
                return false;
            }
            if sec.out == NONE && sec.kind != SecKind::Merge {
                return false;
            }
            if name.starts_with(b".L")
                && (self.cfg.discard == Discard::Locals || sec.kind == SecKind::Merge)
            {
                return false;
            }
        }
        true
    }

    /// Whether global entry `i` of `o` is the one that writes symbol `id`: (write, local).
    fn global_owner(&self, o: &Object<'a>, i: u32, s: &Sym) -> Option<SymId> {
        let id = o.global_id(i);
        if id == NONE {
            return None;
        }
        let sym = self.syms.get(id);
        let d = sym.def();
        if d != UNDEF && def_class(d) <= CLASS_COMMON {
            if def_prio(d) != o.prio || def_index(d) != i {
                return None;
            }
            // Not if its section was dropped.
            if s.shndx < SHN_LORESERVE
                && !o
                    .secs
                    .get(s.shndx as usize)
                    .is_some_and(|x| x.is_live() && x.kind != SecKind::Discarded)
            {
                return None;
            }
            return Some(id);
        }
        // Undefined, imported and linker-made symbols: only if live code uses them.
        if !sym.has(USED | NEEDS_DYNSYM | EXPORTED) {
            return None;
        }
        if s.is_undef() && sym.first_ref.load(Ordering::Relaxed) == o.prio {
            // Its first undefined entry in this object: skip later duplicates (`foo@V`).
            let first = (o.first_global..i).all(|j| o.global_id(j) != id);
            return first.then_some(id);
        }
        None
    }

    /// What one object contributes, and the lengths of its kept local names (for the write).
    fn count_symtab(&self, o: &Object<'a>) -> (SymCount, Vec<u32>) {
        let mut c = SymCount::default();
        let mut lens = Vec::new();
        if !o.alive.load(Ordering::Relaxed) {
            return (c, lens);
        }
        for i in 1..o.first_global.min(o.nsyms) {
            let s = o.sym::<T>(i);
            if self.keep_local(o, i, &s) {
                c.locals += 1;
                let n = o.sym_name(&s).len();
                lens.push(n as u32);
                c.strs += n as u64 + 1;
            }
        }
        for i in o.first_global..o.nsyms {
            let s = o.sym::<T>(i);
            if let Some(id) = self.global_owner(o, i, &s) {
                let sym = self.syms.get(id);
                if sym.has(LOCALIZED) && self.cfg.discard == Discard::All {
                    continue;
                }
                if sym.has(LOCALIZED) {
                    c.locals += 1;
                } else {
                    c.globals += 1;
                }
                c.strs += sym.name.len() as u64 + 1;
            }
        }
        (c, lens)
    }

    pub fn plan_symtab(&self, _outs: &[OutSec]) -> SymtabPlan {
        let mut plan = SymtabPlan::default();
        if self.cfg.strip == Strip::All {
            return plan;
        }
        let (counts, lens): (Vec<SymCount>, Vec<Vec<u32>>) =
            self.objs.par_iter().map(|o| self.count_symtab(o)).unzip();
        plan.local_lens = lens;
        let nlocal: u64 = counts.iter().map(|c| c.locals).sum();
        let mut local = 1u64;
        let mut global = 1 + nlocal;
        let mut strs = 1u64;
        for c in &counts {
            plan.obj.push((local, global, strs));
            local += c.locals;
            global += c.globals;
            strs += c.strs;
        }
        plan.first_global = 1 + nlocal;
        plan.nsyms = global;
        plan.strsize = strs;
        plan
    }

    fn write_symtab(&self, lay: &Layout, out: OutBuf) {
        let (Some(st), Some(sr)) = (lay.out(Synthetic::Symtab), lay.out(Synthetic::Strtab)) else {
            return;
        };
        let symsz = if T::IS64 { 24 } else { 16 };
        let tls_start = lay.tls.map_or(0, |t| t.0);
        out.slice(st.offset, symsz).fill(0);
        out.slice(sr.offset, 1)[0] = 0;
        self.objs.par_iter().enumerate().for_each(|(oi, o)| {
            if !o.alive.load(Ordering::Relaxed) {
                return;
            }
            let (mut li, mut gi, mut so) = lay.symtab.obj[oi];
            let put = |idx: &mut u64,
                       name: &[u8],
                       info: u8,
                       other: u8,
                       shndx: u32,
                       value: u64,
                       size: u64,
                       so: &mut u64| {
                let e = out.slice(st.offset + *idx * symsz, symsz);
                let n = *so;
                out.slice(sr.offset + n, name.len() as u64 + 1)[..name.len()].copy_from_slice(name);
                self.put_sym(e, n as u32, info, other, shndx, value, size);
                *idx += 1;
                *so += name.len() as u64 + 1;
            };
            let mut lens = lay.symtab.local_lens[oi].iter();
            for i in 1..o.first_global.min(o.nsyms) {
                let s = o.sym::<T>(i);
                if !self.keep_local(o, i, &s) {
                    continue;
                }
                let len = *lens.next().unwrap() as usize;
                let name = &o.strtab[s.name as usize..s.name as usize + len];
                let (shndx, mut value) = if s.ty() == STT_FILE {
                    (SHN_ABS, 0)
                } else if s.shndx == SHN_ABS {
                    (SHN_ABS, s.value)
                } else {
                    let sec = &o.secs[s.shndx as usize];
                    let shndx = if sec.kind == SecKind::Merge {
                        self.merged
                            .get(sec.aux as usize)
                            .map_or(SHN_ABS, |m| lay.outs[m.out as usize].shndx)
                    } else {
                        lay.outs[sec.out as usize].shndx
                    };
                    (shndx, self.local_addr(o, i))
                };
                if s.ty() == STT_TLS {
                    value = value.wrapping_sub(tls_start);
                }
                put(
                    &mut li, name, s.info, s.other, shndx, value, s.size, &mut so,
                );
            }
            for i in o.first_global..o.nsyms {
                let s = o.sym::<T>(i);
                let Some(id) = self.global_owner(o, i, &s) else {
                    continue;
                };
                let sym = self.syms.get(id);
                let f = sym.flags();
                if f & LOCALIZED != 0 && self.cfg.discard == Discard::All {
                    continue;
                }
                let d = sym.def();
                let defined = d != UNDEF
                    && (def_class(d) != CLASS_LAZY || f & (NEEDS_COPY | NEEDS_CPLT) != 0);
                let (shndx, mut value) = if !defined {
                    (SHN_UNDEF, if f & NEEDS_CPLT != 0 { sym.addr() } else { 0 })
                } else {
                    (self.sym_shndx(lay, id), sym.addr())
                };
                let mut ty = if d != UNDEF && def_class(d) <= CLASS_COMMON {
                    match s.ty() {
                        STT_COMMON => STT_OBJECT,
                        t => t,
                    }
                } else if f & IS_TLS != 0 {
                    STT_TLS
                } else if f & IS_FUNC != 0 {
                    STT_FUNC
                } else {
                    s.ty()
                };
                if ty == STT_TLS && defined {
                    value = value.wrapping_sub(tls_start);
                }
                if d == UNDEF && ty == STT_COMMON {
                    ty = STT_OBJECT;
                }
                let size = self.sym_size(id);
                let vis = match sym.vis.load(Ordering::Relaxed) {
                    1 => STV_PROTECTED,
                    2 => STV_HIDDEN,
                    _ => STV_DEFAULT,
                };
                if f & LOCALIZED != 0 {
                    put(
                        &mut li,
                        sym.name,
                        (STB_LOCAL << 4) | ty,
                        vis,
                        shndx,
                        value,
                        size,
                        &mut so,
                    );
                } else {
                    let bind = if self.sym_is_weak(id) {
                        STB_WEAK
                    } else {
                        STB_GLOBAL
                    };
                    put(
                        &mut gi,
                        sym.name,
                        (bind << 4) | ty,
                        vis,
                        shndx,
                        value,
                        size,
                        &mut so,
                    );
                }
            }
            if self.bid.on {
                let (l0, g0, s0) = lay.symtab.obj[oi];
                let h = |a: u64, b: u64, base: u64, size: u64| {
                    xxhash_rust::xxh3::xxh3_64_with_seed(
                        out.slice(base + a * size, (b - a) * size),
                        a,
                    )
                };
                let v = h(l0, li, st.offset, symsz)
                    ^ h(g0, gi, st.offset, symsz).rotate_left(21)
                    ^ h(s0, so, sr.offset, 1).rotate_left(42);
                self.bid.put_hash(self.bid.sym_base as usize + oi, v);
            }
        });
    }

    /// The ELF header and program headers (`head`) and the section header table (`sh`).
    fn write_headers(&self, lay: &Layout, head: &mut [u8], sh: &mut [u8]) {
        let e = &mut head[..lay.ehdr_size as usize];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = if T::IS64 { ELFCLASS64 } else { ELFCLASS32 };
        e[5] = if T::BE { ELFDATA2MSB } else { ELFDATA2LSB };
        e[6] = 1;
        e[7] = 0; // ELFOSABI_NONE (System V)
        let ty = if self.cfg.pic() { ET_DYN } else { ET_EXEC };
        wr16::<T>(e, 16, ty);
        wr16::<T>(e, 18, T::E_MACHINE);
        wr32::<T>(e, 20, 1);
        let nsec = lay.outs.iter().filter(|o| o.shndx != 0).count() as u64 + 1;
        let shstrndx = lay.out(Synthetic::Shstrtab).map_or(0, |o| o.shndx);
        if T::IS64 {
            wr64::<T>(e, 24, lay.entry);
            wr64::<T>(e, 32, lay.ehdr_size);
            wr64::<T>(e, 40, lay.shoff);
            wr32::<T>(e, 48, T::e_flags(self));
            wr16::<T>(e, 52, 64);
            wr16::<T>(e, 54, 56);
            wr16::<T>(e, 56, lay.phdrs.len() as u16);
            wr16::<T>(e, 58, 64);
            wr16::<T>(e, 60, if nsec >= 0xff00 { 0 } else { nsec as u16 });
            wr16::<T>(
                e,
                62,
                if shstrndx >= 0xff00 {
                    SHN_XINDEX as u16
                } else {
                    shstrndx as u16
                },
            );
        } else {
            wr32::<T>(e, 24, lay.entry as u32);
            wr32::<T>(e, 28, lay.ehdr_size as u32);
            wr32::<T>(e, 32, lay.shoff as u32);
            wr32::<T>(e, 36, T::e_flags(self));
            wr16::<T>(e, 40, 52);
            wr16::<T>(e, 42, 32);
            wr16::<T>(e, 44, lay.phdrs.len() as u16);
            wr16::<T>(e, 46, 40);
            wr16::<T>(e, 48, if nsec >= 0xff00 { 0 } else { nsec as u16 });
            wr16::<T>(
                e,
                50,
                if shstrndx >= 0xff00 {
                    SHN_XINDEX as u16
                } else {
                    shstrndx as u16
                },
            );
        }
        let phent = if T::IS64 { 56 } else { 32 };
        for (i, p) in lay.phdrs.iter().enumerate() {
            let b = &mut head[(lay.ehdr_size as usize + i * phent)..][..phent];
            if T::IS64 {
                wr32::<T>(b, 0, p.ty);
                wr32::<T>(b, 4, p.flags);
                wr64::<T>(b, 8, p.offset);
                wr64::<T>(b, 16, p.vaddr);
                wr64::<T>(b, 24, p.vaddr);
                wr64::<T>(b, 32, p.filesz);
                wr64::<T>(b, 40, p.memsz);
                wr64::<T>(b, 48, p.align);
            } else {
                wr32::<T>(b, 0, p.ty);
                wr32::<T>(b, 4, p.offset as u32);
                wr32::<T>(b, 8, p.vaddr as u32);
                wr32::<T>(b, 12, p.vaddr as u32);
                wr32::<T>(b, 16, p.filesz as u32);
                wr32::<T>(b, 20, p.memsz as u32);
                wr32::<T>(b, 24, p.flags);
                wr32::<T>(b, 28, p.align as u32);
            }
        }
        // Section headers.
        let shent = if T::IS64 { 64 } else { 40 };
        sh[..shent].fill(0);
        if nsec >= 0xff00 {
            if T::IS64 {
                wr64::<T>(sh, 32, nsec);
            } else {
                wr32::<T>(sh, 20, nsec as u32);
            }
        }
        if shstrndx >= 0xff00 {
            wr32::<T>(sh, if T::IS64 { 40 } else { 24 }, shstrndx);
        }
        let idx = |s: Synthetic| lay.out(s).map_or(0, |o| o.shndx);
        let text = lay
            .outs
            .iter()
            .find(|o| o.name == b".text" && o.shndx != 0)
            .map_or(0, |o| o.shndx);
        for (i, o) in lay.outs.iter().enumerate() {
            if o.shndx == 0 {
                continue;
            }
            let (link, info) = match o.synth {
                // `.dynsym`'s info: one past the last local symbol (only the null one).
                Synthetic::Dynsym => (idx(Synthetic::Dynstr), 1),
                Synthetic::GnuHash | Synthetic::Hash | Synthetic::VerSym | Synthetic::RelaDyn => {
                    (idx(Synthetic::Dynsym), 0)
                }
                Synthetic::RelaPlt => (
                    if self.has_dynamic {
                        idx(Synthetic::Dynsym)
                    } else {
                        0
                    },
                    if self.has_dynamic {
                        idx(Synthetic::GotPlt)
                    } else {
                        0
                    },
                ),
                Synthetic::VerNeed | Synthetic::VerDef => (idx(Synthetic::Dynstr), o.info),
                Synthetic::Dynamic => (idx(Synthetic::Dynstr), 0),
                Synthetic::Symtab => (idx(Synthetic::Strtab), lay.symtab.first_global as u32),
                Synthetic::Exidx => (text, 0),
                _ => (0, 0),
            };
            let b = &mut sh[o.shndx as usize * shent..][..shent];
            let name = lay.symtab.shname[i];
            let size = o.size;
            if T::IS64 {
                wr32::<T>(b, 0, name);
                wr32::<T>(b, 4, o.ty);
                wr64::<T>(b, 8, o.flags);
                wr64::<T>(b, 16, o.addr);
                wr64::<T>(b, 24, o.offset);
                wr64::<T>(b, 32, size);
                wr32::<T>(b, 40, link);
                wr32::<T>(b, 44, info);
                wr64::<T>(b, 48, o.align);
                wr64::<T>(b, 56, o.entsize);
            } else {
                wr32::<T>(b, 0, name);
                wr32::<T>(b, 4, o.ty);
                wr32::<T>(b, 8, o.flags as u32);
                wr32::<T>(b, 12, o.addr as u32);
                wr32::<T>(b, 16, o.offset as u32);
                wr32::<T>(b, 20, size as u32);
                wr32::<T>(b, 24, link);
                wr32::<T>(b, 28, info);
                wr32::<T>(b, 32, o.align as u32);
                wr32::<T>(b, 36, o.entsize as u32);
            }
        }
    }

    /// The value a GOT slot of `r` holds statically (the symbol's address).
    fn slot_value(&self, r: SymRef) -> u64 {
        if r.obj != NONE {
            let o = &self.objs[r.obj as usize];
            return self.local_addr(o, r.idx);
        }
        if r.idx == NONE {
            return 0;
        }
        self.syms.get(r.idx).addr()
    }

    fn slot_dynsym(&self, r: SymRef) -> u32 {
        self.aux_of(r).map_or(0, |a| a.dynsym)
    }

    fn write_got(&self, lay: &Layout, out: OutBuf, rela: &DynWriter) -> (u64, u64) {
        let Some(g) = lay.out(Synthetic::Got) else {
            return (0, 0);
        };
        let w = word::<T>();
        let buf = out.slice(g.offset, g.size);
        if T::GOT0_DYNAMIC && !buf.is_empty() {
            // `.got[0]`: `_DYNAMIC`, or on POWER the TOC base.
            let v = if matches!(T::M, Machine::Ppc64 | Machine::Ppc64le) {
                lay.got + 0x8000
            } else {
                lay.addr_of(Synthetic::Dynamic)
            };
            wrw::<T>(buf, 0, v);
        }
        let shared = self.cfg.shared;
        let pic = self.cfg.pic();
        let (mut nrel, mut nsym) = (0u64, self.scan.nrelative);
        for e in &self.scan.got {
            let at = e.word as usize * w as usize;
            let addr = lay.got + e.word as u64 * w;
            let imported = self.slot_imported(e.sym);
            let abs = self.slot_abs(e.sym);
            let dynsym = self.slot_dynsym(e.sym);
            let s = self.slot_value(e.sym);
            match e.kind {
                GotKind::Addr => {
                    if imported {
                        rela.put::<T>(nsym, addr, dynsym, T::R_GLOB_DAT, 0);
                        nsym += 1;
                    } else {
                        wrw::<T>(buf, at, s);
                        if pic && !abs {
                            rela.put::<T>(nrel, addr, 0, T::R_RELATIVE, s as i64);
                            nrel += 1;
                        }
                    }
                }
                GotKind::TpOff => {
                    if imported {
                        rela.put::<T>(nsym, addr, dynsym, T::R_TPOFF, 0);
                        nsym += 1;
                    } else if shared {
                        let off = s.wrapping_sub(lay.tls.map_or(0, |t| t.0));
                        if !T::RELA_DYN {
                            wrw::<T>(buf, at, off);
                        }
                        rela.put::<T>(nsym, addr, 0, T::R_TPOFF, off as i64);
                        nsym += 1;
                    } else {
                        wrw::<T>(buf, at, self.tp_offset(lay, s));
                    }
                }
                GotKind::TlsGd => {
                    if imported {
                        rela.put::<T>(nsym, addr, dynsym, T::R_DTPMOD, 0);
                        rela.put::<T>(nsym + 1, addr + w, dynsym, T::R_DTPOFF, 0);
                        nsym += 2;
                    } else if shared {
                        rela.put::<T>(nsym, addr, 0, T::R_DTPMOD, 0);
                        nsym += 1;
                        wrw::<T>(buf, at + w as usize, self.dtp_offset(lay, s));
                    } else {
                        wrw::<T>(buf, at, 1);
                        wrw::<T>(buf, at + w as usize, self.dtp_offset(lay, s));
                    }
                }
                GotKind::TlsDesc => {
                    if imported {
                        rela.put::<T>(nsym, addr, dynsym, T::R_TLSDESC, 0);
                        nsym += 1;
                    } else if shared || self.has_dynamic {
                        let off = s.wrapping_sub(lay.tls.map_or(0, |t| t.0));
                        rela.put::<T>(nsym, addr, 0, T::R_TLSDESC, off as i64);
                        nsym += 1;
                    } else {
                        wrw::<T>(buf, at + w as usize, self.tp_offset(lay, s));
                    }
                }
                GotKind::TlsLd => {
                    if shared {
                        rela.put::<T>(nsym, addr, 0, T::R_DTPMOD, 0);
                        nsym += 1;
                    } else {
                        wrw::<T>(buf, at, 1);
                    }
                }
            }
        }
        (nrel, nsym)
    }

    fn write_plt_and_gotplt(&self, lay: &Layout, out: OutBuf) {
        let n = self.scan.plt.len() + self.scan.iplt.len();
        let w = word::<T>();
        let gp = lay.out(Synthetic::GotPlt);
        if let Some(gp) = gp {
            let buf = out.slice(gp.offset, gp.size);
            if self.has_dynamic && T::GOTPLT_RESERVED > 0 {
                wrw::<T>(buf, 0, lay.addr_of(Synthetic::Dynamic));
            }
        }
        if n == 0 {
            return;
        }
        let (Some(plt), Some(gp), Some(rp)) =
            (lay.out(Synthetic::Plt), gp, lay.out(Synthetic::RelaPlt))
        else {
            return;
        };
        let reserved = if self.has_dynamic {
            T::GOTPLT_RESERVED
        } else {
            0
        };
        let pbuf = out.slice(plt.offset, plt.size);
        T::write_plt0(self, &mut pbuf[..T::PLT0_SIZE as usize], plt.addr, gp.addr);
        let relsz = if T::RELA_DYN { 3 * w } else { 2 * w };
        let gbuf = out.slice(gp.offset, gp.size);
        let rbuf = out.slice(rp.offset, rp.size);
        for (i, r) in self.scan.plt.iter().chain(&self.scan.iplt).enumerate() {
            let ent = plt.addr + T::PLT0_SIZE + i as u64 * T::PLT_SIZE;
            let slot = gp.addr + (reserved + i as u64) * w;
            let e = &mut pbuf[(T::PLT0_SIZE + i as u64 * T::PLT_SIZE) as usize..]
                [..T::PLT_SIZE as usize];
            T::write_plt(self, e, ent, slot, i as u64, plt.addr);
            let at = ((reserved + i as u64) * w) as usize;
            let rel = &mut rbuf[i * relsz as usize..][..relsz as usize];
            if i < self.scan.plt.len() {
                wrw::<T>(gbuf, at, T::gotplt_initial(plt.addr, ent));
                write_rel::<T>(rel, slot, self.slot_dynsym(*r), T::R_JUMP_SLOT, 0);
            } else {
                // An IFUNC defined here: the slot gets its resolver's result.
                let resolver = match r.obj {
                    NONE => {
                        let (o, i) = self.def_obj(r.idx).unwrap();
                        self.local_value(i, o)
                    }
                    oi => self.local_value(r.idx, &self.objs[oi as usize]),
                };
                wrw::<T>(gbuf, at, resolver);
                write_rel::<T>(rel, slot, 0, T::R_IRELATIVE, resolver as i64);
            }
        }
    }

    pub fn write(&mut self, lay: &mut Layout, timer: &mut Timer) -> Result<()> {
        self.plt_base.store(lay.plt, Ordering::Relaxed);
        let size = lay.file_size as usize;
        let file = OutputFile::create_with_mode(&self.cfg.output, size, 0o777);
        let mut file =
            file.map_err(|e| err!("cannot create {}: {e}", self.cfg.output.display()))?;
        let bytes = file.bytes();
        timer.phase("create output");
        let out = OutBuf::new(bytes);
        let lay: &Layout = lay;
        self.bid = BuildIdSlots::default();
        if lay.build_id_size > 0 && matches!(self.cfg.build_id, BuildId::Hash(_)) {
            let mut b = BuildIdSlots {
                on: true,
                ..Default::default()
            };
            let mut n = 0u32;
            for o in &self.objs {
                b.sec_base.push(n);
                n += o.secs.len() as u32;
            }
            for m in &self.merged {
                b.merged_base.push(n);
                n += m.uniq.len() as u32;
            }
            b.sym_base = n;
            n += self.objs.len() as u32;
            b.eh_base = n;
            n += self.objs.len() as u32;
            b.slots = Some(SyncVec::new(n as usize, 0u64));
            self.bid = b;
        }
        let rela_off = lay.out(Synthetic::RelaDyn).map_or(0, |o| o.offset);
        let dw = DynWriter {
            buf: lay.out(Synthetic::RelaDyn).map(|_| out),
            off: rela_off,
            rel: 0,
            sym: 0,
        };
        let eh_table = std::sync::Mutex::new(Vec::new());
        let errors = std::sync::Mutex::new(Vec::new());
        let u0 = super::prof::usage();
        rayon::scope(|sc| {
            // Input sections.
            sc.spawn(|_| {
                super::prof::time("input sections", || {
                    let r: Vec<Result<()>> = self
                        .objs
                        .par_iter()
                        .enumerate()
                        .map(|(oi, o)| self.write_object(lay, out, dw, oi, o))
                        .collect();
                    for e in r {
                        if let Err(e) = e {
                            errors.lock().unwrap().push(e);
                        }
                    }
                })
            });
            sc.spawn(|_| super::prof::time("merged", || self.write_merged(out)));
            sc.spawn(|_| {
                if let Some(eh) = lay.out(Synthetic::EhFrame) {
                    match self.write_eh_frame(lay, out, eh.offset, eh.addr, dw) {
                        Ok(t) => *eh_table.lock().unwrap() = t,
                        Err(e) => errors.lock().unwrap().push(e),
                    }
                }
            });
            sc.spawn(|_| super::prof::time("symtab", || self.write_symtab(lay, out)));
            sc.spawn(|_| {
                let (rel, sym) = self.write_got(lay, out, &dw);
                debug_assert!(rel <= self.scan.got_rel);
                let _ = sym;
                self.write_plt_and_gotplt(lay, out);
                self.write_small_synthetics(lay, out);
                if let Some(rd) = lay.out(Synthetic::RelaDyn) {
                    // Copy relocations follow the GOT's.
                    let w = word::<T>();
                    let relsz = if T::RELA_DYN { 3 * w } else { 2 * w };
                    let base = self.scan.nrelative + self.scan.got_sym;
                    let bss = lay.out(Synthetic::Bss).map_or(0, |o| o.addr) + lay.bss_extra;
                    for (k, &(id, off)) in self.scan.copyrels.iter().enumerate() {
                        let e = out.slice(rd.offset + (base + k as u64) * relsz, relsz);
                        let dynsym = self.slot_dynsym(SymRef::global(id));
                        write_rel::<T>(e, bss + off, dynsym, T::R_COPY, 0);
                    }
                }
            });
            sc.spawn(|_| {
                let head = out.slice(0, lay.ehdr_size + lay.phdr_size);
                let sh = out.slice(lay.shoff, lay.file_size - lay.shoff);
                self.write_headers(lay, head, sh);
            });
        });
        super::prof::report_usage("write", u0);
        super::prof::report_sums(&[
            "alloc copy",
            "alloc relocate",
            "debug copy",
            "debug relocate",
        ]);
        let mut errs = errors.into_inner().unwrap();
        if let Some(e) = errs.pop() {
            for x in errs {
                crate::diag::error(x);
            }
            return Err(e);
        }
        self.check_errors()?;
        if let Some(h) = lay.out(Synthetic::EhFrameHdr) {
            let table = eh_table.into_inner().unwrap();
            let buf = out.slice(h.offset, h.size);
            self.write_eh_frame_hdr(buf, h.addr, lay.addr_of(Synthetic::EhFrame), table);
        }
        timer.phase("write sections");
        if let Some(b) = lay.out(Synthetic::BuildId) {
            let id = self.build_id(lay, out, lay.build_id_size as usize);
            let note = out.slice(b.offset, b.size);
            wr32::<T>(note, 0, 4);
            wr32::<T>(note, 4, id.len() as u32);
            wr32::<T>(note, 8, NT_GNU_BUILD_ID);
            note[12..16].copy_from_slice(b"GNU\0");
            note[16..].copy_from_slice(&id);
            timer.phase("build ID");
        }
        file.commit(lay.file_size as usize)
            .map_err(|e| err!("cannot write {}: {e}", self.cfg.output.display()))?;
        timer.phase("commit output");
        Ok(())
    }

    fn build_id(&self, lay: &Layout, out: OutBuf, size: usize) -> Vec<u8> {
        match &self.cfg.build_id {
            BuildId::Hex(b) => return b.clone(),
            BuildId::Uuid => {
                let mut v = vec![0u8; 16];
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let h = xxhash_rust::xxh3::xxh3_128(
                    &[t.to_le_bytes(), (std::process::id() as u128).to_le_bytes()].concat(),
                );
                v.copy_from_slice(&h.to_le_bytes());
                v[6] = (v[6] & 0x0f) | 0x40;
                v[8] = (v[8] & 0x3f) | 0x80;
                return v;
            }
            _ => {}
        }
        // The writers' hashes (hashed in parallel chunks, without a copy), then the linker's own
        // sections and the headers.
        let mut all: Vec<u8> = Vec::new();
        all.extend_from_slice(&lay.file_size.to_le_bytes());
        if let Some(s) = &self.bid.slots {
            let slots = s.as_slice();
            let chunks: Vec<u64> = slots
                .par_chunks(1 << 14)
                .map(|c| {
                    let mut b = Vec::with_capacity(c.len() * 8);
                    if cfg!(target_endian = "little") {
                        // SAFETY: plain integers, viewed as their bytes.
                        b.extend_from_slice(unsafe {
                            std::slice::from_raw_parts(c.as_ptr().cast::<u8>(), c.len() * 8)
                        });
                    } else {
                        c.iter().for_each(|v| b.extend_from_slice(&v.to_le_bytes()));
                    }
                    xxhash_rust::xxh3::xxh3_64(&b)
                })
                .collect();
            for h in chunks {
                all.extend_from_slice(&h.to_le_bytes());
            }
        }
        let tail: Vec<(u64, u64)> = lay
            .outs
            .iter()
            .filter(|o| {
                o.shndx != 0
                    && !o.nobits()
                    && !matches!(
                        o.synth,
                        Synthetic::None
                            | Synthetic::Symtab
                            | Synthetic::Strtab
                            | Synthetic::EhFrame
                            | Synthetic::BuildId
                    )
            })
            .map(|o| (o.offset, o.size))
            .chain([
                (0, lay.ehdr_size + lay.phdr_size),
                (lay.shoff, lay.file_size - lay.shoff),
            ])
            .collect();
        let tail_hashes: Vec<u64> = tail
            .par_iter()
            .map(|&(off, len)| xxhash_rust::xxh3::xxh3_64_with_seed(out.slice(off, len), off))
            .collect();
        for h in tail_hashes {
            all.extend_from_slice(&h.to_le_bytes());
        }
        let mut d = [0u8; 32];
        d[..16].copy_from_slice(&xxhash_rust::xxh3::xxh3_128_with_seed(&all, 0).to_le_bytes());
        d[16..].copy_from_slice(&xxhash_rust::xxh3::xxh3_128_with_seed(&all, 1).to_le_bytes());
        let mut v = d.to_vec();
        v.resize(size, 0);
        if size > 32 {
            v[32..].fill(0);
        }
        v
    }

    fn write_object(
        &self,
        lay: &Layout,
        out: OutBuf,
        dw: DynWriter,
        oi: usize,
        o: &Object<'a>,
    ) -> Result<()> {
        if !o.alive.load(Ordering::Relaxed) {
            return Ok(());
        }
        // Each section's first dynamic relocation of each kind.
        let mut rel = self.scan.obj_rel[oi];
        let mut sym = self.scan.nrelative + self.scan.obj_sym[oi];
        let mut tasks = Vec::with_capacity(o.secs.len());
        for (si, s) in o.secs.iter().enumerate() {
            if !s.is_live()
                || s.out == NONE
                || !matches!(s.kind, SecKind::Alloc | SecKind::NonAlloc)
            {
                continue;
            }
            tasks.push((si as u32, rel, sym));
            rel += s.nrel as u64;
            sym += s.nsym as u64;
        }
        let r: Vec<Result<()>> = tasks
            .par_iter()
            .with_min_len(16)
            .map(|&(si, rel, sym)| {
                let s = &o.secs[si as usize];
                let os = &lay.outs[s.out as usize];
                if s.fl & FL_NOBITS != 0 || os.nobits() {
                    return Ok(());
                }
                let file_off = if os.is_alloc() { os.offset + (s.addr - os.addr) } else { os.offset + s.addr };
                let t = super::prof::start();
                let buf = out.slice(file_off, s.size as u64);
                buf.copy_from_slice(o.sec_data(si));
                super::prof::add(if os.is_alloc() { 0 } else { 2 }, t);
                if s.rel_len == 0 {
                    let slot = self.bid.sec_base.get(oi).map_or(0, |b| *b as usize + si as usize);
                    self.bid.put(slot, buf, file_off);
                }
                let t = super::prof::start();
                let _guard = Defer(move || super::prof::add(if os.is_alloc() { 1 } else { 3 }, t));
                if s.rel_len == 0 {
                    return Ok(());
                }
                let (raw, rela) = o.rel_data::<T>(si);
                let n = o.rel_count::<T>(si);
                let mut rc = RelocCtx::new(
                    self,
                    lay,
                    o,
                    si,
                    if os.is_alloc() { s.addr } else { 0 },
                    0,
                    Rels::Raw { data: raw, rela, n },
                    DynWriter { rel, sym, ..dw },
                );
                let slot = self.bid.sec_base.get(oi).map_or(0, |b| *b as usize + si as usize);
                if os.is_alloc() {
                    T::apply_alloc(&mut rc, buf)?;
                    if rc.dw.rel - rel != s.nrel as u64 || rc.dw.sym - sym != s.nsym as u64 {
                        bail!(
                            "internal error: {}({}) emitted {}+{} dynamic relocations, planned {}+{}",
                            o.name,
                            String::from_utf8_lossy(o.sec_name::<T>(si)),
                            rc.dw.rel - rel,
                            rc.dw.sym - sym,
                            s.nrel,
                            s.nsym
                        );
                    }
                } else {
                    T::apply_nonalloc(&mut rc, buf)?;
                }
                self.bid.put(slot, buf, file_off);
                Ok(())
            })
            .collect();
        r.into_iter().collect()
    }

    fn write_small_synthetics(&self, lay: &Layout, out: OutBuf) {
        let sec = |s: Synthetic| {
            lay.out(s)
                .filter(|o| o.size > 0)
                .map(|o| out.slice(o.offset, o.size))
        };
        if let (Some(b), Some(i)) = (sec(Synthetic::Interp), &self.interp) {
            b[..i.len()].copy_from_slice(i.as_bytes());
        }
        if let Some(b) = sec(Synthetic::Dynstr) {
            b.copy_from_slice(&lay.dynamic.strtab);
        }
        if let Some(b) = sec(Synthetic::Dynsym) {
            self.write_dynsym(lay, b);
        }
        if let Some(b) = sec(Synthetic::GnuHash) {
            self.write_gnu_hash(lay, b);
        }
        if let Some(b) = sec(Synthetic::Hash) {
            self.write_sysv_hash(lay, b);
        }
        self.write_versions(
            lay,
            sec(Synthetic::VerSym),
            sec(Synthetic::VerNeed),
            sec(Synthetic::VerDef),
        );
        if let Some(b) = sec(Synthetic::Dynamic) {
            self.write_dynamic(lay, b);
        }
        if let Some(b) = sec(Synthetic::Shstrtab) {
            b.copy_from_slice(&lay.symtab.shstrtab);
        }
        if let Some(b) = sec(Synthetic::Attributes)
            && let Some(o) = self
                .objs
                .iter()
                .find(|o| o.alive.load(Ordering::Relaxed) && o.attributes != 0)
        {
            let h = o.shdr::<T>(o.attributes);
            b.copy_from_slice(&o.data[h.offset as usize..(h.offset + h.size) as usize]);
        }
        if T::M == Machine::Arm
            && let Some(b) = sec(Synthetic::Exidx)
        {
            self.write_exidx(lay, b);
        }
        self.write_thunks(lay, out);
    }
}
