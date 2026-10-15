//! `.eh_frame`: split into CIEs and FDEs, FDEs of dead code dropped, and `.eh_frame_hdr`'s
//! sorted search table, which unwinders binary-search through `PT_GNU_EH_FRAME`.

use std::sync::atomic::Ordering;

use rayon::prelude::*;

use super::layout::Layout;
use super::object::{Object, SecKind};
use super::resolve::Ctx;
use super::target::{Rel, Target, rd32, wr32};
use super::write::{DynWriter, RelocCtx, Rels};
use super::*;
use crate::diag::Result;
use crate::{bail, err};

#[derive(Clone, Copy)]
pub struct Rec {
    /// The input `.eh_frame` section and the record's offset in it.
    pub sec: u32,
    pub off: u32,
    pub size: u32,
    pub rel_start: u32,
    pub rel_end: u32,
    /// FDEs: the CIE's index. CIEs: unused.
    pub cie: u32,
    /// FDEs: the section the FDE describes.
    pub target: u32,
    /// Offset in this object's share of the output, or NONE if dropped.
    pub out: u32,
}

#[derive(Default)]
pub struct ObjEh {
    pub rels: Vec<Rel>,
    pub cies: Vec<Rec>,
    /// Sorted by `target`.
    pub fdes: Vec<Rec>,
    pub out_off: u64,
    pub size: u64,
    pub first_fde: u64,
    pub live_fdes: u64,
}

#[derive(Default)]
pub struct EhFrameInfo {
    pub objs: Vec<ObjEh>,
    pub size: u64,
    pub nfdes: u64,
    /// The output section's address, once laid out.
    pub addr: u64,
}

impl ObjEh {
    /// FDEs describing section `s`.
    pub fn fdes_of(&self, s: u32) -> &[Rec] {
        let a = self.fdes.partition_point(|f| f.target < s);
        let b = self.fdes.partition_point(|f| f.target <= s);
        &self.fdes[a..b]
    }
}

pub fn parse_obj<T: Target>(ctx: &Ctx<'_, T>, o: &Object<'_>) -> Result<ObjEh> {
    let mut eh = ObjEh::default();
    for &si in &o.eh_frames {
        let d = o.sec_data(si);
        let (raw, rela) = o.rel_data::<T>(si);
        let n = o.rel_count::<T>(si);
        let start = eh.rels.len();
        for k in 0..n {
            eh.rels.push(o.rel::<T>(raw, rela, k, si));
        }
        let rels = &mut eh.rels[start..];
        if !rels.is_sorted_by_key(|r| r.offset) {
            rels.sort_by_key(|r| r.offset);
        }
        let mut ri = start;
        let mut off = 0usize;
        let first_cie = eh.cies.len();
        while off + 4 <= d.len() {
            let len = rd32::<T>(d, off) as usize;
            if len == 0 {
                break;
            }
            if len == 0xffff_ffff {
                bail!("{}: 64-bit .eh_frame records are not supported", o.name);
            }
            let size = len + 4;
            if off + size > d.len() || size < 8 {
                bail!("{}: truncated .eh_frame record at offset {off:#x}", o.name);
            }
            while ri < eh.rels.len() && (eh.rels[ri].offset as usize) < off {
                ri += 1;
            }
            let rs = ri;
            while ri < eh.rels.len() && (eh.rels[ri].offset as usize) < off + size {
                ri += 1;
            }
            let id = rd32::<T>(d, off + 4);
            let mut rec = Rec {
                sec: si,
                off: off as u32,
                size: size as u32,
                rel_start: rs as u32,
                rel_end: ri as u32,
                cie: NONE,
                target: NONE,
                out: NONE,
            };
            if id == 0 {
                eh.cies.push(rec);
            } else {
                let cie_off = (off + 4).checked_sub(id as usize).ok_or_else(|| {
                    err!(
                        "{}: bad CIE pointer in .eh_frame at offset {off:#x}",
                        o.name
                    )
                })?;
                let cie = (first_cie..eh.cies.len())
                    .find(|&c| eh.cies[c].off as usize == cie_off && eh.cies[c].sec == si)
                    .ok_or_else(|| err!("{}: FDE at {off:#x} without its CIE", o.name))?;
                rec.cie = cie as u32;
                // The first relocation, at pc_begin, names the code the FDE describes.
                if rs < ri && eh.rels[rs].offset as usize == off + 8 {
                    let r = eh.rels[rs];
                    rec.target = target_section(ctx, o, r.sym);
                }
                eh.fdes.push(rec);
            }
            off += size;
        }
    }
    eh.fdes.sort_by_key(|f| f.target);
    Ok(eh)
}

impl EhFrameInfo {
    /// The address of offset `value` in input `.eh_frame` section `sec` of object `oi`: in the
    /// record it falls in, if that was kept, else counted from the start of the object's records.
    /// GCC's crtbegin defines `__EH_FRAME_BEGIN__` at the start of its (empty) `.eh_frame`;
    /// where it registers the frames itself (musl), libgcc walks the records from there to the
    /// terminator. (Counting on outside records keeps a PC-relative bias: x86-64's
    /// `lea __EH_FRAME_BEGIN__(%rip)` is `.eh_frame - 4`.)
    pub fn symbol_addr(&self, oi: usize, sec: u32, value: u64) -> u64 {
        let Some(eh) = self.objs.get(oi) else {
            return self.addr.wrapping_add(value);
        };
        let base = self.addr + eh.out_off;
        eh.cies
            .iter()
            .chain(&eh.fdes)
            .find(|r| {
                r.sec == sec
                    && r.out != NONE
                    && (r.off as u64..r.off as u64 + r.size as u64).contains(&value)
            })
            .map_or(base.wrapping_add(value), |r| {
                base + r.out as u64 + (value - r.off as u64)
            })
    }
}

/// The input section a symbol of `o` is defined in, if in `o`.
fn target_section<T: Target>(ctx: &Ctx<'_, T>, o: &Object<'_>, sym: u32) -> u32 {
    if sym < o.first_global {
        let s = o.sym::<T>(sym);
        if s.shndx < SHN_LORESERVE && s.shndx != SHN_UNDEF {
            return s.shndx;
        }
        return NONE;
    }
    let id = o.global_id(sym);
    if id == NONE {
        return NONE;
    }
    match ctx.def_obj(id) {
        Some((d, i)) if d.prio == o.prio => {
            let s = d.sym::<T>(i);
            if s.shndx < SHN_LORESERVE && s.shndx != SHN_UNDEF {
                s.shndx
            } else {
                NONE
            }
        }
        _ => NONE,
    }
}

impl<T: Target> Ctx<'_, T> {
    /// Offset `value` of `o`'s input `.eh_frame` section `sec`, in the output.
    pub fn eh_frame_addr(&self, o: &Object<'_>, sec: u32, value: u64) -> u64 {
        self.ehframe
            .symbol_addr(self.obj_index(o) as usize, sec, value)
    }

    pub fn parse_eh_frames(&mut self) -> Result<()> {
        let objs: Vec<Result<ObjEh>> = self
            .objs
            .par_iter()
            .map(|o| {
                if !o.alive.load(Ordering::Relaxed) || o.eh_frames.is_empty() {
                    Ok(ObjEh::default())
                } else {
                    parse_obj(self, o)
                }
            })
            .collect();
        self.ehframe.objs = objs.into_iter().collect::<Result<_>>()?;
        Ok(())
    }

    /// After GC: which records survive, and where they go.
    pub fn size_eh_frame(&mut self) {
        let objs = &self.objs;
        self.ehframe
            .objs
            .par_iter_mut()
            .zip(objs.par_iter())
            .for_each(|(eh, o)| {
                if eh.fdes.is_empty() {
                    return;
                }
                let mut cie_used = vec![false; eh.cies.len()];
                for f in &mut eh.fdes {
                    let live = f.target != NONE
                        && o.secs
                            .get(f.target as usize)
                            .is_some_and(|s| s.is_live() && s.kind != SecKind::Discarded);
                    if live {
                        cie_used[f.cie as usize] = true;
                    } else {
                        f.out = NONE;
                    }
                    f.out = if live { 0 } else { NONE };
                }
                let mut off = 0u64;
                for (c, used) in eh.cies.iter_mut().zip(&cie_used) {
                    if *used {
                        c.out = off as u32;
                        off += c.size as u64;
                    } else {
                        c.out = NONE;
                    }
                }
                // FDEs in input order (by section, then offset) — the order code is laid out.
                let mut order: Vec<usize> = (0..eh.fdes.len())
                    .filter(|&i| eh.fdes[i].out != NONE)
                    .collect();
                order.sort_by_key(|&i| (eh.fdes[i].sec, eh.fdes[i].off));
                for &i in &order {
                    eh.fdes[i].out = off as u32;
                    off += eh.fdes[i].size as u64;
                }
                eh.live_fdes = order.len() as u64;
                eh.size = off;
            });
        let mut off = 0u64;
        let mut nfdes = 0u64;
        for eh in &mut self.ehframe.objs {
            eh.out_off = off;
            eh.first_fde = nfdes;
            off += eh.size;
            nfdes += eh.live_fdes;
        }
        self.ehframe.nfdes = nfdes;
        // A zero terminator, for unwinders that walk the section instead of using the table;
        // also when no record survives but an input has the section, as crtbegin's
        // `__EH_FRAME_BEGIN__` may then still be walked.
        let inputs = self
            .objs
            .iter()
            .any(|o| o.alive.load(Ordering::Relaxed) && !o.eh_frames.is_empty());
        self.ehframe.size = if off > 0 || inputs { off + 4 } else { 0 };
    }

    /// Write `.eh_frame` at `buf` (address `addr`) and return the `.eh_frame_hdr` table:
    /// (initial location, FDE address) per live FDE, in object order.
    pub fn write_eh_frame(
        &self,
        lay: &Layout,
        out: OutBuf,
        file_off: u64,
        addr: u64,
        dyn_w: DynWriter,
    ) -> Result<Vec<(u64, u64)>> {
        let table = SyncVec::new(self.ehframe.nfdes as usize, (0u64, 0u64));
        let errors: Vec<Result<()>> = self
            .objs
            .par_iter()
            .enumerate()
            .map(|(oi, o)| {
                let eh = &self.ehframe.objs[oi];
                if eh.size == 0 {
                    return Ok(());
                }
                let base = eh.out_off;
                let mut n = 0;
                let mut fdes: Vec<&Rec> = eh.fdes.iter().filter(|f| f.out != NONE).collect();
                fdes.sort_by_key(|f| f.out);
                for rec in eh
                    .cies
                    .iter()
                    .filter(|c| c.out != NONE)
                    .chain(fdes.iter().copied())
                {
                    let d = o.sec_data(rec.sec);
                    let pos = base + rec.out as u64;
                    let buf = out.slice(file_off + pos, rec.size as u64);
                    buf.copy_from_slice(&d[rec.off as usize..(rec.off + rec.size) as usize]);
                    let rels = &eh.rels[rec.rel_start as usize..rec.rel_end as usize];
                    let mut rc = RelocCtx::new(
                        self,
                        lay,
                        o,
                        rec.sec,
                        addr + pos,
                        rec.off as u64,
                        Rels::Slice(rels),
                        DynWriter { buf: None, ..dyn_w },
                    );
                    T::apply_alloc(&mut rc, buf)?;
                    if rec.cie != NONE {
                        let cie = &eh.cies[rec.cie as usize];
                        let cie_ptr = rec.out + 4 - cie.out;
                        wr32::<T>(buf, 4, cie_ptr);
                        let pc = match rels.first() {
                            Some(r) if r.offset == rec.off as u64 + 8 => rc.sa(r),
                            _ => 0,
                        };
                        table.set((eh.first_fde + n) as usize, (pc, addr + pos));
                        n += 1;
                    }
                }
                let start = file_off + base;
                self.bid.put(
                    self.bid.eh_base as usize + oi,
                    out.slice(start, eh.size),
                    start,
                );
                Ok(())
            })
            .collect();
        for e in errors {
            e?;
        }
        if self.ehframe.size >= 4 {
            out.slice(file_off + self.ehframe.size - 4, 4).fill(0);
        }
        Ok(table.into_vec())
    }

    /// `.eh_frame_hdr`: version 1, `.eh_frame` pointer, count, sorted (pc, fde) table.
    pub fn write_eh_frame_hdr(
        &self,
        buf: &mut [u8],
        hdr_addr: u64,
        eh_addr: u64,
        mut table: Vec<(u64, u64)>,
    ) {
        table.par_sort_unstable_by_key(|e| e.0);
        buf[0] = 1;
        buf[1] = 0x1b; // DW_EH_PE_pcrel | sdata4
        buf[2] = 0x03; // DW_EH_PE_udata4
        buf[3] = 0x3b; // DW_EH_PE_datarel | sdata4
        wr32::<T>(buf, 4, eh_addr.wrapping_sub(hdr_addr + 4) as u32);
        wr32::<T>(buf, 8, table.len() as u32);
        buf[12..12 + table.len() * 8]
            .par_chunks_mut(8)
            .zip(table.par_iter())
            .for_each(|(c, &(pc, fde))| {
                wr32::<T>(c, 0, pc.wrapping_sub(hdr_addr) as u32);
                wr32::<T>(c, 4, fde.wrapping_sub(hdr_addr) as u32);
            });
    }
}

pub fn hdr_size(nfdes: u64) -> u64 {
    12 + nfdes * 8
}
