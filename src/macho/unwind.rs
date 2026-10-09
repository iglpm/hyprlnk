//! Unwind information: `__compact_unwind` entries and `__eh_frame` records read from objects,
//! and the `__unwind_info` section built from the live ones.

use super::arch::{reloc_is_subtractor, reloc_is_unsigned};
use super::config::Arch;
use super::object::*;
use super::*;
use crate::bail;
use crate::diag::Result;

pub const UNWIND_MODE_MASK: u32 = 0x0f00_0000;
pub const UNWIND_ARM64_MODE_DWARF: u32 = 0x0300_0000;
pub const UNWIND_X86_64_MODE_DWARF: u32 = 0x0400_0000;
pub const UNWIND_X86_64_MODE_STACK_IND: u32 = 0x0300_0000;
pub const UNWIND_HAS_LSDA: u32 = 0x4000_0000;
pub const UNWIND_PERSONALITY_MASK: u32 = 0x3000_0000;

pub fn dwarf_mode(arch: Arch) -> u32 {
    if arch.is_arm() {
        UNWIND_ARM64_MODE_DWARF
    } else {
        UNWIND_X86_64_MODE_DWARF
    }
}

pub fn is_dwarf(arch: Arch, encoding: u32) -> bool {
    encoding & UNWIND_MODE_MASK == dwarf_mode(arch)
}

/// The in-place value of a relocated field.
fn inplace(data: &[u8], off: usize, len: u8) -> i64 {
    match len {
        2 => data
            .get(off..off + 4)
            .map_or(0, |b| i32::from_le_bytes(b.try_into().unwrap()) as i64),
        3 => data
            .get(off..off + 8)
            .map_or(0, |b| i64::from_le_bytes(b.try_into().unwrap())),
        _ => 0,
    }
}

/// An absolute pointer field (`UNSIGNED`) as a reference, extern or section-relative.
fn pointer_ref(obj: &ObjFile, sec: &Section, r: RawReloc) -> Ref {
    let v = inplace(sec.data, r.addr as usize, r.len);
    if r.ext {
        match obj.sym_ref(r.sym, v) {
            (Ref::Sym(i), a) if a != 0 => {
                // An external symbol with an addend: keep it local when it's defined here.
                match obj.local_ref(i, a) {
                    Ref::None => Ref::Sym(i),
                    local => local,
                }
            }
            (r, _) => r,
        }
    } else {
        obj.section_ref(r.sym, v as u64)
    }
}

/// The object-local place an external symbol index names (functions and LSDAs are always local).
fn localize(obj: &ObjFile, r: Ref) -> Ref {
    match r {
        Ref::Sym(i) => match obj.local_ref(i, 0) {
            Ref::None => Ref::Sym(i),
            l => l,
        },
        r => r,
    }
}

pub fn parse_compact_unwind(obj: &mut ObjFile) -> Result<()> {
    let Some(si) = obj
        .sections
        .iter()
        .position(|s| s.kind == SecKind::CompactUnwind)
    else {
        return Ok(());
    };
    let arch = obj.arch.unwrap();
    let sec = &obj.sections[si];
    if !sec.size.is_multiple_of(32) {
        bail!(
            "{}: __compact_unwind is not a multiple of 32 bytes",
            obj.name
        );
    }
    let n = (sec.size / 32) as usize;
    let d = sec.data;
    let mut entries: Vec<CuEntry> = (0..n)
        .map(|i| CuEntry {
            atom: NONE,
            off: 0,
            length: u32le(d, i * 32 + 8),
            encoding: u32le(d, i * 32 + 12),
            personality: Ref::None,
            lsda: Ref::None,
        })
        .collect();
    let mut funcs: Vec<Ref> = vec![Ref::None; n];
    for i in 0..sec.nrelocs() {
        let r = raw_reloc(sec.relocs, i);
        if !reloc_is_unsigned(arch, r.ty) {
            continue;
        }
        let e = r.addr as usize / 32;
        if e >= n {
            continue;
        }
        let target = pointer_ref(obj, sec, r);
        match r.addr % 32 {
            0 => funcs[e] = localize(obj, target),
            16 => entries[e].personality = target,
            24 => entries[e].lsda = localize(obj, target),
            _ => {}
        }
    }
    for (e, f) in entries.iter_mut().zip(funcs) {
        if let Ref::Atom { atom, off } = f {
            e.atom = atom;
            e.off = off.max(0) as u32;
        }
    }
    entries.retain(|e| e.atom != NONE);
    entries.sort_by_key(|e| (e.atom, e.off));
    for (i, e) in entries.iter().enumerate().rev() {
        obj.atoms[e.atom as usize].aux = i as u32;
    }
    obj.cu = entries;
    Ok(())
}

fn ptr_size(enc: u8) -> Option<u8> {
    if enc == 0xff {
        return Some(0);
    }
    match enc & 0x0f {
        0x00 => Some(8),
        0x02 | 0x0a => Some(2),
        0x03 | 0x0b => Some(4),
        0x04 | 0x0c => Some(8),
        _ => None,
    }
}

fn read_signed(d: &[u8], off: usize, size: u8) -> i64 {
    match size {
        2 => d
            .get(off..off + 2)
            .map_or(0, |b| i16::from_le_bytes(b.try_into().unwrap()) as i64),
        4 => d
            .get(off..off + 4)
            .map_or(0, |b| i32::from_le_bytes(b.try_into().unwrap()) as i64),
        8 => d
            .get(off..off + 8)
            .map_or(0, |b| i64::from_le_bytes(b.try_into().unwrap())),
        _ => 0,
    }
}

/// A pc-relative pointer field in `__eh_frame` at section offset `field`: from its
/// SUBTRACTOR/UNSIGNED pair if there is one, else from the value in place.
fn eh_pointer(obj: &ObjFile, si: usize, atom: &Atom, field: u32, size: u8) -> Ref {
    let arch = obj.arch.unwrap();
    let sec = &obj.sections[si];
    let mut i = atom.rel_lo as usize;
    while i < atom.rel_hi as usize {
        let r = raw_reloc(sec.relocs, i);
        if r.addr == field && reloc_is_subtractor(arch, r.ty) && i + 1 < atom.rel_hi as usize {
            let m = raw_reloc(sec.relocs, i + 1);
            let a = inplace(sec.data, field as usize, m.len);
            // value = M + A - S, and it means target - field: target = (M + A) + (field - S).
            let s_addr = if r.ext {
                obj.nlist(r.sym).value
            } else {
                obj.sections.get(r.sym as usize - 1).map_or(0, |s| s.addr)
            };
            let delta = (sec.addr + field as u64) as i64 - s_addr as i64;
            return if m.ext {
                let base = obj.nlist(m.sym);
                if base.ty & N_TYPE == N_SECT {
                    obj.local_ref(m.sym, a + delta)
                } else {
                    Ref::Sym(m.sym)
                }
            } else {
                obj.section_ref(m.sym, (a + delta) as u64)
            };
        }
        if r.addr == field && reloc_is_unsigned(arch, r.ty) {
            return localize(obj, pointer_ref(obj, sec, r));
        }
        i += 1;
    }
    let v = read_signed(sec.data, field as usize, size);
    if v == 0 && size != 8 {
        return Ref::None;
    }
    let target = (sec.addr + field as u64).wrapping_add(v as u64);
    match obj.locate(target) {
        Some((_, atom, off)) => Ref::Atom { atom, off },
        None => Ref::None,
    }
}

pub fn parse_eh_frame(obj: &mut ObjFile) -> Result<()> {
    let Some(si) = obj.sections.iter().position(|s| s.kind == SecKind::EhFrame) else {
        return Ok(());
    };
    let range = obj.sections[si].atoms.clone();
    let d = obj.sections[si].data;
    let mut cie_of_atom: Vec<(u32, u32)> = Vec::new();
    let mut cies = Vec::new();
    let mut fdes = Vec::new();
    for ai in range.clone() {
        let a = &obj.atoms[ai as usize];
        if a.flags & ATOM_CIE == 0 {
            continue;
        }
        let base = a.off as usize;
        let mut p = base + 9;
        let aug = cstr(d, p);
        p += aug.len() + 1;
        if aug.windows(2).any(|w| w == b"eh") {
            p += 8;
        }
        let version = d.get(base + 8).copied().unwrap_or(1);
        let _ = read_uleb(d, &mut p);
        let _ = read_sleb(d, &mut p);
        if version == 1 {
            p += 1;
        } else {
            let _ = read_uleb(d, &mut p);
        }
        let mut cie = Cie {
            atom: ai,
            fde_ptr_size: 8,
            lsda_ptr_size: 0,
            has_aug_data: aug.first() == Some(&b'z'),
            personality: Ref::None,
        };
        if cie.has_aug_data {
            let _ = read_uleb(d, &mut p);
            for &c in &aug[1..] {
                match c {
                    b'P' => {
                        let enc = d.get(p).copied().unwrap_or(0xff);
                        p += 1;
                        let size = ptr_size(enc).ok_or_else(|| {
                            crate::err!(
                                "{}: unsupported personality encoding {enc:#x} in __eh_frame",
                                obj.name
                            )
                        })?;
                        let field = p as u32;
                        let sec = &obj.sections[si];
                        for i in a.rel_lo..a.rel_hi {
                            let r = raw_reloc(sec.relocs, i as usize);
                            if r.addr == field && r.ext {
                                cie.personality = Ref::Sym(r.sym);
                            }
                        }
                        p += size as usize;
                    }
                    b'L' => {
                        let enc = d.get(p).copied().unwrap_or(0xff);
                        p += 1;
                        cie.lsda_ptr_size = ptr_size(enc).ok_or_else(|| {
                            crate::err!(
                                "{}: unsupported LSDA encoding {enc:#x} in __eh_frame",
                                obj.name
                            )
                        })?;
                    }
                    b'R' => {
                        let enc = d.get(p).copied().unwrap_or(0);
                        p += 1;
                        cie.fde_ptr_size = ptr_size(enc).filter(|&s| s != 0).ok_or_else(|| {
                            crate::err!(
                                "{}: unsupported FDE pointer encoding {enc:#x} in __eh_frame",
                                obj.name
                            )
                        })?;
                    }
                    _ => {}
                }
            }
        }
        cie_of_atom.push((ai, cies.len() as u32));
        cies.push(cie);
    }
    for ai in range {
        let a = &obj.atoms[ai as usize];
        if a.flags & ATOM_FDE == 0 {
            continue;
        }
        let base = a.off as usize;
        let back = u32le(d, base + 4) as usize;
        let cie_off = (base + 4).wrapping_sub(back) as u32;
        let Some(&(_, cie)) = cie_of_atom
            .iter()
            .find(|(c, _)| obj.atoms[*c as usize].off == cie_off)
        else {
            bail!("{}: __eh_frame FDE at {base:#x} has no CIE", obj.name);
        };
        let c = cies[cie as usize];
        let size = c.fde_ptr_size;
        let func = eh_pointer(obj, si, a, (base + 8) as u32, size);
        let range = read_signed(d, base + 8 + size as usize, size) as u32;
        let mut lsda = Ref::None;
        let mut lsda_field = 0;
        if c.has_aug_data {
            let mut p = base + 8 + 2 * size as usize;
            let _ = read_uleb(d, &mut p);
            if c.lsda_ptr_size != 0 {
                lsda_field = p as u32;
                lsda = eh_pointer(obj, si, a, p as u32, c.lsda_ptr_size);
            }
        }
        fdes.push(Fde {
            atom: ai,
            cie,
            func: localize(obj, func),
            range,
            lsda,
            lsda_field,
        });
    }
    let mut fde_of = Vec::with_capacity(fdes.len());
    for (i, f) in fdes.iter().enumerate() {
        obj.atoms[f.atom as usize].aux = i as u32;
        if let Ref::Atom { atom, off } = f.func
            && off >= 0
        {
            fde_of.push((atom, off as u32, i as u32));
        }
    }
    for (i, c) in cies.iter().enumerate() {
        obj.atoms[c.atom as usize].aux = i as u32;
    }
    fde_of.sort_unstable();
    fde_of.dedup_by_key(|e| (e.0, e.1));
    obj.cies = cies;
    obj.fdes = fdes;
    obj.fde_of = fde_of;
    Ok(())
}

impl ObjFile<'_> {
    /// The FDEs of functions in `atom`: (atom, offset, FDE index).
    pub fn fdes_of(&self, atom: u32) -> &[(u32, u32, u32)] {
        let lo = self.fde_of.partition_point(|e| e.0 < atom);
        let hi = self.fde_of.partition_point(|e| e.0 <= atom);
        &self.fde_of[lo..hi]
    }

    pub fn fde_at(&self, atom: u32, off: u32) -> Option<u32> {
        self.fdes_of(atom).iter().find(|e| e.1 == off).map(|e| e.2)
    }

    /// The compact-unwind entries describing `atom`.
    pub fn cu_for(&self, atom: u32) -> &[CuEntry] {
        let first = self.atoms[atom as usize].aux;
        let a = &self.atoms[atom as usize];
        let sec = &self.sections[a.sec as usize];
        if first == NONE
            || !sec.is_code()
            || first as usize >= self.cu.len()
            || self.cu[first as usize].atom != atom
        {
            return &[];
        }
        let mut end = first as usize;
        while end < self.cu.len() && self.cu[end].atom == atom {
            end += 1;
        }
        &self.cu[first as usize..end]
    }

    /// Whether the FDE of the function at `off` in `atom` must be kept: no compact encoding
    /// describes that function, or one that defers to DWARF does.
    pub fn needs_fde(&self, atom: u32, off: u32) -> bool {
        let arch = self.arch.unwrap();
        let mut at = self.cu_for(atom).iter().filter(|e| e.off == off).peekable();
        at.peek().is_none() || at.any(|e| is_dwarf(arch, e.encoding))
    }
}

const COMMON_ENCODINGS_MAX: usize = 127;
const COMPACT_ENCODINGS_MAX: usize = 256;
const SECOND_LEVEL_PAGE_BYTES: u64 = 4096;
const SECOND_LEVEL_PAGE_WORDS: usize = 1024;
const REGULAR_ENTRIES_MAX: usize = (4096 - 8) / 8;
const COMPRESSED_FUNC_OFFSET_MASK: u64 = 0x00ff_ffff;
pub const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
pub const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;

#[derive(Debug, Clone, Copy)]
pub struct UEntry {
    pub func: u64,
    pub len: u32,
    pub encoding: u32,
    pub personality: u32,
    pub lsda: u64,
}

pub struct Page {
    pub first: usize,
    pub count: usize,
    pub compressed: bool,
    pub local: Vec<u32>,
}

/// `__unwind_info`'s structure: decided during layout (its size moves what follows),
/// written once the GOT slots of the personality routines have addresses.
pub struct UnwindPlan {
    pub size: u64,
    pub entries: Vec<UEntry>,
    pub common: Vec<u32>,
    pub common_index: std::collections::HashMap<u32, u32>,
    pub personalities: Vec<super::symtab::SymId>,
    pub pages: Vec<Page>,
    /// Number of LSDA entries before each entry.
    pub lsda_before: Vec<u32>,
    pub nlsda: usize,
}

fn can_fold(arch: Arch, encoding: u32) -> bool {
    if is_dwarf(arch, encoding) {
        return false;
    }
    !(!arch.is_arm() && encoding & UNWIND_MODE_MASK == UNWIND_X86_64_MODE_STACK_IND)
}

impl super::resolve::Linker<'_> {
    pub fn plan_unwind_info(&self, layout: &super::layout::Layout) -> Result<UnwindPlan> {
        use rayon::prelude::*;
        let arch = self.arch;
        let eh = layout.find_section(b"__TEXT", b"__eh_frame");
        let eh_addr = eh.map_or(0, |i| layout.sections[i].addr);
        let base = layout.image_base;
        let dwarf = dwarf_mode(arch);
        // (func, len, encoding, personality symbol, lsda address)
        type Raw = (u64, u32, u32, u32, u64);
        let per_obj: Vec<Result<Vec<Raw>>> = self
            .objs
            .par_iter()
            .enumerate()
            .map(|(oi, obj)| {
                let oi = oi as u32;
                let mut v = Vec::new();
                for s in &obj.sections {
                    if s.out == NONE || !s.is_code() {
                        continue;
                    }
                    if layout.sections[s.out as usize].segname != b"__TEXT" {
                        continue;
                    }
                    for ai in s.atoms.clone() {
                        let a = &obj.atoms[ai as usize];
                        if !a.is_live() {
                            continue;
                        }
                        let addr = self.provisional_addr(layout, oi, ai);
                        let fde_enc = |fde: u32| -> Result<u32> {
                            let fa = obj.fdes[fde as usize].atom;
                            let off = self.provisional_addr(layout, oi, fa) - eh_addr;
                            if off > 0x00ff_ffff {
                                bail!("__eh_frame is larger than 16 MiB; compact unwind can't refer into it");
                            }
                            Ok(dwarf | off as u32)
                        };
                        let lsda_addr = |r: Ref| -> u64 {
                            match r {
                                Ref::Atom { atom, off } => (self.provisional_addr(layout, oi, atom) as i64 + off) as u64,
                                Ref::Sym(i) => {
                                    let id = obj.global(i);
                                    match self.symtab.get(id).def {
                                        super::symtab::Def::Defined { obj: o2, atom, off } => {
                                            self.provisional_addr(layout, o2, atom) + off as u64
                                        }
                                        _ => 0,
                                    }
                                }
                                _ => 0,
                            }
                        };
                        let cu = obj.cu_for(ai);
                        let fdes = obj.fdes_of(ai);
                        if cu.is_empty() && fdes.is_empty() {
                            if a.flags & ATOM_HAS_SYMBOL != 0 && a.size > 0 {
                                v.push((addr, a.size, 0, NONE, 0));
                            }
                            continue;
                        }
                        for e in cu {
                            let mut enc = e.encoding;
                            let mut pers = NONE;
                            let mut lsda = lsda_addr(e.lsda);
                            if is_dwarf(arch, enc) {
                                // The unwinder reads the LSDA (and personality) from the FDE.
                                enc = match obj.fde_at(ai, e.off) {
                                    Some(f) => fde_enc(f)?,
                                    None => dwarf,
                                };
                                lsda = 0;
                            } else if let Ref::Sym(i) = e.personality {
                                pers = obj.global(i);
                            }
                            v.push((addr + e.off as u64, e.length, enc, pers, lsda));
                        }
                        // Functions only DWARF describes.
                        for &(_, off, f) in fdes {
                            if cu.iter().any(|e| e.off == off) {
                                continue;
                            }
                            let fde = &obj.fdes[f as usize];
                            v.push((addr + off as u64, fde.range, fde_enc(f)?, NONE, 0));
                        }
                    }
                }
                Ok(v)
            })
            .collect();
        let mut raw = Vec::new();
        for r in per_obj {
            raw.extend(r?);
        }
        raw.par_sort_by_key(|e| e.0);

        // Personalities, in order of first use; at most three fit the encoding.
        let mut personalities: Vec<super::symtab::SymId> = Vec::new();
        let mut entries: Vec<UEntry> = Vec::with_capacity(raw.len());
        for (func, len, mut enc, pers, lsda) in raw {
            if pers != NONE {
                let idx = match personalities.iter().position(|&p| p == pers) {
                    Some(i) => i,
                    None => {
                        personalities.push(pers);
                        personalities.len() - 1
                    }
                };
                if idx >= 3 {
                    bail!(
                        "too many personality routines for compact unwind info (at most 3): {}",
                        personalities
                            .iter()
                            .map(|&p| crate::diag::symbol(self.symtab.get(p).name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                enc = (enc & !UNWIND_PERSONALITY_MASK) | (((idx + 1) as u32) << 28);
            }
            if lsda != 0 {
                enc |= UNWIND_HAS_LSDA;
            }
            entries.push(UEntry {
                func: func - base,
                len,
                encoding: enc,
                personality: pers,
                lsda: if lsda == 0 { 0 } else { lsda - base },
            });
        }
        // Fold runs of identical encodings without LSDAs.
        let mut folded: Vec<UEntry> = Vec::with_capacity(entries.len());
        for e in entries {
            if let Some(last) = folded.last_mut()
                && last.encoding == e.encoding
                && last.personality == e.personality
                && last.lsda == 0
                && e.lsda == 0
                && can_fold(arch, e.encoding)
            {
                last.len = (e.func + e.len as u64 - last.func) as u32;
                continue;
            }
            folded.push(e);
        }
        let entries = folded;

        // Frequencies by sorting (DWARF-mode encodings are mostly unique), then the top 127.
        let mut encs: Vec<u32> = entries.iter().map(|e| e.encoding).collect();
        encs.par_sort_unstable();
        let mut common: Vec<(u32, usize)> = Vec::new();
        for &e in &encs {
            match common.last_mut() {
                Some((x, n)) if *x == e => *n += 1,
                _ => common.push((e, 1)),
            }
        }
        let by_use = |a: &(u32, usize), b: &(u32, usize)| b.1.cmp(&a.1).then(b.0.cmp(&a.0));
        if common.len() > COMMON_ENCODINGS_MAX {
            common.select_nth_unstable_by(COMMON_ENCODINGS_MAX - 1, by_use);
            common.truncate(COMMON_ENCODINGS_MAX);
        }
        common.sort_by(by_use);
        let common: Vec<u32> = common.into_iter().map(|c| c.0).collect();
        let common_index: std::collections::HashMap<u32, u32> = common
            .iter()
            .enumerate()
            .map(|(i, &e)| (e, i as u32))
            .collect();

        let mut pages = Vec::new();
        let mut i = 0;
        while i < entries.len() {
            let first = i;
            let limit = entries[i].func + COMPRESSED_FUNC_OFFSET_MASK;
            let mut local: Vec<u32> = Vec::new();
            let mut words = SECOND_LEVEL_PAGE_WORDS - 3;
            while words >= 1 && i < entries.len() {
                let e = &entries[i];
                if e.func >= limit {
                    break;
                }
                if common_index.contains_key(&e.encoding) || local.contains(&e.encoding) {
                    i += 1;
                    words -= 1;
                } else if words >= 2 && common.len() + local.len() < COMPACT_ENCODINGS_MAX {
                    local.push(e.encoding);
                    i += 1;
                    words -= 2;
                } else {
                    break;
                }
            }
            let count = i - first;
            if i < entries.len() && count < REGULAR_ENTRIES_MAX {
                let count = REGULAR_ENTRIES_MAX.min(entries.len() - first);
                i = first + count;
                pages.push(Page {
                    first,
                    count,
                    compressed: false,
                    local: Vec::new(),
                });
            } else {
                pages.push(Page {
                    first,
                    count,
                    compressed: true,
                    local,
                });
            }
        }
        let mut lsda_before = Vec::with_capacity(entries.len() + 1);
        let mut n = 0u32;
        for e in &entries {
            lsda_before.push(n);
            if e.lsda != 0 {
                n += 1;
            }
        }
        lsda_before.push(n);
        let header = 28 + 4 * common.len() as u64 + 4 * personalities.len() as u64;
        let index = 12 * (pages.len() as u64 + 1);
        let size = header + index + 8 * n as u64 + SECOND_LEVEL_PAGE_BYTES * pages.len() as u64;
        Ok(UnwindPlan {
            size,
            entries,
            common,
            common_index,
            personalities,
            pages,
            lsda_before,
            nlsda: n as usize,
        })
    }

    /// Fill `__unwind_info`; `got_addr` gives the GOT slot of a personality routine.
    pub fn write_unwind_info(
        &self,
        plan: &UnwindPlan,
        out: &mut [u8],
        base: u64,
        got_addr: impl Fn(super::symtab::SymId) -> u64,
    ) {
        let ncommon = plan.common.len() as u32;
        let npers = plan.personalities.len() as u32;
        let common_off = 28u32;
        let pers_off = common_off + 4 * ncommon;
        let index_off = pers_off + 4 * npers;
        let nindex = plan.pages.len() as u32 + 1;
        let lsda_off = index_off + 12 * nindex;
        let pages_off = lsda_off + 8 * plan.nlsda as u32;
        put32(out, 0, 1);
        put32(out, 4, common_off);
        put32(out, 8, ncommon);
        put32(out, 12, pers_off);
        put32(out, 16, npers);
        put32(out, 20, index_off);
        put32(out, 24, nindex);
        for (i, &e) in plan.common.iter().enumerate() {
            put32(out, (common_off + 4 * i as u32) as usize, e);
        }
        for (i, &p) in plan.personalities.iter().enumerate() {
            put32(
                out,
                (pers_off + 4 * i as u32) as usize,
                (got_addr(p) - base) as u32,
            );
        }
        let mut lsda_at = lsda_off as usize;
        for e in &plan.entries {
            if e.lsda != 0 {
                put32(out, lsda_at, e.func as u32);
                put32(out, lsda_at + 4, e.lsda as u32);
                lsda_at += 8;
            }
        }
        let mut ix = index_off as usize;
        for (pi, page) in plan.pages.iter().enumerate() {
            let e0 = &plan.entries[page.first];
            put32(out, ix, e0.func as u32);
            put32(
                out,
                ix + 4,
                pages_off + (pi as u32) * SECOND_LEVEL_PAGE_BYTES as u32,
            );
            put32(out, ix + 8, lsda_off + 8 * plan.lsda_before[page.first]);
            ix += 12;
            let p = (pages_off as usize) + pi * SECOND_LEVEL_PAGE_BYTES as usize;
            if page.compressed {
                put32(out, p, UNWIND_SECOND_LEVEL_COMPRESSED);
                put16(out, p + 4, 12);
                put16(out, p + 6, page.count as u16);
                put16(out, p + 8, (12 + 4 * page.count) as u16);
                put16(out, p + 10, page.local.len() as u16);
                let mut q = p + 12;
                for e in &plan.entries[page.first..page.first + page.count] {
                    let idx = match plan.common_index.get(&e.encoding) {
                        Some(&i) => i,
                        None => {
                            plan.common.len() as u32
                                + page.local.iter().position(|&l| l == e.encoding).unwrap() as u32
                        }
                    };
                    put32(out, q, (idx << 24) | (e.func - e0.func) as u32);
                    q += 4;
                }
                for &l in &page.local {
                    put32(out, q, l);
                    q += 4;
                }
            } else {
                put32(out, p, UNWIND_SECOND_LEVEL_REGULAR);
                put16(out, p + 4, 8);
                put16(out, p + 6, page.count as u16);
                let mut q = p + 8;
                for e in &plan.entries[page.first..page.first + page.count] {
                    put32(out, q, e.func as u32);
                    put32(out, q + 4, e.encoding);
                    q += 8;
                }
            }
        }
        let end = plan.entries.last().map_or(0, |e| e.func + e.len as u64);
        put32(out, ix, end as u32);
        put32(out, ix + 4, 0);
        put32(out, ix + 8, lsda_off + 8 * plan.nlsda as u32);
    }
}
