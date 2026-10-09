//! The symbol table (with the debug map's stabs), string table, indirect symbols, function
//! starts and data-in-code entries. Each object's share is planned and written in parallel.

use rayon::prelude::*;

use super::layout::Layout;
use super::object::*;
use super::resolve::Linker;
use super::symtab::{Def, LIVE, SymId, Synthetic};
use super::*;

#[derive(Default)]
pub struct ObjSyms {
    /// (nlist index, private extern turned local)
    pub locals: Vec<(u32, bool)>,
    pub exts: Vec<u32>,
    pub source: Option<Vec<u8>>,
    pub oso: Vec<u8>,
    pub nstabs: u32,
    pub stab_str: u64,
    pub local_str: u64,
    pub ext_str: u64,
    pub stab_base: u32,
    pub local_base: u32,
    pub ext_base: u32,
    pub stab_strx: u64,
    pub local_strx: u64,
    pub ext_strx: u64,
}

pub struct SymtabPlan {
    pub objs: Vec<ObjSyms>,
    pub synth_locals: Vec<SymId>,
    pub synth_exts: Vec<SymId>,
    pub undefs: Vec<SymId>,
    pub nlocal: u32,
    pub iextdef: u32,
    pub nextdef: u32,
    pub iundef: u32,
    pub nundef: u32,
    pub nsyms: u32,
    pub strsize: u64,
    pub synth_local_strx: u64,
    pub synth_ext_strx: u64,
    pub undef_strx: u64,
    pub indirect: Vec<u32>,
}

fn private_label(name: &[u8]) -> bool {
    matches!(name.first(), Some(b'l' | b'L'))
}

fn nlist_bytes(out: &mut [u8], strx: u32, ty: u8, sect: u8, desc: u16, value: u64) {
    put32(out, 0, strx);
    out[4] = ty;
    out[5] = sect;
    put16(out, 6, desc);
    put64(out, 8, value);
}

impl Linker<'_> {
    pub fn plan_symtab(&self, layout: &Layout) -> SymtabPlan {
        let strip_debug = self.cfg.strip_debug;
        let strip_locals = self.cfg.strip_locals;
        let cwd = std::env::current_dir().unwrap_or_default();
        let mut objs: Vec<ObjSyms> = self
            .objs
            .par_iter()
            .enumerate()
            .map(|(oi, obj)| {
                let oi = oi as u32;
                let mut o = ObjSyms::default();
                for i in 0..obj.nsyms() as u32 {
                    let s = obj.nlist(i);
                    if s.ty & N_STAB != 0 {
                        continue;
                    }
                    let name = cstr(obj.strtab, s.strx as usize);
                    if s.ty & N_EXT != 0 {
                        let id = obj.global(i);
                        if id == NONE {
                            continue;
                        }
                        let sym = self.symtab.get(id);
                        let Def::Defined { obj: d, atom, .. } = sym.def else {
                            continue;
                        };
                        if d != oi || !obj.atoms[atom as usize].is_live() {
                            continue;
                        }
                        if sym.private_extern {
                            if !strip_locals {
                                o.locals.push((i, true));
                                o.local_str += name.len() as u64 + 1;
                            }
                        } else {
                            o.exts.push(i);
                            o.ext_str += name.len() as u64 + 1;
                        }
                        continue;
                    }
                    if strip_locals || private_label(name) || name.is_empty() {
                        continue;
                    }
                    match s.ty & N_TYPE {
                        N_SECT => {
                            let a = obj.sym_atom[i as usize];
                            if a == NONE || !obj.atoms[a as usize].is_live() {
                                continue;
                            }
                        }
                        N_ABS => {}
                        _ => continue,
                    }
                    o.locals.push((i, false));
                    o.local_str += name.len() as u64 + 1;
                }
                if !strip_debug
                    && obj.debug_info.is_some()
                    && !(o.locals.is_empty() && o.exts.is_empty())
                    && let Some(src) = super::dwarf::source_file(obj)
                {
                    {
                        // `archive(member)` for archive members, as dsymutil expects.
                        let mut oso = obj.name.clone();
                        if !std::path::Path::new(&oso).is_absolute() {
                            oso = cwd.join(&oso).display().to_string();
                        }
                        let mut oso = oso.into_bytes();
                        if let Some(prefix) = &self.cfg.oso_prefix
                            && let Some(rest) = oso.strip_prefix(prefix.as_bytes())
                        {
                            oso = rest.to_vec();
                        }
                        // Stabs name their symbols with the symbols' own strings.
                        let mut n = 3u32;
                        let str_size = src.len() as u64 + 1 + oso.len() as u64 + 1;
                        let mut count = |i: u32| {
                            let s = obj.nlist(i);
                            if s.ty & N_TYPE != N_SECT {
                                return;
                            }
                            let a = obj.sym_atom[i as usize];
                            let code = obj.sections[obj.atoms[a as usize].sec as usize].is_code();
                            n += if code { 2 } else { 1 };
                        };
                        for &(i, _) in &o.locals {
                            count(i);
                        }
                        for &i in &o.exts {
                            count(i);
                        }
                        o.nstabs = n;
                        o.stab_str = str_size;
                        o.source = Some(src);
                        o.oso = oso;
                    }
                }
                o
            })
            .collect();

        let mut synth_locals = Vec::new();
        let mut synth_exts = Vec::new();
        let mut undefs = Vec::new();
        for id in 0..self.symtab.len() as SymId {
            let s = self.symtab.get(id);
            match s.def {
                Def::Synthetic(Synthetic::Header)
                | Def::Synthetic(Synthetic::Common(_))
                | Def::Absolute { .. } => {
                    if matches!(s.def, Def::Absolute { .. }) && !s.has(LIVE) && self.cfg.dead_strip
                    {
                        continue;
                    }
                    if s.private_extern {
                        // `___dso_handle` and the other hidden header names stay out, as in ld64.
                        if !strip_locals && !matches!(s.def, Def::Synthetic(Synthetic::Header)) {
                            synth_locals.push(id);
                        }
                    } else {
                        synth_exts.push(id);
                    }
                }
                Def::Dylib { .. } | Def::DynamicLookup if s.has(LIVE) => undefs.push(id),
                _ => {}
            }
        }

        // Indices and string offsets: stabs, locals, externals, undefined.
        let mut idx = 0u32;
        let mut strx = 2u64; // " \0": index 1 is the empty string.
        for o in &mut objs {
            o.stab_base = idx;
            o.stab_strx = strx;
            idx += o.nstabs;
            strx += o.stab_str;
        }
        for o in &mut objs {
            o.local_base = idx;
            o.local_strx = strx;
            idx += o.locals.len() as u32;
            strx += o.local_str;
        }
        let synth_local_strx = strx;
        idx += synth_locals.len() as u32;
        strx += synth_locals
            .iter()
            .map(|&id| self.symtab.get(id).name.len() as u64 + 1)
            .sum::<u64>();
        let nlocal = idx;
        for o in &mut objs {
            o.ext_base = idx;
            o.ext_strx = strx;
            idx += o.exts.len() as u32;
            strx += o.ext_str;
        }
        let synth_ext_strx = strx;
        idx += synth_exts.len() as u32;
        strx += synth_exts
            .iter()
            .map(|&id| self.symtab.get(id).name.len() as u64 + 1)
            .sum::<u64>();
        let iundef = idx;
        let undef_strx = strx;
        idx += undefs.len() as u32;
        strx += undefs
            .iter()
            .map(|&id| self.symtab.get(id).name.len() as u64 + 1)
            .sum::<u64>();

        let mut plan = SymtabPlan {
            objs,
            nlocal,
            iextdef: nlocal,
            nextdef: iundef - nlocal,
            iundef,
            nundef: undefs.len() as u32,
            synth_locals,
            synth_exts,
            undefs,
            nsyms: idx,
            strsize: align_up(strx, 8),
            synth_local_strx,
            synth_ext_strx,
            undef_strx,
            indirect: Vec::new(),
        };
        plan.indirect = self.indirect_symbols(layout, &plan);
        plan
    }

    /// The symbol table index of each stub, GOT slot and TLV pointer, in that order.
    fn indirect_symbols(&self, _layout: &Layout, plan: &SymtabPlan) -> Vec<u32> {
        let index_of = |id: SymId| -> u32 {
            let s = self.symtab.get(id);
            match s.def {
                Def::Dylib { .. } | Def::DynamicLookup => {
                    plan.iundef + plan.undefs.iter().position(|&u| u == id).unwrap_or(0) as u32
                }
                Def::Defined { obj, .. } if !s.private_extern => {
                    let o = &plan.objs[obj as usize];
                    let objf = &self.objs[obj as usize];
                    match o.exts.iter().position(|&i| objf.global(i) == id) {
                        Some(p) => o.ext_base + p as u32,
                        None => INDIRECT_SYMBOL_LOCAL,
                    }
                }
                Def::Absolute { .. } => INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS,
                _ => INDIRECT_SYMBOL_LOCAL,
            }
        };
        let mut v = Vec::with_capacity(self.stubs.len() + self.got.len() + self.tlvps.len());
        for list in [&self.stubs, &self.got, &self.tlvps, &self.auth_got] {
            for &id in list.iter() {
                v.push(index_of(id));
            }
        }
        v
    }

    /// Fill the symbol table and string table.
    pub fn write_symtab(
        &self,
        layout: &Layout,
        plan: &SymtabPlan,
        syms: &mut [u8],
        strs: &mut [u8],
    ) {
        strs[0] = b' ';
        strs[1] = 0;
        // Carve the outputs into each object's disjoint pieces.
        let mut sym_pieces: Vec<(usize, usize)> = Vec::new();
        let mut str_pieces: Vec<(usize, usize)> = Vec::new();
        for o in &plan.objs {
            sym_pieces.push((o.stab_base as usize * 16, o.nstabs as usize * 16));
            str_pieces.push((o.stab_strx as usize, o.stab_str as usize));
        }
        for o in &plan.objs {
            sym_pieces.push((o.local_base as usize * 16, o.locals.len() * 16));
            str_pieces.push((o.local_strx as usize, o.local_str as usize));
        }
        for o in &plan.objs {
            sym_pieces.push((o.ext_base as usize * 16, o.exts.len() * 16));
            str_pieces.push((o.ext_strx as usize, o.ext_str as usize));
        }
        let n = plan.objs.len();
        let mut sym_slices = split_pieces(syms, &sym_pieces);
        let mut str_slices = split_pieces(strs, &str_pieces);
        let ext_syms = sym_slices.split_off(2 * n);
        let local_syms = sym_slices.split_off(n);
        let stab_syms = sym_slices;
        let ext_strs = str_slices.split_off(2 * n);
        let local_strs = str_slices.split_off(n);
        let stab_strs = str_slices;
        let work: Vec<_> = stab_syms
            .into_iter()
            .zip(local_syms)
            .zip(ext_syms)
            .zip(stab_strs.into_iter().zip(local_strs).zip(ext_strs))
            .enumerate()
            .collect();
        work.into_par_iter()
            .for_each(|(oi, (((ss, ls), es), ((sst, lst), est)))| {
                self.write_obj_syms(layout, plan, oi, ss, ls, es, sst, lst, est);
            });

        // Linker-made symbols and imports.
        let base = layout.image_base;
        let write_synth = |list: &[SymId],
                           first: u32,
                           mut strx: u64,
                           ty_extra: u8,
                           syms: &mut [u8],
                           strs: &mut [u8]| {
            for (k, &id) in list.iter().enumerate() {
                let s = self.symtab.get(id);
                let at = (first as usize + k) * 16;
                let (ty, sect, value, mut desc) = match s.def {
                    Def::Absolute { value } => (N_ABS, 0, value, 0u16),
                    Def::Synthetic(Synthetic::Common(_)) => (
                        N_SECT,
                        layout.common.map_or(0, |c| layout.sections[c].index),
                        self.sym_addr(layout, id).unwrap_or(0),
                        0,
                    ),
                    _ => (N_SECT, 1, base, 0),
                };
                if s.referenced_dynamically {
                    desc |= REFERENCED_DYNAMICALLY;
                }
                nlist_bytes(
                    &mut syms[at..at + 16],
                    strx as u32,
                    ty | ty_extra,
                    sect,
                    desc,
                    value,
                );
                strs[strx as usize..strx as usize + s.name.len()].copy_from_slice(s.name);
                strs[strx as usize + s.name.len()] = 0;
                strx += s.name.len() as u64 + 1;
            }
        };
        let first_synth_local = plan.nlocal - plan.synth_locals.len() as u32;
        write_synth(
            &plan.synth_locals,
            first_synth_local,
            plan.synth_local_strx,
            N_PEXT,
            syms,
            strs,
        );
        let first_synth_ext = plan.iundef - plan.synth_exts.len() as u32;
        write_synth(
            &plan.synth_exts,
            first_synth_ext,
            plan.synth_ext_strx,
            N_EXT,
            syms,
            strs,
        );
        let mut strx = plan.undef_strx;
        for (k, &id) in plan.undefs.iter().enumerate() {
            let s = self.symtab.get(id);
            let at = (plan.iundef as usize + k) * 16;
            let ordinal: u16 = match s.def {
                Def::Dylib { dylib } if !self.cfg.flat_namespace => {
                    self.dylibs[dylib as usize].ordinal as u16
                }
                Def::DynamicLookup if !self.cfg.flat_namespace => DYNAMIC_LOOKUP_ORDINAL as u16,
                _ => 0,
            };
            let mut desc = ordinal << 8;
            if s.weak_import() {
                desc |= N_WEAK_REF;
            }
            if s.weak_def {
                desc |= N_REF_TO_WEAK;
            }
            nlist_bytes(
                &mut syms[at..at + 16],
                strx as u32,
                N_EXT | N_UNDF,
                0,
                desc,
                0,
            );
            strs[strx as usize..strx as usize + s.name.len()].copy_from_slice(s.name);
            strs[strx as usize + s.name.len()] = 0;
            strx += s.name.len() as u64 + 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_obj_syms(
        &self,
        layout: &Layout,
        plan: &SymtabPlan,
        oi: usize,
        stab_syms: &mut [u8],
        local_syms: &mut [u8],
        ext_syms: &mut [u8],
        stab_strs: &mut [u8],
        local_strs: &mut [u8],
        ext_strs: &mut [u8],
    ) {
        let obj = &self.objs[oi];
        let o = &plan.objs[oi];
        let sym_info = |i: u32| -> (u8, u8, u64, u64, bool) {
            // (type, section, value, size for stabs, code)
            let s = obj.nlist(i);
            match s.ty & N_TYPE {
                N_SECT => {
                    let ai = obj.sym_atom[i as usize];
                    let a = &obj.atoms[ai as usize];
                    let sec = &obj.sections[a.sec as usize];
                    let off = s.value - sec.addr - a.off as u64;
                    let out = sec.out;
                    let index = if out == NONE {
                        0
                    } else {
                        layout.sections[out as usize].index
                    };
                    (
                        N_SECT,
                        index,
                        a.addr + off,
                        (a.size as u64).saturating_sub(off),
                        sec.is_code(),
                    )
                }
                _ => (N_ABS, 0, s.value, 0, false),
            }
        };
        let desc_of = |i: u32| -> u16 {
            let d = obj.nlist(i).desc;
            d & (N_WEAK_DEF
                | REFERENCED_DYNAMICALLY
                | N_NO_DEAD_STRIP
                | N_ALT_ENTRY
                | N_COLD_FUNC
                | N_SYMBOL_RESOLVER)
        };
        let put_str = |strs: &mut [u8], strp: &mut usize, base: u64, s: &[u8]| -> u32 {
            let at = *strp;
            strs[at..at + s.len()].copy_from_slice(s);
            strs[at + s.len()] = 0;
            *strp += s.len() + 1;
            (base + at as u64) as u32
        };
        let stabs = o.nstabs > 0;
        let mut strxs: Vec<u32> = Vec::with_capacity(if stabs {
            o.locals.len() + o.exts.len()
        } else {
            0
        });
        let mut sp = 0usize;
        let mut strp = 0usize;
        for &(i, pext) in &o.locals {
            let (ty, sect, value, _, _) = sym_info(i);
            let name = cstr(obj.strtab, obj.nlist(i).strx as usize);
            let strx = put_str(local_strs, &mut strp, o.local_strx, name);
            let ty = if pext { ty | N_PEXT } else { ty };
            nlist_bytes(
                &mut local_syms[sp..sp + 16],
                strx,
                ty,
                sect,
                desc_of(i),
                value,
            );
            sp += 16;
            if stabs {
                strxs.push(strx);
            }
        }
        let mut sp = 0usize;
        let mut strp = 0usize;
        for &i in &o.exts {
            let (ty, sect, value, _, _) = sym_info(i);
            let name = cstr(obj.strtab, obj.nlist(i).strx as usize);
            let strx = put_str(ext_strs, &mut strp, o.ext_strx, name);
            nlist_bytes(
                &mut ext_syms[sp..sp + 16],
                strx,
                ty | N_EXT,
                sect,
                desc_of(i),
                value,
            );
            sp += 16;
            if stabs {
                strxs.push(strx);
            }
        }
        if !stabs {
            return;
        }
        let mut sp = 0usize;
        let mut strp = 0usize;
        let mut stab = |ty: u8, sect: u8, desc: u16, value: u64, strx: u32, syms: &mut [u8]| {
            nlist_bytes(&mut syms[sp..sp + 16], strx, ty, sect, desc, value);
            sp += 16;
        };
        let src = o.source.as_deref().unwrap_or(b"");
        let x = put_str(stab_strs, &mut strp, o.stab_strx, src);
        stab(N_SO, 0, 0, 0, x, stab_syms);
        let x = put_str(stab_strs, &mut strp, o.stab_strx, &o.oso);
        let subtype = (self.arch.cpusubtype() & 0xff) as u8;
        stab(N_OSO, subtype, 1, obj.mtime, x, stab_syms);
        let all = o
            .locals
            .iter()
            .map(|&(i, p)| (i, !p))
            .chain(o.exts.iter().map(|&i| (i, true)));
        for (k, (i, ext)) in all.enumerate() {
            let s = obj.nlist(i);
            if s.ty & N_TYPE != N_SECT {
                continue;
            }
            let (_, sect, value, size, code) = sym_info(i);
            let x = strxs[k];
            if code {
                stab(N_FUN, sect, 0, value, x, stab_syms);
                stab(N_FUN, 0, 0, size, 1, stab_syms);
            } else {
                let ext = ext && s.ty & N_PEXT == 0;
                stab(
                    if ext { N_GSYM } else { N_STSYM },
                    sect,
                    0,
                    if ext { 0 } else { value },
                    x,
                    stab_syms,
                );
            }
        }
        stab(N_SO, 1, 0, 0, 1, stab_syms);
    }

    /// `LC_FUNCTION_STARTS`: ULEB deltas between the starts of functions, from `__TEXT`.
    pub fn function_starts(&self, layout: &Layout) -> Vec<u8> {
        let mut addrs: Vec<u64> = self
            .objs
            .par_iter()
            .flat_map_iter(|obj| {
                let mut v = Vec::new();
                for s in &obj.sections {
                    if s.out == NONE || !s.is_code() {
                        continue;
                    }
                    for a in &obj.atoms[s.atoms.start as usize..s.atoms.end as usize] {
                        if a.is_live() && a.flags & ATOM_HAS_SYMBOL != 0 && a.size > 0 {
                            v.push(a.addr);
                        }
                    }
                }
                v
            })
            .collect();
        addrs.par_sort_unstable();
        addrs.dedup();
        let mut out = Vec::with_capacity(addrs.len() * 2 + 8);
        let mut prev = layout.text_seg().vmaddr;
        for a in addrs {
            if a > prev {
                push_uleb(&mut out, a - prev);
                prev = a;
            }
        }
        out.push(0);
        super::dyldinfo::pad8(&mut out);
        out
    }

    /// `LC_DATA_IN_CODE`: the objects' entries, at their new offsets from the header.
    pub fn data_in_code(&self, layout: &Layout) -> Vec<u8> {
        let mut out = Vec::new();
        for obj in &self.objs {
            let d = obj.data_in_code;
            for e in d.as_chunks::<8>().0 {
                let addr = u32le(e, 0) as u64;
                let Some((_, atom, off)) = obj.locate(addr) else {
                    continue;
                };
                let a = &obj.atoms[atom as usize];
                if !a.is_live() {
                    continue;
                }
                let new = (a.addr as i64 + off) as u64 - layout.image_base;
                out.extend_from_slice(&(new as u32).to_le_bytes());
                out.extend_from_slice(&e[4..8]);
            }
        }
        out
    }
}

/// Split `buf` into the given (offset, length) pieces, which must be in order and disjoint.
pub fn split_pieces<'b>(buf: &'b mut [u8], pieces: &[(usize, usize)]) -> Vec<&'b mut [u8]> {
    let mut order: Vec<usize> = (0..pieces.len()).collect();
    order.sort_by_key(|&i| pieces[i].0);
    let mut out: Vec<Option<&'b mut [u8]>> = (0..pieces.len()).map(|_| None).collect();
    let mut rest: &'b mut [u8] = buf;
    let mut consumed = 0usize;
    for i in order {
        let (off, len) = pieces[i];
        if len == 0 {
            out[i] = Some(&mut []);
            continue;
        }
        let tail = std::mem::take(&mut rest);
        let (_, tail) = tail.split_at_mut(off - consumed);
        let (piece, tail) = tail.split_at_mut(len);
        out[i] = Some(piece);
        rest = tail;
        consumed = off + len;
    }
    out.into_iter().map(|p| p.unwrap()).collect()
}
