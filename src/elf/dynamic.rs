//! What the dynamic loader reads: `.dynsym` (ordered for `.gnu.hash`), `.dynstr`, symbol
//! versions, `.hash`/`.gnu.hash` and the `.dynamic` entries.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use super::layout::{Layout, Synthetic};
use super::resolve::{Ctx, FileRef};
use super::symbols::*;
use super::target::{Target, word, wr16, wr32, wrw};
use super::*;

/// Where a `.dynamic` entry's value comes from.
#[derive(Debug, Clone, Copy)]
pub enum DynVal {
    Num(u64),
    /// An offset in `.dynstr`.
    Str(u32),
    Addr(Synthetic),
    AddrPlus(Synthetic, u64),
    /// Address/size of a named output section (`.init_array`...).
    SecAddr(&'static [u8]),
    SecSize(&'static [u8]),
    SymAddr(SymId),
    RelaCount,
    RelaSize,
}

/// A version needed from a library: (hash, flags, index, name offset).
pub type Vernaux = (u32, u16, u16, u32);

#[derive(Default)]
pub struct DynInfo {
    pub order: Vec<SymId>,
    pub names: Vec<u32>,
    pub strtab: Vec<u8>,
    /// Index of the first symbol `.gnu.hash` covers.
    pub first_hashed: u32,
    pub nbuckets: u32,
    pub bloom_words: u32,
    pub sysv_buckets: u32,
    pub versym: Vec<u16>,
    /// (file name offset, its versions).
    pub verneed: Vec<(u32, Vec<Vernaux>)>,
    /// (index, flags, hash, name offset).
    pub verdef: Vec<(u16, u16, u32, u32)>,
    pub entries: Vec<(u64, DynVal)>,
}

pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in name {
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

struct StrTab {
    data: Vec<u8>,
    map: HashMap<Vec<u8>, u32>,
}

impl StrTab {
    fn new() -> StrTab {
        StrTab {
            data: vec![0],
            map: HashMap::new(),
        }
    }
    fn add(&mut self, s: &[u8]) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&o) = self.map.get(s) {
            return o;
        }
        let o = self.data.len() as u32;
        self.data.extend_from_slice(s);
        self.data.push(0);
        self.map.insert(s.to_vec(), o);
        o
    }
}

impl DynInfo {
    pub fn gnu_hash_size<T: Target>(&self) -> u64 {
        let nhashed = self.order.len() as u64 + 1 - self.first_hashed as u64;
        16 + self.bloom_words as u64 * word::<T>() + self.nbuckets as u64 * 4 + nhashed * 4
    }

    pub fn sysv_hash_size(&self) -> u64 {
        (2 + self.sysv_buckets as u64 + self.order.len() as u64 + 1) * 4
    }

    pub fn has_versions(&self) -> bool {
        !self.verneed.is_empty() || !self.verdef.is_empty()
    }

    pub fn verneed_size(&self) -> u64 {
        self.verneed
            .iter()
            .map(|(_, v)| 16 + 16 * v.len() as u64)
            .sum()
    }

    pub fn verdef_size(&self) -> u64 {
        self.verdef.len() as u64 * 28
    }
}

impl<T: Target> Ctx<'_, T> {
    pub fn dso_needed(&self, k: usize) -> bool {
        let d = &self.dsos[k];
        !d.as_needed || d.used.load(Ordering::Relaxed)
    }

    pub fn plan_dynamic(&mut self, outs: &[super::layout::OutSec]) -> DynInfo {
        let mut info = DynInfo::default();
        if !self.has_dynamic {
            return info;
        }
        let mut st = StrTab::new();
        let needed: Vec<u32> = (0..self.dsos.len())
            .filter(|&k| self.dso_needed(k))
            .map(|k| st.add(self.dsos[k].soname.as_bytes()))
            .collect();
        let soname = self.cfg.soname.as_ref().map(|s| st.add(s.as_bytes()));
        let rpath =
            (!self.cfg.rpaths.is_empty()).then(|| st.add(self.cfg.rpaths.join(":").as_bytes()));

        // Order: undefined symbols, then defined ones grouped by .gnu.hash bucket.
        let dynsyms = std::mem::take(&mut self.scan.dynsyms);
        let defined = |id: SymId| {
            let s = self.syms.get(id);
            let f = s.flags();
            f & IMPORTED == 0 && s.def() != UNDEF || f & (NEEDS_COPY | NEEDS_CPLT) != 0
        };
        let (mut undef, mut def): (Vec<SymId>, Vec<SymId>) =
            dynsyms.into_iter().partition(|&id| !defined(id));
        undef.sort_unstable();
        let first_hashed = undef.len() as u32 + 1;
        let nbuckets = if self.cfg.hash_gnu {
            ((def.len() + 1) / 4).max(1) as u32
        } else {
            1
        };
        let mut hashed: Vec<(u32, u32, SymId)> = def
            .drain(..)
            .map(|id| {
                let h = gnu_hash(self.syms.get(id).name);
                (h % nbuckets, h, id)
            })
            .collect();
        hashed.sort_unstable_by_key(|&(b, _, id)| (b, id));
        let mut order = undef;
        order.extend(hashed.iter().map(|e| e.2));
        for (k, &id) in order.iter().enumerate() {
            let a = self.syms.get(id).aux() as usize;
            self.scan.aux[a].dynsym = k as u32 + 1;
        }
        info.names = order
            .iter()
            .map(|&id| st.add(self.syms.get(id).name))
            .collect();
        info.first_hashed = first_hashed;
        info.nbuckets = nbuckets;
        let nbits = (hashed.len() as u64 * 12).max(1);
        info.bloom_words = (nbits / (word::<T>() * 8)).max(1).next_power_of_two() as u32;
        info.sysv_buckets = (order.len() as u32 / 2).max(1);

        // Version definitions (named nodes of the version script) come first.
        let mut verdef = Vec::new();
        if let Some(vs) = &self.version_script
            && !vs.is_anonymous()
        {
            let base = self.cfg.soname.clone().unwrap_or_else(|| {
                self.cfg
                    .output
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            let off = st.add(base.as_bytes());
            verdef.push((
                VER_NDX_GLOBAL,
                VER_FLG_BASE,
                sysv_hash(base.as_bytes()),
                off,
            ));
            for (i, n) in vs.nodes.iter().enumerate() {
                if n.name.is_empty() {
                    continue;
                }
                let off = st.add(n.name.as_bytes());
                verdef.push((i as u16 + 2, 0, sysv_hash(n.name.as_bytes()), off));
            }
        }
        let next_index = verdef.iter().map(|v| v.0).max().unwrap_or(1) + 1;
        // Version needs: per shared object, the versions its imported symbols use.
        let mut needs: Vec<(u32, Vec<(u16, u16)>)> = Vec::new(); // (dso, [(dso version, out index)])
        let mut next = next_index;
        let mut versym = vec![VER_NDX_LOCAL; order.len() + 1];
        let mut any_ver = false;
        for (k, &id) in order.iter().enumerate() {
            let s = self.syms.get(id);
            let f = s.flags();
            let d = s.def();
            let v = if f & IMPORTED != 0 && d != UNDEF && def_class(d) == CLASS_LAZY {
                let FileRef::Dso(di) = self.file(def_prio(d)) else {
                    unreachable!()
                };
                let dv = self.dsos[di as usize].syms[def_index(d) as usize].ver;
                if dv >= 2 && !self.dsos[di as usize].version_name(dv).is_empty() {
                    any_ver = true;
                    let e = match needs.iter().position(|n| n.0 == di) {
                        Some(e) => e,
                        None => {
                            needs.push((di, Vec::new()));
                            needs.len() - 1
                        }
                    };
                    match needs[e].1.iter().find(|x| x.0 == dv) {
                        Some(x) => x.1,
                        None => {
                            needs[e].1.push((dv, next));
                            next += 1;
                            next - 1
                        }
                    }
                } else {
                    VER_NDX_GLOBAL
                }
            } else if f & IMPORTED != 0 || d == UNDEF {
                VER_NDX_GLOBAL
            } else {
                let v = s.ver.load(Ordering::Relaxed) as u16;
                if v > VER_NDX_GLOBAL {
                    any_ver = true;
                }
                v.max(VER_NDX_GLOBAL)
            };
            versym[k + 1] = v;
        }
        needs.sort_by_key(|n| n.0);
        for (di, vers) in &needs {
            let dso = &self.dsos[*di as usize];
            let file = st.add(dso.soname.as_bytes());
            let auxes = vers
                .iter()
                .map(|&(dv, idx)| {
                    let name = dso.version_name(dv);
                    (sysv_hash(name), 0u16, idx, st.add(name))
                })
                .collect();
            info.verneed.push((file, auxes));
        }
        info.verdef = verdef;
        if any_ver || !info.verdef.is_empty() {
            info.versym = versym;
        } else {
            info.verneed.clear();
        }

        // .dynamic.
        let has_versions = any_ver || !info.verdef.is_empty();
        let mut e = std::mem::take(&mut info.entries);
        let e = &mut e;
        for n in needed {
            e.push((DT_NEEDED, DynVal::Str(n)));
        }
        if let Some(s) = soname {
            e.push((DT_SONAME, DynVal::Str(s)));
        }
        if let Some(r) = rpath {
            e.push((
                if self.cfg.new_dtags {
                    DT_RUNPATH
                } else {
                    DT_RPATH
                },
                DynVal::Str(r),
            ));
        }
        for (tag, name) in [(DT_INIT, &self.cfg.init), (DT_FINI, &self.cfg.fini)] {
            if let Some(id) = self.syms.find(name.as_bytes())
                && self.syms.get(id).def() != UNDEF
                && !self.syms.get(id).has(IMPORTED)
            {
                e.push((tag, DynVal::SymAddr(id)));
            }
        }
        let has = |n: &[u8]| outs.iter().any(|o| o.name == n);
        if has(b".init_array") {
            e.push((DT_INIT_ARRAY, DynVal::SecAddr(b".init_array")));
            e.push((DT_INIT_ARRAYSZ, DynVal::SecSize(b".init_array")));
        }
        if has(b".fini_array") {
            e.push((DT_FINI_ARRAY, DynVal::SecAddr(b".fini_array")));
            e.push((DT_FINI_ARRAYSZ, DynVal::SecSize(b".fini_array")));
        }
        if !self.cfg.shared && has(b".preinit_array") {
            e.push((DT_PREINIT_ARRAY, DynVal::SecAddr(b".preinit_array")));
            e.push((DT_PREINIT_ARRAYSZ, DynVal::SecSize(b".preinit_array")));
        }
        if self.cfg.hash_sysv {
            e.push((DT_HASH, DynVal::Addr(Synthetic::Hash)));
        }
        if self.cfg.hash_gnu {
            e.push((DT_GNU_HASH, DynVal::Addr(Synthetic::GnuHash)));
        }
        e.push((DT_STRTAB, DynVal::Addr(Synthetic::Dynstr)));
        e.push((DT_SYMTAB, DynVal::Addr(Synthetic::Dynsym)));
        e.push((DT_STRSZ, DynVal::Num(st.data.len() as u64)));
        e.push((DT_SYMENT, DynVal::Num(if T::IS64 { 24 } else { 16 })));
        if !self.cfg.shared {
            e.push((DT_DEBUG, DynVal::Num(0)));
        }
        let nplt = self.scan.plt.len() + self.scan.iplt.len();
        if nplt > 0 || T::GOTPLT_RESERVED > 0 {
            e.push((DT_PLTGOT, DynVal::Addr(Synthetic::GotPlt)));
        }
        if nplt > 0 {
            let relsz = if T::RELA_DYN { 3 } else { 2 } * word::<T>();
            e.push((DT_PLTRELSZ, DynVal::Num(nplt as u64 * relsz)));
            e.push((
                DT_PLTREL,
                DynVal::Num(if T::RELA_DYN { DT_RELA } else { DT_REL }),
            ));
            e.push((DT_JMPREL, DynVal::Addr(Synthetic::RelaPlt)));
        }
        if self.scan.rela_dyn_count() > 0 {
            if T::RELA_DYN {
                e.push((DT_RELA, DynVal::Addr(Synthetic::RelaDyn)));
                e.push((DT_RELASZ, DynVal::RelaSize));
                e.push((DT_RELAENT, DynVal::Num(3 * word::<T>())));
                if self.scan.nrelative > 0 {
                    e.push((DT_RELACOUNT, DynVal::RelaCount));
                }
            } else {
                e.push((DT_REL, DynVal::Addr(Synthetic::RelaDyn)));
                e.push((DT_RELSZ, DynVal::RelaSize));
                e.push((DT_RELENT, DynVal::Num(2 * word::<T>())));
                if self.scan.nrelative > 0 {
                    e.push((DT_RELCOUNT, DynVal::RelaCount));
                }
            }
        }
        if has_versions {
            e.push((DT_VERSYM, DynVal::Addr(Synthetic::VerSym)));
            if !info.verneed.is_empty() {
                e.push((DT_VERNEED, DynVal::Addr(Synthetic::VerNeed)));
                e.push((DT_VERNEEDNUM, DynVal::Num(info.verneed.len() as u64)));
            }
            if !info.verdef.is_empty() {
                e.push((DT_VERDEF, DynVal::Addr(Synthetic::VerDef)));
                e.push((DT_VERDEFNUM, DynVal::Num(info.verdef.len() as u64)));
            }
        }
        if matches!(T::M, Machine::Ppc64 | Machine::Ppc64le) && nplt > 0 {
            // 32 bytes before the first lazy entry, as glibc expects.
            e.push((
                DT_PPC64_GLINK,
                DynVal::AddrPlus(Synthetic::Plt, T::PLT0_SIZE - 32),
            ));
        }
        let mut flags = 0;
        let mut flags1 = 0;
        if self.cfg.z_now {
            flags |= DF_BIND_NOW;
            flags1 |= DF_1_NOW;
        }
        if self.cfg.z_origin {
            flags |= DF_ORIGIN;
            flags1 |= DF_1_ORIGIN;
        }
        if self.scan.textrel.load(Ordering::Relaxed) {
            flags |= DF_TEXTREL;
            e.push((DT_TEXTREL, DynVal::Num(0)));
        }
        if self.scan.static_tls.load(Ordering::Relaxed) {
            flags |= DF_STATIC_TLS;
        }
        if self.cfg.bsymbolic == super::config::Bsymbolic::All {
            flags |= DF_SYMBOLIC;
        }
        if self.cfg.pie && !self.cfg.shared {
            flags1 |= DF_1_PIE;
        }
        if self.cfg.z_nodelete {
            flags1 |= DF_1_NODELETE;
        }
        if self.cfg.z_nodlopen {
            flags1 |= DF_1_NOOPEN;
        }
        if self.cfg.z_initfirst {
            flags1 |= DF_1_INITFIRST;
        }
        if self.cfg.z_interpose {
            flags1 |= DF_1_INTERPOSE;
        }
        if self.cfg.z_nodefaultlib {
            flags1 |= DF_1_NODEFLIB;
        }
        if flags != 0 {
            e.push((DT_FLAGS, DynVal::Num(flags)));
        }
        if flags1 != 0 {
            e.push((DT_FLAGS_1, DynVal::Num(flags1)));
        }
        e.push((DT_NULL, DynVal::Num(0)));
        info.entries = std::mem::take(e);
        info.order = order;
        info.strtab = st.data;
        info
    }

    fn dyn_value(&self, lay: &Layout, v: DynVal) -> u64 {
        let sec = |n: &[u8]| lay.outs.iter().find(|o| o.name == n && o.shndx != 0);
        match v {
            DynVal::Num(n) => n,
            DynVal::Str(s) => s as u64,
            DynVal::Addr(s) => lay.addr_of(s),
            DynVal::AddrPlus(s, n) => lay.addr_of(s) + n,
            DynVal::SecAddr(n) => sec(n).map_or(0, |o| o.addr),
            DynVal::SecSize(n) => sec(n).map_or(0, |o| o.size),
            DynVal::SymAddr(id) => self.syms.get(id).addr(),
            DynVal::RelaCount => self.scan.nrelative,
            DynVal::RelaSize => {
                self.scan.rela_dyn_count() * if T::RELA_DYN { 3 } else { 2 } * word::<T>()
            }
        }
    }

    pub fn write_dynamic(&self, lay: &Layout, buf: &mut [u8]) {
        let w = word::<T>() as usize;
        for (i, &(tag, v)) in lay.dynamic.entries.iter().enumerate() {
            wrw::<T>(buf, i * 2 * w, tag);
            wrw::<T>(buf, i * 2 * w + w, self.dyn_value(lay, v));
        }
    }

    /// The output section index a defined dynamic or static symbol belongs to.
    pub fn sym_shndx(&self, lay: &Layout, id: SymId) -> u32 {
        let s = self.syms.get(id);
        let f = s.flags();
        if f & NEEDS_COPY != 0 && f & IMPORTED != 0 {
            return lay.out(Synthetic::Bss).map_or(SHN_ABS, |o| {
                if o.shndx != 0 {
                    o.shndx
                } else {
                    lay.outs[o.link as usize - 1].shndx
                }
            });
        }
        if f & IMPORTED != 0 {
            return SHN_UNDEF;
        }
        let d = s.def();
        if d == UNDEF {
            return SHN_UNDEF;
        }
        if f & IS_ABS != 0 {
            return SHN_ABS;
        }
        if f & IS_IFUNC != 0 && s.aux() != NONE && self.scan.aux[s.aux() as usize].plt != NONE {
            return lay.out(Synthetic::Plt).map_or(SHN_ABS, |o| o.shndx);
        }
        match def_class(d) {
            CLASS_COMMON => lay.out(Synthetic::Bss).map_or(SHN_ABS, |o| {
                if o.shndx != 0 {
                    o.shndx
                } else {
                    lay.outs[o.link as usize - 1].shndx
                }
            }),
            CLASS_INTERNAL => self.addr_shndx(lay, s.addr()),
            _ => {
                let (o, i) = self.def_obj(id).unwrap();
                let sym = o.sym::<T>(i);
                match o.secs.get(sym.shndx as usize) {
                    Some(sec) if sec.kind == super::object::SecKind::Merge => {
                        lay.outs[self.merged[sec.aux as usize].out as usize].shndx
                    }
                    Some(sec) if sec.out != NONE => lay.outs[sec.out as usize].shndx,
                    _ => SHN_ABS,
                }
            }
        }
    }

    /// The section containing `addr` (for linker-defined symbols), or SHN_ABS.
    pub fn addr_shndx(&self, lay: &Layout, addr: u64) -> u32 {
        let mut best = None;
        for o in &lay.outs {
            if o.is_alloc() && o.shndx != 0 && o.addr <= addr && addr <= o.addr + o.size {
                best = Some(o.shndx);
                if addr < o.addr + o.size {
                    break;
                }
            }
        }
        best.unwrap_or(SHN_ABS)
    }

    pub fn write_dynsym(&self, lay: &Layout, buf: &mut [u8]) {
        let info = &lay.dynamic;
        let symsz = if T::IS64 { 24 } else { 16 };
        for (k, &id) in info.order.iter().enumerate() {
            let s = self.syms.get(id);
            let f = s.flags();
            let e = &mut buf[(k + 1) * symsz..(k + 2) * symsz];
            let defined = f & IMPORTED == 0 && s.def() != UNDEF || f & NEEDS_COPY != 0;
            let mut ty = if f & IS_TLS != 0 {
                STT_TLS
            } else if f & (IS_IFUNC | IS_FUNC) != 0 {
                STT_FUNC
            } else if s.def() != UNDEF && def_class(s.def()) <= CLASS_COMMON {
                let (o, i) = self.def_obj(id).unwrap();
                match o.sym::<T>(i).ty() {
                    STT_COMMON => STT_OBJECT,
                    t => t,
                }
            } else if s.def() != UNDEF && def_class(s.def()) == CLASS_LAZY {
                let FileRef::Dso(di) = self.file(def_prio(s.def())) else {
                    unreachable!()
                };
                self.dsos[di as usize].syms[def_index(s.def()) as usize].ty()
            } else {
                STT_NOTYPE
            };
            if ty == STT_GNU_IFUNC {
                ty = STT_FUNC;
            }
            let bind = if self.sym_is_weak(id) {
                STB_WEAK
            } else {
                STB_GLOBAL
            };
            let vis = match s.vis.load(Ordering::Relaxed) {
                1 => STV_PROTECTED,
                _ => STV_DEFAULT,
            };
            let (shndx, value) = if defined {
                (self.sym_shndx(lay, id), s.addr())
            } else if f & NEEDS_CPLT != 0 {
                (SHN_UNDEF, s.addr())
            } else {
                (SHN_UNDEF, 0)
            };
            let size = self.sym_size(id);
            self.put_sym(e, info.names[k], (bind << 4) | ty, vis, shndx, value, size);
        }
    }

    pub fn sym_is_weak(&self, id: SymId) -> bool {
        let s = self.syms.get(id);
        let d = s.def();
        if d == UNDEF {
            return !s.has(STRONG_REF);
        }
        match def_class(d) {
            CLASS_WEAK => true,
            CLASS_LAZY => {
                // An import is weak only if every reference is weak.
                !s.has(STRONG_REF)
            }
            _ => false,
        }
    }

    pub fn sym_size(&self, id: SymId) -> u64 {
        let s = self.syms.get(id);
        let d = s.def();
        if d == UNDEF {
            return 0;
        }
        match def_class(d) {
            CLASS_LAZY => {
                let FileRef::Dso(di) = self.file(def_prio(d)) else {
                    return 0;
                };
                self.dsos[di as usize].syms[def_index(d) as usize].size
            }
            CLASS_INTERNAL => 0,
            _ => self.def_obj(id).map_or(0, |(o, i)| o.sym::<T>(i).size),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_sym(
        &self,
        e: &mut [u8],
        name: u32,
        info: u8,
        other: u8,
        shndx: u32,
        value: u64,
        size: u64,
    ) {
        let sh = if shndx >= SHN_LORESERVE && shndx != SHN_ABS && shndx != SHN_COMMON {
            SHN_XINDEX
        } else {
            shndx
        } as u16;
        if T::IS64 {
            wr32::<T>(e, 0, name);
            e[4] = info;
            e[5] = other;
            wr16::<T>(e, 6, sh);
            wrw::<T>(e, 8, value);
            wrw::<T>(e, 16, size);
        } else {
            wr32::<T>(e, 0, name);
            wr32::<T>(e, 4, value as u32);
            wr32::<T>(e, 8, size as u32);
            e[12] = info;
            e[13] = other;
            wr16::<T>(e, 14, sh);
        }
    }

    pub fn write_gnu_hash(&self, lay: &Layout, buf: &mut [u8]) {
        let info = &lay.dynamic;
        let w = word::<T>() as usize;
        let nb = info.nbuckets as usize;
        let mw = info.bloom_words as usize;
        let shift2 = 26u32;
        wr32::<T>(buf, 0, info.nbuckets);
        wr32::<T>(buf, 4, info.first_hashed);
        wr32::<T>(buf, 8, info.bloom_words);
        wr32::<T>(buf, 12, shift2);
        let bloom_off = 16;
        let buckets_off = bloom_off + mw * w;
        let chains_off = buckets_off + nb * 4;
        let first = info.first_hashed as usize;
        let c = (w * 8) as u32;
        let mut bloom = vec![0u64; mw];
        let hashed = &info.order[first - 1..];
        let hashes: Vec<u32> = hashed
            .iter()
            .map(|&id| gnu_hash(self.syms.get(id).name))
            .collect();
        for &h in &hashes {
            let word_i = ((h / c) as usize) & (mw - 1);
            bloom[word_i] |= (1u64 << (h % c)) | (1u64 << ((h >> shift2) % c));
        }
        for (i, b) in bloom.iter().enumerate() {
            wrw::<T>(buf, bloom_off + i * w, *b);
        }
        let mut last_in_bucket = vec![usize::MAX; nb];
        for (i, &h) in hashes.iter().enumerate() {
            let b = (h % info.nbuckets) as usize;
            if last_in_bucket[b] == usize::MAX {
                wr32::<T>(buf, buckets_off + b * 4, (first + i) as u32);
            }
            last_in_bucket[b] = i;
        }
        for (i, &h) in hashes.iter().enumerate() {
            let b = (h % info.nbuckets) as usize;
            let v = if last_in_bucket[b] == i {
                h | 1
            } else {
                h & !1
            };
            wr32::<T>(buf, chains_off + i * 4, v);
        }
    }

    pub fn write_sysv_hash(&self, lay: &Layout, buf: &mut [u8]) {
        let info = &lay.dynamic;
        let nb = info.sysv_buckets as usize;
        let n = info.order.len() + 1;
        wr32::<T>(buf, 0, nb as u32);
        wr32::<T>(buf, 4, n as u32);
        let mut buckets = vec![0u32; nb];
        let mut chains = vec![0u32; n];
        for (k, &id) in info.order.iter().enumerate() {
            let i = k + 1;
            let b = (sysv_hash(self.syms.get(id).name) as usize) % nb;
            chains[i] = buckets[b];
            buckets[b] = i as u32;
        }
        for (i, b) in buckets.iter().enumerate() {
            wr32::<T>(buf, 8 + i * 4, *b);
        }
        for (i, c) in chains.iter().enumerate() {
            wr32::<T>(buf, 8 + nb * 4 + i * 4, *c);
        }
    }

    pub fn write_versions(
        &self,
        lay: &Layout,
        versym: Option<&mut [u8]>,
        verneed: Option<&mut [u8]>,
        verdef: Option<&mut [u8]>,
    ) {
        let info = &lay.dynamic;
        if let Some(b) = versym {
            for (i, v) in info.versym.iter().enumerate() {
                wr16::<T>(b, i * 2, *v);
            }
        }
        if let Some(b) = verneed {
            let mut off = 0usize;
            for (k, (file, auxes)) in info.verneed.iter().enumerate() {
                wr16::<T>(b, off, 1);
                wr16::<T>(b, off + 2, auxes.len() as u16);
                wr32::<T>(b, off + 4, *file);
                wr32::<T>(b, off + 8, 16);
                let next = if k + 1 < info.verneed.len() {
                    16 + 16 * auxes.len() as u32
                } else {
                    0
                };
                wr32::<T>(b, off + 12, next);
                let mut a = off + 16;
                for (j, &(hash, flags, idx, name)) in auxes.iter().enumerate() {
                    wr32::<T>(b, a, hash);
                    wr16::<T>(b, a + 4, flags);
                    wr16::<T>(b, a + 6, idx);
                    wr32::<T>(b, a + 8, name);
                    wr32::<T>(b, a + 12, if j + 1 < auxes.len() { 16 } else { 0 });
                    a += 16;
                }
                off = a;
            }
        }
        if let Some(b) = verdef {
            for (k, &(idx, flags, hash, name)) in info.verdef.iter().enumerate() {
                let off = k * 28;
                wr16::<T>(b, off, 1);
                wr16::<T>(b, off + 2, flags);
                wr16::<T>(b, off + 4, idx);
                wr16::<T>(b, off + 6, 1);
                wr32::<T>(b, off + 8, hash);
                wr32::<T>(b, off + 12, 20);
                wr32::<T>(b, off + 16, if k + 1 < info.verdef.len() { 28 } else { 0 });
                wr32::<T>(b, off + 20, name);
                wr32::<T>(b, off + 24, 0);
            }
        }
    }
}
