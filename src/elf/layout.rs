//! Output sections and addresses.
//!
//! Input sections map to output sections by name (`.text.foo` → `.text`, as lld does).
//! Output sections are ordered by segment — read-only, code, RELRO, writable, then
//! non-allocated — and inside a section each object's sections form one block; blocks are
//! placed by a prefix sum, so each object's sections are placed in parallel.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use rayon::prelude::*;

use super::config::BuildId;
use super::object::{Object, SecKind};
use super::resolve::{Ctx, Synth};
use super::symbols::*;
use super::target::{Target, word};
use super::*;
use crate::diag::{Result, Timer};
use crate::{bail, err};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Synthetic {
    None,
    Interp,
    BuildId,
    Dynsym,
    Dynstr,
    GnuHash,
    Hash,
    VerSym,
    VerNeed,
    VerDef,
    RelaDyn,
    RelaPlt,
    Plt,
    Got,
    GotPlt,
    Dynamic,
    EhFrame,
    EhFrameHdr,
    Symtab,
    Strtab,
    Shstrtab,
    /// Copy relocations and common symbols live at the end of `.bss`.
    Bss,
    Attributes,
    Exidx,
    Thunks,
}

#[derive(Debug, Clone)]
pub struct OutSec {
    pub name: Vec<u8>,
    pub ty: u32,
    pub flags: u64,
    pub align: u64,
    pub size: u64,
    pub addr: u64,
    pub offset: u64,
    pub entsize: u64,
    pub link: u32,
    pub info: u32,
    pub synth: Synthetic,
    /// Merged sections appended after the input sections: (merged index, offset).
    pub merged: Vec<(u32, u64)>,
    /// Bytes of input sections (before merged ones and synthetic tails).
    pub input_size: u64,
    pub relro: bool,
    /// Index in the section header table.
    pub shndx: u32,
    first_seen: u64,
}

impl OutSec {
    pub fn new(name: &[u8], ty: u32, flags: u64, synth: Synthetic) -> OutSec {
        OutSec {
            name: name.to_vec(),
            ty,
            flags,
            align: 1,
            size: 0,
            addr: 0,
            offset: 0,
            entsize: 0,
            link: 0,
            info: 0,
            synth,
            merged: Vec::new(),
            input_size: 0,
            relro: false,
            shndx: 0,
            first_seen: u64::MAX,
        }
    }

    pub fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }

    pub fn nobits(&self) -> bool {
        self.ty == SHT_NOBITS
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Phdr {
    pub ty: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// Where the linker's own sections ended up (output section indices).
#[derive(Debug, Clone, Default)]
pub struct Synths {
    pub map: HashMap<SynthKey, u32>,
}

pub type SynthKey = Synthetic;

impl Synths {
    pub fn get(&self, s: Synthetic) -> Option<u32> {
        self.map.get(&s).copied()
    }
}

#[derive(Default)]
pub struct Layout {
    pub outs: Vec<OutSec>,
    pub phdrs: Vec<Phdr>,
    pub synth: Synths,
    pub file_size: u64,
    pub shoff: u64,
    pub ehdr_size: u64,
    pub phdr_size: u64,
    /// PT_TLS: (address, file size, memory size, alignment).
    pub tls: Option<(u64, u64, u64, u64)>,
    pub base: u64,
    /// Per object: (output section, block start) for its blocks.
    pub dynamic: super::dynamic::DynInfo,
    pub symtab: super::write::SymtabPlan,
    pub commons: Vec<(SymId, u64)>,
    pub bss_extra: u64,
    pub build_id_size: u64,
    pub entry: u64,
    pub got: u64,
    pub gotplt: u64,
    pub plt: u64,
}

impl Layout {
    pub fn out(&self, s: Synthetic) -> Option<&OutSec> {
        self.synth.get(s).map(|i| &self.outs[i as usize])
    }
    pub fn addr_of(&self, s: Synthetic) -> u64 {
        self.out(s).map_or(0, |o| o.addr)
    }
}

/// lld's output section names: `.text.foo` → `.text`, and so on.
///
/// `name` may be the rest of a string table from the name on: known prefixes are matched in
/// place, and the end of the name is only searched for names that keep their own.
/// Whether `--strip-debug` / `--strip-all` drop a non-allocated section (`name` may run on).
fn strip_drops(strip: super::config::Strip, name: &[u8]) -> bool {
    use super::config::Strip;
    if strip == Strip::None {
        return false;
    }
    let n = cstr(name, 0);
    n.starts_with(b".debug")
        || n.starts_with(b".zdebug")
        || n.starts_with(b".gdb_index")
        || n == b".stab"
        || n == b".stabstr"
        || strip == Strip::All && n == b".comment"
}

pub fn output_name(name: &[u8], keep_text_prefix: bool) -> &[u8] {
    let ends_after = |p: &[u8]| matches!(name.get(p.len()), None | Some(0) | Some(b'.'));
    if keep_text_prefix {
        for p in [
            &b".text.hot"[..],
            b".text.unlikely",
            b".text.startup",
            b".text.exit",
            b".text.split",
        ] {
            if name.starts_with(p) && ends_after(p) {
                return &name[..p.len()];
            }
        }
    }
    const PREFIXES: &[&[u8]] = &[
        b".ldata",
        b".lrodata",
        b".lbss",
        b".gcc_except_table",
        b".init_array",
        b".fini_array",
        b".preinit_array",
        b".tbss",
        b".tdata",
        b".ARM.exidx",
        b".ARM.extab",
        b".ctors",
        b".dtors",
        b".text",
        b".data.rel.ro",
        b".data",
        b".rodata",
        b".bss.rel.ro",
        b".bss",
        b".sdata",
        b".sbss",
        b".srodata",
        b".toc",
    ];
    // Every prefix starts with '.': compare the second byte first.
    let second = name.get(1).copied();
    for p in PREFIXES {
        if Some(p[1]) == second && name.starts_with(p) && ends_after(p) {
            return p;
        }
    }
    cstr(name, 0)
}

fn is_relro_name(n: &[u8]) -> bool {
    matches!(
        n,
        b".data.rel.ro"
            | b".bss.rel.ro"
            | b".ctors"
            | b".dtors"
            | b".jcr"
            | b".init_array"
            | b".fini_array"
            | b".preinit_array"
            | b".toc"
            | b".openbsd.randomdata"
    )
}

/// (segment class, order inside it): 0 read-only, 1 code, 2 RELRO, 3 writable, 4 not loaded.
fn rank(o: &OutSec, relro_on: bool) -> (u32, u32) {
    use Synthetic as S;
    if !o.is_alloc() {
        let r = match o.synth {
            S::Symtab => 10,
            S::Shstrtab => 11,
            S::Strtab => 12,
            _ => 1,
        };
        return (4, r);
    }
    let write = o.flags & SHF_WRITE != 0;
    let exec = o.flags & SHF_EXECINSTR != 0;
    let tls = o.flags & SHF_TLS != 0;
    if !write && !exec {
        let r = match o.synth {
            S::Interp => 0,
            _ if o.ty == SHT_NOTE => 1,
            S::Dynsym => 2,
            S::VerSym => 3,
            S::VerDef => 4,
            S::VerNeed => 5,
            S::GnuHash => 6,
            S::Hash => 7,
            S::Dynstr => 8,
            S::RelaDyn => 9,
            S::RelaPlt => 10,
            S::EhFrameHdr => 30,
            S::EhFrame => 31,
            S::Exidx => 25,
            _ => 20,
        };
        return (0, r);
    }
    if exec && !write {
        let r = match o.synth {
            S::Plt => 10,
            S::Thunks => 5,
            _ => 0,
        };
        return (1, r);
    }
    let relro = relro_on
        && (tls
            || o.relro
            || matches!(o.synth, S::Dynamic | S::Got)
            || is_relro_name(&o.name)
            || matches!(o.ty, SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY));
    if relro {
        let r = match o.synth {
            _ if tls && o.ty != SHT_NOBITS => 0,
            _ if tls => 1,
            S::Dynamic => 5,
            S::Got => 6,
            S::GotPlt => 7,
            _ if o.ty == SHT_NOBITS => 8,
            _ => 2,
        };
        return (2, r);
    }
    let r = match o.synth {
        S::GotPlt => 5,
        S::Bss => 10,
        _ if o.ty == SHT_NOBITS => 9,
        _ => 0,
    };
    (3, r)
}

impl<'a, T: Target> Ctx<'a, T> {
    pub fn layout(&mut self, timer: &mut Timer) -> Result<Layout> {
        let keep = self.cfg.z_keep_text_section_prefix;
        let mut mk = super::prof::Marks::new();
        // 1. Output sections in first-seen order. One pass over the sections: each object
        // keeps its own small table of output names (in `out`, temporarily, the index in it).
        type Acc = (u64, u32, u64, bool);
        type Seen<'s> = Vec<(&'s [u8], bool)>;
        let strip = self.cfg.strip;
        let per_obj: Vec<(Seen<'a>, Vec<Acc>)> = self
            .objs
            .par_iter_mut()
            .map(|o| {
                let mut seen: Vec<(&'a [u8], bool)> = Vec::new();
                let mut acc: Vec<Acc> = Vec::new();
                if !o.alive.load(Ordering::Relaxed) {
                    return (seen, acc);
                }
                let shstrtab = o.shstrtab;
                for si in 0..o.secs.len() {
                    let s = &o.secs[si];
                    if !s.is_live()
                        || !matches!(s.kind, SecKind::Alloc | SecKind::NonAlloc | SecKind::Merge)
                    {
                        continue;
                    }
                    let (flags, ty, align) = (s.flags as u64, s.ty, s.align());
                    let raw = shstrtab.get(s.name as usize..).unwrap_or(&[]);
                    if s.kind == SecKind::NonAlloc && strip_drops(strip, raw) {
                        continue;
                    }
                    let key = (output_name(raw, keep), flags & SHF_ALLOC != 0);
                    let k = match seen.iter().rposition(|x| *x == key) {
                        Some(k) => k,
                        None => {
                            seen.push(key);
                            acc.push((0, ty, 1, true));
                            seen.len() - 1
                        }
                    };
                    o.secs[si].out = k as u32;
                    let e = &mut acc[k];
                    e.0 |= flags
                        & (SHF_ALLOC
                            | SHF_WRITE
                            | SHF_EXECINSTR
                            | SHF_TLS
                            | SHF_MERGE
                            | SHF_STRINGS);
                    if e.1 == SHT_NOBITS && ty != SHT_NOBITS
                        || e.1 == SHT_PROGBITS && ty != SHT_NOBITS
                    {
                        e.1 = ty;
                    }
                    e.2 = e.2.max(align);
                    if flags & SHF_MERGE == 0 {
                        e.3 = false;
                    }
                }
                (seen, acc)
            })
            .collect();
        mk.mark("1a per object");
        let mut index: HashMap<(&'a [u8], bool), u32> = HashMap::new();
        let mut outs: Vec<OutSec> = Vec::new();
        let mut remaps: Vec<Vec<u32>> = Vec::with_capacity(per_obj.len());
        for (keys, acc) in &per_obj {
            let mut remap = Vec::with_capacity(keys.len());
            for (&(name, alloc), &(f, ty, align, all_merge)) in keys.iter().zip(acc) {
                let oi = *index.entry((name, alloc)).or_insert_with(|| {
                    let mut o = OutSec::new(name, SHT_NULL, 0, Synthetic::None);
                    o.first_seen = outs.len() as u64;
                    outs.push(o);
                    (outs.len() - 1) as u32
                });
                remap.push(oi);
                let o = &mut outs[oi as usize];
                if o.ty == SHT_NULL {
                    o.ty = ty;
                    o.flags = f;
                } else {
                    if o.ty == SHT_NOBITS && ty != SHT_NOBITS {
                        o.ty = ty;
                    }
                    o.flags |= f & !(SHF_MERGE | SHF_STRINGS);
                }
                if !all_merge {
                    o.flags &= !(SHF_MERGE | SHF_STRINGS);
                }
                o.align = o.align.max(align);
            }
            remaps.push(remap);
        }
        drop(per_obj);
        mk.mark("1b merge tables");
        // 2. Local key indices → output section indices.
        self.objs
            .par_iter_mut()
            .zip(remaps.par_iter())
            .for_each(|(o, remap)| {
                if remap.is_empty() {
                    return;
                }
                for s in &mut o.secs {
                    if s.out != NONE
                        && s.is_live()
                        && matches!(s.kind, SecKind::Alloc | SecKind::NonAlloc | SecKind::Merge)
                    {
                        s.out = remap[s.out as usize];
                    }
                }
            });
        drop(remaps);
        mk.mark("1-2 output sections");
        for o in &mut outs {
            if o.flags & SHF_MERGE != 0 {
                // Merged contents of different entry sizes can share a section name.
                o.flags &= !(SHF_MERGE | SHF_STRINGS);
            }
            if o.ty == SHT_NULL {
                o.ty = SHT_PROGBITS;
            }
            if o.name == b".debug_str" || o.name == b".comment" || o.name == b".debug_line_str" {
                o.flags |= SHF_MERGE | SHF_STRINGS;
                o.entsize = 1;
            }
        }
        // Merged sections join their output sections.
        for (mi, m) in self.merged.iter().enumerate() {
            let oi = *index
                .get(&(m.name, m.flags & SHF_ALLOC != 0))
                .ok_or_else(|| {
                    err!(
                        "internal error: merged section {} has no output section",
                        String::from_utf8_lossy(m.name)
                    )
                })?;
            let o = &mut outs[oi as usize];
            o.merged.push((mi as u32, 0));
            o.align = o.align.max(1 << m.p2align);
        }
        drop(index);

        // 3. The linker's own sections.
        let mut synth = Synths::default();
        let add = |outs: &mut Vec<OutSec>, synth: &mut Synths, o: OutSec| {
            synth.map.insert(o.synth, outs.len() as u32);
            outs.push(o);
        };
        let w = word::<T>();
        let has_dyn = self.has_dynamic;
        let relsz = if T::RELA_DYN { 3 * w } else { 2 * w };
        mk.mark("3a");
        let dyninfo = self.plan_dynamic(&outs);
        if let Some(i) = &self.interp {
            let mut o = OutSec::new(b".interp", SHT_PROGBITS, SHF_ALLOC, Synthetic::Interp);
            o.size = i.len() as u64 + 1;
            add(&mut outs, &mut synth, o);
        }
        let build_id_size = match &self.cfg.build_id {
            BuildId::None => 0,
            BuildId::Hash(n) => *n as u64,
            BuildId::Uuid => 16,
            BuildId::Hex(b) => b.len() as u64,
        };
        if build_id_size > 0 {
            let mut o = OutSec::new(
                b".note.gnu.build-id",
                SHT_NOTE,
                SHF_ALLOC,
                Synthetic::BuildId,
            );
            o.size = 16 + build_id_size;
            o.align = 4;
            add(&mut outs, &mut synth, o);
        }
        if has_dyn {
            let symsz = if T::IS64 { 24 } else { 16 };
            let mut o = OutSec::new(b".dynsym", SHT_DYNSYM, SHF_ALLOC, Synthetic::Dynsym);
            o.size = (dyninfo.order.len() as u64 + 1) * symsz;
            o.align = w;
            o.entsize = symsz;
            o.info = 1;
            add(&mut outs, &mut synth, o);
            let mut o = OutSec::new(b".dynstr", SHT_STRTAB, SHF_ALLOC, Synthetic::Dynstr);
            o.size = dyninfo.strtab.len() as u64;
            add(&mut outs, &mut synth, o);
            if self.cfg.hash_gnu {
                let mut o = OutSec::new(b".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, Synthetic::GnuHash);
                o.size = dyninfo.gnu_hash_size::<T>();
                o.align = w;
                add(&mut outs, &mut synth, o);
            }
            if self.cfg.hash_sysv {
                let mut o = OutSec::new(b".hash", SHT_HASH, SHF_ALLOC, Synthetic::Hash);
                o.size = dyninfo.sysv_hash_size();
                o.align = 4;
                o.entsize = 4;
                add(&mut outs, &mut synth, o);
            }
            if dyninfo.has_versions() {
                let mut o = OutSec::new(
                    b".gnu.version",
                    SHT_GNU_VERSYM,
                    SHF_ALLOC,
                    Synthetic::VerSym,
                );
                o.size = (dyninfo.order.len() as u64 + 1) * 2;
                o.align = 2;
                o.entsize = 2;
                add(&mut outs, &mut synth, o);
                if !dyninfo.verneed.is_empty() {
                    let mut o = OutSec::new(
                        b".gnu.version_r",
                        SHT_GNU_VERNEED,
                        SHF_ALLOC,
                        Synthetic::VerNeed,
                    );
                    o.size = dyninfo.verneed_size();
                    o.align = 4;
                    o.info = dyninfo.verneed.len() as u32;
                    add(&mut outs, &mut synth, o);
                }
                if !dyninfo.verdef.is_empty() {
                    let mut o = OutSec::new(
                        b".gnu.version_d",
                        SHT_GNU_VERDEF,
                        SHF_ALLOC,
                        Synthetic::VerDef,
                    );
                    o.size = dyninfo.verdef_size();
                    o.align = 4;
                    o.info = dyninfo.verdef.len() as u32;
                    add(&mut outs, &mut synth, o);
                }
            }
        }
        let n_rela_dyn = self.scan.rela_dyn_count();
        if n_rela_dyn > 0 && has_dyn {
            let name: &[u8] = if T::RELA_DYN {
                b".rela.dyn"
            } else {
                b".rel.dyn"
            };
            let mut o = OutSec::new(
                name,
                if T::RELA_DYN { SHT_RELA } else { SHT_REL },
                SHF_ALLOC,
                Synthetic::RelaDyn,
            );
            o.size = n_rela_dyn * relsz;
            o.align = w;
            o.entsize = relsz;
            add(&mut outs, &mut synth, o);
        } else if n_rela_dyn > 0 {
            bail!("internal error: dynamic relocations in a static executable");
        }
        let nplt = self.scan.plt.len() as u64;
        let niplt = self.scan.iplt.len() as u64;
        if nplt + niplt > 0 {
            let name: &[u8] = match (has_dyn, T::RELA_DYN) {
                (true, true) => b".rela.plt",
                (true, false) => b".rel.plt",
                (false, true) => b".rela.iplt",
                (false, false) => b".rel.iplt",
            };
            let mut o = OutSec::new(
                name,
                if T::RELA_DYN { SHT_RELA } else { SHT_REL },
                SHF_ALLOC | if has_dyn { SHF_INFO_LINK } else { 0 },
                Synthetic::RelaPlt,
            );
            o.size = (nplt + niplt) * relsz;
            o.align = w;
            o.entsize = relsz;
            add(&mut outs, &mut synth, o);
            let mut o = OutSec::new(
                b".plt",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                Synthetic::Plt,
            );
            o.size = T::PLT0_SIZE + (nplt + niplt) * T::PLT_SIZE;
            o.align = T::PLT_ALIGN;
            add(&mut outs, &mut synth, o);
        }
        if self.scan.got_words > 0
            || has_dyn && T::GOT0_DYNAMIC
            || self.syms.find(b"_GLOBAL_OFFSET_TABLE_").is_some()
            || matches!(T::M, Machine::Ppc64 | Machine::Ppc64le)
        {
            let mut o = OutSec::new(b".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, Synthetic::Got);
            o.size = self.scan.got_words.max(self.scan.got_header) * w;
            o.align = w;
            o.relro = true;
            add(&mut outs, &mut synth, o);
        }
        if nplt + niplt > 0 || has_dyn {
            let reserved = if has_dyn { T::GOTPLT_RESERVED } else { 0 };
            let mut o = OutSec::new(
                b".got.plt",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_WRITE,
                Synthetic::GotPlt,
            );
            o.size = (reserved + nplt + niplt) * w;
            o.align = w;
            o.relro = self.cfg.z_now;
            if o.size > 0 {
                add(&mut outs, &mut synth, o);
            }
        }
        if has_dyn {
            let mut o = OutSec::new(
                b".dynamic",
                SHT_DYNAMIC,
                SHF_ALLOC | if self.cfg.z_rodynamic { 0 } else { SHF_WRITE },
                Synthetic::Dynamic,
            );
            o.size = dyninfo.entries.len() as u64 * 2 * w;
            o.align = w;
            o.entsize = 2 * w;
            add(&mut outs, &mut synth, o);
        }
        if self.ehframe.size > 0 {
            let mut o = OutSec::new(
                b".eh_frame",
                if T::M == Machine::X86_64 {
                    SHT_X86_64_UNWIND
                } else {
                    SHT_PROGBITS
                },
                SHF_ALLOC,
                Synthetic::EhFrame,
            );
            o.size = self.ehframe.size;
            o.align = w;
            add(&mut outs, &mut synth, o);
            if self.cfg.eh_frame_hdr {
                let mut o = OutSec::new(
                    b".eh_frame_hdr",
                    SHT_PROGBITS,
                    SHF_ALLOC,
                    Synthetic::EhFrameHdr,
                );
                o.size = super::ehframe::hdr_size(self.ehframe.nfdes);
                o.align = 4;
                add(&mut outs, &mut synth, o);
            }
        }
        if !self.thunks.list.is_empty() {
            let mut o = OutSec::new(
                b".text.thunks",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                Synthetic::Thunks,
            );
            o.size = self.thunks.list.len() as u64 * T::THUNK_SIZE;
            o.align = 16;
            add(&mut outs, &mut synth, o);
        }
        if T::M == Machine::Arm {
            let size = self.exidx_size();
            if size > 0 {
                let mut o = OutSec::new(
                    b".ARM.exidx",
                    SHT_ARM_EXIDX,
                    SHF_ALLOC | SHF_LINK_ORDER,
                    Synthetic::Exidx,
                );
                o.size = size;
                o.align = 4;
                add(&mut outs, &mut synth, o);
            }
        }
        // Common symbols and copy relocations.
        mk.mark("3b synthetic");
        let commons = self.assign_commons();
        let mut bss_extra = 0u64;
        let mut bss_align = 1u64;
        for &(id, off) in &commons {
            let (sz, al) = self.common_size_align(id);
            bss_extra = bss_extra.max(off + sz);
            bss_align = bss_align.max(al);
        }
        let copy_base = align_up(bss_extra, self.scan.copy_align.max(1));
        if !self.scan.copyrels.is_empty() {
            bss_extra = copy_base + self.scan.copy_size;
            bss_align = bss_align.max(self.scan.copy_align);
        }
        if bss_extra > 0 {
            let mut o = OutSec::new(b".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, Synthetic::Bss);
            o.size = bss_extra;
            o.align = bss_align;
            add(&mut outs, &mut synth, o);
        }
        let attrs = self
            .objs
            .iter()
            .find(|o| o.alive.load(Ordering::Relaxed) && o.attributes != 0);
        if let Some(o) = attrs {
            let h = o.shdr::<T>(o.attributes);
            let name: &[u8] = if T::M == Machine::Arm {
                b".ARM.attributes"
            } else {
                b".riscv.attributes"
            };
            let mut s = OutSec::new(name, h.ty, 0, Synthetic::Attributes);
            s.size = h.size;
            add(&mut outs, &mut synth, s);
        }
        if self.cfg.strip != super::config::Strip::All {
            let symsz = if T::IS64 { 24 } else { 16 };
            let mut o = OutSec::new(b".symtab", SHT_SYMTAB, 0, Synthetic::Symtab);
            o.align = w;
            o.entsize = symsz;
            add(&mut outs, &mut synth, o);
            add(
                &mut outs,
                &mut synth,
                OutSec::new(b".strtab", SHT_STRTAB, 0, Synthetic::Strtab),
            );
        }
        add(
            &mut outs,
            &mut synth,
            OutSec::new(b".shstrtab", SHT_STRTAB, 0, Synthetic::Shstrtab),
        );
        mk.mark("3c commons/bss");
        timer.phase("output sections");

        // 4. Order.
        let relro_on = self.cfg.z_relro && has_dyn;
        let mut order: Vec<usize> = (0..outs.len()).collect();
        order.sort_by_key(|&i| {
            let o = &outs[i];
            let (c, r) = rank(o, relro_on);
            (c, r, o.first_seen, i)
        });
        let mut remap = vec![0u32; outs.len()];
        for (new, &old) in order.iter().enumerate() {
            remap[old] = new as u32;
        }
        let mut sorted: Vec<OutSec> = order.iter().map(|&i| outs[i].clone()).collect();
        for (k, v) in synth.map.iter_mut() {
            let _ = k;
            *v = remap[*v as usize];
        }
        for o in &mut sorted {
            o.relro = relro_on && rank(o, true).0 == 2;
        }
        let remap_ref = &remap;
        self.objs.par_iter_mut().for_each(|o| {
            for s in &mut o.secs {
                if s.out != NONE {
                    s.out = remap_ref[s.out as usize];
                }
            }
        });
        let mut outs = sorted;

        mk.mark("4 order");
        // 5. Each object's block in each output section.
        let blocks: Vec<Vec<(u32, u64, u64)>> = self
            .objs
            .par_iter_mut()
            .map(|o| {
                let mut blocks: Vec<(u32, u64, u64)> = Vec::new();
                if !o.alive.load(Ordering::Relaxed) {
                    return blocks;
                }
                for s in &mut o.secs {
                    if s.out == NONE || !s.is_live() || s.kind == SecKind::Merge {
                        continue;
                    }
                    let b = match blocks.iter().position(|b| b.0 == s.out) {
                        Some(b) => b,
                        None => {
                            blocks.push((s.out, 0, 1));
                            blocks.len() - 1
                        }
                    };
                    let (_, size, align) = &mut blocks[b];
                    let a = s.align();
                    let off = align_up(*size, a);
                    s.addr = off;
                    *size = off + s.size as u64;
                    *align = (*align).max(a);
                }
                blocks
            })
            .collect();
        let mut cursor = vec![0u64; outs.len()];
        let starts: Vec<Vec<u64>> = blocks
            .iter()
            .map(|bs| {
                bs.iter()
                    .map(|&(o, size, align)| {
                        let start = align_up(cursor[o as usize], align);
                        cursor[o as usize] = start + size;
                        start
                    })
                    .collect()
            })
            .collect();
        for (i, o) in outs.iter_mut().enumerate() {
            if o.synth == Synthetic::None {
                o.input_size = cursor[i];
                let mut size = cursor[i];
                let mut merged = std::mem::take(&mut o.merged);
                for (mi, off) in &mut merged {
                    let m = &self.merged[*mi as usize];
                    let a = 1u64 << m.p2align;
                    *off = align_up(size, a);
                    size = *off + m.size;
                }
                o.merged = merged;
                o.size = size;
            }
        }
        // Linker-provided names for output sections the inputs didn't create.
        if let Some(i) = synth.get(Synthetic::Bss)
            && let Some(j) = outs
                .iter()
                .position(|o| o.name == b".bss" && o.synth == Synthetic::None)
        {
            // Inputs had a `.bss`: append ours to it.
            let base = align_up(outs[j].size, outs[i as usize].align);
            outs[j].align = outs[j].align.max(outs[i as usize].align);
            outs[j].size = base + outs[i as usize].size;
            outs[i as usize].size = 0;
            outs[i as usize].offset = base;
            outs[i as usize].link = j as u32 + 1;
        }

        mk.mark("5 blocks");
        // 6. Symbol table plan (sizes).
        let symtab = self.plan_symtab(&outs);
        if let Some(i) = synth.get(Synthetic::Symtab) {
            outs[i as usize].size = symtab.nsyms * if T::IS64 { 24 } else { 16 };
            outs[i as usize].info = symtab.first_global as u32;
        }
        if let Some(i) = synth.get(Synthetic::Strtab) {
            outs[i as usize].size = symtab.strsize;
        }
        // Section header string table and indices: empty sections are dropped.
        let mut shstr = vec![0u8];
        let mut shndx = 1u32;
        for o in outs.iter_mut() {
            let keep = o.size > 0
                || matches!(
                    o.synth,
                    Synthetic::Shstrtab
                        | Synthetic::Symtab
                        | Synthetic::Strtab
                        | Synthetic::Dynamic
                        | Synthetic::Got
                        | Synthetic::GotPlt
                        | Synthetic::Dynsym
                )
                || o.synth == Synthetic::None && o.input_size > 0;
            if o.synth == Synthetic::Bss && o.link != 0 {
                o.shndx = 0;
                continue;
            }
            if !keep {
                o.shndx = 0;
                continue;
            }
            o.shndx = shndx;
            shndx += 1;
            o.link = 0;
        }
        let mut name_offs = vec![0u32; outs.len()];
        for (i, o) in outs.iter().enumerate() {
            if o.shndx == 0 {
                continue;
            }
            name_offs[i] = shstr.len() as u32;
            shstr.extend_from_slice(&o.name);
            shstr.push(0);
        }
        if let Some(i) = synth.get(Synthetic::Shstrtab) {
            outs[i as usize].size = shstr.len() as u64;
        }
        let nshdr = shndx;

        mk.mark("6 symtab plan");
        // 7. Program headers.
        let has_tls = outs
            .iter()
            .any(|o| o.is_alloc() && o.flags & SHF_TLS != 0 && o.size > 0);
        let mut nph = 0u64;
        let classes: Vec<u32> = {
            let mut v: Vec<u32> = outs
                .iter()
                .filter(|o| o.is_alloc() && o.shndx != 0)
                .map(|o| rank(o, relro_on).0)
                .collect();
            v.dedup();
            v
        };
        nph += classes.len() as u64; // PT_LOADs
        if !self.cfg.shared && self.interp.is_some() || has_dyn && !self.cfg.shared {
            nph += 1; // PT_PHDR
        }
        if self.interp.is_some() {
            nph += 1;
        }
        if has_dyn {
            nph += 1;
        }
        if has_tls {
            nph += 1;
        }
        if synth.get(Synthetic::EhFrameHdr).is_some() {
            nph += 1;
        }
        nph += 1; // PT_GNU_STACK
        if relro_on && outs.iter().any(|o| o.relro && o.shndx != 0) {
            nph += 1;
        }
        let note_groups = {
            let mut n = 0;
            let mut prev = false;
            for o in outs.iter().filter(|o| o.shndx != 0) {
                let is = o.is_alloc() && o.ty == SHT_NOTE;
                if is && !prev {
                    n += 1;
                }
                prev = is;
            }
            n
        };
        nph += note_groups;
        if synth.get(Synthetic::Exidx).is_some() {
            nph += 1;
        }
        if synth.get(Synthetic::Attributes).is_some()
            && matches!(T::M, Machine::RiscV64 | Machine::RiscV32)
        {
            nph += 1;
        }
        let ehdr_size = if T::IS64 { 64 } else { 52 };
        let phent = if T::IS64 { 56 } else { 32 };
        let phdr_size = nph * phent;

        mk.mark("7 phdrs");
        // 8. Addresses.
        let page = self.cfg.z_max_page_size.unwrap_or(T::MAX_PAGE);
        let base = if self.cfg.pic() {
            self.cfg.image_base.unwrap_or(0)
        } else {
            self.cfg.image_base.unwrap_or(match T::M {
                Machine::I386 => 0x0804_8000,
                Machine::Arm | Machine::RiscV32 => 0x10000,
                Machine::Ppc64 | Machine::Ppc64le => 0x1000_0000,
                _ => 0x40_0000,
            })
        };
        let mut off = ehdr_size + phdr_size;
        let mut va = base + off;
        let mut cur_class = None;
        let mut tls_lo = u64::MAX;
        let mut tls_hi = 0u64;
        let mut tls_file_hi = 0u64;
        let mut tls_align = 1u64;
        for o in outs.iter_mut() {
            if !o.is_alloc() || o.shndx == 0 {
                continue;
            }
            let class = rank(o, relro_on).0;
            if cur_class.is_some() && cur_class != Some(class) {
                // A new PT_LOAD: next page in memory, congruent to the file offset.
                if self.cfg.z_separate_code && (class == 1 || cur_class == Some(1)) {
                    off = align_up(off, page);
                }
                va = align_up(va, page) + off % page;
            }
            cur_class = Some(class);
            let tls_bss = o.flags & SHF_TLS != 0 && o.nobits();
            if tls_bss {
                // `.tbss` has room in the TLS block only, not in its segment: it gets its
                // aligned address, and what follows starts where the segment's file contents
                // left off. Aligning the address for it, but not the file offset, put every
                // later section of the segment (`.dynamic`, `.got`) away from where the loader
                // maps it.
                let addr = align_up(va, o.align);
                o.addr = addr;
                o.offset = off;
                tls_lo = tls_lo.min(addr);
                tls_hi = tls_hi.max(addr + o.size);
                tls_align = tls_align.max(o.align);
                continue;
            }
            if o.align > page {
                let a = o.align;
                let na = align_up(va, a);
                off += na - va;
                va = na;
            } else {
                let na = align_up(va, o.align);
                if !o.nobits() {
                    off += na - va;
                }
                va = na;
            }
            o.addr = va;
            o.offset = off;
            if o.flags & SHF_TLS != 0 {
                tls_lo = tls_lo.min(va);
                tls_hi = tls_hi.max(va + o.size);
                if !o.nobits() {
                    tls_file_hi = tls_file_hi.max(va + o.size);
                }
                tls_align = tls_align.max(o.align);
            }
            if tls_bss {
                continue;
            }
            va += o.size;
            if !o.nobits() {
                off += o.size;
            }
        }
        for o in outs.iter_mut() {
            if o.is_alloc() || o.shndx == 0 {
                continue;
            }
            off = align_up(off, o.align.max(1));
            o.offset = off;
            o.addr = 0;
            off += o.size;
        }
        let shoff = align_up(off, w);
        let file_size = shoff + nshdr as u64 * if T::IS64 { 64 } else { 40 };
        let tls = (tls_lo != u64::MAX).then(|| {
            let filesz = tls_file_hi.saturating_sub(tls_lo);
            (tls_lo, filesz, tls_hi - tls_lo, tls_align)
        });
        // The appended `.bss` tail moves with its host section.
        if let Some(i) = synth.get(Synthetic::Bss)
            && outs[i as usize].link != 0
        {
            let host = outs[i as usize].link as usize - 1;
            let off = outs[i as usize].offset;
            outs[i as usize].addr = outs[host].addr + off;
        } else if let Some(i) = synth.get(Synthetic::Bss) {
            outs[i as usize].offset = 0;
        }

        let mut phdrs = Vec::with_capacity(nph as usize);
        let first_alloc = outs.iter().position(|o| o.is_alloc() && o.shndx != 0);
        if !self.cfg.shared && self.interp.is_some() || has_dyn && !self.cfg.shared {
            phdrs.push(Phdr {
                ty: PT_PHDR,
                flags: PF_R,
                offset: ehdr_size,
                vaddr: base + ehdr_size,
                filesz: phdr_size,
                memsz: phdr_size,
                align: w,
            });
        }
        if let Some(i) = synth.get(Synthetic::Interp) {
            let o = &outs[i as usize];
            phdrs.push(Phdr {
                ty: PT_INTERP,
                flags: PF_R,
                offset: o.offset,
                vaddr: o.addr,
                filesz: o.size,
                memsz: o.size,
                align: 1,
            });
        }
        // PT_LOADs.
        let mut cur: Option<(u32, Phdr)> = None;
        let mut loads = Vec::new();
        for (i, o) in outs.iter().enumerate() {
            if !o.is_alloc() || o.shndx == 0 {
                continue;
            }
            let class = rank(o, relro_on).0;
            let tls_bss = o.flags & SHF_TLS != 0 && o.nobits();
            match &mut cur {
                Some((c, p)) if *c == class => {
                    if !tls_bss {
                        let end = o.addr + o.size;
                        p.memsz = end - p.vaddr;
                        if !o.nobits() {
                            p.filesz = o.offset + o.size - p.offset;
                        }
                    }
                }
                _ => {
                    if let Some((_, p)) = cur.take() {
                        loads.push(p);
                    }
                    let flags = match class {
                        0 => PF_R,
                        1 => PF_R | PF_X,
                        _ => PF_R | PF_W,
                    };
                    let (offset, vaddr) = if Some(i) == first_alloc {
                        (0, base)
                    } else {
                        (o.offset, o.addr)
                    };
                    let mut p = Phdr {
                        ty: PT_LOAD,
                        flags,
                        offset,
                        vaddr,
                        filesz: 0,
                        memsz: 0,
                        align: page,
                    };
                    if !tls_bss {
                        p.memsz = o.addr + o.size - vaddr;
                        p.filesz = if o.nobits() {
                            o.offset - offset
                        } else {
                            o.offset + o.size - offset
                        };
                    }
                    cur = Some((class, p));
                }
            }
        }
        if let Some((_, p)) = cur {
            loads.push(p);
        }
        if first_alloc.is_none() {
            // Nothing allocated (unusual): still load the headers.
            loads.push(Phdr {
                ty: PT_LOAD,
                flags: PF_R,
                offset: 0,
                vaddr: base,
                filesz: ehdr_size + phdr_size,
                memsz: ehdr_size + phdr_size,
                align: page,
            });
            nph += 1;
        }
        phdrs.extend(loads);
        if let Some(i) = synth.get(Synthetic::Dynamic) {
            let o = &outs[i as usize];
            phdrs.push(Phdr {
                ty: PT_DYNAMIC,
                flags: PF_R | PF_W,
                offset: o.offset,
                vaddr: o.addr,
                filesz: o.size,
                memsz: o.size,
                align: w,
            });
        }
        if let Some((addr, filesz, memsz, align)) = tls {
            let off = outs
                .iter()
                .find(|o| o.flags & SHF_TLS != 0 && o.shndx != 0 && o.is_alloc())
                .map_or(0, |o| o.offset);
            phdrs.push(Phdr {
                ty: PT_TLS,
                flags: PF_R,
                offset: off,
                vaddr: addr,
                filesz,
                memsz,
                align,
            });
        }
        if let Some(i) = synth.get(Synthetic::EhFrameHdr) {
            let o = &outs[i as usize];
            phdrs.push(Phdr {
                ty: PT_GNU_EH_FRAME,
                flags: PF_R,
                offset: o.offset,
                vaddr: o.addr,
                filesz: o.size,
                memsz: o.size,
                align: 4,
            });
        }
        phdrs.push(Phdr {
            ty: PT_GNU_STACK,
            flags: PF_R | PF_W | if self.exec_stack { PF_X } else { 0 },
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: self.cfg.z_stack_size.unwrap_or(0),
            align: if T::IS64 { 16 } else { 4 },
        });
        if relro_on {
            let rel: Vec<&OutSec> = outs
                .iter()
                .filter(|o| o.relro && o.shndx != 0 && o.is_alloc())
                .collect();
            if let (Some(first), Some(_)) = (rel.first(), rel.last()) {
                let end = rel
                    .iter()
                    .filter(|o| !(o.flags & SHF_TLS != 0 && o.nobits()))
                    .map(|o| o.addr + o.size)
                    .max()
                    .unwrap_or(first.addr);
                let memsz = align_up(end, page) - first.addr;
                let filesz = rel
                    .iter()
                    .filter(|o| !o.nobits())
                    .map(|o| o.offset + o.size)
                    .max()
                    .unwrap_or(first.offset)
                    - first.offset;
                phdrs.push(Phdr {
                    ty: PT_GNU_RELRO,
                    flags: PF_R,
                    offset: first.offset,
                    vaddr: first.addr,
                    filesz,
                    memsz,
                    align: 1,
                });
            }
        }
        {
            let mut i = 0;
            let live: Vec<&OutSec> = outs.iter().filter(|o| o.shndx != 0).collect();
            while i < live.len() {
                if live[i].is_alloc() && live[i].ty == SHT_NOTE {
                    let start = i;
                    while i < live.len() && live[i].is_alloc() && live[i].ty == SHT_NOTE {
                        i += 1;
                    }
                    let (a, b) = (live[start], live[i - 1]);
                    phdrs.push(Phdr {
                        ty: PT_NOTE,
                        flags: PF_R,
                        offset: a.offset,
                        vaddr: a.addr,
                        filesz: b.offset + b.size - a.offset,
                        memsz: b.addr + b.size - a.addr,
                        align: a.align.max(4),
                    });
                } else {
                    i += 1;
                }
            }
        }
        if let Some(i) = synth.get(Synthetic::Exidx) {
            let o = &outs[i as usize];
            phdrs.push(Phdr {
                ty: PT_ARM_EXIDX,
                flags: PF_R,
                offset: o.offset,
                vaddr: o.addr,
                filesz: o.size,
                memsz: o.size,
                align: 4,
            });
        }
        if let Some(i) = synth.get(Synthetic::Attributes)
            && matches!(T::M, Machine::RiscV64 | Machine::RiscV32)
        {
            let o = &outs[i as usize];
            phdrs.push(Phdr {
                ty: PT_RISCV_ATTRIBUTES,
                flags: PF_R,
                offset: o.offset,
                vaddr: 0,
                filesz: o.size,
                memsz: 0,
                align: 1,
            });
        }
        if phdrs.len() as u64 != nph {
            bail!(
                "internal error: planned {nph} program headers, made {}",
                phdrs.len()
            );
        }

        mk.mark("8 addresses");
        // 9. Input section addresses.
        let outs_ref = &outs;
        self.objs
            .par_iter_mut()
            .zip(starts.par_iter())
            .zip(blocks.par_iter())
            .for_each(|((o, st), bl)| {
                for s in &mut o.secs {
                    if s.out == NONE || !s.is_live() || s.kind == SecKind::Merge {
                        continue;
                    }
                    let k = bl.iter().position(|b| b.0 == s.out).unwrap();
                    let out = &outs_ref[s.out as usize];
                    // Non-allocated sections: the offset in their output section (what
                    // debug info refers to), not a file offset.
                    s.addr += st[k] + if out.is_alloc() { out.addr } else { 0 };
                }
            });
        for (oi, o) in outs.iter().enumerate() {
            for &(mi, off) in &o.merged {
                let m = &mut self.merged[mi as usize];
                m.out = oi as u32;
                m.addr = if o.is_alloc() { o.addr + off } else { off };
                m.file_off = o.offset + off;
            }
        }
        let mut lay = Layout {
            outs,
            phdrs,
            synth,
            file_size,
            shoff,
            ehdr_size,
            phdr_size,
            tls,
            base,
            dynamic: dyninfo,
            symtab,
            commons,
            bss_extra: copy_base,
            build_id_size,
            entry: 0,
            got: 0,
            gotplt: 0,
            plt: 0,
        };
        lay.got = lay.addr_of(Synthetic::Got);
        lay.gotplt = lay.addr_of(Synthetic::GotPlt);
        lay.plt = lay.addr_of(Synthetic::Plt);
        lay.symtab.shstrtab = shstr;
        lay.symtab.shname = name_offs;
        mk.mark("9 input addresses");
        self.assign_addresses(&mut lay)?;
        mk.mark("10 symbol addresses");
        timer.phase("layout");
        Ok(lay)
    }

    /// Common symbols that won: laid out in `.bss` in symbol-id order.
    fn assign_commons(&self) -> Vec<(SymId, u64)> {
        let ids: Vec<SymId> = self.syms.par_filter(|s| {
            let d = s.def();
            d != UNDEF && def_class(d) == CLASS_COMMON
        });
        let mut off = 0u64;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let (sz, al) = self.common_size_align(id);
            off = align_up(off, al);
            out.push((id, off));
            off += sz;
        }
        out
    }

    fn common_size_align(&self, id: SymId) -> (u64, u64) {
        match self.def_obj(id) {
            Some((o, i)) => {
                let s = o.sym::<T>(i);
                let al = if s.value.is_power_of_two() {
                    s.value
                } else {
                    word::<T>()
                };
                (s.size, al)
            }
            None => (0, 1),
        }
    }

    /// Final addresses of global symbols (and the entry point).
    fn assign_addresses(&mut self, lay: &mut Layout) -> Result<()> {
        self.ehframe.addr = lay.addr_of(Synthetic::EhFrame);
        let bss = lay.out(Synthetic::Bss).map(|o| o.addr).unwrap_or(0);
        let commons: HashMap<SymId, u64> = lay.commons.iter().copied().collect();
        let copy_base = bss + lay.bss_extra;
        let plt = lay.plt;
        let lay_ref = &*lay;
        self.syms.par_for_each(|id, sym| {
            let d = sym.def();
            let f = sym.flags();
            let a = if d == UNDEF {
                0
            } else {
                match def_class(d) {
                    CLASS_LAZY => {
                        if f & NEEDS_COPY != 0 {
                            let aux = &self.scan.aux[sym.aux() as usize];
                            copy_base + self.scan.copyrels[aux.copy as usize].1
                        } else if f & NEEDS_CPLT != 0 {
                            let aux = &self.scan.aux[sym.aux() as usize];
                            plt + T::PLT0_SIZE + aux.plt as u64 * T::PLT_SIZE
                        } else {
                            0
                        }
                    }
                    CLASS_INTERNAL => self.internal_value(lay_ref, def_index(d) as usize),
                    CLASS_COMMON => bss + commons.get(&id).copied().unwrap_or(0),
                    _ => {
                        if f & IS_IFUNC != 0 && sym.aux() != NONE {
                            let aux = &self.scan.aux[sym.aux() as usize];
                            if aux.plt != NONE {
                                plt + T::PLT0_SIZE + aux.plt as u64 * T::PLT_SIZE
                            } else {
                                self.local_value(def_index(d), self.def_obj(id).unwrap().0)
                            }
                        } else {
                            let (o, i) = self.def_obj(id).unwrap();
                            self.local_value(i, o)
                        }
                    }
                }
            };
            sym.addr.store(a, Ordering::Relaxed);
        });
        // Defsyms referring to symbols, now that those have addresses.
        for s in &self.internal {
            if let Synth::Defsym(super::config::DefsymExpr::Symbol(t, add)) = &s.kind {
                let v = self
                    .syms
                    .find(t.as_bytes())
                    .map(|id| self.syms.get(id).addr())
                    .ok_or_else(|| err!("--defsym: undefined symbol {t}"))?;
                if self.syms.get(s.id).def() != UNDEF
                    && def_class(self.syms.get(s.id).def()) == CLASS_INTERNAL
                {
                    self.syms
                        .get(s.id)
                        .addr
                        .store(v.wrapping_add(*add as u64), Ordering::Relaxed);
                }
            }
        }
        lay.entry = match self.entry {
            Some(e) if self.syms.get(e).def() != UNDEF => self.syms.get(e).addr(),
            Some(e) => {
                if !self.cfg.shared && self.cfg.entry.is_some() {
                    if let Some(v) = self
                        .cfg
                        .entry
                        .as_deref()
                        .and_then(super::config::parse_number)
                    {
                        v
                    } else {
                        crate::diag::warn(format!(
                            "cannot find entry symbol {}; not setting start address",
                            String::from_utf8_lossy(self.syms.get(e).name)
                        ));
                        0
                    }
                } else {
                    if !self.cfg.shared {
                        crate::diag::warn(format!(
                            "cannot find entry symbol {}; not setting start address",
                            String::from_utf8_lossy(self.syms.get(e).name)
                        ));
                    }
                    0
                }
            }
            None => 0,
        };
        Ok(())
    }

    /// The address of symbol `i` of object `o` (a defined, non-TLS-relative address).
    #[inline]
    pub fn local_value(&self, i: u32, o: &Object<'a>) -> u64 {
        let s = o.sym::<T>(i);
        if s.shndx == SHN_ABS || s.shndx == SHN_UNDEF {
            return s.value;
        }
        if s.shndx == SHN_COMMON {
            return 0;
        }
        let Some(sec) = o.secs.get(s.shndx as usize) else {
            return s.value;
        };
        match sec.kind {
            SecKind::Merge => self.merged_addr(o, s.shndx, s.value).unwrap_or(0),
            // `.eh_frame` is rebuilt from its records rather than laid out as sections.
            SecKind::EhFrame => self.eh_frame_addr(o, s.shndx, s.value),
            _ => sec.addr.wrapping_add(s.value),
        }
    }

    fn internal_value(&self, lay: &Layout, k: usize) -> u64 {
        let find = |name: &[u8]| lay.outs.iter().find(|o| o.name == name && o.shndx != 0);
        let alloc_end = |pred: &dyn Fn(&OutSec) -> bool| {
            lay.outs
                .iter()
                .filter(|o| o.is_alloc() && o.shndx != 0 && pred(o))
                .map(|o| o.addr + o.size)
                .max()
                .unwrap_or(0)
        };
        match &self.internal[k].kind {
            Synth::GotBase => {
                if matches!(
                    T::M,
                    Machine::X86_64 | Machine::I386 | Machine::Arm | Machine::S390x
                ) {
                    if lay.gotplt != 0 { lay.gotplt } else { lay.got }
                } else if matches!(T::M, Machine::Ppc64 | Machine::Ppc64le) {
                    lay.got + 0x8000
                } else {
                    lay.got
                }
            }
            Synth::Dynamic => lay.addr_of(Synthetic::Dynamic),
            Synth::EhdrStart => lay.base,
            Synth::DsoHandle => lay.base,
            Synth::End => alloc_end(&|o| !(o.flags & SHF_TLS != 0 && o.nobits())),
            Synth::Etext => alloc_end(&|o| o.flags & SHF_EXECINSTR != 0),
            Synth::Edata => alloc_end(&|o| !o.nobits()),
            Synth::BssStart => lay
                .outs
                .iter()
                .find(|o| o.is_alloc() && o.nobits() && o.flags & SHF_TLS == 0 && o.shndx != 0)
                .map_or_else(|| alloc_end(&|o| !o.nobits()), |o| o.addr),
            Synth::InitArrayStart => find(b".init_array").map_or(0, |o| o.addr),
            Synth::InitArrayEnd => find(b".init_array").map_or(0, |o| o.addr + o.size),
            Synth::FiniArrayStart => find(b".fini_array").map_or(0, |o| o.addr),
            Synth::FiniArrayEnd => find(b".fini_array").map_or(0, |o| o.addr + o.size),
            Synth::PreinitArrayStart => find(b".preinit_array").map_or(0, |o| o.addr),
            Synth::PreinitArrayEnd => find(b".preinit_array").map_or(0, |o| o.addr + o.size),
            Synth::RelaIpltStart | Synth::RelaIpltEnd => {
                // Static executables: the IRELATIVE relocations crt1 applies.
                if self.has_dynamic {
                    0
                } else {
                    let o = lay.out(Synthetic::RelaPlt);
                    match (o, &self.internal[k].kind) {
                        (Some(o), Synth::RelaIpltStart) => o.addr,
                        (Some(o), _) => o.addr + o.size,
                        (None, _) => 0,
                    }
                }
            }
            Synth::EhFrameHdr => lay.addr_of(Synthetic::EhFrameHdr),
            Synth::TlsModuleBase => lay.tls.map_or(0, |t| t.0),
            Synth::ExidxStart => lay.addr_of(Synthetic::Exidx),
            Synth::ExidxEnd => lay.out(Synthetic::Exidx).map_or(0, |o| o.addr + o.size),
            Synth::GlobalPointer => find(b".sdata")
                .map(|o| o.addr + 0x800)
                .unwrap_or_else(|| lay.got + 0x800),
            Synth::Toc => lay.got + 0x8000,
            Synth::Start(n) => find(n).map_or(0, |o| o.addr),
            Synth::Stop(n) => find(n).map_or(0, |o| o.addr + o.size),
            Synth::Defsym(super::config::DefsymExpr::Value(v)) => *v,
            Synth::Defsym(_) => 0,
        }
    }
}
