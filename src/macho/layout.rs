//! Output segments and sections, and the address of every atom.

use std::collections::HashMap;

use rayon::prelude::*;

use super::arch;
use super::config::{Config, OutputKind};
use super::object::*;
use super::resolve::Linker;
use super::symtab::{Def, Synthetic};
use super::*;
use crate::bail;
use crate::diag::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Atoms,
    ObjcStubs,
    AuthGot,
    Stubs,
    Got,
    ThreadPtrs,
    UnwindInfo,
    Data(usize),
    Empty,
}

pub struct OutSection {
    pub segname: Vec<u8>,
    pub sectname: Vec<u8>,
    pub seg: usize,
    pub flags: u32,
    pub align: u8,
    pub addr: u64,
    pub size: u64,
    pub file_off: u64,
    pub content: Content,
    /// (object, input section) contributions, in order.
    pub chunks: Vec<(u32, u32)>,
    pub reserved1: u32,
    pub reserved2: u32,
    /// Bytes the linker appends after the input atoms (common symbols, selector names, selector
    /// references).
    pub tail: u64,
    /// The 1-based section number symbols refer to.
    pub index: u8,
    order: (i64, usize),
}

impl OutSection {
    pub fn is_zerofill(&self) -> bool {
        matches!(
            self.flags & SECTION_TYPE,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }

    pub fn is_code(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }
}

/// Selector stubs: their section, and where the names and references the linker adds start.
#[derive(Clone, Copy)]
pub struct ObjcLayout {
    pub stubs: usize,
    pub methname: usize,
    pub methname_base: u64,
    pub selrefs: usize,
    pub selrefs_base: u64,
}

pub fn objc_stub_size(arch: super::config::Arch) -> u64 {
    if arch.is_arm() { 32 } else { 16 }
}

pub struct Segment {
    pub name: Vec<u8>,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub flags: u32,
    pub sections: Vec<usize>,
}

pub struct Layout {
    pub segments: Vec<Segment>,
    pub sections: Vec<OutSection>,
    pub image_base: u64,
    pub page: u64,
    pub sizeofcmds: u64,
    pub ncmds: u32,
    pub chained: bool,
    pub signed: bool,
    pub build_version: bool,
    pub stubs: Option<usize>,
    /// arm64e: the signed slots stubs jump through, one per stub.
    pub auth_got: Option<usize>,
    pub got: Option<usize>,
    pub tlvp: Option<usize>,
    pub unwind: Option<usize>,
    pub common: Option<usize>,
    /// Where common symbols start in `common`, after its input atoms.
    pub common_base: u64,
    pub objc: Option<ObjcLayout>,
    pub unwind_plan: Option<super::unwind::UnwindPlan>,
    /// Start of the thread-local template (`__thread_data` then `__thread_bss`).
    pub tlv_start: u64,
    pub linkedit: usize,
    /// Dylibs with a load command, in ordinal order.
    pub dylib_cmds: Vec<u32>,
    pub sectcreate: Vec<Vec<u8>>,
}

impl Layout {
    pub fn text_seg(&self) -> &Segment {
        self.segments.iter().find(|s| s.name == b"__TEXT").unwrap()
    }

    pub fn find_section(&self, seg: &[u8], sect: &[u8]) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.segname == seg && s.sectname == sect)
    }
}

/// Where an input section goes. ld64 renames a few legacy sections and moves data that is
/// only written by dyld into `__DATA_CONST`.
pub fn output_name<'s>(cfg: &Config, sec: &Section<'s>) -> (&'s [u8], &'s [u8]) {
    let (seg, sect) = (sec.segname, sec.sectname);
    let data_const = data_const(cfg);
    match (seg, sect) {
        (b"__TEXT", b"__StaticInit" | b"__textcoal_nt") => (b"__TEXT", b"__text"),
        (b"__TEXT", b"__const_coal") => (b"__TEXT", b"__const"),
        (b"__DATA", b"__datacoal_nt") => (b"__DATA", b"__data"),
        (b"__DATA", b"__const_coal") => (b"__DATA", b"__const"),
        (b"__DATA", b"__const" | b"__mod_init_func" | b"__mod_term_func" | b"__cfstring")
        | (
            b"__DATA",
            b"__objc_classlist" | b"__objc_nlclslist" | b"__objc_catlist" | b"__objc_nlcatlist"
            | b"__objc_protolist" | b"__objc_imageinfo",
        ) if data_const => (b"__DATA_CONST", sect),
        _ if sec.kind == SecKind::NonLazyPointers => {
            if data_const {
                (b"__DATA_CONST", b"__const")
            } else {
                (b"__DATA", b"__const")
            }
        }
        _ => (seg, sect),
    }
}

pub fn data_const(cfg: &Config) -> bool {
    if let Some(v) = cfg.data_const {
        return v;
    }
    let min = match cfg.platform {
        PLATFORM_MACOS | PLATFORM_MACCATALYST => 0x000a_0f00,
        PLATFORM_IOS | PLATFORM_IOSSIMULATOR | PLATFORM_TVOS | PLATFORM_TVOSSIMULATOR => {
            0x000d_0000
        }
        PLATFORM_WATCHOS | PLATFORM_WATCHOSSIMULATOR => 0x0006_0000,
        PLATFORM_BRIDGEOS => 0x0004_0000,
        _ => 0,
    };
    cfg.min_version >= min && (cfg.kind != OutputKind::Execute || cfg.is_pie())
}

pub fn use_chained_fixups(cfg: &Config, arch: super::config::Arch) -> bool {
    if arch == super::config::Arch::Arm64e {
        return true;
    }
    if let Some(v) = cfg.fixup_chains {
        return v;
    }
    let min = match cfg.platform {
        PLATFORM_MACOS => 0x000d_0000,
        PLATFORM_IOS | PLATFORM_TVOS | PLATFORM_MACCATALYST => 0x000d_0400,
        PLATFORM_WATCHOS => 0x0008_0000,
        PLATFORM_IOSSIMULATOR | PLATFORM_TVOSSIMULATOR => 0x0010_0000,
        PLATFORM_DRIVERKIT => 0x0016_0000,
        PLATFORM_XROS | PLATFORM_XROS_SIMULATOR => 0x0001_0000,
        _ => u32::MAX,
    };
    cfg.is_pie() && cfg.min_version >= min
}

pub fn use_build_version(cfg: &Config) -> bool {
    let min = match cfg.platform {
        PLATFORM_MACOS => 0x000a_0e00,
        PLATFORM_IOS | PLATFORM_TVOS => 0x000c_0000,
        PLATFORM_IOSSIMULATOR | PLATFORM_TVOSSIMULATOR => 0x000d_0000,
        PLATFORM_WATCHOS => 0x0005_0000,
        PLATFORM_WATCHOSSIMULATOR => 0x0006_0000,
        _ => 0,
    };
    cfg.min_version >= min
}

fn segment_rank(name: &[u8]) -> i64 {
    match name {
        b"__PAGEZERO" => -4,
        b"__TEXT" => -3,
        b"__DATA_CONST" => -2,
        b"__DATA" => -1,
        b"__LINKEDIT" => i64::MAX,
        _ => 0,
    }
}

fn section_rank(seg: &[u8], name: &[u8], flags: u32) -> i64 {
    const MAX: i64 = i64::MAX / 2;
    if seg == b"__TEXT" {
        return match name {
            b"__text" => -5,
            b"__stubs" => -4,
            b"__stub_helper" => -3,
            b"__objc_stubs" => -2,
            b"__init_offsets" => -1,
            b"__unwind_info" => MAX - 1,
            b"__eh_frame" => MAX,
            _ => 0,
        };
    }
    if seg == b"__DATA" || seg == b"__DATA_CONST" {
        return match flags & SECTION_TYPE {
            S_THREAD_LOCAL_VARIABLE_POINTERS => MAX - 3,
            S_THREAD_LOCAL_REGULAR => MAX - 2,
            S_THREAD_LOCAL_ZEROFILL => MAX - 1,
            S_ZEROFILL | S_GB_ZEROFILL => MAX,
            _ => match name {
                b"__got" => -3,
                b"__la_symbol_ptr" => -2,
                b"__const" => -1,
                _ => 0,
            },
        };
    }
    0
}

pub const LC_DYLINKER_PATH: &[u8] = b"/usr/lib/dyld";

pub fn dylib_cmd_size(name: &str) -> u64 {
    align_up(24 + name.len() as u64 + 1, 8)
}

impl Linker<'_> {
    pub fn layout(&mut self) -> Result<Layout> {
        let cfg = &self.cfg;
        let arch = self.arch;
        let page = arch.page_size();
        let mut sections: Vec<OutSection> = Vec::new();
        let mut by_name: HashMap<(Vec<u8>, Vec<u8>), usize> = HashMap::new();
        let mut seen = 0usize;
        let mut add = |sections: &mut Vec<OutSection>,
                       seg: &[u8],
                       name: &[u8],
                       flags: u32,
                       content: Content|
         -> usize {
            let key = (seg.to_vec(), name.to_vec());
            if let Some(&i) = by_name.get(&key) {
                return i;
            }
            seen += 1;
            sections.push(OutSection {
                segname: seg.to_vec(),
                sectname: name.to_vec(),
                seg: 0,
                flags,
                align: 0,
                addr: 0,
                size: 0,
                file_off: 0,
                content,
                chunks: Vec::new(),
                reserved1: 0,
                reserved2: 0,
                tail: 0,
                index: 0,
                order: (section_rank(seg, name, flags), seen),
            });
            by_name.insert(key, sections.len() - 1);
            sections.len() - 1
        };

        // Input sections with something live in them, in input order.
        let mut stubs = None;
        if !self.stubs.is_empty() {
            let name: &[u8] = if arch == super::config::Arch::Arm64e {
                b"__auth_stubs"
            } else {
                b"__stubs"
            };
            let i = add(
                &mut sections,
                b"__TEXT",
                name,
                S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                Content::Stubs,
            );
            sections[i].align = arch::stub_align(arch);
            sections[i].reserved2 = arch::stub_size(arch) as u32;
            stubs = Some(i);
        }
        let mut assignments: Vec<(u32, u32, usize)> = Vec::new();
        for (oi, obj) in self.objs.iter().enumerate() {
            for (si, s) in obj.sections.iter().enumerate() {
                if matches!(
                    s.kind,
                    SecKind::Debug | SecKind::CompactUnwind | SecKind::Skip
                ) {
                    continue;
                }
                let any_live = obj.atoms[s.atoms.start as usize..s.atoms.end as usize]
                    .iter()
                    .any(|a| a.is_live() && a.flags & ATOM_DUPLICATE == 0);
                if !any_live {
                    continue;
                }
                let (seg, name) = output_name(cfg, s);
                let mut flags = s.flags & !(0x300 | S_ATTR_LIVE_SUPPORT | S_ATTR_NO_DEAD_STRIP);
                if s.kind == SecKind::NonLazyPointers {
                    flags = S_REGULAR;
                }
                let i = add(&mut sections, seg, name, flags, Content::Atoms);
                let o = &mut sections[i];
                if o.flags & SECTION_TYPE != flags & SECTION_TYPE
                    && o.flags & SECTION_TYPE == S_REGULAR
                {
                    o.flags = (o.flags & !SECTION_TYPE) | (flags & SECTION_TYPE);
                }
                o.flags |= flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS);
                o.chunks.push((oi as u32, si as u32));
                assignments.push((oi as u32, si as u32, i));
            }
        }
        for (oi, si, i) in assignments {
            self.objs[oi as usize].sections[si as usize].out = i as u32;
        }
        let data_seg: &[u8] = if data_const(cfg) {
            b"__DATA_CONST"
        } else {
            b"__DATA"
        };
        let mut auth_got = None;
        if !self.auth_got.is_empty() {
            let i = add(
                &mut sections,
                data_seg,
                b"__auth_got",
                S_NON_LAZY_SYMBOL_POINTERS,
                Content::AuthGot,
            );
            sections[i].align = 3;
            sections[i].size = self.auth_got.len() as u64 * 8;
            auth_got = Some(i);
        }
        let mut got = None;
        if !self.got.is_empty() {
            let i = add(
                &mut sections,
                data_seg,
                b"__got",
                S_NON_LAZY_SYMBOL_POINTERS,
                Content::Got,
            );
            sections[i].align = 3;
            got = Some(i);
        }
        let mut tlvp = None;
        if !self.tlvps.is_empty() {
            let i = add(
                &mut sections,
                b"__DATA",
                b"__thread_ptrs",
                S_THREAD_LOCAL_VARIABLE_POINTERS,
                Content::ThreadPtrs,
            );
            sections[i].align = 3;
            tlvp = Some(i);
        }
        // Common symbols follow whatever input sections already fill `__DATA,__common`.
        let mut common = None;
        if !self.commons.is_empty() {
            let i = add(
                &mut sections,
                b"__DATA",
                b"__common",
                S_ZEROFILL,
                Content::Atoms,
            );
            sections[i].align = sections[i].align.max(self.commons_align);
            common = Some(i);
        }
        let mut sectcreate = Vec::new();
        for (seg, sect, path) in &cfg.sectcreate {
            let data = std::fs::read(path)
                .map_err(|e| crate::err!("-sectcreate: cannot read {}: {e}", path.display()))?;
            let i = add(
                &mut sections,
                seg.as_bytes(),
                sect.as_bytes(),
                S_REGULAR,
                Content::Data(sectcreate.len()),
            );
            sections[i].size = data.len() as u64;
            sectcreate.push(data);
        }
        for (seg, sect) in &self.boundaries {
            if sect.is_empty() {
                continue;
            }
            add(&mut sections, seg, sect, S_REGULAR, Content::Empty);
        }
        let mut objc = None;
        if !self.objc_stubs.is_empty() {
            let st = add(
                &mut sections,
                b"__TEXT",
                b"__objc_stubs",
                S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                Content::ObjcStubs,
            );
            sections[st].align = if arch.is_arm() { 5 } else { 4 };
            sections[st].size = self.objc_stubs.len() as u64 * objc_stub_size(arch);
            let mn = add(
                &mut sections,
                b"__TEXT",
                b"__objc_methname",
                S_CSTRING_LITERALS,
                Content::Atoms,
            );
            let sr = add(
                &mut sections,
                b"__DATA",
                b"__objc_selrefs",
                S_LITERAL_POINTERS | S_ATTR_NO_DEAD_STRIP,
                Content::Atoms,
            );
            objc = Some((st, mn, sr));
        }
        let any_code = sections
            .iter()
            .any(|s| s.segname == b"__TEXT" && s.is_code());
        let unwind = if any_code {
            let i = add(
                &mut sections,
                b"__TEXT",
                b"__unwind_info",
                S_REGULAR,
                Content::UnwindInfo,
            );
            sections[i].align = 2;
            Some(i)
        } else {
            None
        };

        // Segments, in ld64's order.
        let mut seg_names: Vec<Vec<u8>> = Vec::new();
        if cfg.kind == OutputKind::Execute {
            seg_names.push(b"__PAGEZERO".to_vec());
        }
        seg_names.push(b"__TEXT".to_vec());
        for s in &sections {
            if !seg_names.contains(&s.segname) {
                seg_names.push(s.segname.clone());
            }
        }
        seg_names.push(b"__LINKEDIT".to_vec());
        let first_seen: HashMap<Vec<u8>, usize> = seg_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), i))
            .collect();
        seg_names.sort_by_key(|n| (segment_rank(n), first_seen[n]));

        let mut order: Vec<usize> = (0..sections.len()).collect();
        order.sort_by_key(|&i| {
            let s = &sections[i];
            (
                seg_names.iter().position(|n| *n == s.segname).unwrap(),
                s.order,
            )
        });
        // Renumber so that section indices are in address order.
        let mut remap = vec![0usize; sections.len()];
        let mut sorted: Vec<OutSection> = Vec::with_capacity(sections.len());
        let mut slots: Vec<Option<OutSection>> = sections.into_iter().map(Some).collect();
        for (new, &old) in order.iter().enumerate() {
            remap[old] = new;
            sorted.push(slots[old].take().unwrap());
        }
        let mut sections = sorted;
        for obj in &mut self.objs {
            for s in &mut obj.sections {
                if s.out != NONE {
                    s.out = remap[s.out as usize] as u32;
                }
            }
        }
        let fix = |o: Option<usize>| o.map(|i| remap[i]);
        let (stubs, got, tlvp, common, unwind) =
            (fix(stubs), fix(got), fix(tlvp), fix(common), fix(unwind));
        let auth_got = fix(auth_got);
        let objc = objc.map(|(a, b, c)| (remap[a], remap[b], remap[c]));
        let mut segments: Vec<Segment> = seg_names
            .iter()
            .map(|n| {
                let (prot, flags) = match n.as_slice() {
                    b"__PAGEZERO" => (0, 0),
                    b"__TEXT" => (VM_PROT_READ | VM_PROT_EXECUTE, 0),
                    b"__DATA_CONST" => (VM_PROT_READ | VM_PROT_WRITE, SG_READ_ONLY),
                    b"__LINKEDIT" => (VM_PROT_READ, 0),
                    _ => (VM_PROT_READ | VM_PROT_WRITE, 0),
                };
                Segment {
                    name: n.clone(),
                    vmaddr: 0,
                    vmsize: 0,
                    fileoff: 0,
                    filesize: 0,
                    maxprot: prot,
                    initprot: prot,
                    flags,
                    sections: Vec::new(),
                }
            })
            .collect();
        for (i, s) in sections.iter_mut().enumerate() {
            s.seg = segments.iter().position(|g| g.name == s.segname).unwrap();
            segments[s.seg].sections.push(i);
            s.index = (i + 1).min(255) as u8;
        }
        if sections.len() > 255 {
            bail!(
                "too many output sections ({}; Mach-O allows 255)",
                sections.len()
            );
        }

        // Atom offsets within each (object, section) chunk, in parallel.
        let chunk_info: Vec<Vec<(u64, u8)>> = self
            .objs
            .par_iter_mut()
            .map(|obj| {
                let mut info = vec![(0u64, 0u8); obj.sections.len()];
                for (si, s) in obj.sections.iter().enumerate() {
                    if s.out == NONE {
                        continue;
                    }
                    let mut off = 0u64;
                    let mut align = 0u8;
                    for a in &mut obj.atoms[s.atoms.start as usize..s.atoms.end as usize] {
                        if !a.is_live() || a.flags & ATOM_DUPLICATE != 0 {
                            continue;
                        }
                        off = align_up(off, 1 << a.align);
                        a.addr = off;
                        off += a.size as u64;
                        align = align.max(a.align);
                    }
                    info[si] = (off, align);
                }
                info
            })
            .collect();
        for s in sections.iter_mut().filter(|s| s.content == Content::Atoms) {
            let mut off = 0u64;
            let mut align = s.align;
            for &(oi, si) in &s.chunks {
                let (size, a) = chunk_info[oi as usize][si as usize];
                off = align_up(off, 1 << a);
                self.objs[oi as usize].sections[si as usize].out_off = off;
                off += size;
                align = align.max(a);
            }
            s.size = off;
            s.align = align;
        }
        let mut common_base = 0;
        if let Some(i) = common {
            let s = &mut sections[i];
            common_base = align_up(s.size, 1 << self.commons_align);
            s.size = common_base + self.commons_size;
            s.tail = s.size - common_base;
            s.align = s.align.max(self.commons_align);
        }
        let objc = objc.map(|(st, mn, sr)| {
            let names: u64 = self
                .objc_stubs
                .iter()
                .map(|(_, sel)| sel.len() as u64 + 1)
                .sum();
            let m = &mut sections[mn];
            let methname_base = m.size;
            m.size += names;
            m.tail = names;
            let r = &mut sections[sr];
            let selrefs_base = align_up(r.size, 8);
            r.size = selrefs_base + 8 * self.objc_stubs.len() as u64;
            r.tail = r.size - selrefs_base;
            r.align = r.align.max(3);
            ObjcLayout {
                stubs: st,
                methname: mn,
                methname_base,
                selrefs: sr,
                selrefs_base,
            }
        });
        if let Some(i) = stubs {
            sections[i].size = self.stubs.len() as u64 * arch::stub_size(arch);
        }
        if let Some(i) = got {
            sections[i].size = self.got.len() as u64 * 8;
        }
        if let Some(i) = tlvp {
            sections[i].size = self.tlvps.len() as u64 * 8;
        }
        // Indirect symbol table: stubs, then GOT, then TLV pointers.
        let mut indirect = 0u32;
        for (o, n) in [
            (stubs, self.stubs.len()),
            (got, self.got.len()),
            (tlvp, self.tlvps.len()),
            (auth_got, self.auth_got.len()),
        ] {
            if let Some(i) = o {
                sections[i].reserved1 = indirect;
                indirect += n as u32;
            }
        }

        // Load commands.
        let chained = use_chained_fixups(cfg, arch);
        let build_version = use_build_version(cfg);
        let signed = cfg.adhoc_codesign.unwrap_or(arch.is_arm());
        let dylib_cmds: Vec<u32> = {
            let mut v: Vec<u32> = (0..self.dylibs.len() as u32)
                .filter(|&d| self.dylibs[d as usize].ordinal != 0)
                .collect();
            v.sort_by_key(|&d| self.dylibs[d as usize].ordinal);
            v
        };
        let mut ncmds = 0u32;
        let mut size = 0u64;
        let mut cmd = |n: u64| {
            ncmds += 1;
            size += n;
        };
        for g in &segments {
            cmd(72 + 80 * g.sections.len() as u64);
        }
        if chained {
            cmd(16);
            cmd(16);
        } else {
            cmd(48);
        }
        cmd(24); // LC_SYMTAB
        cmd(80); // LC_DYSYMTAB
        match cfg.kind {
            OutputKind::Execute => cmd(align_up(12 + LC_DYLINKER_PATH.len() as u64 + 1, 8)),
            OutputKind::Dylib => cmd(dylib_cmd_size(&self.install_name())),
            OutputKind::Bundle => {}
        }
        if cfg.uuid != super::config::UuidMode::None {
            cmd(24);
        }
        cmd(if build_version { 32 } else { 16 });
        cmd(16); // LC_SOURCE_VERSION
        if cfg.kind == OutputKind::Execute {
            cmd(24); // LC_MAIN
        }
        if let Some(u) = &cfg.umbrella {
            cmd(align_up(12 + u.len() as u64 + 1, 8));
        }
        for c in &cfg.allowable_clients {
            cmd(align_up(12 + c.len() as u64 + 1, 8));
        }
        let mut install_names = 0u64;
        for &d in &dylib_cmds {
            let n = &self.dylibs[d as usize].install_name;
            install_names += n.len() as u64;
            cmd(dylib_cmd_size(n));
        }
        for r in &cfg.rpaths {
            cmd(align_up(12 + r.len() as u64 + 1, 8));
        }
        cmd(16); // LC_FUNCTION_STARTS
        cmd(16); // LC_DATA_IN_CODE
        if signed {
            cmd(16);
        }
        let mut headerpad = cfg.headerpad;
        if cfg.headerpad_max_install_names {
            headerpad =
                headerpad.max((dylib_cmds.len() as u64 * 1024).saturating_sub(install_names));
        }
        let header_end = 32 + size + headerpad;

        let image_base = match cfg.image_base {
            Some(b) => b,
            None if cfg.kind == OutputKind::Execute => cfg.pagezero_size.unwrap_or(0x1_0000_0000),
            None => 0,
        };
        let mut layout = Layout {
            segments,
            sections,
            image_base,
            page,
            sizeofcmds: size,
            ncmds,
            chained,
            signed,
            build_version,
            stubs,
            auth_got,
            got,
            tlvp,
            unwind,
            common,
            common_base,
            objc,
            unwind_plan: None,
            tlv_start: 0,
            linkedit: 0,
            dylib_cmds,
            sectcreate,
        };
        layout.linkedit = layout.segments.len() - 1;
        self.assign_addresses(&mut layout, header_end)?;
        if let Some(u) = layout.unwind {
            let plan = self.plan_unwind_info(&layout)?;
            layout.sections[u].size = plan.size;
            layout.unwind_plan = Some(plan);
            self.assign_addresses(&mut layout, header_end)?;
        }
        self.finalize_addresses(&layout);
        Ok(layout)
    }

    pub fn install_name(&self) -> String {
        match &self.cfg.install_name {
            Some(n) => n.clone(),
            None => self.cfg.output.display().to_string(),
        }
    }

    fn assign_addresses(&self, layout: &mut Layout, header_end: u64) -> Result<()> {
        let page = layout.page;
        let mut vm = 0u64;
        let mut file = 0u64;
        let nseg = layout.segments.len();
        for gi in 0..nseg {
            let name = layout.segments[gi].name.clone();
            if name == b"__PAGEZERO" {
                let g = &mut layout.segments[gi];
                g.vmaddr = 0;
                g.vmsize = layout.image_base;
                vm = layout.image_base;
                continue;
            }
            if name == b"__LINKEDIT" {
                let g = &mut layout.segments[gi];
                g.vmaddr = vm;
                g.fileoff = file;
                continue;
            }
            if name == b"__TEXT" && vm == 0 {
                vm = layout.image_base;
            }
            let seg_vm = vm;
            let seg_file = file;
            let mut addr = seg_vm;
            if name == b"__TEXT" {
                addr += header_end;
            }
            let mut file_end = addr;
            let secs = layout.segments[gi].sections.clone();
            for &si in &secs {
                let s = &mut layout.sections[si];
                addr = align_up(addr, 1 << s.align);
                s.addr = addr;
                if s.is_zerofill() {
                    s.file_off = 0;
                } else {
                    s.file_off = seg_file + (addr - seg_vm);
                    file_end = addr + s.size;
                }
                addr += s.size;
            }
            let g = &mut layout.segments[gi];
            g.vmaddr = seg_vm;
            g.fileoff = seg_file;
            g.vmsize = align_up(addr - seg_vm, page).max(if name == b"__TEXT" { page } else { 0 });
            g.filesize = align_up(file_end.max(seg_vm) - seg_vm, page);
            if name == b"__TEXT" {
                g.filesize = g.filesize.max(align_up(header_end, page));
            }
            vm = seg_vm + g.vmsize;
            file = seg_file + g.filesize;
        }
        if vm > u32::MAX as u64 + layout.image_base && self.arch.is_arm() && false {
            bail!("image too large");
        }
        layout.tlv_start = layout
            .sections
            .iter()
            .filter(|s| {
                matches!(
                    s.flags & SECTION_TYPE,
                    S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL
                )
            })
            .map(|s| s.addr)
            .min()
            .unwrap_or(0);
        Ok(())
    }

    /// The address of an atom while layout is still moving sections (atom offsets are relative).
    pub fn provisional_addr(&self, layout: &Layout, oi: u32, ai: u32) -> u64 {
        let obj = &self.objs[oi as usize];
        let a = &obj.atoms[ai as usize];
        if a.flags & ATOM_DUPLICATE != 0 {
            let (ro, ra) = self.lits[a.aux as usize];
            return self.provisional_addr(layout, ro, ra);
        }
        let s = &obj.sections[a.sec as usize];
        if s.out == NONE {
            return 0;
        }
        layout.sections[s.out as usize].addr + s.out_off + a.addr
    }

    fn finalize_addresses(&mut self, layout: &Layout) {
        let sections = &layout.sections;
        self.objs.par_iter_mut().for_each(|obj| {
            let outs: Vec<(u32, u64)> = obj.sections.iter().map(|s| (s.out, s.out_off)).collect();
            for a in &mut obj.atoms {
                if a.flags & ATOM_DUPLICATE != 0 {
                    continue;
                }
                let (out, off) = outs[a.sec as usize];
                if out != NONE && a.is_live() {
                    a.addr += sections[out as usize].addr + off;
                }
            }
        });
        // Duplicate literals take their twin's address.
        let lits: Vec<u64> = self
            .lits
            .iter()
            .map(|&(o, a)| self.objs[o as usize].atoms[a as usize].addr)
            .collect();
        self.objs.par_iter_mut().for_each(|obj| {
            for a in &mut obj.atoms {
                if a.flags & ATOM_DUPLICATE != 0 {
                    a.addr = lits[a.aux as usize];
                }
            }
        });
    }

    /// A symbol's address in the image, or `None` for imported ones.
    pub fn sym_addr(&self, layout: &Layout, id: super::symtab::SymId) -> Option<u64> {
        let s = self.symtab.get(id);
        Some(match s.def {
            Def::Defined { obj, atom, off } => {
                self.objs[obj as usize].atoms[atom as usize].addr + off as u64
            }
            Def::Absolute { value } => value,
            Def::Synthetic(Synthetic::Header) => layout.image_base,
            Def::Synthetic(Synthetic::ObjcStub(i)) => {
                layout.sections[layout.objc?.stubs].addr + i as u64 * objc_stub_size(self.arch)
            }
            Def::Synthetic(Synthetic::Common(i)) => {
                layout.sections[layout.common?].addr
                    + layout.common_base
                    + self.commons[i as usize].1
            }
            Def::Synthetic(Synthetic::SectionStart(i))
            | Def::Synthetic(Synthetic::SectionEnd(i)) => {
                let (seg, sect) = &self.boundaries[i as usize];
                let sec = layout.find_section(seg, sect)?;
                let s2 = &layout.sections[sec];
                if matches!(s.def, Def::Synthetic(Synthetic::SectionEnd(_))) {
                    s2.addr + s2.size
                } else {
                    s2.addr
                }
            }
            Def::Synthetic(Synthetic::SegmentStart(i))
            | Def::Synthetic(Synthetic::SegmentEnd(i)) => {
                let (seg, _) = &self.boundaries[i as usize];
                let g = layout.segments.iter().find(|g| &g.name == seg)?;
                if matches!(s.def, Def::Synthetic(Synthetic::SegmentEnd(_))) {
                    g.vmaddr + g.vmsize
                } else {
                    g.vmaddr
                }
            }
            _ => return None,
        })
    }
}
