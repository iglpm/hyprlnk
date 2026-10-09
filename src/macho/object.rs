//! Mach-O relocatable objects, borrowed from the input's bytes and split into atoms.
//!
//! An atom is the unit of dead stripping and placement: with `MH_SUBSECTIONS_VIA_SYMBOLS` a
//! section splits at every symbol; C strings and fixed-size literals split by content so they
//! can be deduplicated; `__eh_frame` splits into CIEs and FDEs.

use std::sync::atomic::{AtomicBool, Ordering};

use super::config::Arch;
use super::symtab::{SymId, hash_name};
use super::*;
use crate::diag::Result;
use crate::{bail, err};

pub const NONE: u32 = u32::MAX;
pub const SYM_EXT: u32 = 0x8000_0000;
pub const SYM_SLOW: u32 = 0x7fff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Object,
    Dylib,
    Fat,
    Archive,
    ThinArchive,
    Tbd,
    Bitcode,
    OtherMachO,
    Unknown,
}

pub fn identify(d: &[u8]) -> FileKind {
    if crate::archive::is_archive(d) {
        return FileKind::Archive;
    }
    if crate::archive::is_thin_archive(d) {
        return FileKind::ThinArchive;
    }
    if d.len() >= 4 {
        let m = u32le(d, 0);
        if m == MH_MAGIC_64 && d.len() >= 32 {
            return match u32le(d, 12) {
                MH_OBJECT => FileKind::Object,
                MH_DYLIB | MH_DYLIB_STUB => FileKind::Dylib,
                _ => FileKind::OtherMachO,
            };
        }
        if m == MH_MAGIC || m == MH_CIGAM_64 {
            return FileKind::OtherMachO;
        }
        let be = u32be(d, 0);
        if (be == FAT_MAGIC || be == FAT_MAGIC_64) && d.len() >= 8 && u32be(d, 4) < 64 {
            return FileKind::Fat;
        }
        if d.starts_with(b"BC\xC0\xDE") || d.starts_with(&[0xDE, 0xC0, 0x17, 0x0B]) {
            return FileKind::Bitcode;
        }
    }
    if super::tbd::is_tbd(d) {
        return FileKind::Tbd;
    }
    FileKind::Unknown
}

/// The slice of a universal file for `arch` (by CPU type; an exact subtype wins).
pub fn fat_slice(d: &[u8], arch: Arch) -> Result<&[u8]> {
    let wide = u32be(d, 0) == FAT_MAGIC_64;
    let n = u32be(d, 4) as usize;
    let entry = if wide { 32 } else { 20 };
    let mut best: Option<(&[u8], bool)> = None;
    let mut archs = Vec::new();
    for i in 0..n {
        let o = 8 + i * entry;
        if o + entry > d.len() {
            bail!("truncated universal header");
        }
        let cputype = u32be(d, o);
        let subtype = u32be(d, o + 4) & !CPU_SUBTYPE_MASK;
        let (off, size) = if wide {
            (
                u64::from_be_bytes(d[o + 8..o + 16].try_into().unwrap()) as usize,
                u64::from_be_bytes(d[o + 16..o + 24].try_into().unwrap()) as usize,
            )
        } else {
            (u32be(d, o + 8) as usize, u32be(d, o + 12) as usize)
        };
        if let Some(a) = Arch::from_cpu(cputype, subtype) {
            archs.push(a.name());
        }
        if cputype != arch.cputype() {
            continue;
        }
        let slice = d
            .get(off..off + size)
            .ok_or_else(|| err!("universal file slice runs past the end"))?;
        let exact = subtype == arch.cpusubtype() & !CPU_SUBTYPE_MASK;
        if best.is_none_or(|(_, e)| !e && exact) {
            best = Some((slice, exact));
        }
    }
    best.map(|(s, _)| s).ok_or_else(|| {
        err!(
            "universal file has no {} slice (it has {})",
            arch.name(),
            if archs.is_empty() {
                "none".to_string()
            } else {
                archs.join(", ")
            }
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecKind {
    Regular,
    ZeroFill,
    CString,
    Literal(u8),
    LiteralPointers,
    ThreadVars,
    ThreadData,
    ThreadBss,
    InitFuncs,
    TermFuncs,
    NonLazyPointers,
    CompactUnwind,
    EhFrame,
    Debug,
    Skip,
}

impl SecKind {
    pub fn is_zerofill(self) -> bool {
        matches!(self, SecKind::ZeroFill | SecKind::ThreadBss)
    }

    /// Split by content rather than by symbol, deduplicated across inputs.
    pub fn is_literal(self) -> bool {
        matches!(self, SecKind::CString | SecKind::Literal(_))
    }
}

pub struct Section<'a> {
    pub segname: &'a [u8],
    pub sectname: &'a [u8],
    pub addr: u64,
    pub size: u64,
    pub data: &'a [u8],
    pub align: u8,
    pub flags: u32,
    pub reserved1: u32,
    pub relocs: &'a [u8],
    pub kind: SecKind,
    pub atoms: std::ops::Range<u32>,
    /// Output section and offset in it, assigned by the layout.
    pub out: u32,
    pub out_off: u64,
}

impl Section<'_> {
    pub fn is_code(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    pub fn nrelocs(&self) -> usize {
        self.relocs.len() / 8
    }
}

pub const ATOM_NO_DEAD_STRIP: u8 = 1;
/// A literal whose identical twin elsewhere is the one written.
pub const ATOM_DUPLICATE: u8 = 2;
/// Starts at a symbol (a function or object) rather than at a section boundary or literal.
pub const ATOM_HAS_SYMBOL: u8 = 4;
/// An `__eh_frame` CIE.
pub const ATOM_CIE: u8 = 8;
/// An `__eh_frame` FDE.
pub const ATOM_FDE: u8 = 16;
pub const ATOM_ALT_ENTRY_INSIDE: u8 = 32;

pub struct Atom {
    pub off: u32,
    pub size: u32,
    pub sec: u32,
    pub align: u8,
    pub flags: u8,
    pub live: AtomicBool,
    pub rel_lo: u32,
    pub rel_hi: u32,
    /// Literal atoms: the index of their deduplicated string. Code atoms: their first
    /// compact-unwind entry. FDE atoms: their index in `fdes`.
    pub aux: u32,
    /// The output address, once laid out.
    pub addr: u64,
}

impl Atom {
    #[inline]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RawReloc {
    pub addr: u32,
    pub sym: u32,
    pub pcrel: bool,
    pub len: u8,
    pub ext: bool,
    pub ty: u8,
}

#[inline]
pub fn raw_reloc(d: &[u8], i: usize) -> RawReloc {
    let o = i * 8;
    let addr = u32le(d, o);
    let info = u32le(d, o + 4);
    RawReloc {
        addr,
        sym: info & 0x00ff_ffff,
        pcrel: info & (1 << 24) != 0,
        len: ((info >> 25) & 3) as u8,
        ext: info & (1 << 27) != 0,
        ty: (info >> 28) as u8,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Nlist {
    pub strx: u32,
    pub ty: u8,
    pub sect: u8,
    pub desc: u16,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    Defined {
        atom: u32,
        off: u32,
    },
    Absolute {
        value: u64,
    },
    Undefined,
    Common {
        size: u64,
        align: u8,
    },
    /// `N_INDR`: an alias for another symbol, by name.
    Indirect {
        target: u32,
    },
}

pub struct External<'a> {
    pub index: u32,
    pub name: &'a [u8],
    pub hash: u64,
    pub kind: ExtKind,
    pub desc: u16,
    pub private_extern: bool,
    /// The global id, when the symbol was already known while this object was parsed.
    pub id: SymId,
}

/// Where a reference leads: an external symbol (by its index in this object's symbol
/// table; `sym_ids` makes it global), or a place in this object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ref {
    Sym(u32),
    Atom { atom: u32, off: i64 },
    Abs(u64),
    None,
}

#[derive(Debug, Clone, Copy)]
pub struct CuEntry {
    pub atom: u32,
    pub off: u32,
    pub length: u32,
    pub encoding: u32,
    pub personality: Ref,
    pub lsda: Ref,
}

#[derive(Debug, Clone, Copy)]
pub struct Cie {
    pub atom: u32,
    pub fde_ptr_size: u8,
    pub lsda_ptr_size: u8,
    pub has_aug_data: bool,
    pub personality: Ref,
}

#[derive(Debug, Clone, Copy)]
pub struct Fde {
    pub atom: u32,
    pub cie: u32,
    pub func: Ref,
    /// The length of the code it describes.
    pub range: u32,
    pub lsda: Ref,
    pub lsda_field: u32,
}

pub struct ObjFile<'a> {
    pub name: String,
    pub arch: Option<Arch>,
    pub subsections: bool,
    pub sections: Vec<Section<'a>>,
    pub atoms: Vec<Atom>,
    pub nlist: &'a [u8],
    pub strtab: &'a [u8],
    pub sym_atom: Vec<u32>,
    /// Per symbol: `SYM_EXT` if external, and its offset in its atom when that's all a
    /// reference needs (`SYM_SLOW` otherwise: literals, eh_frame, absolute symbols).
    pub sym_info: Vec<u32>,
    pub sym_ids: Vec<SymId>,
    pub externals: Vec<External<'a>>,
    pub cu: Vec<CuEntry>,
    pub cies: Vec<Cie>,
    pub fdes: Vec<Fde>,
    /// (function atom, offset in it, FDE index), sorted. Functions start atoms unless the
    /// object lacks `MH_SUBSECTIONS_VIA_SYMBOLS` (hand-written assembly, often).
    pub fde_of: Vec<(u32, u32, u32)>,
    pub linker_options: Vec<Vec<String>>,
    pub data_in_code: &'a [u8],
    pub indirect: &'a [u8],
    pub platform: Option<(u32, u32)>,
    pub debug_info: Option<u16>,
    pub mtime: u64,
    pub from_archive: bool,
    pub has_objc: bool,
}

impl<'a> ObjFile<'a> {
    #[inline]
    pub fn nlist(&self, i: u32) -> Nlist {
        let o = i as usize * 16;
        let d = self.nlist;
        Nlist {
            strx: u32le(d, o),
            ty: d[o + 4],
            sect: d[o + 5],
            desc: u16le(d, o + 6),
            value: u64le(d, o + 8),
        }
    }

    pub fn nsyms(&self) -> usize {
        self.nlist.len() / 16
    }

    pub fn sym_name(&self, i: u32) -> &'a [u8] {
        if (i as usize) < self.nsyms() {
            cstr(self.strtab, self.nlist(i).strx as usize)
        } else {
            b"<bad symbol index>"
        }
    }

    pub fn parse(data: &'a [u8], name: String, from_archive: bool) -> Result<ObjFile<'a>> {
        parse(data, name, from_archive)
    }

    /// The atom containing `off` in section `sec`.
    pub fn atom_at(&self, sec: u32, off: u64) -> Option<u32> {
        let s = self.sections.get(sec as usize)?;
        let atoms = &self.atoms[s.atoms.start as usize..s.atoms.end as usize];
        if atoms.is_empty() {
            return None;
        }
        let i = atoms.partition_point(|a| a.off as u64 <= off);
        if i == 0 {
            return None;
        }
        Some(s.atoms.start + i as u32 - 1)
    }

    /// The section and atom holding object address `addr`.
    pub fn locate(&self, addr: u64) -> Option<(u32, u32, i64)> {
        for (i, s) in self.sections.iter().enumerate() {
            if addr >= s.addr && addr < s.addr + s.size.max(1) && !s.atoms.is_empty() {
                let atom = self.atom_at(i as u32, addr - s.addr)?;
                let off = (addr - s.addr) as i64 - self.atoms[atom as usize].off as i64;
                return Some((i as u32, atom, off));
            }
        }
        // One past the end of a section (a label at its end) belongs to its last atom.
        for (i, s) in self.sections.iter().enumerate() {
            if addr == s.addr + s.size && !s.atoms.is_empty() {
                let atom = s.atoms.end - 1;
                let off = (addr - s.addr) as i64 - self.atoms[atom as usize].off as i64;
                return Some((i as u32, atom, off));
            }
        }
        None
    }

    /// A local symbol plus addend, as a place in this object.
    pub fn local_ref(&self, idx: u32, addend: i64) -> Ref {
        if let Some(&info) = self.sym_info.get(idx as usize)
            && info & SYM_SLOW != SYM_SLOW
        {
            return Ref::Atom {
                atom: self.sym_atom[idx as usize],
                off: (info & SYM_SLOW) as i64 + addend,
            };
        }
        let s = self.nlist(idx);
        match s.ty & N_TYPE {
            N_SECT if s.sect > 0 => {
                let sec = (s.sect - 1) as u32;
                let Some(section) = self.sections.get(sec as usize) else {
                    return Ref::None;
                };
                if section.atoms.is_empty() {
                    return Ref::None;
                }
                let sec_off = s.value.wrapping_sub(section.addr) as i64;
                if section.kind.is_literal() || section.kind == SecKind::EhFrame {
                    let target = sec_off + addend;
                    match self.atom_at(sec, target.max(0) as u64) {
                        Some(a) => Ref::Atom {
                            atom: a,
                            off: target - self.atoms[a as usize].off as i64,
                        },
                        None => Ref::None,
                    }
                } else {
                    let a = self.sym_atom[idx as usize];
                    if a == NONE {
                        return Ref::None;
                    }
                    Ref::Atom {
                        atom: a,
                        off: sec_off - self.atoms[a as usize].off as i64 + addend,
                    }
                }
            }
            N_ABS => Ref::Abs((s.value as i64 + addend) as u64),
            _ => Ref::None,
        }
    }

    /// Object address `addr` in section `sec` (1-based, as non-extern relocations name it).
    pub fn section_ref(&self, sect1: u32, addr: u64) -> Ref {
        let Some(s) = self.sections.get(sect1.wrapping_sub(1) as usize) else {
            return Ref::None;
        };
        let off = addr.wrapping_sub(s.addr);
        let sec = sect1 - 1;
        let atom = if off >= s.size && s.size > 0 && !s.atoms.is_empty() {
            Some(s.atoms.end - 1)
        } else {
            self.atom_at(sec, off)
        };
        match atom {
            Some(a) => Ref::Atom {
                atom: a,
                off: off as i64 - self.atoms[a as usize].off as i64,
            },
            None => Ref::None,
        }
    }

    /// An extern relocation's target: external symbols stay symbols (the addend is separate);
    /// local ones become a place in this object with the addend folded in.
    pub fn sym_ref(&self, idx: u32, addend: i64) -> (Ref, i64) {
        let ext = match self.sym_info.get(idx as usize) {
            Some(&info) => info & SYM_EXT != 0,
            None => (idx as usize) < self.nsyms() && self.nlist(idx).ty & N_EXT != 0,
        };
        if ext {
            (Ref::Sym(idx), addend)
        } else {
            (self.local_ref(idx, addend), 0)
        }
    }

    /// The global symbol an external symbol index resolved to.
    #[inline]
    pub fn global(&self, idx: u32) -> SymId {
        self.sym_ids.get(idx as usize).copied().unwrap_or(NONE)
    }
}

fn kind_of(segname: &[u8], sectname: &[u8], flags: u32) -> SecKind {
    if flags & S_ATTR_DEBUG != 0 {
        if segname == b"__LD" && sectname == b"__compact_unwind" {
            return SecKind::CompactUnwind;
        }
        return SecKind::Debug;
    }
    if segname == b"__DWARF" {
        return SecKind::Debug;
    }
    if segname == b"__LD" && sectname == b"__compact_unwind" {
        return SecKind::CompactUnwind;
    }
    if segname == b"__TEXT" && sectname == b"__eh_frame" {
        return SecKind::EhFrame;
    }
    if segname == b"__LLVM" {
        return SecKind::Skip;
    }
    match flags & SECTION_TYPE {
        S_ZEROFILL | S_GB_ZEROFILL => SecKind::ZeroFill,
        S_CSTRING_LITERALS => SecKind::CString,
        S_4BYTE_LITERALS => SecKind::Literal(4),
        S_8BYTE_LITERALS => SecKind::Literal(8),
        S_16BYTE_LITERALS => SecKind::Literal(16),
        S_LITERAL_POINTERS => SecKind::LiteralPointers,
        S_THREAD_LOCAL_VARIABLES => SecKind::ThreadVars,
        S_THREAD_LOCAL_REGULAR => SecKind::ThreadData,
        S_THREAD_LOCAL_ZEROFILL => SecKind::ThreadBss,
        S_MOD_INIT_FUNC_POINTERS => SecKind::InitFuncs,
        S_MOD_TERM_FUNC_POINTERS => SecKind::TermFuncs,
        S_NON_LAZY_SYMBOL_POINTERS => SecKind::NonLazyPointers,
        _ => SecKind::Regular,
    }
}

fn parse<'a>(data: &'a [u8], name: String, from_archive: bool) -> Result<ObjFile<'a>> {
    if data.len() < 32 || u32le(data, 0) != MH_MAGIC_64 {
        bail!("{name}: not a 64-bit Mach-O object");
    }
    let cputype = u32le(data, 4);
    let cpusubtype = u32le(data, 8);
    let ncmds = u32le(data, 16) as usize;
    let flags = u32le(data, 24);
    let mut obj = ObjFile {
        name,
        arch: Arch::from_cpu(cputype, cpusubtype),
        subsections: flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0,
        sections: Vec::new(),
        atoms: Vec::new(),
        nlist: &[],
        strtab: &[],
        sym_atom: Vec::new(),
        sym_info: Vec::new(),
        sym_ids: Vec::new(),
        externals: Vec::new(),
        cu: Vec::new(),
        cies: Vec::new(),
        fdes: Vec::new(),
        fde_of: Vec::new(),
        linker_options: Vec::new(),
        data_in_code: &[],
        indirect: &[],
        platform: None,
        debug_info: None,
        mtime: 0,
        from_archive,
        has_objc: false,
    };
    if obj.arch.is_none() {
        bail!("{}: unsupported CPU type {cputype:#x}", obj.name);
    }
    let bad = |what: &str| err!("{}: malformed object: {what}", obj.name);
    let mut off = 32usize;
    for _ in 0..ncmds {
        if off + 8 > data.len() {
            return Err(bad("load commands run past the end"));
        }
        let cmd = u32le(data, off);
        let size = u32le(data, off + 4) as usize;
        if size < 8 || off + size > data.len() {
            return Err(bad("bad load command size"));
        }
        let lc = &data[off..off + size];
        match cmd {
            LC_SEGMENT_64 => {
                let nsects = u32le(lc, 64) as usize;
                if 72 + nsects * 80 > size {
                    return Err(bad("segment command too small"));
                }
                for i in 0..nsects {
                    let h = &lc[72 + i * 80..72 + (i + 1) * 80];
                    let segname = name16(&h[16..32]);
                    let sectname = name16(&h[0..16]);
                    let addr = u64le(h, 32);
                    let size = u64le(h, 40);
                    let foff = u32le(h, 48) as usize;
                    let align = u32le(h, 52);
                    let reloff = u32le(h, 56) as usize;
                    let nreloc = u32le(h, 60) as usize;
                    let sflags = u32le(h, 64);
                    let kind = kind_of(segname, sectname, sflags);
                    let sdata: &[u8] = if kind.is_zerofill() || size == 0 {
                        &[]
                    } else {
                        data.get(foff..foff + size as usize).ok_or_else(|| {
                            bad(&format!(
                                "section {} runs past the end of the file",
                                String::from_utf8_lossy(sectname)
                            ))
                        })?
                    };
                    let relocs = data
                        .get(reloff..reloff + nreloc * 8)
                        .ok_or_else(|| bad("relocations run past the end of the file"))?;
                    if segname == b"__DATA" && sectname.starts_with(b"__objc_") {
                        obj.has_objc = true;
                    }
                    obj.sections.push(Section {
                        segname,
                        sectname,
                        addr,
                        size,
                        data: sdata,
                        align: align.min(31) as u8,
                        flags: sflags,
                        reserved1: u32le(h, 68),
                        relocs,
                        kind,
                        atoms: 0..0,
                        out: NONE,
                        out_off: 0,
                    });
                }
            }
            LC_SYMTAB => {
                let symoff = u32le(lc, 8) as usize;
                let nsyms = u32le(lc, 12) as usize;
                let stroff = u32le(lc, 16) as usize;
                let strsize = u32le(lc, 20) as usize;
                obj.nlist = data
                    .get(symoff..symoff + nsyms * 16)
                    .ok_or_else(|| bad("symbol table runs past the end"))?;
                obj.strtab = data
                    .get(stroff..stroff + strsize)
                    .ok_or_else(|| bad("string table runs past the end"))?;
            }
            LC_DYSYMTAB => {
                let indoff = u32le(lc, 56) as usize;
                let nind = u32le(lc, 60) as usize;
                obj.indirect = data.get(indoff..indoff + nind * 4).unwrap_or(&[]);
            }
            LC_DATA_IN_CODE => {
                let o = u32le(lc, 8) as usize;
                let n = u32le(lc, 12) as usize;
                obj.data_in_code = data.get(o..o + n).unwrap_or(&[]);
            }
            LC_BUILD_VERSION => {
                obj.platform = Some((u32le(lc, 8), u32le(lc, 12)));
            }
            LC_VERSION_MIN_MACOSX => obj.platform = Some((PLATFORM_MACOS, u32le(lc, 8))),
            LC_VERSION_MIN_IPHONEOS => obj.platform = Some((PLATFORM_IOS, u32le(lc, 8))),
            LC_VERSION_MIN_TVOS => obj.platform = Some((PLATFORM_TVOS, u32le(lc, 8))),
            LC_VERSION_MIN_WATCHOS => obj.platform = Some((PLATFORM_WATCHOS, u32le(lc, 8))),
            LC_LINKER_OPTION => {
                let count = u32le(lc, 8) as usize;
                let mut p = 12;
                let mut opts = Vec::with_capacity(count);
                for _ in 0..count {
                    let s = cstr(lc, p);
                    p += s.len() + 1;
                    opts.push(String::from_utf8_lossy(s).into_owned());
                }
                obj.linker_options.push(opts);
            }
            _ => {}
        }
        off += size;
    }
    for (i, s) in obj.sections.iter().enumerate() {
        if s.segname == b"__DWARF" && s.sectname == b"__debug_info" && s.size > 0 {
            obj.debug_info = Some(i as u16);
        }
    }
    split_atoms(&mut obj)?;
    super::unwind::parse_compact_unwind(&mut obj)?;
    super::unwind::parse_eh_frame(&mut obj)?;
    Ok(obj)
}

/// Section offsets of the symbols defined in each section, for splitting and lookups.
fn split_atoms(obj: &mut ObjFile) -> Result<()> {
    let nsyms = obj.nsyms();
    let nsect = obj.sections.len();
    obj.sym_atom = vec![NONE; nsyms];
    obj.sym_ids = vec![NONE; nsyms];
    // (section, offset, symbol index, alt entry)
    let mut by_sect: Vec<Vec<(u64, u32, bool)>> = vec![Vec::new(); nsect];
    let mut nexternal = 0;
    for i in 0..nsyms as u32 {
        let s = obj.nlist(i);
        if s.ty & N_STAB != 0 {
            continue;
        }
        if s.ty & N_EXT != 0 {
            nexternal += 1;
        }
        if s.ty & N_TYPE == N_SECT {
            let sec = s.sect as usize;
            if sec == 0 || sec > nsect {
                bail!(
                    "{}: symbol {} is in section {sec}, which doesn't exist",
                    obj.name,
                    String::from_utf8_lossy(obj.sym_name(i))
                );
            }
            let section = &obj.sections[sec - 1];
            let off = s.value.wrapping_sub(section.addr);
            by_sect[sec - 1].push((off, i, s.desc & N_ALT_ENTRY != 0));
        }
    }
    obj.externals.reserve(nexternal);

    let mut atoms: Vec<Atom> = Vec::with_capacity(nsyms + nsect);
    for (si, syms) in by_sect.iter_mut().enumerate() {
        let start = atoms.len() as u32;
        let s = &obj.sections[si];
        syms.sort_unstable_by_key(|&(off, idx, _)| (off, idx));
        let sec_align = s.align;
        let size = s.size;
        let mk = |off: u64, end: u64, flags: u8| Atom {
            off: off as u32,
            size: (end - off) as u32,
            sec: si as u32,
            align: sec_align.min(if off == 0 {
                31
            } else {
                off.trailing_zeros().min(31) as u8
            }),
            flags,
            live: AtomicBool::new(false),
            rel_lo: 0,
            rel_hi: 0,
            aux: NONE,
            addr: 0,
        };
        match s.kind {
            SecKind::Debug | SecKind::CompactUnwind | SecKind::Skip => {}
            SecKind::CString => {
                let d = s.data;
                let mut p = 0usize;
                while p < d.len() {
                    let end = match memchr0(&d[p..]) {
                        Some(n) => p + n + 1,
                        None => d.len(),
                    };
                    let mut a = mk(p as u64, end as u64, 0);
                    // Strings keep the section's alignment only where it starts; ld64 aligns
                    // each to the section's alignment when it is more than 1.
                    a.align = sec_align;
                    atoms.push(a);
                    p = end;
                }
            }
            SecKind::Literal(n) => {
                let n = n as u64;
                if !size.is_multiple_of(n) {
                    bail!(
                        "{}: literal section {} is not a multiple of {n} bytes",
                        obj.name,
                        String::from_utf8_lossy(s.sectname)
                    );
                }
                let mut p = 0;
                while p < size {
                    let mut a = mk(p, p + n, 0);
                    a.align = sec_align.max(n.trailing_zeros() as u8);
                    atoms.push(a);
                    p += n;
                }
            }
            SecKind::LiteralPointers | SecKind::NonLazyPointers => {
                let mut p = 0;
                while p < size {
                    atoms.push(mk(p, (p + 8).min(size), 0));
                    p += 8;
                }
            }
            SecKind::EhFrame => {
                let d = s.data;
                let mut p = 0usize;
                while p + 4 <= d.len() {
                    let len = u32le(d, p) as usize;
                    if len == 0xffff_ffff {
                        bail!("{}: 64-bit DWARF in __eh_frame is not supported", obj.name);
                    }
                    let end = (p + 4 + len).min(d.len());
                    if len == 0 {
                        break;
                    }
                    let id = if p + 8 <= d.len() { u32le(d, p + 4) } else { 0 };
                    let flag = if id == 0 { ATOM_CIE } else { ATOM_FDE };
                    let mut a = mk(p as u64, end as u64, flag);
                    // Records follow each other with no gap: padding would read as the
                    // zero-length terminator that ends a scan of the section.
                    a.align = 2;
                    atoms.push(a);
                    p = end;
                }
            }
            _ => {
                let split =
                    obj.subsections && !matches!(s.kind, SecKind::InitFuncs | SecKind::TermFuncs);
                let mut cur = 0u64;
                let mut has_sym = syms.first().is_some_and(|&(o, _, _)| o == 0);
                for &(off, _, alt) in syms.iter() {
                    if !split || alt || off <= cur || off >= size {
                        continue;
                    }
                    let f = if has_sym { ATOM_HAS_SYMBOL } else { 0 };
                    atoms.push(mk(cur, off, f));
                    cur = off;
                    has_sym = true;
                }
                if size > cur || atoms.len() as u32 == start {
                    let f = if has_sym { ATOM_HAS_SYMBOL } else { 0 };
                    atoms.push(mk(cur, size.max(cur), f));
                }
            }
        }
        let end = atoms.len() as u32;
        obj.sections[si].atoms = start..end;
    }
    obj.atoms = atoms;

    // Map every section symbol to its atom.
    let mut alt_inside = Vec::new();
    for (si, syms) in by_sect.iter().enumerate() {
        let range = obj.sections[si].atoms.clone();
        if range.is_empty() {
            continue;
        }
        let atoms = &obj.atoms[range.start as usize..range.end as usize];
        let mut k = 0usize;
        for &(off, idx, alt) in syms.iter() {
            while k + 1 < atoms.len() && atoms[k + 1].off as u64 <= off {
                k += 1;
            }
            let a = range.start + k as u32;
            obj.sym_atom[idx as usize] = a;
            if alt && off != atoms[k].off as u64 {
                alt_inside.push(a);
            }
        }
    }
    for a in alt_inside {
        obj.atoms[a as usize].flags |= ATOM_ALT_ENTRY_INSIDE;
    }
    obj.sym_info = (0..nsyms as u32)
        .map(|i| {
            let s = obj.nlist(i);
            let ext = if s.ty & N_EXT != 0 && s.ty & N_STAB == 0 {
                SYM_EXT
            } else {
                0
            };
            let a = obj.sym_atom[i as usize];
            if a == NONE || s.ty & N_STAB != 0 || s.ty & N_TYPE != N_SECT {
                return ext | SYM_SLOW;
            }
            let at = &obj.atoms[a as usize];
            let sec = &obj.sections[at.sec as usize];
            let off = s.value.wrapping_sub(sec.addr).wrapping_sub(at.off as u64);
            if sec.kind.is_literal() || sec.kind == SecKind::EhFrame || off >= SYM_SLOW as u64 {
                ext | SYM_SLOW
            } else {
                ext | off as u32
            }
        })
        .collect();

    // No-dead-strip marks, from the section or the symbol.
    for si in 0..nsect {
        let s = &obj.sections[si];
        if s.flags & S_ATTR_NO_DEAD_STRIP != 0
            || matches!(s.kind, SecKind::InitFuncs | SecKind::TermFuncs)
        {
            for a in s.atoms.clone() {
                obj.atoms[a as usize].flags |= ATOM_NO_DEAD_STRIP;
            }
        }
    }
    for i in 0..nsyms as u32 {
        let s = obj.nlist(i);
        if s.ty & N_STAB == 0
            && s.ty & N_TYPE == N_SECT
            && s.desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0
        {
            let a = obj.sym_atom[i as usize];
            if a != NONE {
                obj.atoms[a as usize].flags |= ATOM_NO_DEAD_STRIP;
            }
        }
    }

    assign_relocs(obj)?;

    // Externals, with names hashed here, on the parsing thread.
    for i in 0..nsyms as u32 {
        let s = obj.nlist(i);
        if s.ty & N_STAB != 0 || s.ty & N_EXT == 0 {
            continue;
        }
        let name = cstr(obj.strtab, s.strx as usize);
        let kind = match s.ty & N_TYPE {
            N_UNDF if s.value != 0 => ExtKind::Common {
                size: s.value,
                align: ((s.desc >> 8) & 0xf) as u8,
            },
            N_UNDF => ExtKind::Undefined,
            N_ABS => ExtKind::Absolute { value: s.value },
            N_SECT => {
                let a = obj.sym_atom[i as usize];
                if a == NONE {
                    // In a section that isn't linked (debug info): nothing can refer to it.
                    continue;
                }
                let sec = &obj.sections[s.sect as usize - 1];
                let off = s.value - sec.addr - obj.atoms[a as usize].off as u64;
                ExtKind::Defined {
                    atom: a,
                    off: off as u32,
                }
            }
            N_INDR => ExtKind::Indirect {
                target: s.value as u32,
            },
            _ => ExtKind::Undefined,
        };
        obj.externals.push(External {
            index: i,
            name,
            hash: hash_name(name),
            kind,
            desc: s.desc,
            private_extern: s.ty & N_PEXT != 0,
            id: NONE,
        });
    }
    Ok(())
}

/// Give every atom the range of its section's relocations. LLVM writes them in descending
/// address order; any monotonic order keeps each atom's relocations contiguous, and pairs
/// (SUBTRACTOR/UNSIGNED, ADDEND/x) share an address, so they stay together.
fn assign_relocs(obj: &mut ObjFile) -> Result<()> {
    for si in 0..obj.sections.len() {
        let s = &obj.sections[si];
        let n = s.nrelocs();
        if n == 0 || s.atoms.is_empty() {
            continue;
        }
        let rel = s.relocs;
        let addr = |i: usize| u32le(rel, i * 8);
        if (0..n).any(|i| addr(i) & 0x8000_0000 != 0) {
            bail!("{}: scattered relocations are not supported", obj.name);
        }
        let desc = (1..n).all(|i| addr(i - 1) >= addr(i));
        let asc = !desc && (1..n).all(|i| addr(i - 1) <= addr(i));
        if !desc && !asc {
            // Rare (hand-written assembly): reorder a copy, keeping pairs in their order.
            let mut idx: Vec<usize> = (0..n).collect();
            idx.sort_by_key(|&i| std::cmp::Reverse(addr(i)));
            let mut sorted = Vec::with_capacity(rel.len());
            for i in idx {
                sorted.extend_from_slice(&rel[i * 8..i * 8 + 8]);
            }
            obj.sections[si].relocs = Box::leak(sorted.into_boxed_slice());
        }
        let desc = desc || !asc;
        let s = &obj.sections[si];
        let rel = s.relocs;
        let addr = |i: usize| u32le(rel, i * 8);
        let range = s.atoms.clone();
        let mut r = 0usize;
        if desc {
            for ai in range.clone().rev() {
                let lo = obj.atoms[ai as usize].off;
                let begin = r;
                while r < n && (addr(r) >= lo || ai == range.start) {
                    r += 1;
                }
                let a = &mut obj.atoms[ai as usize];
                a.rel_lo = begin as u32;
                a.rel_hi = r as u32;
            }
        } else {
            for ai in range.clone() {
                let a = &obj.atoms[ai as usize];
                let hi = a.off as u64 + a.size as u64;
                let begin = r;
                while r < n && ((addr(r) as u64) < hi || ai + 1 == range.end) {
                    r += 1;
                }
                let a = &mut obj.atoms[ai as usize];
                a.rel_lo = begin as u32;
                a.rel_hi = r as u32;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_files() {
        assert_eq!(identify(b"!<arch>\nxxxx"), FileKind::Archive);
        let mut obj = vec![0u8; 32];
        obj[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        obj[12..16].copy_from_slice(&MH_OBJECT.to_le_bytes());
        assert_eq!(identify(&obj), FileKind::Object);
        obj[12..16].copy_from_slice(&MH_DYLIB.to_le_bytes());
        assert_eq!(identify(&obj), FileKind::Dylib);
        assert_eq!(identify(b"--- !tapi-tbd\n"), FileKind::Tbd);
        let mut fat = vec![0u8; 8];
        fat[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(identify(&fat), FileKind::Fat);
    }

    #[test]
    fn decodes_relocations() {
        // address 0x10, symbol 5, pcrel, length 2, extern, type 2 (BRANCH26)
        let info: u32 = 5 | (1 << 24) | (2 << 25) | (1 << 27) | (2 << 28);
        let mut d = Vec::new();
        d.extend_from_slice(&0x10u32.to_le_bytes());
        d.extend_from_slice(&info.to_le_bytes());
        let r = raw_reloc(&d, 0);
        assert_eq!(
            (r.addr, r.sym, r.pcrel, r.len, r.ext, r.ty),
            (0x10, 5, true, 2, true, 2)
        );
    }
}
