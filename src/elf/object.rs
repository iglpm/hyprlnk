//! Relocatable objects and shared objects, parsed in place. Section headers become compact
//! [`Sec`] records; symbols and relocations are decoded from the raw tables when needed.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::target::{Rel, Target, rd16, rd32, rdw};
use super::*;
use crate::diag::Result;
use crate::{bail, err};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecKind {
    /// Not copied to the output (relocations, symbol tables, groups, notes we drop).
    Ignore,
    Alloc,
    NonAlloc,
    /// SHF_MERGE contents, split and deduplicated.
    Merge,
    EhFrame,
    /// `.ARM.exidx`: linked to a code section, sorted by it.
    Exidx,
    /// Dropped: a COMDAT group that lost, or a section that failed `--gc-sections`.
    Discarded,
}

/// One input section. `addr` is the output address once laid out (for non-allocated
/// sections: the offset in the output file).
pub struct Sec {
    pub addr: u64,
    pub offset: u32,
    pub size: u32,
    pub out: u32,
    /// The relocations of this section: their offset and length in the file (0: none);
    /// [`FL_RELA`] tells their format.
    pub rel_off: u32,
    pub rel_len: u32,
    /// From the section header, kept so later passes don't read it again: the name's offset in
    /// the section name table, the type, and the flags (all defined ones fit in 32 bits).
    pub name: u32,
    pub ty: u32,
    pub flags: u32,
    /// Dynamic relocations this section emits: relative ones, and the rest. After layout,
    /// the index of its first one of each kind in its file's share.
    pub nrel: u32,
    pub nsym: u32,
    /// Kind-specific: the merge record for [`SecKind::Merge`].
    pub aux: u32,
    pub kind: SecKind,
    pub p2align: u8,
    pub live: AtomicBool,
    /// SHF_WRITE, SHF_EXECINSTR, SHF_TLS folded into bits 0..3.
    pub fl: u8,
}

pub const FL_WRITE: u8 = 1;
pub const FL_EXEC: u8 = 2;
pub const FL_TLS: u8 = 4;
pub const FL_NOBITS: u8 = 8;
/// The relocations are SHT_RELA (else SHT_REL).
pub const FL_RELA: u8 = 16;
/// Compressed in the file (SHF_COMPRESSED); `size` is the uncompressed size and the data is in
/// [`Object::inflated`] once decompressed.
pub const FL_COMPRESSED: u8 = 32;

/// `ch_type` of a compressed section.
pub const ELFCOMPRESS_ZLIB: u32 = 1;
pub const ELFCOMPRESS_ZSTD: u32 = 2;

impl Sec {
    #[inline]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn align(&self) -> u64 {
        1 << self.p2align
    }

    #[inline]
    pub fn has(&self, flags: u64) -> bool {
        self.flags as u64 & flags != 0
    }
}

/// A raw section header, decoded.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shdr {
    pub name: u32,
    pub ty: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Sym {
    pub name: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u32,
}

impl Sym {
    #[inline]
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
    #[inline]
    pub fn ty(&self) -> u8 {
        self.info & 0xf
    }
    #[inline]
    pub fn vis(&self) -> u8 {
        self.other & 3
    }
    #[inline]
    pub fn is_undef(&self) -> bool {
        self.shndx == SHN_UNDEF
    }
    #[inline]
    pub fn is_common(&self) -> bool {
        self.shndx == SHN_COMMON || self.ty() == STT_COMMON && self.shndx != SHN_UNDEF
    }
    #[inline]
    pub fn is_abs(&self) -> bool {
        self.shndx == SHN_ABS
    }
}

pub struct Group<'a> {
    pub signature: &'a [u8],
    pub members: Vec<u32>,
}

pub struct Object<'a> {
    pub name: String,
    pub data: &'a [u8],
    pub prio: u32,
    pub member: bool,
    pub alive: AtomicBool,
    pub shdr_off: usize,
    pub shstrtab: &'a [u8],
    pub secs: Vec<Sec>,
    pub symtab: &'a [u8],
    pub strtab: &'a [u8],
    pub shndx_table: &'a [u8],
    pub nsyms: u32,
    pub first_global: u32,
    /// Global symbol ids, by `index - first_global`.
    pub sym_ids: Vec<AtomicU32>,
    pub groups: Vec<Group<'a>>,
    pub eh_frames: Vec<u32>,
    pub exec_stack: bool,
    /// Local symbols that need GOT entries or similar: (index, flags).
    pub local_needs: Mutex<Vec<(u32, u32)>>,
    /// Compressed sections: (section, offset and length of the compressed data, `ch_type`).
    pub compressed: Vec<(u32, u32, u32, u32)>,
    /// Their uncompressed contents, by section, once decompressed (loaded files only).
    pub inflated: Vec<(u32, &'a [u8])>,
    /// With `--gc-sections`, sections are scanned as they are marked: (section, dynamic
    /// relocations: relative ones, the rest), for the sections that emit any.
    pub scanned: Mutex<Vec<(u32, u32, u32)>>,
    pub e_flags: u32,
    /// Has SHF_MERGE sections (searched only then).
    pub has_merge: bool,
    pub compressed_debug: bool,
    /// `.riscv.attributes` / `.ARM.attributes`, kept from the first object that has them.
    pub attributes: u32,
}

/// A NUL-terminated name, compared without finding its end first.
#[derive(Clone, Copy)]
pub struct NameAt<'n>(pub &'n [u8]);

impl NameAt<'_> {
    #[inline]
    pub fn is(&self, s: &[u8]) -> bool {
        self.0.len() > s.len() && self.0.starts_with(s) && self.0[s.len()] == 0
    }
}

pub fn shdr<T: Target>(d: &[u8], off: usize) -> Shdr {
    if T::IS64 {
        Shdr {
            name: rd32::<T>(d, off),
            ty: rd32::<T>(d, off + 4),
            flags: rdw::<T>(d, off + 8),
            addr: rdw::<T>(d, off + 16),
            offset: rdw::<T>(d, off + 24),
            size: rdw::<T>(d, off + 32),
            link: rd32::<T>(d, off + 40),
            info: rd32::<T>(d, off + 44),
            align: rdw::<T>(d, off + 48),
            entsize: rdw::<T>(d, off + 56),
        }
    } else {
        Shdr {
            name: rd32::<T>(d, off),
            ty: rd32::<T>(d, off + 4),
            flags: rd32::<T>(d, off + 8) as u64,
            addr: rd32::<T>(d, off + 12) as u64,
            offset: rd32::<T>(d, off + 16) as u64,
            size: rd32::<T>(d, off + 20) as u64,
            link: rd32::<T>(d, off + 24),
            info: rd32::<T>(d, off + 28),
            align: rd32::<T>(d, off + 32) as u64,
            entsize: rd32::<T>(d, off + 36) as u64,
        }
    }
}

pub fn shdr_size<T: Target>() -> usize {
    if T::IS64 { 64 } else { 40 }
}

pub fn sym_size<T: Target>() -> usize {
    if T::IS64 { 24 } else { 16 }
}

#[inline]
pub fn read_sym<T: Target>(tab: &[u8], i: usize) -> Sym {
    if T::IS64 {
        let b = &tab[i * 24..i * 24 + 24];
        Sym {
            name: rd32::<T>(b, 0),
            info: b[4],
            other: b[5],
            shndx: rd16::<T>(b, 6) as u32,
            value: rdw::<T>(b, 8),
            size: rdw::<T>(b, 16),
        }
    } else {
        let b = &tab[i * 16..i * 16 + 16];
        Sym {
            name: rd32::<T>(b, 0),
            value: rd32::<T>(b, 4) as u64,
            size: rd32::<T>(b, 8) as u64,
            info: b[12],
            other: b[13],
            shndx: rd16::<T>(b, 14) as u32,
        }
    }
}

/// The ELF header fields every parser needs: (section header offset, count, shstrndx).
fn section_table<T: Target>(d: &[u8], name: &str) -> Result<(usize, u32, u32)> {
    let ehsize = if T::IS64 { 64 } else { 52 };
    if d.len() < ehsize {
        bail!("{name}: truncated ELF header");
    }
    let (shoff, shentsize, shnum, shstrndx) = if T::IS64 {
        (
            rdw::<T>(d, 0x28) as usize,
            rd16::<T>(d, 0x3a) as usize,
            rd16::<T>(d, 0x3c) as u32,
            rd16::<T>(d, 0x3e) as u32,
        )
    } else {
        (
            rd32::<T>(d, 0x20) as usize,
            rd16::<T>(d, 0x2e) as usize,
            rd16::<T>(d, 0x30) as u32,
            rd16::<T>(d, 0x32) as u32,
        )
    };
    if shoff == 0 {
        return Ok((0, 0, 0));
    }
    if shentsize != shdr_size::<T>() {
        bail!("{name}: unexpected section header size {shentsize}");
    }
    if shoff + shdr_size::<T>() > d.len() {
        bail!("{name}: section headers past the end of the file");
    }
    let first = shdr::<T>(d, shoff);
    let shnum = if shnum == 0 { first.size as u32 } else { shnum };
    let shstrndx = if shstrndx == SHN_XINDEX {
        first.link
    } else {
        shstrndx
    };
    if shoff + shnum as usize * shdr_size::<T>() > d.len() {
        bail!("{name}: section headers past the end of the file");
    }
    Ok((shoff, shnum, shstrndx))
}

/// A compressed section's header: (`ch_type`, uncompressed size, alignment).
fn chdr<T: Target>(d: &[u8], off: u64, size: u64) -> Option<(u32, u64, u64)> {
    let off = off as usize;
    let hdr = if T::IS64 { 24 } else { 12 };
    if size < hdr as u64 || off.checked_add(hdr)? > d.len() {
        return None;
    }
    Some(if T::IS64 {
        (
            rd32::<T>(d, off),
            rdw::<T>(d, off + 8),
            rdw::<T>(d, off + 16),
        )
    } else {
        (
            rd32::<T>(d, off),
            rd32::<T>(d, off + 4) as u64,
            rd32::<T>(d, off + 8) as u64,
        )
    })
}

fn slice<'a>(d: &'a [u8], off: u64, size: u64, name: &str, what: &str) -> Result<&'a [u8]> {
    let end = off
        .checked_add(size)
        .filter(|e| *e <= d.len() as u64)
        .ok_or_else(|| err!("{name}: {what} runs past the end of the file"))?;
    Ok(&d[off as usize..end as usize])
}

impl<'a> Object<'a> {
    pub fn parse<T: Target>(
        name: String,
        data: &'a [u8],
        prio: u32,
        member: bool,
    ) -> Result<Object<'a>> {
        if data.len() < 20 || data[4] != if T::IS64 { ELFCLASS64 } else { ELFCLASS32 } {
            bail!("{name}: wrong ELF class for {}", T::M.name());
        }
        let machine = rd16::<T>(data, 18);
        if machine != T::E_MACHINE {
            bail!("{name}: not an object for {}", T::M.name());
        }
        // Offsets into the file are kept in 32 bits.
        if data.len() > u32::MAX as usize {
            bail!("{name}: object files of 4 GiB or more are not supported");
        }
        let e_flags = rd32::<T>(data, if T::IS64 { 0x30 } else { 0x24 });
        let (shoff, shnum, shstrndx) = section_table::<T>(data, &name)?;
        let mut obj = Object {
            name,
            data,
            prio,
            member,
            alive: AtomicBool::new(!member),
            shdr_off: shoff,
            shstrtab: &[],
            secs: Vec::with_capacity(shnum as usize),
            symtab: &[],
            strtab: &[],
            shndx_table: &[],
            nsyms: 0,
            first_global: 0,
            sym_ids: Vec::new(),
            groups: Vec::new(),
            eh_frames: Vec::new(),
            exec_stack: true,
            local_needs: Mutex::new(Vec::new()),
            compressed: Vec::new(),
            inflated: Vec::new(),
            scanned: Mutex::new(Vec::new()),
            e_flags,
            has_merge: false,
            compressed_debug: false,
            attributes: 0,
        };
        if shnum == 0 {
            return Ok(obj);
        }
        if shstrndx < shnum {
            let h = obj.shdr::<T>(shstrndx);
            obj.shstrtab = slice(data, h.offset, h.size, &obj.name, "the section name table")?;
        }
        let mut stack_note = false;
        // Relocation sections, groups and the extended index table need the whole table first.
        let mut deferred: Vec<u32> = Vec::with_capacity(shnum as usize / 2);
        for i in 0..shnum {
            let h = obj.shdr::<T>(i);
            // Names are long (mangled) and only a few matter here: compare in place.
            let sname = NameAt(obj.shstrtab.get(h.name as usize..).unwrap_or(&[]));
            let mut kind = SecKind::Ignore;
            // A compressed section's uncompressed size and alignment.
            let mut inflated: Option<(u64, u64)> = None;
            let nobits = h.ty == SHT_NOBITS;
            if !nobits && h.ty != SHT_NULL {
                slice(data, h.offset, h.size, &obj.name, "a section")?;
            }
            match h.ty {
                SHT_REL | SHT_RELA | SHT_GROUP | SHT_SYMTAB_SHNDX => deferred.push(i),
                SHT_NULL | SHT_STRTAB | SHT_LLVM_ADDRSIG => {}
                SHT_SYMTAB => {
                    obj.symtab = slice(data, h.offset, h.size, &obj.name, "the symbol table")?;
                    obj.nsyms = (h.size / sym_size::<T>() as u64) as u32;
                    obj.first_global = h.info.min(obj.nsyms);
                    if h.link < shnum {
                        let s = obj.shdr::<T>(h.link);
                        obj.strtab = slice(data, s.offset, s.size, &obj.name, "the string table")?;
                    }
                }
                t if (0x6fff_4c00..=0x6fff_4cff).contains(&t) => {}
                _ if h.flags & SHF_EXCLUDE != 0 => {}
                _ if sname.is(b".note.GNU-stack") => {
                    stack_note = true;
                    obj.exec_stack = h.flags & SHF_EXECINSTR != 0;
                }
                _ if sname.is(b".note.gnu.property") || sname.0.starts_with(b".gnu.lto_") => {
                    if sname.0.starts_with(b".gnu.lto_") && !sname.is(b".gnu.lto_.lto") {
                        bail!(
                            "{}: GCC LTO objects are not supported; build without -flto",
                            obj.name
                        );
                    }
                }
                _ if sname.is(b".llvm.lto") || sname.is(b".llvmbc") && h.flags & SHF_ALLOC != 0 => {
                    bail!("{}: LLVM LTO objects are not supported", obj.name);
                }
                SHT_ARM_EXIDX if T::M == super::Machine::Arm => kind = SecKind::Exidx,
                SHT_ARM_ATTRIBUTES
                    if matches!(
                        T::M,
                        super::Machine::Arm | super::Machine::RiscV64 | super::Machine::RiscV32
                    ) =>
                {
                    obj.attributes = i;
                }
                _ if h.flags & SHF_ALLOC != 0 => {
                    kind = if sname.is(b".eh_frame") {
                        obj.eh_frames.push(i);
                        SecKind::EhFrame
                    } else if h.flags & SHF_MERGE != 0
                        && h.entsize > 0
                        && !nobits
                        && h.size.is_multiple_of(h.entsize)
                    {
                        obj.has_merge = true;
                        SecKind::Merge
                    } else {
                        SecKind::Alloc
                    };
                }
                _ => {
                    if h.flags & SHF_COMPRESSED != 0 {
                        // Linked as if uncompressed: the header tells the size and alignment.
                        match chdr::<T>(data, h.offset, h.size) {
                            Some((ty @ (ELFCOMPRESS_ZLIB | ELFCOMPRESS_ZSTD), size, align)) => {
                                let hdr = if T::IS64 { 24 } else { 12 };
                                obj.compressed.push((
                                    i,
                                    (h.offset + hdr) as u32,
                                    (h.size - hdr) as u32,
                                    ty,
                                ));
                                inflated = Some((size, align));
                                if h.flags & SHF_MERGE != 0
                                    && h.entsize > 0
                                    && size.is_multiple_of(h.entsize)
                                {
                                    obj.has_merge = true;
                                    kind = SecKind::Merge;
                                } else {
                                    kind = SecKind::NonAlloc;
                                }
                            }
                            _ => obj.compressed_debug = true,
                        }
                    } else if h.flags & SHF_MERGE != 0
                        && h.entsize > 0
                        && h.size.is_multiple_of(h.entsize)
                    {
                        obj.has_merge = true;
                        kind = SecKind::Merge;
                    } else {
                        kind = SecKind::NonAlloc;
                    }
                }
            }
            let (size, align) = inflated.unwrap_or((h.size, h.align));
            if size > u32::MAX as u64 {
                bail!("{}: section larger than 4 GiB", obj.name);
            }
            let mut fl = 0;
            if h.flags & SHF_WRITE != 0 {
                fl |= FL_WRITE;
            }
            if h.flags & SHF_EXECINSTR != 0 {
                fl |= FL_EXEC;
            }
            if h.flags & SHF_TLS != 0 {
                fl |= FL_TLS;
            }
            if nobits {
                fl |= FL_NOBITS;
            }
            if inflated.is_some() {
                fl |= FL_COMPRESSED;
            }
            let align = align.max(1);
            obj.secs.push(Sec {
                addr: 0,
                offset: if nobits { 0 } else { h.offset as u32 },
                size: size as u32,
                out: NONE,
                rel_off: 0,
                rel_len: 0,
                name: h.name,
                ty: h.ty,
                flags: h.flags as u32,
                nrel: 0,
                nsym: 0,
                aux: 0,
                kind,
                p2align: if align.is_power_of_two() {
                    align.trailing_zeros() as u8
                } else {
                    0
                },
                live: AtomicBool::new(false),
                fl,
            });
        }
        if !stack_note {
            // No marker: GNU ld assumes an executable stack. Nothing produces that anymore.
            obj.exec_stack = false;
        }
        for &i in &deferred {
            let h = obj.shdr::<T>(i);
            match h.ty {
                SHT_REL | SHT_RELA => {
                    let target = h.info;
                    if target >= shnum || target == 0 {
                        continue;
                    }
                    slice(data, h.offset, h.size, &obj.name, "relocations")?;
                    let t = &mut obj.secs[target as usize];
                    if t.kind != SecKind::Ignore && h.size > 0 {
                        t.rel_off = h.offset as u32;
                        t.rel_len = h.size as u32;
                        if h.ty == SHT_RELA {
                            t.fl |= FL_RELA;
                        }
                    }
                }
                SHT_GROUP => {
                    let body = slice(data, h.offset, h.size, &obj.name, "a group")?;
                    if body.len() < 4 || rd32::<T>(body, 0) & GRP_COMDAT == 0 {
                        continue;
                    }
                    let members: Vec<u32> = (1..body.len() / 4)
                        .map(|k| rd32::<T>(body, k * 4))
                        .filter(|&m| m < shnum)
                        .collect();
                    let sig = if (h.info as usize) < obj.nsyms as usize {
                        let s = read_sym::<T>(obj.symtab, h.info as usize);
                        cstr(obj.strtab, s.name as usize)
                    } else {
                        &[]
                    };
                    // A group's signature is a symbol name, or the group section's name when
                    // the symbol is a section symbol (old assemblers).
                    let sig = if sig.is_empty() {
                        cstr(obj.shstrtab, h.name as usize)
                    } else {
                        sig
                    };
                    obj.groups.push(Group {
                        signature: sig,
                        members,
                    });
                }
                SHT_SYMTAB_SHNDX => {
                    obj.shndx_table =
                        slice(data, h.offset, h.size, &obj.name, "the section index table")?;
                }
                _ => {}
            }
        }
        // Relocated mergeable data can't be split into pieces: keep such sections whole.
        for s in obj.secs.iter_mut() {
            if s.kind == SecKind::Merge && s.rel_len != 0 {
                s.kind = if s.has(SHF_ALLOC) {
                    SecKind::Alloc
                } else {
                    SecKind::NonAlloc
                };
            }
        }
        if obj.nsyms > 0 && obj.strtab.is_empty() {
            bail!("{}: symbol table without a string table", obj.name);
        }
        obj.sym_ids = (obj.first_global..obj.nsyms)
            .map(|_| AtomicU32::new(NONE))
            .collect();
        Ok(obj)
    }

    #[inline]
    pub fn shdr<T: Target>(&self, i: u32) -> Shdr {
        shdr::<T>(self.data, self.shdr_off + i as usize * shdr_size::<T>())
    }

    pub fn sec_name<T: Target>(&self, i: u32) -> &'a [u8] {
        cstr(self.shstrtab, self.shdr::<T>(i).name as usize)
    }

    #[inline]
    pub fn sym<T: Target>(&self, i: u32) -> Sym {
        let mut s = read_sym::<T>(self.symtab, i as usize);
        if s.shndx == SHN_XINDEX && !self.shndx_table.is_empty() {
            s.shndx = rd32::<T>(self.shndx_table, i as usize * 4);
        } else if s.shndx >= SHN_LORESERVE && s.shndx != SHN_ABS && s.shndx != SHN_COMMON {
            // Processor-specific (e.g. SHN_MIPS_*, small commons): treat as absolute.
            s.shndx = SHN_ABS;
        }
        s
    }

    #[inline]
    pub fn sym_name(&self, s: &Sym) -> &'a [u8] {
        cstr(self.strtab, s.name as usize)
    }

    #[inline]
    pub fn global_id(&self, i: u32) -> u32 {
        self.sym_ids[(i - self.first_global) as usize].load(Ordering::Relaxed)
    }

    /// The contents of section `i` (empty for SHT_NOBITS).
    #[inline]
    pub fn sec_data(&self, i: u32) -> &'a [u8] {
        let s = &self.secs[i as usize];
        if s.fl & (FL_NOBITS | FL_COMPRESSED) != 0 {
            if s.fl & FL_COMPRESSED == 0 {
                return &[];
            }
            return match self.inflated.binary_search_by_key(&i, |e| e.0) {
                Ok(k) => self.inflated[k].1,
                Err(_) => &[],
            };
        }
        &self.data[s.offset as usize..s.offset as usize + s.size as usize]
    }

    /// The relocations of section `i`, raw, and whether they are RELA.
    pub fn rel_data<T: Target>(&self, i: u32) -> (&'a [u8], bool) {
        let s = &self.secs[i as usize];
        let (off, len) = (s.rel_off as usize, s.rel_len as usize);
        (
            &self.data[off..off + len],
            s.rel_len == 0 || s.fl & FL_RELA != 0,
        )
    }

    pub fn rel_count<T: Target>(&self, i: u32) -> usize {
        let (d, rela) = self.rel_data::<T>(i);
        let sz = match (T::IS64, rela) {
            (true, true) => 24,
            (true, false) => 16,
            (false, true) => 12,
            (false, false) => 8,
        };
        d.len() / sz
    }

    /// Decode relocation `k` of section `i`; REL addends are read from the section.
    #[inline]
    pub fn rel<T: Target>(&self, raw: &[u8], rela: bool, k: usize, sec: u32) -> Rel {
        let mut r = T::decode_rel(raw, k, rela);
        if !rela {
            let d = self.sec_data(sec);
            if let Some(loc) = d.get(r.offset as usize..) {
                r.addend = T::implicit_addend(r.ty, loc);
            }
        }
        r
    }

    pub fn display_sym<T: Target>(&self, i: u32) -> String {
        crate::diag::symbol(self.sym_name(&self.sym::<T>(i)))
    }
}

/// A defined or referenced symbol of a shared object.
#[derive(Clone, Copy)]
pub struct DsoSym<'a> {
    pub name: &'a [u8],
    pub value: u64,
    pub size: u64,
    pub ver: u16,
    pub info: u8,
    pub defined: bool,
    /// A non-default version (`name@VER`): only explicit references bind to it.
    pub hidden: bool,
}

impl DsoSym<'_> {
    pub fn ty(&self) -> u8 {
        self.info & 0xf
    }
}

pub struct Dso<'a> {
    pub name: String,
    pub soname: String,
    pub prio: u32,
    pub as_needed: bool,
    pub used: AtomicBool,
    pub syms: Vec<DsoSym<'a>>,
    pub sym_ids: Vec<AtomicU32>,
    /// Version names by version index (0 and 1 are unnamed).
    pub versions: Vec<&'a [u8]>,
    /// Section address → file offset map for finding symbol sections (copy relocations).
    pub segments: Vec<(u64, u64, u32)>,
}

impl<'a> Dso<'a> {
    pub fn parse<T: Target>(
        name: String,
        data: &'a [u8],
        prio: u32,
        as_needed: bool,
    ) -> Result<Dso<'a>> {
        if data.len() < 20 || data[4] != if T::IS64 { ELFCLASS64 } else { ELFCLASS32 } {
            bail!("{name}: wrong ELF class for {}", T::M.name());
        }
        if rd16::<T>(data, 18) != T::E_MACHINE {
            bail!("{name}: not a shared object for {}", T::M.name());
        }
        let (shoff, shnum, _) = section_table::<T>(data, &name)?;
        let soname_default = std::path::Path::new(&name)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        let mut dso = Dso {
            soname: soname_default,
            name,
            prio,
            as_needed,
            used: AtomicBool::new(false),
            syms: Vec::new(),
            sym_ids: Vec::new(),
            versions: Vec::new(),
            segments: Vec::new(),
        };
        if shnum == 0 {
            bail!(
                "{}: shared objects without section headers are not supported",
                dso.name
            );
        }
        let hdr = |i: u32| shdr::<T>(data, shoff + i as usize * shdr_size::<T>());
        let mut dynsym = None;
        let mut versym: &[u8] = &[];
        let mut dynamic = None;
        let mut verdef = None;
        for i in 0..shnum {
            let h = hdr(i);
            match h.ty {
                SHT_DYNSYM => dynsym = Some(h),
                SHT_GNU_VERSYM => versym = slice(data, h.offset, h.size, &dso.name, "versions")?,
                SHT_DYNAMIC => dynamic = Some(h),
                SHT_GNU_VERDEF => verdef = Some(h),
                _ => {}
            }
            if h.flags & SHF_ALLOC != 0 && h.ty != SHT_NOBITS && h.size > 0 {
                dso.segments.push((h.addr, h.size, i));
            }
        }
        if let Some(d) = dynamic {
            let body = slice(data, d.offset, d.size, &dso.name, ".dynamic")?;
            let strtab = hdr(d.link);
            let strs = slice(data, strtab.offset, strtab.size, &dso.name, ".dynstr")?;
            let w = if T::IS64 { 8 } else { 4 };
            for e in body.chunks_exact(2 * w) {
                let tag = rdw::<T>(e, 0);
                if tag == DT_SONAME {
                    dso.soname =
                        String::from_utf8_lossy(cstr(strs, rdw::<T>(e, w) as usize)).into_owned();
                } else if tag == DT_NULL {
                    break;
                }
            }
        }
        if let Some(v) = verdef {
            let body = slice(data, v.offset, v.size, &dso.name, "version definitions")?;
            let strtab = hdr(v.link);
            let strs = slice(data, strtab.offset, strtab.size, &dso.name, ".dynstr")?;
            let mut off = 0usize;
            for _ in 0..v.info {
                if off + 20 > body.len() {
                    break;
                }
                let ndx = rd16::<T>(body, off + 4) as usize;
                let aux = rd32::<T>(body, off + 12) as usize;
                let next = rd32::<T>(body, off + 16) as usize;
                if off + aux + 8 <= body.len() {
                    let vname = cstr(strs, rd32::<T>(body, off + aux) as usize);
                    if dso.versions.len() <= ndx {
                        dso.versions.resize(ndx + 1, &[]);
                    }
                    dso.versions[ndx] = vname;
                }
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
        let Some(ds) = dynsym else {
            return Ok(dso);
        };
        let tab = slice(data, ds.offset, ds.size, &dso.name, ".dynsym")?;
        let strh = hdr(ds.link);
        let strs = slice(data, strh.offset, strh.size, &dso.name, ".dynstr")?;
        let n = ds.size as usize / sym_size::<T>();
        let first = (ds.info as usize).clamp(1, n.max(1));
        dso.syms.reserve(n - first.min(n));
        for i in first..n {
            let s = read_sym::<T>(tab, i);
            let bind = s.bind();
            if bind == STB_LOCAL {
                continue;
            }
            let vs = if versym.len() >= (i + 1) * 2 {
                rd16::<T>(versym, i * 2)
            } else {
                VER_NDX_GLOBAL
            };
            let ver = vs & !VERSYM_HIDDEN;
            dso.syms.push(DsoSym {
                name: cstr(strs, s.name as usize),
                value: s.value,
                size: s.size,
                ver,
                info: s.info,
                defined: s.shndx != SHN_UNDEF,
                hidden: vs & VERSYM_HIDDEN != 0 || ver == VER_NDX_LOCAL,
            });
        }
        dso.sym_ids = dso.syms.iter().map(|_| AtomicU32::new(NONE)).collect();
        Ok(dso)
    }

    pub fn version_name(&self, v: u16) -> &'a [u8] {
        self.versions.get(v as usize).copied().unwrap_or(&[])
    }
}
