//! COFF object files, regular and `/bigobj`, borrowed from the input's bytes.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::diag::Result;
use crate::{bail, err};

pub const NONE: u32 = u32::MAX;

const BIGOBJ_CLASS_ID: [u8; 16] = [
    0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Archive,
    ThinArchive,
    Object,
    BigObject,
    ShortImport,
    AnonObject,
    Bitcode,
    Resource,
    Elf,
    MachO,
    Unknown,
}

pub fn identify(d: &[u8]) -> FileKind {
    if crate::archive::is_archive(d) {
        return FileKind::Archive;
    }
    if crate::archive::is_thin_archive(d) {
        return FileKind::ThinArchive;
    }
    if d.starts_with(b"BC\xC0\xDE") || d.starts_with(&[0xDE, 0xC0, 0x17, 0x0B]) {
        return FileKind::Bitcode;
    }
    if d.starts_with(b"\x7fELF") {
        return FileKind::Elf;
    }
    if d.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || d.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
        return FileKind::MachO;
    }
    if d.starts_with(&[
        0, 0, 0, 0, 0x20, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0,
    ]) {
        return FileKind::Resource;
    }
    if d.len() >= 6 && u16le(d, 0) == 0 && u16le(d, 2) == 0xFFFF {
        if u16le(d, 4) == 0 {
            return FileKind::ShortImport;
        }
        if d.len() >= 56 && d[12..28] == BIGOBJ_CLASS_ID {
            return FileKind::BigObject;
        }
        return FileKind::AnonObject;
    }
    if d.len() >= 20 {
        let machine = u16le(d, 0);
        if matches!(
            machine,
            IMAGE_FILE_MACHINE_UNKNOWN
                | IMAGE_FILE_MACHINE_AMD64
                | IMAGE_FILE_MACHINE_I386
                | IMAGE_FILE_MACHINE_ARM64
                | IMAGE_FILE_MACHINE_ARMNT
                | IMAGE_FILE_MACHINE_ARM64EC
                | IMAGE_FILE_MACHINE_ARM64X
        ) {
            return FileKind::Object;
        }
    }
    FileKind::Unknown
}

#[derive(Debug, Clone, Copy)]
pub struct Comdat {
    pub selection: u8,
    pub assoc: u32,
    pub leader: u32,
}

pub struct Section<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub size: u32,
    pub chars: u32,
    pub align: u32,
    pub va: u32,
    pub relocs: &'a [u8],
    pub comdat: Option<Comdat>,
    pub assoc_child: u32,
    pub assoc_next: u32,
    pub discarded: bool,
    pub debug: bool,
    pub live: AtomicBool,
    pub folded_into: Option<(u32, u32)>,
    pub rva: u32,
    pub out: u32,
}

impl Section<'_> {
    pub fn is_comdat(&self) -> bool {
        self.chars & IMAGE_SCN_LNK_COMDAT != 0
    }

    pub fn has_data(&self) -> bool {
        self.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0
    }

    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    pub fn nrelocs(&self) -> usize {
        self.relocs.len() / 10
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    Defined { sec: u32, value: u32 },
    Absolute { value: u32 },
    Undefined,
    Common { size: u32 },
    Weak { alias: u32 },
}

#[derive(Debug, Clone, Copy)]
pub struct ExternalSym<'a> {
    pub index: u32,
    pub name: &'a [u8],
    pub hash: u64,
    pub kind: ExtKind,
    pub function: bool,
    pub id: u32,
}

pub struct ObjFile<'a> {
    pub name: String,
    pub machine: u16,
    sym_size: usize,
    big: bool,
    symtab: &'a [u8],
    strtab: &'a [u8],
    pub nsyms: u32,
    pub sections: Vec<Section<'a>>,
    pub externals: Vec<ExternalSym<'a>>,
    pub directives: Vec<&'a [u8]>,
    pub feat00: u32,
    pub sxdata: &'a [u8],
    pub debug_s: Vec<u32>,
    pub debug_t: Option<u32>,
    pub sym_ids: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct RawSym {
    pub value: u32,
    pub section: i32,
}

impl<'a> ObjFile<'a> {
    pub fn parse(data: &'a [u8], name: String) -> Result<ObjFile<'a>> {
        let big = identify(data) == FileKind::BigObject;
        let (machine, nsecs, symtab_off, nsyms, sec_table, sym_size) = if big {
            (
                u16le(data, 6),
                u32le(data, 44) as usize,
                u32le(data, 48) as usize,
                u32le(data, 52) as usize,
                56,
                20,
            )
        } else {
            if data.len() < 20 {
                bail!("{name}: truncated COFF header");
            }
            (
                u16le(data, 0),
                u16le(data, 2) as usize,
                u32le(data, 8) as usize,
                u32le(data, 12) as usize,
                20 + u16le(data, 16) as usize,
                18,
            )
        };
        if sec_table + nsecs * 40 > data.len() {
            bail!("{name}: section table runs past the end of the file");
        }
        let (symtab, strtab) = if nsyms == 0 {
            (&data[..0], &data[..0])
        } else {
            let end = symtab_off
                .checked_add(nsyms * sym_size)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| err!("{name}: symbol table runs past the end of the file"))?;
            let strtab = if end + 4 <= data.len() {
                let size = (u32le(data, end) as usize).max(4);
                &data[end..(end + size).min(data.len())]
            } else {
                &data[..0]
            };
            (&data[symtab_off..end], strtab)
        };

        let mut obj = ObjFile {
            name,
            machine,
            sym_size,
            big,
            symtab,
            strtab,
            nsyms: nsyms as u32,
            sections: Vec::with_capacity(nsecs),
            externals: Vec::new(),
            directives: Vec::new(),
            feat00: 0,
            sxdata: &data[..0],
            debug_s: Vec::new(),
            debug_t: None,
            sym_ids: vec![NONE; nsyms],
        };

        for i in 0..nsecs {
            let h = &data[sec_table + i * 40..sec_table + i * 40 + 40];
            let section = obj.parse_section(data, h)?;
            match section.name {
                b".sxdata" => obj.sxdata = section.data,
                b".debug$S" => obj.debug_s.push(i as u32),
                b".debug$T" => obj.debug_t = Some(i as u32),
                _ => {}
            }
            obj.sections.push(section);
        }
        obj.parse_symbols()?;
        for i in (0..obj.sections.len()).rev() {
            if let Some(c) = obj.sections[i].comdat
                && c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE
                && (c.assoc as usize) < obj.sections.len()
                && c.assoc as usize != i
            {
                let parent = c.assoc as usize;
                obj.sections[i].assoc_next = obj.sections[parent].assoc_child;
                obj.sections[parent].assoc_child = i as u32;
            }
        }
        Ok(obj)
    }

    fn parse_section(&mut self, data: &'a [u8], h: &'a [u8]) -> Result<Section<'a>> {
        let name = self.section_name(&h[..8])?;
        let va = u32le(h, 12);
        let raw_size = u32le(h, 16) as usize;
        let raw_ptr = u32le(h, 20) as usize;
        let reloc_ptr = u32le(h, 24) as usize;
        let mut nrelocs = u16le(h, 32) as usize;
        let chars = u32le(h, 36);
        let bss = chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
        let contents = if bss || raw_size == 0 {
            &data[..0]
        } else {
            data.get(raw_ptr..raw_ptr + raw_size).ok_or_else(|| {
                err!(
                    "{}: section {} runs past the end of the file",
                    self.name,
                    String::from_utf8_lossy(name)
                )
            })?
        };
        let mut reloc_start = reloc_ptr;
        if chars & IMAGE_SCN_LNK_NRELOC_OVFL != 0 && nrelocs == 0xFFFF {
            // The real count is in the first record, which counts itself.
            if reloc_ptr + 10 > data.len() {
                bail!("{}: truncated relocations", self.name);
            }
            nrelocs = (u32le(data, reloc_ptr) as usize).saturating_sub(1);
            reloc_start += 10;
        }
        let relocs = data
            .get(reloc_start..reloc_start + nrelocs * 10)
            .ok_or_else(|| err!("{}: relocations run past the end of the file", self.name))?;
        let shift = (chars & IMAGE_SCN_ALIGN_MASK) >> 20;
        let align = if shift > 0 { 1 << (shift - 1) } else { 1 };
        let discarded =
            chars & (IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_LNK_INFO) != 0 || is_removed_name(name);
        if chars & IMAGE_SCN_LNK_INFO != 0 && name == b".drectve" && !contents.is_empty() {
            self.directives.push(contents);
        }
        Ok(Section {
            name,
            data: contents,
            size: raw_size as u32,
            chars,
            align,
            va,
            relocs,
            comdat: None,
            assoc_child: NONE,
            assoc_next: NONE,
            discarded,
            debug: name.starts_with(b".debug$"),
            live: AtomicBool::new(false),
            folded_into: None,
            rva: 0,
            out: NONE,
        })
    }

    fn section_name(&self, raw: &'a [u8]) -> Result<&'a [u8]> {
        if raw[0] != b'/' {
            return Ok(until_nul(raw));
        }
        // A long name: "/<decimal offset>" or "//<base64 offset>".
        let off = if raw[1] == b'/' {
            let mut v: u64 = 0;
            for &c in until_nul(&raw[2..]) {
                let d = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'a'..=b'z' => c - b'a' + 26,
                    b'0'..=b'9' => c - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    _ => bail!("{}: bad section name", self.name),
                };
                v = v * 64 + d as u64;
            }
            v as usize
        } else {
            std::str::from_utf8(until_nul(&raw[1..]))
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| err!("{}: bad section name", self.name))?
        };
        Ok(until_nul(self.strtab.get(off..).unwrap_or(&[])))
    }

    #[inline]
    fn sym_record(&self, i: usize) -> &'a [u8] {
        &self.symtab[i * self.sym_size..(i + 1) * self.sym_size]
    }

    #[inline]
    pub fn raw_sym(&self, i: u32) -> Option<RawSym> {
        if i >= self.nsyms {
            return None;
        }
        let e = self.sym_record(i as usize);
        let section = if self.big {
            u32le(e, 12) as i32
        } else {
            u16le(e, 12) as i16 as i32
        };
        Some(RawSym {
            value: u32le(e, 8),
            section,
        })
    }

    pub fn sym_name(&self, i: u32) -> &'a [u8] {
        if i >= self.nsyms {
            return b"<bad symbol index>";
        }
        self.name_of(self.sym_record(i as usize))
    }

    fn name_of(&self, e: &'a [u8]) -> &'a [u8] {
        if e[..4] == [0, 0, 0, 0] {
            let off = u32le(e, 4) as usize;
            until_nul(self.strtab.get(off..).unwrap_or(&[]))
        } else {
            until_nul(&e[..8])
        }
    }

    fn parse_symbols(&mut self) -> Result<()> {
        let n = self.nsyms as usize;
        let nsecs = self.sections.len();
        let mut awaiting_leader = vec![false; nsecs];
        let mut i = 0;
        while i < n {
            let e = self.sym_record(i);
            let value = u32le(e, 8);
            let (section, ty, class, naux) = if self.big {
                (u32le(e, 12) as i32, u16le(e, 16), e[18], e[19] as usize)
            } else {
                (
                    u16le(e, 12) as i16 as i32,
                    u16le(e, 14),
                    e[16],
                    e[17] as usize,
                )
            };
            if i + naux >= n && naux > 0 {
                bail!(
                    "{}: symbol {i} has auxiliary records past the end",
                    self.name
                );
            }
            let in_section = section > 0;
            if in_section && section as usize > nsecs {
                bail!(
                    "{}: symbol {i} refers to section {section}, which doesn't exist",
                    self.name
                );
            }
            let sec = (section - 1) as u32;

            let is_section_def =
                class == IMAGE_SYM_CLASS_STATIC && value == 0 && naux > 0 && in_section;
            if is_section_def {
                let aux = self.sym_record(i + 1);
                let s = &mut self.sections[sec as usize];
                if s.is_comdat() && s.comdat.is_none() {
                    let mut number = u16le(aux, 12) as u32;
                    if self.big {
                        number |= (u16le(aux, 16) as u32) << 16;
                    }
                    let selection = aux[14];
                    s.comdat = Some(Comdat {
                        selection,
                        assoc: number.wrapping_sub(1),
                        leader: NONE,
                    });
                    if selection != IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                        awaiting_leader[sec as usize] = true;
                    }
                }
            } else if in_section && awaiting_leader[sec as usize] {
                awaiting_leader[sec as usize] = false;
                if let Some(c) = &mut self.sections[sec as usize].comdat {
                    c.leader = i as u32;
                }
            }

            if class == IMAGE_SYM_CLASS_STATIC
                && section == IMAGE_SYM_ABSOLUTE
                && &e[..8] == b"@feat.00"
            {
                self.feat00 = value;
            }
            let kind = match class {
                IMAGE_SYM_CLASS_EXTERNAL => match section {
                    s if s > 0 => Some(ExtKind::Defined { sec, value }),
                    IMAGE_SYM_UNDEFINED if value > 0 => Some(ExtKind::Common { size: value }),
                    IMAGE_SYM_UNDEFINED => Some(ExtKind::Undefined),
                    IMAGE_SYM_ABSOLUTE => Some(ExtKind::Absolute { value }),
                    _ => None,
                },
                IMAGE_SYM_CLASS_WEAK_EXTERNAL if naux > 0 => {
                    let alias = u32le(self.sym_record(i + 1), 0);
                    Some(ExtKind::Weak { alias })
                }
                _ => None,
            };
            if let Some(kind) = kind {
                let name = self.name_of(e);
                self.externals.push(ExternalSym {
                    index: i as u32,
                    name,
                    hash: crate::coff::symtab::hash_name(name),
                    kind,
                    function: (ty >> 4) & 0xF == 2,
                    id: NONE,
                });
            }
            i += 1 + naux;
        }
        Ok(())
    }

    pub fn propagate_discards(&mut self) {
        for i in 0..self.sections.len() {
            if self.sections[i].discarded {
                continue;
            }
            let mut cur = i;
            for _ in 0..16 {
                match self.sections[cur].comdat {
                    Some(c)
                        if c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE
                            && (c.assoc as usize) < self.sections.len()
                            && c.assoc as usize != cur =>
                    {
                        cur = c.assoc as usize;
                        if self.sections[cur].discarded {
                            self.sections[i].discarded = true;
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }
}

fn is_removed_name(name: &[u8]) -> bool {
    name.starts_with(b".debug_")
        || name.starts_with(b".gfids$")
        || name.starts_with(b".giats$")
        || name.starts_with(b".gljmp$")
        || name.starts_with(b".gehcont$")
        || name == b".sxdata"
        || name == b".voltbl"
        || name == b".llvm_addrsig"
        || name == b".llvm.call-graph-profile"
}

fn until_nul(s: &[u8]) -> &[u8] {
    match s.iter().position(|&b| b == 0) {
        Some(p) => &s[..p],
        None => s,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[derive(Default)]
    #[allow(clippy::type_complexity)]
    pub struct ObjBuilder {
        pub sections: Vec<(Vec<u8>, Vec<u8>, u32, Vec<(u32, u32, u16)>)>,
        pub symbols: Vec<(Vec<u8>, u32, i16, u8, Vec<[u8; 18]>)>,
    }

    impl ObjBuilder {
        pub fn section(&mut self, name: &str, data: &[u8], chars: u32) -> i16 {
            self.sections
                .push((name.as_bytes().to_vec(), data.to_vec(), chars, Vec::new()));
            self.sections.len() as i16
        }

        pub fn reloc(&mut self, sec: i16, offset: u32, sym: u32, ty: u16) {
            self.sections[sec as usize - 1].3.push((offset, sym, ty));
        }

        pub fn symbol(&mut self, name: &str, value: u32, sec: i16, class: u8) -> u32 {
            let idx = self.index();
            self.symbols
                .push((name.as_bytes().to_vec(), value, sec, class, Vec::new()));
            idx
        }

        pub fn symbol_aux(
            &mut self,
            name: &str,
            value: u32,
            sec: i16,
            class: u8,
            aux: [u8; 18],
        ) -> u32 {
            let idx = self.index();
            self.symbols
                .push((name.as_bytes().to_vec(), value, sec, class, vec![aux]));
            idx
        }

        fn index(&self) -> u32 {
            self.symbols.iter().map(|s| 1 + s.4.len() as u32).sum()
        }

        pub fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let nsyms = self.index();
            let mut strtab = vec![0u8; 4];
            let header_len = 20 + 40 * self.sections.len();
            let mut data_off = header_len;
            let mut layout = Vec::new();
            for (_, data, _, relocs) in &self.sections {
                let d = data_off;
                data_off += data.len();
                let r = data_off;
                data_off += relocs.len() * 10;
                layout.push((d, r));
            }
            let symtab_off = data_off;
            out.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
            out.extend_from_slice(&(self.sections.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(symtab_off as u32).to_le_bytes());
            out.extend_from_slice(&nsyms.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            for (i, (name, data, chars, relocs)) in self.sections.iter().enumerate() {
                let mut n = [0u8; 8];
                n[..name.len()].copy_from_slice(name);
                out.extend_from_slice(&n);
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                let ptr = if chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                    0
                } else {
                    layout[i].0
                };
                out.extend_from_slice(&(ptr as u32).to_le_bytes());
                out.extend_from_slice(&(layout[i].1 as u32).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&(relocs.len() as u16).to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&chars.to_le_bytes());
            }
            for (_, data, _, relocs) in &self.sections {
                out.extend_from_slice(data);
                for (off, sym, ty) in relocs {
                    out.extend_from_slice(&off.to_le_bytes());
                    out.extend_from_slice(&sym.to_le_bytes());
                    out.extend_from_slice(&ty.to_le_bytes());
                }
            }
            for (name, value, sec, class, aux) in &self.symbols {
                if name.len() <= 8 {
                    let mut n = [0u8; 8];
                    n[..name.len()].copy_from_slice(name);
                    out.extend_from_slice(&n);
                } else {
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes());
                    strtab.extend_from_slice(name);
                    strtab.push(0);
                }
                out.extend_from_slice(&value.to_le_bytes());
                out.extend_from_slice(&sec.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.push(*class);
                out.push(aux.len() as u8);
                for a in aux {
                    out.extend_from_slice(a);
                }
            }
            let len = strtab.len() as u32;
            strtab[..4].copy_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&strtab);
            out
        }
    }

    pub fn comdat_aux(len: u32, selection: u8, assoc: u16) -> [u8; 18] {
        let mut a = [0u8; 18];
        a[..4].copy_from_slice(&len.to_le_bytes());
        a[12..14].copy_from_slice(&assoc.to_le_bytes());
        a[14] = selection;
        a
    }

    #[test]
    fn parses_sections_symbols_and_comdats() {
        let code = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x0050_0000;
        let mut b = ObjBuilder::default();
        let text = b.section(".text", &[0xC3], code);
        let f = b.section(".text", &[0x90, 0xC3], code | IMAGE_SCN_LNK_COMDAT);
        let pdata = b.section(
            ".pdata",
            &[0; 12],
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_LNK_COMDAT,
        );
        b.section(
            ".drectve",
            b"/DEFAULTLIB:msvcrt",
            IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE,
        );
        b.symbol_aux(
            ".text",
            0,
            text,
            IMAGE_SYM_CLASS_STATIC,
            comdat_aux(1, 0, 0),
        );
        b.symbol("main", 0, text, IMAGE_SYM_CLASS_EXTERNAL);
        b.symbol_aux(
            ".text",
            0,
            f,
            IMAGE_SYM_CLASS_STATIC,
            comdat_aux(2, IMAGE_COMDAT_SELECT_ANY, 0),
        );
        let leader = b.symbol(
            "a_function_with_a_long_name",
            0,
            f,
            IMAGE_SYM_CLASS_EXTERNAL,
        );
        b.symbol_aux(
            ".pdata",
            0,
            pdata,
            IMAGE_SYM_CLASS_STATIC,
            comdat_aux(12, IMAGE_COMDAT_SELECT_ASSOCIATIVE, f as u16),
        );
        b.symbol("printf", 0, 0, IMAGE_SYM_CLASS_EXTERNAL);
        b.reloc(text, 0, leader, IMAGE_REL_AMD64_REL32);
        let bytes = b.build();
        assert_eq!(identify(&bytes), FileKind::Object);
        let obj = ObjFile::parse(&bytes, "t.obj".into()).unwrap();
        assert_eq!(obj.sections.len(), 4);
        assert_eq!(obj.sections[0].align, 16);
        assert_eq!(obj.sections[0].nrelocs(), 1);
        assert!(obj.sections[3].discarded);
        assert_eq!(obj.directives, [&b"/DEFAULTLIB:msvcrt"[..]]);
        let c = obj.sections[1].comdat.unwrap();
        assert_eq!((c.selection, c.leader), (IMAGE_COMDAT_SELECT_ANY, leader));
        assert_eq!(obj.sections[1].assoc_child, 2);
        let ext: Vec<_> = obj.externals.iter().map(|e| (e.name, e.kind)).collect();
        assert_eq!(
            ext,
            [
                (&b"main"[..], ExtKind::Defined { sec: 0, value: 0 }),
                (
                    b"a_function_with_a_long_name",
                    ExtKind::Defined { sec: 1, value: 0 }
                ),
                (b"printf", ExtKind::Undefined),
            ]
        );
        assert_eq!(obj.sym_name(leader), b"a_function_with_a_long_name");
    }

    #[test]
    fn identifies_inputs() {
        assert_eq!(identify(b"!<arch>\nxxxx"), FileKind::Archive);
        assert_eq!(identify(b"BC\xC0\xDE...."), FileKind::Bitcode);
        assert_eq!(
            identify(&[0, 0, 0xFF, 0xFF, 0, 0, 0x64, 0x86]),
            FileKind::ShortImport
        );
        assert_eq!(identify(b"\x7fELF\x02\x01\x01"), FileKind::Elf);
        assert_eq!(identify(b"hello"), FileKind::Unknown);
    }
}
