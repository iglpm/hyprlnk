//! Writing the image.
//!
//! The whole file is built in one zero-initialized buffer. Sections are cut
//! into batches of about equal size, and each batch is copied and relocated
//! on its own thread, collecting the base relocations it needs. `.reloc` is
//! built from those and appended (it is the last section, so nothing moves),
//! the exception table is sorted, and the headers go in last.

use std::sync::atomic::Ordering::Relaxed;

use rayon::prelude::*;

use super::layout::{ChunkRef, HEADERS_BEFORE_SECTIONS, Layout};
use super::object::{NONE, ObjFile, Section};
use super::resolve::Linker;
use super::symtab::{Def, SymId};
use super::synth::*;
use super::*;
use crate::diag::{Result, Timer};
use crate::{bail, err};

/// What a relocation points at.
#[derive(Debug, Clone, Copy)]
struct Target {
    va: u64,
    /// An absolute symbol: its address doesn't move with the image, so it
    /// needs no base relocation.
    absolute: bool,
    /// Output section index, or [`NONE`].
    out: u32,
}

/// Base relocations a batch needs: RVAs of 64-bit and 32-bit addresses.
#[derive(Default)]
struct BaseRelocs {
    dir64: Vec<u32>,
    highlow: Vec<u32>,
}

/// The MS-DOS program that prints "This program cannot be run in DOS mode."
const DOS_STUB: [u8; 56] = [
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
    0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x24, 0x00, 0x00,
];
const PE_OFFSET: usize = 64 + DOS_STUB.len();
const COFF_HEADER: usize = PE_OFFSET + 4;
const OPT_HEADER: usize = COFF_HEADER + 20;
const SECTION_TABLE: usize = HEADERS_BEFORE_SECTIONS as usize;

struct Item {
    file_off: u32,
    size: u32,
    chunk: ChunkRef,
}

impl Linker<'_> {
    fn sym_target(&self, id: SymId) -> Option<Target> {
        let ib = self.image_base;
        let synth = |k: usize, off: u32| {
            let c = &self.synth[k];
            Target {
                va: ib + c.rva as u64 + off as u64,
                absolute: false,
                out: c.out,
            }
        };
        Some(match self.symtab.get(id).def {
            Def::Defined { obj, sec, value } => {
                let s = &self.objs[obj as usize].sections[sec as usize];
                if !s.is_live() {
                    return None;
                }
                Target {
                    va: ib + s.rva as u64 + value as u64,
                    absolute: false,
                    out: s.out,
                }
            }
            Def::Absolute { va } => Target {
                va,
                absolute: true,
                out: NONE,
            },
            Def::Synthetic { chunk, off } => synth(chunk as usize, off),
            Def::Import { imp } => {
                let i = &self.imports[imp as usize];
                if !i.live.load(Relaxed) {
                    return None;
                }
                synth(IDATA_IAT, i.iat_off)
            }
            Def::Thunk { imp } => {
                let i = &self.imports[imp as usize];
                if !i.thunk_live.load(Relaxed) {
                    return None;
                }
                synth(THUNKS, i.thunk_off)
            }
            Def::LocalImport { slot } => synth(LOCAL_IMPORTS, slot * 8),
            Def::ImageBase => Target {
                va: ib,
                absolute: false,
                out: NONE,
            },
            Def::Undefined | Def::Lazy { .. } | Def::Common { .. } => return None,
        })
    }

    fn reloc_target(&self, obj: &ObjFile, idx: u32) -> Option<Target> {
        match obj.sym_ids.get(idx as usize) {
            Some(&id) if id != NONE => self.sym_target(id),
            _ => {
                let raw = obj.raw_sym(idx)?;
                if raw.section > 0 {
                    let s = obj.sections.get((raw.section - 1) as usize)?;
                    s.is_live().then(|| Target {
                        va: self.image_base + s.rva as u64 + raw.value as u64,
                        absolute: false,
                        out: s.out,
                    })
                } else if raw.section == IMAGE_SYM_ABSOLUTE {
                    Some(Target {
                        va: raw.value as u64,
                        absolute: true,
                        out: NONE,
                    })
                } else {
                    None
                }
            }
        }
    }

    fn apply_relocs(
        &self,
        obj: &ObjFile,
        sec: &Section,
        buf: &mut [u8],
        br: &mut BaseRelocs,
    ) -> Result<()> {
        let ib = self.image_base;
        for r in sec.relocs.as_chunks::<10>().0 {
            let ty = u16le(r, 8);
            if ty == IMAGE_REL_AMD64_ABSOLUTE {
                continue;
            }
            let off = u32le(r, 0).wrapping_sub(sec.va) as usize;
            let idx = u32le(r, 4);
            let width = match ty {
                IMAGE_REL_AMD64_ADDR64 => 8,
                IMAGE_REL_AMD64_SECTION => 2,
                IMAGE_REL_AMD64_SECREL7 => 1,
                _ => 4,
            };
            if off + width > buf.len() {
                bail!(
                    "{}: relocation at offset {off:#x} is outside its {}-byte section {}",
                    obj.name,
                    buf.len(),
                    String::from_utf8_lossy(sec.name)
                );
            }
            let t = match self.reloc_target(obj, idx) {
                Some(t) => t,
                None if self.cfg.force_unresolved => Target {
                    va: 0,
                    absolute: true,
                    out: NONE,
                },
                None => bail!(
                    "{}: relocation in section {} refers to {}, which is undefined or was discarded",
                    obj.name,
                    String::from_utf8_lossy(sec.name),
                    crate::diag::symbol(obj.sym_name(idx))
                ),
            };
            let p = ib + sec.rva as u64 + off as u64;
            match ty {
                IMAGE_REL_AMD64_ADDR64 => {
                    put64(buf, off, t.va.wrapping_add(u64le(buf, off)));
                    if !t.absolute {
                        br.dir64.push(p as u32 - ib as u32);
                    }
                }
                IMAGE_REL_AMD64_ADDR32 => {
                    let v = t.va.wrapping_add(u32le(buf, off) as u64);
                    if v > u32::MAX as u64 {
                        bail!(
                            "{}: 32-bit absolute address of {} doesn't fit; link with /LARGEADDRESSAWARE:NO and a low /BASE",
                            obj.name,
                            crate::diag::symbol(obj.sym_name(idx))
                        );
                    }
                    put32(buf, off, v as u32);
                    if !t.absolute {
                        br.highlow.push(p as u32 - ib as u32);
                    }
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    let v = t.va.wrapping_sub(ib).wrapping_add(u32le(buf, off) as u64);
                    put32(buf, off, v as u32);
                }
                IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                    let k = (ty - IMAGE_REL_AMD64_REL32) as u64;
                    let a = u32le(buf, off) as i32 as i64;
                    let v = t.va as i64 + a - (p + 4 + k) as i64;
                    if v != v as i32 as i64 {
                        bail!(
                            "{}: relative address of {} is out of range",
                            obj.name,
                            crate::diag::symbol(obj.sym_name(idx))
                        );
                    }
                    put32(buf, off, v as i32 as u32);
                }
                IMAGE_REL_AMD64_SECTION => {
                    let n = if t.out == NONE { 0 } else { t.out + 1 };
                    put16(buf, off, (n as u16).wrapping_add(u16le(buf, off)));
                }
                IMAGE_REL_AMD64_SECREL | IMAGE_REL_AMD64_SECREL7 => {
                    let rel = if t.absolute || t.out == NONE {
                        t.va
                    } else {
                        t.va - ib - self.out_rvas[t.out as usize] as u64
                    };
                    if ty == IMAGE_REL_AMD64_SECREL {
                        put32(buf, off, (rel as u32).wrapping_add(u32le(buf, off)));
                    } else {
                        buf[off] = (buf[off] & 0x80) | ((rel as u8).wrapping_add(buf[off]) & 0x7F);
                    }
                }
                _ => bail!(
                    "{}: unsupported relocation type {ty:#x} in section {}",
                    obj.name,
                    String::from_utf8_lossy(sec.name)
                ),
            }
        }
        Ok(())
    }

    fn write_chunk(&self, c: ChunkRef, dst: &mut [u8], br: &mut BaseRelocs) -> Result<()> {
        match c {
            ChunkRef::Sec { obj, sec } => {
                let o = &self.objs[obj as usize];
                let s = &o.sections[sec as usize];
                dst[..s.data.len()].copy_from_slice(s.data);
                self.apply_relocs(o, s, dst, br)
            }
            ChunkRef::Synth(k) => self.write_synth(k as usize, dst, br),
        }
    }

    fn write_synth(&self, k: usize, dst: &mut [u8], br: &mut BaseRelocs) -> Result<()> {
        let rva = |k: usize| self.synth[k].rva;
        match k {
            IDATA_DIR => {
                for (i, dll) in self.dlls.iter().enumerate() {
                    let o = i * 20;
                    put32(dst, o, rva(IDATA_ILT) + dll.table_off);
                    put32(dst, o + 12, rva(IDATA_DLLS) + dll.name_off);
                    put32(dst, o + 16, rva(IDATA_IAT) + dll.table_off);
                }
            }
            IDATA_ILT | IDATA_IAT => {
                for dll in &self.dlls {
                    for (j, &i) in dll.imports.iter().enumerate() {
                        let imp = &self.imports[i as usize];
                        let v = match imp.name {
                            Some(_) => (rva(IDATA_HINTS) + imp.hint_off) as u64,
                            None => (1 << 63) | imp.ordinal_or_hint as u64,
                        };
                        put64(dst, dll.table_off as usize + j * 8, v);
                    }
                }
            }
            IDATA_HINTS => {
                for imp in &self.imports {
                    if let (true, Some(name)) = (imp.live.load(Relaxed), imp.name) {
                        let o = imp.hint_off as usize;
                        put16(dst, o, imp.ordinal_or_hint);
                        dst[o + 2..o + 2 + name.len()].copy_from_slice(name);
                    }
                }
            }
            IDATA_DLLS => {
                for dll in &self.dlls {
                    let o = dll.name_off as usize;
                    dst[o..o + dll.name.len()].copy_from_slice(dll.name);
                }
            }
            THUNKS => {
                let thunks = rva(THUNKS);
                for imp in &self.imports {
                    if imp.thunk_live.load(Relaxed) {
                        let o = imp.thunk_off as usize;
                        let disp =
                            (rva(IDATA_IAT) + imp.iat_off) as i64 - (thunks as i64 + o as i64 + 6);
                        dst[o..o + 2].copy_from_slice(&[0xFF, 0x25]);
                        put32(dst, o + 2, disp as i32 as u32);
                        dst[o + 6..o + 8].copy_from_slice(&[0xCC, 0xCC]);
                    }
                }
            }
            LOCAL_IMPORTS => {
                for (slot, &target) in self.local_imports.iter().enumerate() {
                    let t = self.sym_target(target).ok_or_else(|| {
                        err!(
                            "{} was discarded",
                            crate::diag::symbol(self.symtab.get(target).name)
                        )
                    })?;
                    put64(dst, slot * 8, t.va);
                    if !t.absolute {
                        br.dir64.push(rva(LOCAL_IMPORTS) + slot as u32 * 8);
                    }
                }
            }
            EDATA => {
                let e = self.edata.as_ref().unwrap();
                let base = rva(EDATA);
                put32(dst, 12, base + e.dll_name_off);
                put32(dst, 16, e.base);
                put32(dst, 20, e.functions.len() as u32);
                put32(dst, 24, e.names.len() as u32);
                put32(dst, 28, base + e.eat_off);
                put32(dst, 32, base + e.name_ptrs_off);
                put32(dst, 36, base + e.ordinals_off);
                for (i, f) in e.functions.iter().enumerate() {
                    if let Some(id) = f {
                        let t = self.sym_target(*id).ok_or_else(|| {
                            err!(
                                "exported symbol {} is undefined",
                                crate::diag::symbol(self.symtab.get(*id).name)
                            )
                        })?;
                        put32(
                            dst,
                            e.eat_off as usize + i * 4,
                            (t.va - self.image_base) as u32,
                        );
                    }
                }
                let o = e.dll_name_off as usize;
                dst[o..o + e.dll_name.len()].copy_from_slice(e.dll_name.as_bytes());
                let mut s = e.strings_off as usize;
                for (i, (name, ord)) in e.names.iter().enumerate() {
                    put32(dst, e.name_ptrs_off as usize + i * 4, base + s as u32);
                    put16(dst, e.ordinals_off as usize + i * 2, *ord);
                    dst[s..s + name.len()].copy_from_slice(name.as_bytes());
                    s += name.len() + 1;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn write(&self, layout: &Layout, timer: &mut Timer) -> Result<()> {
        let path = self.output_path();
        let entry_rva = match self.entry {
            Some(id) => {
                let t = self.sym_target(id).ok_or_else(|| {
                    err!(
                        "entry point {} is undefined",
                        crate::diag::symbol(self.symtab.get(id).name)
                    )
                })?;
                (t.va - self.image_base) as u32
            }
            None => 0,
        };

        // Everything with bytes, in file order.
        let mut items = Vec::new();
        let mut reloc_count = 0usize;
        for sec in &layout.sections {
            for &c in &sec.chunks {
                let (size, _, has_data) = self.chunk_info(c);
                let rva = match c {
                    ChunkRef::Sec { obj, sec } => {
                        let s = &self.objs[obj as usize].sections[sec as usize];
                        reloc_count += s.nrelocs();
                        s.rva
                    }
                    ChunkRef::Synth(k) => self.synth[k as usize].rva,
                };
                if has_data && size > 0 {
                    items.push(Item {
                        file_off: sec.file_off + (rva - sec.rva),
                        size,
                        chunk: c,
                    });
                }
            }
        }
        reloc_count += self.local_imports.len();
        let file_end = layout.file_end as usize;
        let reloc_bound = reloc_count * 2 + (layout.end_rva as usize / 4096 + 2) * 12;
        let capacity = file_end + reloc_bound + self.cfg.file_align as usize;
        if capacity > u32::MAX as usize {
            bail!("the image would be larger than 4 GiB");
        }
        let mut output = crate::fileio::OutputFile::create(&path, capacity)
            .map_err(|e| err!("cannot create '{}': {e}", path.display()))?;
        let whole = output.bytes();

        // Batches of roughly equal size, a few per thread.
        let total: u64 = items.iter().map(|i| i.size as u64).sum();
        let nbatches = (rayon::current_num_threads() * 4).max(1) as u64;
        let target = (total / nbatches).max(64 * 1024);
        let mut groups: Vec<std::ops::Range<usize>> = Vec::new();
        let mut start = 0;
        let mut acc = 0u64;
        for (i, item) in items.iter().enumerate() {
            acc += item.size as u64;
            if acc >= target {
                groups.push(start..i + 1);
                start = i + 1;
                acc = 0;
            }
        }
        if start < items.len() {
            groups.push(start..items.len());
        }
        let mut batches: Vec<(std::ops::Range<usize>, &mut [u8], usize)> = Vec::new();
        let mut rest: &mut [u8] = &mut whole[..file_end];
        let mut consumed = 0usize;
        for (gi, g) in groups.iter().enumerate() {
            let begin = items[g.start].file_off as usize;
            let end = groups
                .get(gi + 1)
                .map_or(file_end, |n| items[n.start].file_off as usize);
            let tail = std::mem::take(&mut rest);
            let (_, tail) = tail.split_at_mut(begin - consumed);
            let (slice, tail) = tail.split_at_mut(end - begin);
            rest = tail;
            consumed = end;
            batches.push((g.clone(), slice, begin));
        }
        let results: Vec<Result<BaseRelocs>> = batches
            .into_par_iter()
            .map(|(range, slice, base)| {
                let mut br = BaseRelocs::default();
                for item in &items[range] {
                    let o = item.file_off as usize - base;
                    self.write_chunk(item.chunk, &mut slice[o..o + item.size as usize], &mut br)?;
                }
                Ok(br)
            })
            .collect();
        let mut entries: Vec<u64> = Vec::with_capacity(reloc_count);
        for r in results {
            let br = r?;
            entries.extend(
                br.dir64
                    .iter()
                    .map(|&r| ((r as u64) << 4) | IMAGE_REL_BASED_DIR64 as u64),
            );
            entries.extend(
                br.highlow
                    .iter()
                    .map(|&r| ((r as u64) << 4) | IMAGE_REL_BASED_HIGHLOW as u64),
            );
        }
        timer.phase("copy and relocate sections");

        // Base relocations.
        let relocatable = !self.cfg.fixed;
        let mut sections_written = layout.sections.len();
        let mut reloc_dir = (0u32, 0u32);
        let mut image_size = layout.end_rva;
        let mut file_len = file_end;
        if relocatable && !entries.is_empty() {
            entries.par_sort_unstable();
            entries.dedup();
            let data = encode_base_relocs(&entries);
            let raw = align_up(data.len() as u64, self.cfg.file_align as u64) as usize;
            let rva = layout.end_rva;
            whole[file_end..file_end + data.len()].copy_from_slice(&data);
            file_len = file_end + raw;
            let buf = &mut *whole;
            let h = SECTION_TABLE + 40 * sections_written;
            buf[h..h + 6].copy_from_slice(b".reloc");
            put32(buf, h + 8, data.len() as u32);
            put32(buf, h + 12, rva);
            put32(buf, h + 16, raw as u32);
            put32(buf, h + 20, file_end as u32);
            put32(
                buf,
                h + 36,
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ,
            );
            sections_written += 1;
            reloc_dir = (rva, data.len() as u32);
            image_size = align_up(
                rva as u64 + data.len() as u64,
                self.cfg.section_align as u64,
            ) as u32;
        }

        let buf = &mut whole[..file_len];

        // The exception table must be sorted by function address: the
        // unwinder binary-searches it.
        if let Some(pdata) = layout.sections.iter().find(|s| s.name == b".pdata")
            && pdata.vsize % 12 == 0
            && pdata.raw_size >= pdata.vsize
        {
            let region = &mut buf[pdata.file_off as usize..(pdata.file_off + pdata.vsize) as usize];
            let mut entries: Vec<[u8; 12]> = region.as_chunks::<12>().0.to_vec();
            entries.par_sort_by_key(|e| u32le(e, 0));
            region.as_chunks_mut::<12>().0.copy_from_slice(&entries);
        }

        // TLS: tell the loader how aligned the thread-local block must be.
        let tls = self.defined_rva(b"_tls_used");
        if let Some(rva) = tls
            && self.tls_align > 0
            && let Some(off) = file_offset(layout, rva + 36)
            && off + 4 <= buf.len()
        {
            let bits = (self.tls_align.trailing_zeros() + 1) << 20;
            let chars = (u32le(buf, off) & !IMAGE_SCN_ALIGN_MASK) | bits;
            put32(buf, off, chars);
        }

        // Data directories.
        let mut dirs = [(0u32, 0u32); 16];
        if let Some(_e) = &self.edata {
            dirs[0] = (self.synth[EDATA].rva, self.synth[EDATA].size);
        }
        if !self.dlls.is_empty() {
            dirs[1] = (self.synth[IDATA_DIR].rva, self.synth[IDATA_DIR].size);
            dirs[12] = (self.synth[IDATA_IAT].rva, self.synth[IDATA_IAT].size);
        }
        if let Some(p) = layout.sections.iter().find(|s| s.name == b".pdata") {
            dirs[3] = (p.rva, p.vsize);
        }
        dirs[5] = reloc_dir;
        if let Some(rva) = tls {
            dirs[9] = (rva, 0x28);
        }
        if let Some(rva) = self.defined_rva(b"_load_config_used")
            && let Some(off) = file_offset(layout, rva)
        {
            dirs[10] = (rva, u32le(buf, off));
        }

        self.write_headers(buf, layout, sections_written, image_size, entry_rva, &dirs);

        // A deterministic timestamp: a hash of the image, as /Brepro does.
        let stamp = match self.cfg.timestamp {
            Some(t) => t,
            None => xxhash_rust::xxh3::xxh3_64(buf) as u32,
        };
        put32(buf, COFF_HEADER + 4, stamp);
        if self.edata.is_some()
            && let Some(off) = file_offset(layout, self.synth[EDATA].rva)
        {
            put32(buf, off + 4, stamp);
        }
        if self.cfg.release_checksum {
            let sum = pe_checksum(buf, OPT_HEADER + 64);
            put32(buf, OPT_HEADER + 64, sum);
        }
        timer.phase("finish image");

        output.commit(file_len).map_err(|e| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                " (is the program still running?)"
            } else {
                ""
            };
            err!("cannot write '{}': {e}{hint}", path.display())
        })?;
        timer.phase("write output file");
        Ok(())
    }

    fn defined_rva(&self, name: &[u8]) -> Option<u32> {
        let id = self.symtab.find(name)?;
        let t = self.sym_target(id)?;
        (!t.absolute).then(|| (t.va - self.image_base) as u32)
    }

    fn write_headers(
        &self,
        buf: &mut [u8],
        layout: &Layout,
        nsections: usize,
        image_size: u32,
        entry_rva: u32,
        dirs: &[(u32, u32); 16],
    ) {
        let cfg = &self.cfg;
        // MS-DOS header and stub.
        buf[0..2].copy_from_slice(b"MZ");
        put16(buf, 2, PE_OFFSET as u16 % 512);
        put16(buf, 4, PE_OFFSET.div_ceil(512) as u16);
        put16(buf, 8, 4);
        put16(buf, 0x18, 0x40);
        put32(buf, 0x3C, PE_OFFSET as u32);
        buf[64..PE_OFFSET].copy_from_slice(&DOS_STUB);
        buf[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        // COFF header.
        let mut chars = 0x0002; // executable
        if cfg.large_address_aware {
            chars |= 0x0020;
        }
        if cfg.dll {
            chars |= 0x2000;
        }
        if cfg.fixed {
            chars |= 0x0001;
        }
        put16(buf, COFF_HEADER, IMAGE_FILE_MACHINE_AMD64);
        put16(buf, COFF_HEADER + 2, nsections as u16);
        put16(buf, COFF_HEADER + 16, 240);
        put16(buf, COFF_HEADER + 18, chars);

        // Optional header.
        let o = OPT_HEADER;
        let mut size_code = 0u32;
        let mut size_init = 0u32;
        let mut size_uninit = 0u32;
        let mut base_of_code = 0u32;
        for s in &layout.sections {
            if s.chars & IMAGE_SCN_CNT_CODE != 0 {
                size_code += s.raw_size;
                if base_of_code == 0 {
                    base_of_code = s.rva;
                }
            }
            if s.chars & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                size_init += s.raw_size;
            }
            if s.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                size_uninit += align_up(s.vsize as u64, cfg.file_align as u64) as u32;
            }
        }
        size_init += dirs[5].1.next_multiple_of(cfg.file_align);
        put16(buf, o, 0x20B);
        buf[o + 2] = 14;
        put32(buf, o + 4, size_code);
        put32(buf, o + 8, size_init);
        put32(buf, o + 12, size_uninit);
        put32(buf, o + 16, entry_rva);
        put32(buf, o + 20, base_of_code);
        put64(buf, o + 24, self.image_base);
        put32(buf, o + 32, cfg.section_align);
        put32(buf, o + 36, cfg.file_align);
        let (os_major, os_minor) = cfg.os_version.unwrap_or((6, 0));
        put16(buf, o + 40, os_major);
        put16(buf, o + 42, os_minor);
        put16(buf, o + 44, cfg.image_version.0);
        put16(buf, o + 46, cfg.image_version.1);
        let (ss_major, ss_minor) = cfg.subsystem_version.unwrap_or((6, 0));
        put16(buf, o + 48, ss_major);
        put16(buf, o + 50, ss_minor);
        put32(buf, o + 56, image_size);
        put32(buf, o + 60, layout.header_size);
        put16(buf, o + 68, self.subsystem.map_or(3, |s| s as u16));
        let mut dll_chars = 0u16;
        let dynamic = cfg.dynamic_base && !cfg.fixed;
        if cfg.high_entropy_va && dynamic && cfg.large_address_aware {
            dll_chars |= 0x0020;
        }
        if dynamic {
            dll_chars |= 0x0040;
        }
        if cfg.integrity_check {
            dll_chars |= 0x0080;
        }
        if cfg.nx_compat {
            dll_chars |= 0x0100;
        }
        if cfg.appcontainer {
            dll_chars |= 0x1000;
        }
        if cfg.terminal_server_aware.unwrap_or(!cfg.dll) {
            dll_chars |= 0x8000;
        }
        put16(buf, o + 70, dll_chars);
        put64(buf, o + 72, cfg.stack.0);
        put64(buf, o + 80, cfg.stack.1);
        put64(buf, o + 88, cfg.heap.0);
        put64(buf, o + 96, cfg.heap.1);
        put32(buf, o + 108, 16);
        for (i, (rva, size)) in dirs.iter().enumerate() {
            put32(buf, o + 112 + i * 8, *rva);
            put32(buf, o + 116 + i * 8, *size);
        }

        // Section table (`.reloc`'s entry was written already).
        for (i, s) in layout.sections.iter().enumerate() {
            let h = SECTION_TABLE + 40 * i;
            buf[h..h + s.name.len()].copy_from_slice(&s.name);
            put32(buf, h + 8, s.vsize);
            put32(buf, h + 12, s.rva);
            put32(buf, h + 16, s.raw_size);
            put32(buf, h + 20, s.file_off);
            let mut chars = s.chars;
            if chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
                chars &= !IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            }
            put32(buf, h + 36, chars);
        }
    }
}

/// The file offset of `rva`, if it is in a section's raw data.
fn file_offset(layout: &Layout, rva: u32) -> Option<usize> {
    layout
        .sections
        .iter()
        .find(|s| rva >= s.rva && rva < s.rva + s.raw_size)
        .map(|s| (s.file_off + (rva - s.rva)) as usize)
}

/// `.reloc` contents from sorted `(rva << 4) | type` entries: one block per
/// 4 KiB page, padded to a multiple of 4 bytes.
fn encode_base_relocs(entries: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 2 + 64);
    let mut i = 0;
    while i < entries.len() {
        let page = (entries[i] >> 4) as u32 & !0xFFF;
        let start = out.len();
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        while i < entries.len() && ((entries[i] >> 4) as u32 & !0xFFF) == page {
            let rva = (entries[i] >> 4) as u32;
            let ty = (entries[i] & 0xF) as u16;
            out.extend_from_slice(&((ty << 12) | (rva & 0xFFF) as u16).to_le_bytes());
            i += 1;
        }
        if (out.len() - start) % 4 != 0 {
            out.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());
        }
        let size = (out.len() - start) as u32;
        out[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
    }
    out
}

/// The PE checksum: a 16-bit one's-complement sum of the file (skipping the
/// checksum field) plus its length.
fn pe_checksum(buf: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, c) in buf.chunks(2).enumerate() {
        if i * 2 == checksum_off || i * 2 == checksum_off + 2 {
            continue;
        }
        let w = if c.len() == 2 {
            u16::from_le_bytes([c[0], c[1]])
        } else {
            c[0] as u16
        };
        sum += w as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(buf.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_relocation_blocks() {
        let e = |rva: u64| (rva << 4) | IMAGE_REL_BASED_DIR64 as u64;
        let out = encode_base_relocs(&[e(0x1008), e(0x1010), e(0x1FF8), e(0x3000)]);
        // Page 0x1000: 3 entries + 1 padding = 8 + 8 bytes.
        assert_eq!(u32le(&out, 0), 0x1000);
        assert_eq!(u32le(&out, 4), 16);
        assert_eq!(u16le(&out, 8), 0xA008);
        assert_eq!(u16le(&out, 12), 0xAFF8);
        assert_eq!(u16le(&out, 14), 0);
        // Page 0x3000: 1 entry + padding.
        assert_eq!(u32le(&out, 16), 0x3000);
        assert_eq!(u32le(&out, 20), 12);
        assert_eq!(out.len(), 28);
    }
}
