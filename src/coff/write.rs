//! Writing the image in place into a memory-mapped output, in parallel batches.

use std::sync::atomic::Ordering::Relaxed;

use rayon::prelude::*;

use super::arch::{self, BaseRel, RelocCtx, Target};
use super::layout::{ChunkRef, Layout, headers_before_sections};
use super::object::{NONE, ObjFile, Section};
use super::resolve::Linker;
use super::symtab::{Def, SymId};
use super::synth::*;
use super::*;
use crate::diag::{Result, Timer};
use crate::{bail, err};

#[derive(Default)]
struct BaseRelocs {
    dir64: Vec<u32>,
    highlow: Vec<u32>,
}

impl BaseRelocs {
    fn push(&mut self, kind: BaseRel, rva: u32) {
        match kind {
            BaseRel::None => {}
            BaseRel::Dir64 => self.dir64.push(rva),
            BaseRel::HighLow => self.highlow.push(rva),
        }
    }
}

const DOS_STUB: [u8; 56] = [
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
    0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x24, 0x00, 0x00,
];
const PE_OFFSET: usize = 64 + DOS_STUB.len();
const COFF_HEADER: usize = PE_OFFSET + 4;
const OPT_HEADER: usize = COFF_HEADER + 20;

pub const DEBUG_DIRECTORY_SIZE: u32 = 28;

struct Item {
    file_off: u32,
    size: u32,
    chunk: ChunkRef,
}

impl Linker<'_> {
    pub fn sym_target(&self, id: SymId) -> Option<Target> {
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
                let s = self.live_section(obj, sec)?;
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
            Def::LocalImport { slot } => synth(LOCAL_IMPORTS, slot * self.machine.ptr_size()),
            Def::ImageBase => Target {
                va: ib,
                absolute: false,
                out: NONE,
            },
            Def::Undefined | Def::Lazy { .. } | Def::Common { .. } => return None,
        })
    }

    pub fn live_section(&self, obj: u32, sec: u32) -> Option<&Section<'_>> {
        let s = &self.objs[obj as usize].sections[sec as usize];
        let s = match s.folded_into {
            Some((o, f)) => &self.objs[o as usize].sections[f as usize],
            None => s,
        };
        s.is_live().then_some(s)
    }

    pub fn reloc_target(&self, obj: &ObjFile, idx: u32) -> Option<Target> {
        match obj.sym_ids.get(idx as usize) {
            Some(&id) if id != NONE => self.sym_target(id),
            _ => {
                let raw = obj.raw_sym(idx)?;
                if raw.section > 0 {
                    let s = obj.sections.get((raw.section - 1) as usize)?;
                    let s = match s.folded_into {
                        Some((o, sec)) => &self.objs[o as usize].sections[sec as usize],
                        None => s,
                    };
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

    pub fn reloc_ctx(&self) -> RelocCtx<'_> {
        RelocCtx {
            image_base: self.image_base,
            out_rvas: &self.out_rvas,
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
        let m = self.machine;
        let ctx = self.reloc_ctx();
        for r in sec.relocs.as_chunks::<10>().0 {
            let ty = u16le(r, 8);
            if m.is_absolute_reloc(ty) {
                continue;
            }
            let off = u32le(r, 0).wrapping_sub(sec.va) as usize;
            let idx = u32le(r, 4);
            if off + m.reloc_width(ty) > buf.len() {
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
            match arch::apply(m, &ctx, ty, buf, off, t, p) {
                Ok(kind) => br.push(kind, (p - ib) as u32),
                Err(msg) => bail!(
                    "{}: {msg} (relocation in section {} against {})",
                    obj.name,
                    String::from_utf8_lossy(sec.name),
                    crate::diag::symbol(obj.sym_name(idx))
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

    fn write_ptr(&self, dst: &mut [u8], off: usize, v: u64) {
        if self.machine.is64() {
            put64(dst, off, v);
        } else {
            put32(dst, off, v as u32);
        }
    }

    fn write_synth(&self, k: usize, dst: &mut [u8], br: &mut BaseRelocs) -> Result<()> {
        let rva = |k: usize| self.synth[k].rva;
        let ptr = self.machine.ptr_size() as usize;
        let ptr_rel = if self.machine.is64() {
            BaseRel::Dir64
        } else {
            BaseRel::HighLow
        };
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
                let ordinal_flag = if self.machine.is64() {
                    1 << 63
                } else {
                    1 << 31
                };
                for dll in &self.dlls {
                    for (j, &i) in dll.imports.iter().enumerate() {
                        let imp = &self.imports[i as usize];
                        let v = match imp.name {
                            Some(_) => (rva(IDATA_HINTS) + imp.hint_off) as u64,
                            None => ordinal_flag | imp.ordinal_or_hint as u64,
                        };
                        self.write_ptr(dst, dll.table_off as usize + j * ptr, v);
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
                let ib = self.image_base;
                let thunks = rva(THUNKS);
                let size = self.machine.thunk_size() as usize;
                for imp in &self.imports {
                    if imp.thunk_live.load(Relaxed) {
                        let o = imp.thunk_off as usize;
                        let thunk = ib + (thunks + imp.thunk_off) as u64;
                        let slot = ib + (rva(IDATA_IAT) + imp.iat_off) as u64;
                        if arch::write_thunk(self.machine, &mut dst[o..o + size], thunk, slot) {
                            br.push(BaseRel::HighLow, thunks + imp.thunk_off + 2);
                        }
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
                    self.write_ptr(dst, slot * ptr, t.va);
                    if !t.absolute {
                        br.push(ptr_rel, rva(LOCAL_IMPORTS) + (slot * ptr) as u32);
                    }
                }
            }
            EDATA => self.write_edata(dst)?,
            SAFESEH => {
                let mut rvas: Vec<u32> = self
                    .seh_handlers
                    .iter()
                    .map(|&(obj, sec, value)| {
                        self.objs[obj as usize].sections[sec as usize].rva + value
                    })
                    .collect();
                rvas.sort_unstable();
                for (i, r) in rvas.iter().enumerate() {
                    put32(dst, i * 4, *r);
                }
            }
            RSRC => {
                if let Some(r) = &self.rsrc {
                    r.write(dst, rva(RSRC));
                }
            }
            DEBUG_DIR => {
                if let Some(pdb) = &self.pdb {
                    let data_size = dst.len() as u32 - DEBUG_DIRECTORY_SIZE;
                    put32(dst, 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
                    put32(dst, 16, data_size);
                    put32(dst, 20, rva(DEBUG_DIR) + DEBUG_DIRECTORY_SIZE);
                    let cv = DEBUG_DIRECTORY_SIZE as usize;
                    dst[cv..cv + 4].copy_from_slice(b"RSDS");
                    put32(dst, cv + 20, 1); // age
                    let path = pdb.rsds_path.as_bytes();
                    dst[cv + 24..cv + 24 + path.len()].copy_from_slice(path);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn write_edata(&self, dst: &mut [u8]) -> Result<()> {
        let e = self.edata.as_ref().unwrap();
        let base = self.synth[EDATA].rva;
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
        Ok(())
    }

    pub fn write(&self, layout: &Layout, timer: &mut Timer) -> Result<()> {
        let path = self.output_path();
        let m = self.machine;
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
        reloc_count += self.local_imports.len() + self.imports.len();
        let file_end = layout.file_end as usize;
        let reloc_bound = reloc_count * 2 + (layout.end_rva as usize / 4096 + 2) * 12;
        let capacity = file_end + reloc_bound + self.cfg.file_align as usize;
        if capacity > u32::MAX as usize {
            bail!("the image would be larger than 4 GiB");
        }
        let mut output = crate::fileio::OutputFile::create(&path, capacity)
            .map_err(|e| err!("cannot create '{}': {e}", path.display()))?;
        let whole = output.bytes();

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

        let (results, pdb) = rayon::join(
            || {
                batches
                    .into_par_iter()
                    .map(|(range, slice, base)| {
                        let mut br = BaseRelocs::default();
                        for item in &items[range] {
                            let o = item.file_off as usize - base;
                            self.write_chunk(
                                item.chunk,
                                &mut slice[o..o + item.size as usize],
                                &mut br,
                            )?;
                        }
                        Ok(br)
                    })
                    .collect::<Vec<Result<BaseRelocs>>>()
            },
            || {
                self.pdb
                    .as_ref()
                    .map(|_| super::pdb::build(self, layout))
                    .transpose()
            },
        );
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
        let pdb = pdb?;
        if let Some(p) = &pdb {
            for (what, d) in &p.timings {
                timer.detail(format!("PDB: {:.2} ms {what}", d.as_secs_f64() * 1e3));
            }
        }
        timer.phase(if self.pdb.is_some() {
            "copy and relocate sections, build PDB"
        } else {
            "copy and relocate sections"
        });

        let section_table = headers_before_sections(m) as usize;
        let mut nsections = layout.sections.len();
        let mut reloc_dir = (0u32, 0u32);
        let mut image_size = layout.end_rva;
        let mut file_len = file_end;
        if !self.cfg.fixed && !entries.is_empty() {
            entries.par_sort_unstable();
            entries.dedup();
            let data = encode_base_relocs(&entries);
            let raw = align_up(data.len() as u64, self.cfg.file_align as u64) as usize;
            let rva = layout.end_rva;
            whole[file_end..file_end + data.len()].copy_from_slice(&data);
            file_len = file_end + raw;
            let buf = &mut *whole;
            let h = section_table + 40 * nsections;
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
            nsections += 1;
            reloc_dir = (rva, data.len() as u32);
            image_size = align_up(
                rva as u64 + data.len() as u64,
                self.cfg.section_align as u64,
            ) as u32;
        }

        let buf = &mut whole[..file_len];

        // The exception table must be sorted by function address: the
        // unwinder binary-searches it.
        if let (Some(entry), Some(pdata)) = (
            m.pdata_entry_size(),
            layout.sections.iter().find(|s| s.name == b".pdata"),
        ) && (pdata.vsize as usize).is_multiple_of(entry)
            && pdata.raw_size >= pdata.vsize
        {
            let region = &mut buf[pdata.file_off as usize..(pdata.file_off + pdata.vsize) as usize];
            if entry == 12 {
                let mut v: Vec<[u8; 12]> = region.as_chunks::<12>().0.to_vec();
                v.par_sort_by_key(|e| u32le(e, 0));
                region.as_chunks_mut::<12>().0.copy_from_slice(&v);
            } else {
                let mut v: Vec<[u8; 8]> = region.as_chunks::<8>().0.to_vec();
                v.par_sort_by_key(|e| u32le(e, 0));
                region.as_chunks_mut::<8>().0.copy_from_slice(&v);
            }
        }

        let tls = self.defined_rva("_tls_used");
        let tls_chars = if m.is64() { 36 } else { 20 };
        if let Some(rva) = tls
            && self.tls_align > 0
            && let Some(off) = file_offset(layout, rva + tls_chars)
            && off + 4 <= buf.len()
        {
            let bits = (self.tls_align.trailing_zeros() + 1) << 20;
            let chars = (u32le(buf, off) & !IMAGE_SCN_ALIGN_MASK) | bits;
            put32(buf, off, chars);
        }

        let mut dirs = [(0u32, 0u32); 16];
        if self.edata.is_some() {
            dirs[0] = (self.synth[EDATA].rva, self.synth[EDATA].size);
        }
        if !self.dlls.is_empty() {
            dirs[1] = (self.synth[IDATA_DIR].rva, self.synth[IDATA_DIR].size);
            dirs[12] = (self.synth[IDATA_IAT].rva, self.synth[IDATA_IAT].size);
        }
        if let Some(r) = layout.sections.iter().find(|s| s.name == b".rsrc") {
            dirs[2] = (r.rva, r.vsize);
        }
        if m.pdata_entry_size().is_some()
            && let Some(p) = layout.sections.iter().find(|s| s.name == b".pdata")
        {
            dirs[3] = (p.rva, p.vsize);
        }
        dirs[5] = reloc_dir;
        if self.pdb.is_some() {
            dirs[6] = (self.synth[DEBUG_DIR].rva, DEBUG_DIRECTORY_SIZE);
        }
        if let Some(rva) = tls {
            dirs[9] = (rva, m.tls_directory_size());
        }
        if let Some(rva) = self.defined_rva("_load_config_used")
            && let Some(off) = file_offset(layout, rva)
        {
            dirs[10] = (rva, u32le(buf, off));
        }

        self.write_headers(buf, layout, nsections, image_size, entry_rva, &dirs);

        let debug_dir = file_offset(layout, self.synth[DEBUG_DIR].rva);
        let mut pdb_file = None;
        if let (Some(pdb), Some(dd)) = (pdb, debug_dir) {
            put32(buf, dd + 24, (dd + DEBUG_DIRECTORY_SIZE as usize) as u32);
            let headers = buf[section_table..section_table + 40 * nsections].to_vec();
            let file = pdb.finish(self, &headers)?;
            let cv = dd + DEBUG_DIRECTORY_SIZE as usize;
            buf[cv + 4..cv + 20].copy_from_slice(&file.guid);
            pdb_file = Some(file);
        }

        // Deterministic timestamp: a hash of the image, as /Brepro does.
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
        if let (true, Some(dd)) = (self.pdb.is_some(), debug_dir) {
            put32(buf, dd + 4, stamp);
        }
        if self.cfg.release_checksum {
            let sum = pe_checksum(buf, OPT_HEADER + 64);
            put32(buf, OPT_HEADER + 64, sum);
        }
        timer.phase("finish image");

        let (image, pdb) = rayon::join(
            || {
                output.commit(file_len).map_err(|e| {
                    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        " (is the program still running?)"
                    } else {
                        ""
                    };
                    err!("cannot write '{}': {e}{hint}", path.display())
                })
            },
            || pdb_file.map(|f| f.write(stamp)).transpose(),
        );
        image?;
        pdb?;
        timer.phase("write output files");
        Ok(())
    }

    pub fn defined_rva(&self, name: &str) -> Option<u32> {
        let id = self.special(name)?;
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
        let m = self.machine;
        let is64 = m.is64();
        let large_address_aware = cfg.large_address_aware.unwrap_or(is64);
        buf[0..2].copy_from_slice(b"MZ");
        put16(buf, 2, PE_OFFSET as u16 % 512);
        put16(buf, 4, PE_OFFSET.div_ceil(512) as u16);
        put16(buf, 8, 4);
        put16(buf, 0x18, 0x40);
        put32(buf, 0x3C, PE_OFFSET as u32);
        buf[64..PE_OFFSET].copy_from_slice(&DOS_STUB);
        buf[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let mut chars = 0x0002; // executable
        if large_address_aware {
            chars |= 0x0020;
        }
        if !is64 {
            chars |= 0x0100; // 32-bit machine
        }
        if cfg.dll {
            chars |= 0x2000;
        }
        if cfg.fixed {
            chars |= 0x0001;
        }
        put16(buf, COFF_HEADER, m.coff());
        put16(buf, COFF_HEADER + 2, nsections as u16);
        put16(buf, COFF_HEADER + 16, m.optional_header_size() as u16);
        put16(buf, COFF_HEADER + 18, chars);

        let o = OPT_HEADER;
        let mut size_code = 0u32;
        let mut size_init = 0u32;
        let mut size_uninit = 0u32;
        let mut base_of_code = 0u32;
        let mut base_of_data = 0u32;
        for s in &layout.sections {
            if s.chars & IMAGE_SCN_CNT_CODE != 0 {
                size_code += s.raw_size;
                if base_of_code == 0 {
                    base_of_code = s.rva;
                }
            } else if base_of_data == 0 {
                base_of_data = s.rva;
            }
            if s.chars & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                size_init += s.raw_size;
            }
            if s.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                size_uninit += align_up(s.vsize as u64, cfg.file_align as u64) as u32;
            }
        }
        size_init += dirs[5].1.next_multiple_of(cfg.file_align);
        put16(buf, o, if is64 { 0x20B } else { 0x10B });
        buf[o + 2] = 14;
        put32(buf, o + 4, size_code);
        put32(buf, o + 8, size_init);
        put32(buf, o + 12, size_uninit);
        put32(buf, o + 16, entry_rva);
        put32(buf, o + 20, base_of_code);
        let o2 = if is64 {
            put64(buf, o + 24, self.image_base);
            o + 32
        } else {
            put32(buf, o + 24, base_of_data);
            put32(buf, o + 28, self.image_base as u32);
            o + 32
        };
        put32(buf, o2, cfg.section_align);
        put32(buf, o2 + 4, cfg.file_align);
        let default_version = (6, 0);
        let (os_major, os_minor) = cfg.os_version.unwrap_or(default_version);
        put16(buf, o2 + 8, os_major);
        put16(buf, o2 + 10, os_minor);
        put16(buf, o2 + 12, cfg.image_version.0);
        put16(buf, o2 + 14, cfg.image_version.1);
        let (ss_major, ss_minor) = cfg.subsystem_version.unwrap_or(default_version);
        put16(buf, o2 + 16, ss_major);
        put16(buf, o2 + 18, ss_minor);
        put32(buf, o2 + 24, image_size);
        put32(buf, o2 + 28, layout.header_size);
        put16(buf, o2 + 36, self.subsystem.map_or(3, |s| s as u16));
        let mut dll_chars = 0u16;
        let dynamic = cfg.dynamic_base && !cfg.fixed;
        if is64 && cfg.high_entropy_va && dynamic && large_address_aware {
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
        put16(buf, o2 + 38, dll_chars);
        let dirs_at = if is64 {
            put64(buf, o2 + 40, cfg.stack.0);
            put64(buf, o2 + 48, cfg.stack.1);
            put64(buf, o2 + 56, cfg.heap.0);
            put64(buf, o2 + 64, cfg.heap.1);
            put32(buf, o2 + 76, 16);
            o2 + 80
        } else {
            put32(buf, o2 + 40, cfg.stack.0 as u32);
            put32(buf, o2 + 44, cfg.stack.1 as u32);
            put32(buf, o2 + 48, cfg.heap.0 as u32);
            put32(buf, o2 + 52, cfg.heap.1 as u32);
            put32(buf, o2 + 60, 16);
            o2 + 64
        };
        for (i, (rva, size)) in dirs.iter().enumerate() {
            put32(buf, dirs_at + i * 8, *rva);
            put32(buf, dirs_at + 4 + i * 8, *size);
        }
        debug_assert_eq!(
            dirs_at + 128,
            OPT_HEADER + m.optional_header_size() as usize
        );

        let table = headers_before_sections(m) as usize;
        for (i, s) in layout.sections.iter().enumerate() {
            let h = table + 40 * i;
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

pub fn file_offset(layout: &Layout, rva: u32) -> Option<usize> {
    layout
        .sections
        .iter()
        .find(|s| rva >= s.rva && rva < s.rva + s.raw_size)
        .map(|s| (s.file_off + (rva - s.rva)) as usize)
}

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
        assert_eq!(u32le(&out, 0), 0x1000);
        assert_eq!(u32le(&out, 4), 16);
        assert_eq!(u16le(&out, 8), 0xA008);
        assert_eq!(u16le(&out, 12), 0xAFF8);
        assert_eq!(u16le(&out, 14), 0);
        assert_eq!(u32le(&out, 16), 0x3000);
        assert_eq!(u32le(&out, 20), 12);
        assert_eq!(out.len(), 28);
    }
}
