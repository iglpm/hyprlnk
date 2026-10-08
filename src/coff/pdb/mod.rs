//! PDB output (`/DEBUG`), built in parallel while the image is written.

mod gsi;
mod hash;
mod modules;
mod msf;
mod strtab;
mod types;

use std::collections::HashMap;
use std::path::PathBuf;

use rayon::prelude::*;

use super::layout::{ChunkRef, Layout};
use super::resolve::Linker;
use super::symtab::Def;
use super::synth::{DEBUG_DIR, SynthChunk};
use super::write::DEBUG_DIRECTORY_SIZE;
use super::*;
use crate::diag::Result;

pub struct PdbPlan {
    pub path: PathBuf,
    pub rsds_path: String,
}

pub fn create_debug_directory(l: &mut Linker) {
    if !l.cfg.debug {
        return;
    }
    let out = l.output_path();
    let path = l
        .cfg
        .pdb
        .clone()
        .unwrap_or_else(|| out.with_extension("pdb"));
    let path = std::path::absolute(&path).unwrap_or(path);
    let rsds_path = match &l.cfg.pdb_alt_path {
        Some(alt) => {
            let pdb_name = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let ext = out
                .extension()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default();
            alt.replace("%_PDB%", &pdb_name).replace("%_EXT%", &ext)
        }
        None => path.display().to_string(),
    };
    l.synth[DEBUG_DIR] = SynthChunk {
        size: DEBUG_DIRECTORY_SIZE + 24 + rsds_path.len() as u32 + 1,
        align: 4,
        ..Default::default()
    };
    l.pdb = Some(PdbPlan { path, rsds_path });
}

pub struct PdbBuild {
    merged: types::Merged,
    tpi_hashes: Vec<u32>,
    ipi_hashes: Vec<u32>,
    modules: Vec<modules::ModuleOut>,
    names: Vec<u8>,
    gsi: gsi::Gsi,
    contribs: Vec<[u32; 5]>,
    pub timings: Vec<(&'static str, std::time::Duration)>,
    injected: Vec<(u32, u32, Vec<u8>)>,
}

pub struct PdbFile {
    pub guid: [u8; 16],
    path: PathBuf,
    streams: Vec<Vec<u8>>,
    named: Vec<(Vec<u8>, u32)>,
}

const STREAM_TPI_HASH: u16 = 5;
const STREAM_IPI_HASH: u16 = 6;
const STREAM_NAMES: u16 = 7;
const STREAM_LINK_INFO: u16 = 8;
const STREAM_GLOBALS: u16 = 9;
const STREAM_PUBLICS: u16 = 10;
const STREAM_SYMBOLS: u16 = 11;
const STREAM_SECTION_HEADERS: u16 = 12;
const FIRST_MODULE_STREAM: u16 = 13;

pub fn build(l: &Linker, layout: &Layout) -> Result<PdbBuild> {
    let mut timings = Vec::new();
    let mut t = std::time::Instant::now();
    let mut lap = |what: &'static str, t: &mut std::time::Instant| {
        timings.push((what, t.elapsed()));
        *t = std::time::Instant::now();
    };
    let obj_types: Vec<Option<types::ObjTypes>> = l
        .objs
        .par_iter()
        .map(|o| {
            let s = o.debug_t?;
            let sec = &o.sections[s as usize];
            (!sec.discarded).then(|| types::hash_object(sec.data))
        })
        .collect();
    lap("hash types", &mut t);
    let merged = types::merge(&obj_types);
    lap("merge types", &mut t);
    drop(obj_types);

    let ((tpi_hashes, ipi_hashes), mut mods) = rayon::join(
        || {
            let hashes = |data: &[u8], offsets: &[u32]| -> Vec<u32> {
                let data = &data[types::STREAM_HEADER..];
                offsets
                    .par_iter()
                    .enumerate()
                    .map(|(i, &o)| {
                        let end = offsets.get(i + 1).map_or(data.len(), |&e| e as usize);
                        types::record_hash(&data[o as usize..end]) % 0x3FFFF
                    })
                    .collect()
            };
            (
                hashes(&merged.tpi, &merged.tpi_offsets),
                hashes(&merged.ipi, &merged.ipi_offsets),
            )
        },
        || {
            l.objs
                .par_iter()
                .enumerate()
                .map(|(oi, o)| modules::build(l, oi, o, &merged))
                .collect::<Vec<_>>()
        },
    );
    lap("module streams", &mut t);
    mods.push(linker_module(l, layout));

    let mut names = strtab::StringTable::new();
    let mut injected = Vec::new();
    for path in &l.cfg.natvis {
        match std::fs::read(path) {
            Ok(content) => {
                let name = path.to_string_lossy().into_owned();
                let vname = name.to_lowercase().replace('/', "\\");
                let ni = names.insert(name.as_bytes());
                let vni = names.insert(vname.as_bytes());
                injected.push((ni, vni, content));
            }
            Err(e) => {
                crate::diag::warn(format!("cannot read natvis file '{}': {e}", path.display()))
            }
        }
    }
    let offsets: Vec<Vec<u32>> = mods
        .iter()
        .map(|m| {
            m.string_patches
                .iter()
                .map(|(_, s)| names.insert(s))
                .collect()
        })
        .collect();
    mods.par_iter_mut()
        .zip(offsets.par_iter())
        .for_each(|(m, offs)| {
            for ((pos, _), &o) in m.string_patches.iter().zip(offs) {
                let p = *pos as usize;
                m.stream[p..p + 4].copy_from_slice(&o.to_le_bytes());
            }
        });

    let globals: Vec<Vec<u8>> = mods
        .iter_mut()
        .map(|m| std::mem::take(&mut m.globals))
        .collect();
    let publics = collect_publics(l);
    lap("strings, publics", &mut t);
    let gsi = gsi::build(publics, &globals);
    lap("globals and publics streams", &mut t);

    let linker_mod = l.objs.len() as u32;
    let mut contribs = Vec::new();
    for (i, sec) in layout.sections.iter().enumerate() {
        for &c in &sec.chunks {
            let (size, _, _) = l.chunk_info(c);
            if size == 0 {
                continue;
            }
            let (rva, chars, module) = match c {
                ChunkRef::Sec { obj, sec: s } => {
                    let s = &l.objs[obj as usize].sections[s as usize];
                    (s.rva, s.chars, obj)
                }
                ChunkRef::Synth(k) => (l.synth[k as usize].rva, sec.chars, linker_mod),
            };
            contribs.push([i as u32 + 1, rva - sec.rva, size, chars, module]);
        }
    }

    lap("section contributions", &mut t);
    Ok(PdbBuild {
        timings,
        merged,
        tpi_hashes,
        ipi_hashes,
        modules: mods,
        names: names.finish(),
        injected,
        gsi,
        contribs,
    })
}

fn collect_publics(l: &Linker) -> Vec<gsi::Public> {
    let ib = l.image_base;
    l.symtab
        .syms
        .par_iter()
        .enumerate()
        .filter_map(|(id, s)| {
            let function = match s.def {
                Def::Defined { .. } => s.function,
                Def::Thunk { .. } => true,
                Def::Synthetic { .. } | Def::Import { .. } | Def::LocalImport { .. } => false,
                _ => return None,
            };
            let mut name: &[u8] = s.name;
            if name.starts_with(b"__") {
                if l.machine == super::arch::Machine::X86 {
                    name = &name[1..];
                }
                if name.starts_with(b"__profd_")
                    || name.starts_with(b"__profc_")
                    || name.starts_with(b"__covrec_")
                {
                    return None;
                }
            }
            let t = l.sym_target(id as u32)?;
            if t.absolute || t.out == u32::MAX {
                return None;
            }
            Some(gsi::Public {
                name: s.name.to_vec(),
                segment: t.out as u16 + 1,
                offset: (t.va - ib) as u32 - l.out_rvas[t.out as usize],
                flags: if function { 2 } else { 0 },
            })
        })
        .collect()
}

fn linker_module(l: &Linker, layout: &Layout) -> modules::ModuleOut {
    let mut syms = 4u32.to_le_bytes().to_vec();
    let mut objname = 0u32.to_le_bytes().to_vec();
    objname.extend_from_slice(b"* Linker *\0");
    syms.extend(modules::record(modules::S_OBJNAME, &objname));
    let mut compile = Vec::new();
    compile.extend_from_slice(&7u32.to_le_bytes()); // CV_CFL_LINK
    let cpu: u16 = match l.machine {
        super::arch::Machine::X64 => 0xD0,
        super::arch::Machine::Arm64 => 0xF6,
        super::arch::Machine::X86 => 0x07,
    };
    compile.extend_from_slice(&cpu.to_le_bytes());
    for v in [0u16, 0, 0, 0, 14, 10, 0, 0] {
        compile.extend_from_slice(&v.to_le_bytes());
    }
    compile.extend_from_slice(format!("hyprlnk {}\0", crate::VERSION).as_bytes());
    syms.extend(modules::record(modules::S_COMPILE3, &compile));
    for (i, s) in layout.sections.iter().enumerate() {
        let mut c = Vec::new();
        c.extend_from_slice(&(i as u16 + 1).to_le_bytes());
        c.push(12); // 4 KiB alignment (log2)
        c.push(0);
        c.extend_from_slice(&s.rva.to_le_bytes());
        c.extend_from_slice(&s.vsize.to_le_bytes());
        c.extend_from_slice(&s.chars.to_le_bytes());
        c.extend_from_slice(&s.name);
        c.push(0);
        syms.extend(modules::record(modules::S_SECTION, &c));
    }
    let sym_bytes = syms.len() as u32;
    syms.extend_from_slice(&0u32.to_le_bytes());
    modules::ModuleOut {
        stream: syms,
        sym_bytes,
        ..Default::default()
    }
}

fn type_stream(
    mut s: Vec<u8>,
    offsets: &[u32],
    hash_stream: u16,
    hashes: &[u32],
) -> (Vec<u8>, Vec<u8>) {
    let record_bytes = s.len() - types::STREAM_HEADER;
    let mut index_offsets = Vec::new();
    let mut last_block = u32::MAX;
    for (i, &o) in offsets.iter().enumerate() {
        if o / 8192 != last_block {
            last_block = o / 8192;
            index_offsets.push((0x1000 + i as u32, o));
        }
    }
    let mut hash = Vec::with_capacity(hashes.len() * 4 + index_offsets.len() * 8);
    for h in hashes {
        hash.extend_from_slice(&h.to_le_bytes());
    }
    for (ti, o) in &index_offsets {
        hash.extend_from_slice(&ti.to_le_bytes());
        hash.extend_from_slice(&o.to_le_bytes());
    }
    let mut h = Vec::with_capacity(types::STREAM_HEADER);
    let put = |h: &mut Vec<u8>, v: u32| h.extend_from_slice(&v.to_le_bytes());
    put(&mut h, 20_040_203); // V80
    put(&mut h, types::STREAM_HEADER as u32);
    put(&mut h, 0x1000);
    put(&mut h, 0x1000 + offsets.len() as u32);
    put(&mut h, record_bytes as u32);
    h.extend_from_slice(&hash_stream.to_le_bytes());
    h.extend_from_slice(&0xFFFFu16.to_le_bytes());
    put(&mut h, 4); // hash key size
    put(&mut h, 0x3FFFF); // buckets
    put(&mut h, 0);
    put(&mut h, hashes.len() as u32 * 4);
    put(&mut h, hashes.len() as u32 * 4);
    put(&mut h, index_offsets.len() as u32 * 8);
    put(&mut h, (hashes.len() * 4 + index_offsets.len() * 8) as u32);
    put(&mut h, 0);
    s[..types::STREAM_HEADER].copy_from_slice(&h);
    (s, hash)
}

impl PdbBuild {
    pub fn finish(mut self, l: &Linker, headers: &[u8]) -> Result<PdbFile> {
        let plan = l.pdb.as_ref().expect("a PDB was planned");
        let (tpi, tpi_hash) = type_stream(
            std::mem::take(&mut self.merged.tpi),
            &self.merged.tpi_offsets,
            STREAM_TPI_HASH,
            &self.tpi_hashes,
        );
        let (ipi, ipi_hash) = type_stream(
            std::mem::take(&mut self.merged.ipi),
            &self.merged.ipi_offsets,
            STREAM_IPI_HASH,
            &self.ipi_hashes,
        );

        let mut next = FIRST_MODULE_STREAM;
        let stream_of: Vec<u16> = self
            .modules
            .iter()
            .map(|m| {
                if m.has_stream() {
                    next += 1;
                    next - 1
                } else {
                    0xFFFF
                }
            })
            .collect();

        let dbi = self.dbi(l, headers, &stream_of);
        let mut streams: Vec<Vec<u8>> = vec![
            Vec::new(), // 0: old directory
            Vec::new(), // 1: info (written last)
            tpi,
            dbi,
            ipi,
            tpi_hash,
            ipi_hash,
            self.names,
            Vec::new(), // /LinkInfo
            self.gsi.globals,
            self.gsi.publics,
            self.gsi.records,
            headers.to_vec(),
        ];
        for m in self.modules {
            if m.has_stream() {
                streams.push(m.stream);
            }
        }
        let mut named: Vec<(Vec<u8>, u32)> = vec![
            (b"/LinkInfo".to_vec(), STREAM_LINK_INFO as u32),
            (b"/names".to_vec(), STREAM_NAMES as u32),
        ];
        if !self.injected.is_empty() {
            named.push((b"/src/headerblock".to_vec(), streams.len() as u32));
            streams.push(source_header_block(&self.injected));
            for (_, vni, content) in self.injected {
                let vname = string_at(&streams[STREAM_NAMES as usize], vni);
                let mut stream_name = b"/src/files/".to_vec();
                stream_name.extend_from_slice(&vname);
                named.push((stream_name, streams.len() as u32));
                streams.push(content);
            }
        }

        let digests: Vec<u128> = streams
            .par_iter()
            .map(|s| xxhash_rust::xxh3::xxh3_128(s))
            .collect();
        let mut all = Vec::with_capacity(digests.len() * 16);
        for d in &digests {
            all.extend_from_slice(&d.to_le_bytes());
        }
        let mut guid = xxhash_rust::xxh3::xxh3_128(&all).to_le_bytes();
        guid[7] = (guid[7] & 0x0F) | 0x40;
        guid[8] = (guid[8] & 0x3F) | 0x80;
        Ok(PdbFile {
            guid,
            path: plan.path.clone(),
            streams,
            named,
        })
    }

    fn dbi(&self, l: &Linker, headers: &[u8], stream_of: &[u16]) -> Vec<u8> {
        let nmods = self.modules.len();
        let linker_mod = nmods - 1;

        let mut first_contrib: Vec<Option<[u32; 5]>> = vec![None; nmods];
        for c in &self.contribs {
            let m = c[4] as usize;
            if first_contrib[m].is_none() {
                first_contrib[m] = Some(*c);
            }
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let absolute = |p: &str| -> String {
            let path = std::path::Path::new(p);
            if path.is_absolute() {
                p.to_string()
            } else {
                cwd.join(path).display().to_string()
            }
        };
        let mut modi = Vec::new();
        for (m, module) in self.modules.iter().enumerate() {
            let (mod_name, obj_name) = if m == linker_mod {
                ("* Linker *".to_string(), String::new())
            } else {
                let name = &l.objs[m].name;
                match (name.rfind('('), name.ends_with(')')) {
                    (Some(p), true) => (
                        name[p + 1..name.len() - 1].to_string(),
                        absolute(&name[..p]),
                    ),
                    _ => {
                        let a = absolute(name);
                        (a.clone(), a)
                    }
                }
            };
            modi.extend_from_slice(&0u32.to_le_bytes());
            write_contrib(
                &mut modi,
                first_contrib[m].unwrap_or([0, 0, 0, 0, m as u32]),
            );
            modi.extend_from_slice(&0u16.to_le_bytes()); // flags
            modi.extend_from_slice(&stream_of[m].to_le_bytes());
            let has = module.has_stream();
            modi.extend_from_slice(&(if has { module.sym_bytes } else { 0 }).to_le_bytes());
            modi.extend_from_slice(&0u32.to_le_bytes()); // C11
            modi.extend_from_slice(&module.c13_bytes.to_le_bytes());
            modi.extend_from_slice(&(module.files.len().min(0xFFFF) as u16).to_le_bytes());
            modi.extend_from_slice(&[0, 0]);
            modi.extend_from_slice(&[0; 12]);
            modi.extend_from_slice(mod_name.as_bytes());
            modi.push(0);
            modi.extend_from_slice(obj_name.as_bytes());
            modi.push(0);
            while modi.len() % 4 != 0 {
                modi.push(0);
            }
        }

        let mut sc = Vec::with_capacity(4 + 28 * self.contribs.len());
        sc.extend_from_slice(&(0xEFFE_0000u32 + 19_970_605).to_le_bytes());
        for c in &self.contribs {
            write_contrib(&mut sc, *c);
        }

        let nsec = headers.len() / 40;
        let mut smap = Vec::with_capacity(4 + 20 * (nsec + 1));
        smap.extend_from_slice(&((nsec + 1) as u16).to_le_bytes());
        smap.extend_from_slice(&((nsec + 1) as u16).to_le_bytes());
        for i in 0..=nsec {
            let (flags, len) = if i < nsec {
                let h = &headers[i * 40..i * 40 + 40];
                let chars = u32le(h, 36);
                let mut f = 0x0108u16; // 32-bit address, selector
                if chars & IMAGE_SCN_MEM_READ != 0 {
                    f |= 1;
                }
                if chars & IMAGE_SCN_MEM_WRITE != 0 {
                    f |= 2;
                }
                if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
                    f |= 4;
                }
                (f, u32le(h, 8))
            } else {
                (0x0208u16, u32::MAX)
            };
            smap.extend_from_slice(&flags.to_le_bytes());
            smap.extend_from_slice(&0u16.to_le_bytes()); // ovl
            smap.extend_from_slice(&0u16.to_le_bytes()); // group
            smap.extend_from_slice(&(i as u16 + 1).to_le_bytes()); // frame
            smap.extend_from_slice(&0xFFFFu16.to_le_bytes());
            smap.extend_from_slice(&0xFFFFu16.to_le_bytes());
            smap.extend_from_slice(&0u32.to_le_bytes());
            smap.extend_from_slice(&len.to_le_bytes());
        }

        let mut fi = Vec::new();
        let total: usize = self.modules.iter().map(|m| m.files.len()).sum();
        fi.extend_from_slice(&(nmods.min(0xFFFF) as u16).to_le_bytes());
        fi.extend_from_slice(&(total.min(0xFFFF) as u16).to_le_bytes());
        let mut first = 0usize;
        for m in &self.modules {
            fi.extend_from_slice(&(first.min(0xFFFF) as u16).to_le_bytes());
            first += m.files.len();
        }
        for m in &self.modules {
            fi.extend_from_slice(&(m.files.len().min(0xFFFF) as u16).to_le_bytes());
        }
        let mut name_buf: Vec<u8> = Vec::new();
        let mut name_offsets: HashMap<&[u8], u32> = HashMap::new();
        for m in &self.modules {
            for f in &m.files {
                let o = *name_offsets.entry(f.as_slice()).or_insert_with(|| {
                    let o = name_buf.len() as u32;
                    name_buf.extend_from_slice(f);
                    name_buf.push(0);
                    o
                });
                fi.extend_from_slice(&o.to_le_bytes());
            }
        }
        fi.extend_from_slice(&name_buf);
        while fi.len() % 4 != 0 {
            fi.push(0);
        }

        let ec = strtab::StringTable::new().finish();
        let mut dbg = Vec::new();
        for i in 0..11u16 {
            let v = if i == 5 {
                STREAM_SECTION_HEADERS
            } else {
                0xFFFF
            };
            dbg.extend_from_slice(&v.to_le_bytes());
        }

        let mut d = Vec::with_capacity(
            64 + modi.len() + sc.len() + smap.len() + fi.len() + ec.len() + dbg.len(),
        );
        d.extend_from_slice(&(-1i32).to_le_bytes());
        d.extend_from_slice(&19_990_903u32.to_le_bytes()); // V70
        d.extend_from_slice(&1u32.to_le_bytes()); // age
        d.extend_from_slice(&STREAM_GLOBALS.to_le_bytes());
        d.extend_from_slice(&(0x8000u16 | (14 << 8) | 11).to_le_bytes()); // build 14.11
        d.extend_from_slice(&STREAM_PUBLICS.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // PDB DLL version
        d.extend_from_slice(&STREAM_SYMBOLS.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // PDB DLL rebuild
        for size in [
            modi.len(),
            sc.len(),
            smap.len(),
            fi.len(),
            0,
            0,
            dbg.len(),
            ec.len(),
        ] {
            d.extend_from_slice(&(size as u32).to_le_bytes());
        }
        d.extend_from_slice(&0u16.to_le_bytes()); // flags
        d.extend_from_slice(&l.machine.coff().to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        debug_assert_eq!(d.len(), 64);
        d.extend_from_slice(&modi);
        d.extend_from_slice(&sc);
        d.extend_from_slice(&smap);
        d.extend_from_slice(&fi);
        d.extend_from_slice(&ec);
        d.extend_from_slice(&dbg);
        d
    }
}

fn write_contrib(out: &mut Vec<u8>, c: [u32; 5]) {
    out.extend_from_slice(&(c[0] as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&c[1].to_le_bytes());
    out.extend_from_slice(&c[2].to_le_bytes());
    out.extend_from_slice(&c[3].to_le_bytes());
    out.extend_from_slice(&(c[4] as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}

impl PdbFile {
    pub fn write(mut self, stamp: u32) -> Result<()> {
        self.streams[1] = info_stream(stamp, &self.guid, &self.named);
        let refs: Vec<&[u8]> = self.streams.iter().map(|s| s.as_slice()).collect();
        msf::write(&self.path, &refs)
    }
}

fn info_stream(signature: u32, guid: &[u8; 16], named: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&20_000_404u32.to_le_bytes()); // VC70
    s.extend_from_slice(&signature.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes()); // age
    s.extend_from_slice(guid);
    let mut strings = Vec::new();
    let mut entries = Vec::new();
    for (name, stream) in named {
        let off = strings.len() as u32;
        strings.extend_from_slice(name);
        strings.push(0);
        let hash = hash::hash_string_v1(name) as u16 as u32;
        entries.push((off, hash, stream.to_le_bytes().to_vec()));
    }
    s.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    s.extend_from_slice(&strings);
    s.extend_from_slice(&hash_table(&entries));
    s.extend_from_slice(&20_140_508u32.to_le_bytes()); // feature: VC140
    s
}

fn hash_table(entries: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    // The capacity the reference grows to: start at 1; whenever an insert
    // reaches the maximum load (2/3 + 1), double that load.
    let max_load = |cap: u32| cap * 2 / 3 + 1;
    let mut cap = 1u32;
    for count in 1..=entries.len() as u32 {
        if count >= max_load(cap) {
            cap = max_load(cap) * 2;
        }
    }
    let mut buckets: Vec<Option<usize>> = vec![None; cap as usize];
    for (i, (_, hash, _)) in entries.iter().enumerate() {
        let mut b = (*hash % cap) as usize;
        while buckets[b].is_some() {
            b = (b + 1) % cap as usize;
        }
        buckets[b] = Some(i);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.extend_from_slice(&cap.to_le_bytes());
    let last = buckets.iter().rposition(|b| b.is_some());
    let words = last.map_or(0, |l| l / 32 + 1);
    out.extend_from_slice(&(words as u32).to_le_bytes());
    for w in 0..words {
        let mut word = 0u32;
        for bit in 0..32 {
            if buckets.get(w * 32 + bit).is_some_and(|b| b.is_some()) {
                word |= 1 << bit;
            }
        }
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // deleted: none
    for i in buckets.iter().flatten() {
        let (key, _, value) = &entries[*i];
        out.extend_from_slice(&key.to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

fn string_at(names: &[u8], offset: u32) -> Vec<u8> {
    let s = names.get(12 + offset as usize..).unwrap_or(&[]);
    s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())].to_vec()
}

fn source_header_block(injected: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    const SRC_VER_ONE: u32 = 19_980_827;
    let entries: Vec<(u32, u32, Vec<u8>)> = injected
        .iter()
        .map(|(ni, vni, content)| {
            let mut e = Vec::with_capacity(40);
            e.extend_from_slice(&40u32.to_le_bytes()); // size of this entry
            e.extend_from_slice(&SRC_VER_ONE.to_le_bytes());
            e.extend_from_slice(&hash::hash_buffer_v8(content).to_le_bytes());
            e.extend_from_slice(&(content.len() as u32).to_le_bytes());
            e.extend_from_slice(&ni.to_le_bytes());
            e.extend_from_slice(&1u32.to_le_bytes()); // object name
            e.extend_from_slice(&vni.to_le_bytes());
            e.extend_from_slice(&[0; 12]); // compression, virtual, padding, reserved
            (*vni, *vni, e)
        })
        .collect();
    let table = hash_table(&entries);
    let mut s = Vec::with_capacity(64 + table.len());
    s.extend_from_slice(&SRC_VER_ONE.to_le_bytes());
    s.extend_from_slice(&((64 + table.len()) as u32).to_le_bytes());
    s.extend_from_slice(&[0; 56]);
    s.extend_from_slice(&table);
    s
}
