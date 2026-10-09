//! Writing the image: header and load commands, sections copied and relocated in parallel
//! batches, LINKEDIT built alongside, then the UUID and the ad-hoc code signature.

use std::collections::HashMap;

use rayon::prelude::*;

use super::arch::{self, Kind};
use super::config::{OutputKind, UuidMode};
use super::dyldinfo::{self, Bind, ExportEntry};
use super::fixups::{self, Fixup};
use super::layout::{Content, Layout};
use super::linkedit::{SymtabPlan, split_pieces};
use super::object::*;
use super::resolve::Linker;
use super::symtab::{Def, SymId, Synthetic};
use super::*;
use crate::diag::{Result, Timer};
use crate::{bail, err};

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CS_ADHOC: u32 = 0x2;
const CS_LINKER_SIGNED: u32 = 0x2_0000;
const CS_SUPPORTSEXECSEG: u32 = 0x2_0400;
const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
const CS_HASHTYPE_SHA256: u8 = 2;
const CS_PAGE_SHIFT: u8 = 12;
const CS_FIXED_HEADERS: u64 = 12 + 8 + 88;

/// Where each LINKEDIT piece goes: (file offset, size).
#[derive(Default, Clone, Copy)]
struct Piece {
    off: u64,
    size: u64,
}

#[derive(Default)]
struct Linkedit {
    rebase: Piece,
    bind: Piece,
    weak_bind: Piece,
    chained: Piece,
    exports: Piece,
    function_starts: Piece,
    data_in_code: Piece,
    symtab: Piece,
    indirect: Piece,
    strtab: Piece,
    signature: Piece,
    end: u64,
}

struct Prepared {
    rebase: Vec<u8>,
    bind: Vec<u8>,
    weak_bind: Vec<u8>,
    chain: Option<(fixups::ChainPlan, Vec<Fixup>)>,
    exports: Vec<u8>,
    function_starts: Vec<u8>,
    data_in_code: Vec<u8>,
    symtab: SymtabPlan,
    flags_weak_defines: bool,
    flags_binds_to_weak: bool,
}

impl Linker<'_> {
    fn seg_of(&self, layout: &Layout, addr: u64) -> Option<usize> {
        layout.segments.iter().position(|g| {
            g.name != b"__PAGEZERO" && addr >= g.vmaddr && addr < g.vmaddr + g.vmsize.max(1)
        })
    }

    fn file_off(&self, layout: &Layout, addr: u64) -> usize {
        let g = &layout.segments[self.seg_of(layout, addr).unwrap()];
        (g.fileoff + (addr - g.vmaddr)) as usize
    }

    fn dylib_ordinal(&self, id: SymId) -> i32 {
        let s = self.symtab.get(id);
        if self.needs_weak_bind(s) {
            return BIND_SPECIAL_DYLIB_WEAK_LOOKUP;
        }
        if self.cfg.flat_namespace {
            return BIND_SPECIAL_DYLIB_FLAT_LOOKUP;
        }
        match s.def {
            Def::Dylib { dylib } => self.dylibs[dylib as usize].ordinal as i32,
            Def::DynamicLookup => BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
            _ => 0,
        }
    }

    fn got_slot(&self, layout: &Layout, id: SymId) -> Option<u64> {
        let s = self.symtab.get(id);
        (s.got != u32::MAX).then(|| layout.sections[layout.got.unwrap()].addr + 8 * s.got as u64)
    }

    /// The slot a stub jumps through: its `__auth_got` slot on arm64e, its GOT slot elsewhere.
    fn stub_slot(&self, layout: &Layout, id: SymId) -> Option<u64> {
        match layout.auth_got {
            Some(a) => {
                let s = self.symtab.get(id);
                (s.auth_got != u32::MAX).then(|| layout.sections[a].addr + 8 * s.auth_got as u64)
            }
            None => self.got_slot(layout, id),
        }
    }

    /// Rebases, binds and weak binds: the sites found while marking, and the linker's own pointers.
    /// Pointers to this image's exported weak definitions are rebased and listed for coalescing
    /// (with chained fixups, bound by weak lookup instead).
    #[allow(clippy::type_complexity)]
    fn collect_fixups(
        &self,
        layout: &Layout,
    ) -> (
        Vec<u64>,
        Vec<(u64, SymId, i64)>,
        Vec<(u64, SymId, i64)>,
        HashMap<u64, u32>,
    ) {
        let mut auths: HashMap<u64, u32> = HashMap::new();
        let mut rebases: Vec<u64> = Vec::new();
        let mut binds: Vec<(u64, SymId, i64)> = Vec::new();
        let mut weak: Vec<(u64, SymId, i64)> = Vec::new();
        let chained = layout.chained;
        let mut pointer = |addr: u64, id: SymId, addend: i64, rebases: &mut Vec<u64>| {
            let s = self.symtab.get(id);
            if self.is_preemptible(s) {
                binds.push((addr, id, addend));
                if s.weak_def && !chained {
                    weak.push((addr, id, addend));
                }
            } else if self.needs_weak_bind(s) {
                if chained {
                    binds.push((addr, id, addend));
                } else {
                    rebases.push(addr);
                    weak.push((addr, id, addend));
                }
            } else if !matches!(s.def, Def::Absolute { .. }) {
                rebases.push(addr);
            }
        };
        for s in &self.sites {
            let addr = self.objs[s.obj as usize].atoms[s.atom as usize].addr + s.off as u64;
            if s.auth != 0 {
                auths.insert(addr, s.auth);
            }
            if s.is_rebase() {
                rebases.push(addr);
            } else {
                pointer(addr, s.bind, s.addend, &mut rebases);
            }
        }
        if let Some(g) = layout.got {
            let base = layout.sections[g].addr;
            for (i, &id) in self.got.iter().enumerate() {
                pointer(base + 8 * i as u64, id, 0, &mut rebases);
            }
        }
        if let Some(a) = layout.auth_got {
            // Signed with IA and the slot's address, as the stubs' `braa x16, x17` expects.
            let base = layout.sections[a].addr;
            for (i, &id) in self.auth_got.iter().enumerate() {
                let addr = base + 8 * i as u64;
                auths.insert(addr, super::gc::auth(0, true, 0));
                pointer(addr, id, 0, &mut rebases);
            }
        }
        if let Some(t) = layout.tlvp {
            let base = layout.sections[t].addr;
            for (i, &id) in self.tlvps.iter().enumerate() {
                binds.push((base + 8 * i as u64, id, 0));
            }
        }
        if let Some(o) = layout.objc {
            let base = layout.sections[o.selrefs].addr + o.selrefs_base;
            rebases.extend((0..self.objc_stubs.len() as u64).map(|i| base + 8 * i));
        }
        rebases.par_sort_unstable();
        rebases.dedup();
        binds.par_sort_unstable_by_key(|b| (b.1, b.0));
        weak.par_sort_unstable_by(|a, b| {
            self.symtab
                .get(a.1)
                .name
                .cmp(self.symtab.get(b.1).name)
                .then(a.0.cmp(&b.0))
        });
        (rebases, binds, weak, auths)
    }

    fn export_entries(&self, layout: &Layout) -> Vec<ExportEntry<'_>> {
        let base = layout.image_base;
        let mut v: Vec<ExportEntry> = (0..self.symtab.len() as SymId)
            .into_par_iter()
            .filter_map(|id| {
                let s = self.symtab.get(id);
                if s.private_extern || !self.is_exported_name(s.name) {
                    return None;
                }
                let live = match s.def {
                    Def::Defined { obj, atom, .. } => {
                        self.objs[obj as usize].atoms[atom as usize].is_live()
                    }
                    Def::Synthetic(Synthetic::Header) | Def::Synthetic(Synthetic::Common(_)) => {
                        true
                    }
                    Def::Absolute { .. } => true,
                    _ => false,
                };
                if !live {
                    return None;
                }
                let mut flags = if s.tlv {
                    dyldinfo::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
                } else if matches!(s.def, Def::Absolute { .. }) {
                    dyldinfo::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
                } else {
                    dyldinfo::EXPORT_SYMBOL_FLAGS_KIND_REGULAR
                };
                if s.weak_def {
                    flags |= dyldinfo::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
                }
                let addr = match s.def {
                    Def::Absolute { value } => value,
                    _ => self.sym_addr(layout, id)? - base,
                };
                Some(ExportEntry {
                    name: s.name,
                    flags,
                    addr,
                })
            })
            .collect();
        dyldinfo::sort_by_name(&mut v);
        v.dedup_by(|a, b| a.name == b.name);
        v
    }

    fn prepare(&self, layout: &Layout, details: &mut Vec<String>) -> Result<Prepared> {
        let time = |t: std::time::Instant| t.elapsed().as_secs_f64() * 1e3;
        let ((fix, exports), (symtab, (function_starts, data_in_code))) = rayon::join(
            || {
                rayon::join(
                    || {
                        let t = std::time::Instant::now();
                        let (rebases, binds, weak, auths) = self.collect_fixups(layout);
                        (
                            self.encode_fixups(layout, rebases, binds, weak, auths),
                            time(t),
                        )
                    },
                    || {
                        let t = std::time::Instant::now();
                        if self.cfg.kind == OutputKind::Execute && self.cfg.no_exported_symbols {
                            return (Vec::new(), 0.0, 0.0);
                        }
                        let entries = self.export_entries(layout);
                        let sorted = time(t);
                        (dyldinfo::build_trie(&entries), sorted, time(t))
                    },
                )
            },
            || {
                rayon::join(
                    || {
                        let t = std::time::Instant::now();
                        (self.plan_symtab(layout), time(t))
                    },
                    || {
                        let t = std::time::Instant::now();
                        (
                            (self.function_starts(layout), self.data_in_code(layout)),
                            time(t),
                        )
                    },
                )
            },
        );
        let (fix, t_fix) = fix;
        let (exports, t_sort, t_trie) = exports;
        let (symtab, t_sym) = symtab;
        let ((function_starts, data_in_code), t_fs) = (function_starts, data_in_code);
        details.push(format!(
            "LINKEDIT: fixups {t_fix:.2} ms, exports {t_sort:.2} + trie {:.2} ms, symtab plan {t_sym:.2} ms, function starts {t_fs:.2} ms",
            t_trie - t_sort
        ));
        let (rebase, bind, weak_bind, chain, binds_to_weak) = fix?;
        let weak_defines = self
            .symtab
            .syms
            .iter()
            .any(|s| self.needs_weak_bind(s) && s.has(super::symtab::LIVE));
        Ok(Prepared {
            rebase,
            bind,
            weak_bind,
            chain,
            exports,
            function_starts,
            data_in_code,
            symtab,
            flags_weak_defines: weak_defines,
            flags_binds_to_weak: binds_to_weak,
        })
    }

    #[allow(clippy::type_complexity)]
    fn encode_fixups(
        &self,
        layout: &Layout,
        rebases: Vec<u64>,
        binds: Vec<(u64, SymId, i64)>,
        weak: Vec<(u64, SymId, i64)>,
        auths: HashMap<u64, u32>,
    ) -> Result<(
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<(fixups::ChainPlan, Vec<Fixup>)>,
        bool,
    )> {
        let binds_to_weak = binds
            .iter()
            .chain(&weak)
            .any(|b| self.symtab.get(b.1).weak_def);
        if layout.chained {
            let mut imports: Vec<fixups::Import> = Vec::new();
            let mut index: HashMap<(SymId, i64), u32> = HashMap::new();
            let mut fx: Vec<Fixup> = Vec::with_capacity(rebases.len() + binds.len());
            for &a in &rebases {
                fx.push(Fixup {
                    addr: a,
                    import: u32::MAX,
                    target: 0,
                    addend: 0,
                    auth: auths.get(&a).copied().unwrap_or(0),
                });
            }
            let limit = if self.arch == super::config::Arch::Arm64e {
                1 << 18
            } else {
                256
            };
            let small = binds.iter().all(|b| (0..limit).contains(&b.2));
            for &(a, id, addend) in &binds {
                let key = (id, if small { 0 } else { addend });
                let imp = *index.entry(key).or_insert_with(|| {
                    let s = self.symtab.get(id);
                    // Weak definitions, here or in a dylib, are coalesced by dyld's weak lookup.
                    let ordinal = if s.weak_def {
                        BIND_SPECIAL_DYLIB_WEAK_LOOKUP
                    } else {
                        self.dylib_ordinal(id)
                    };
                    imports.push(fixups::Import {
                        ordinal,
                        name: s.name,
                        weak: s.weak_import(),
                        addend: key.1,
                    });
                    imports.len() as u32 - 1
                });
                fx.push(Fixup {
                    addr: a,
                    import: imp,
                    target: 0,
                    addend,
                    auth: auths.get(&a).copied().unwrap_or(0),
                });
            }
            fx.par_sort_unstable_by_key(|f| f.addr);
            if self.arch != super::config::Arch::Arm64e && fx.iter().any(|f| f.auth != 0) {
                bail!("signed pointers (ARM64_RELOC_AUTHENTICATED_POINTER) need -arch arm64e");
            }
            let plan = fixups::plan(
                layout,
                &fx,
                &imports,
                self.arch == super::config::Arch::Arm64e,
            )?;
            return Ok((
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Some((plan, fx)),
                binds_to_weak,
            ));
        }
        let seg_off = |a: u64| -> (u8, u64) {
            let gi = self.seg_of(layout, a).unwrap();
            (gi as u8, a - layout.segments[gi].vmaddr)
        };
        let locs: Vec<(u8, u64)> = rebases.iter().map(|&a| seg_off(a)).collect();
        if !auths.is_empty() {
            bail!("signed pointers need chained fixups (-fixup_chains)");
        }
        let rebase = dyldinfo::encode_rebases(&locs);
        let bl: Vec<Bind> = binds
            .iter()
            .map(|&(a, id, addend)| {
                let (seg, off) = seg_off(a);
                let s = self.symtab.get(id);
                Bind {
                    seg,
                    off,
                    ordinal: self.dylib_ordinal(id),
                    name: s.name,
                    flags: if s.weak_import() {
                        dyldinfo::BIND_SYMBOL_FLAGS_WEAK_IMPORT
                    } else {
                        0
                    },
                    addend,
                }
            })
            .collect();
        let bind = dyldinfo::encode_binds(&bl);
        let overrides: Vec<&[u8]> = self
            .symtab
            .syms
            .iter()
            .filter(|s| s.overrides_weak && s.has(super::symtab::LIVE) && !s.private_extern)
            .map(|s| s.name)
            .collect();
        let wl: Vec<Bind> = weak
            .iter()
            .map(|&(a, id, addend)| {
                let (seg, off) = seg_off(a);
                Bind {
                    seg,
                    off,
                    ordinal: 0,
                    name: self.symtab.get(id).name,
                    flags: 0,
                    addend,
                }
            })
            .collect();
        let weak_bind = dyldinfo::encode_weak_binds(&overrides, &wl);
        Ok((rebase, bind, weak_bind, None, binds_to_weak))
    }

    fn plan_linkedit(&self, layout: &Layout, p: &Prepared) -> Linkedit {
        let mut le = Linkedit::default();
        let mut off = layout.segments[layout.linkedit].fileoff;
        let mut take = |size: u64| {
            let piece = Piece { off, size };
            off += size;
            piece
        };
        if let Some((plan, _)) = &p.chain {
            le.chained = take(plan.blob.len() as u64);
        } else {
            le.rebase = take(p.rebase.len() as u64);
            le.bind = take(p.bind.len() as u64);
            le.weak_bind = take(p.weak_bind.len() as u64);
        }
        le.exports = take(p.exports.len() as u64);
        le.function_starts = take(p.function_starts.len() as u64);
        le.data_in_code = take(p.data_in_code.len() as u64);
        le.symtab = take(p.symtab.nsyms as u64 * 16);
        le.indirect = take(align_up(p.symtab.indirect.len() as u64 * 4, 8));
        le.strtab = take(p.symtab.strsize);
        if layout.signed {
            off = align_up(off, 16);
            let name = self.signature_identifier();
            let headers = align_up(CS_FIXED_HEADERS + name.len() as u64 + 1, 16);
            let blocks = off.div_ceil(4096);
            le.signature = Piece {
                off,
                size: headers + blocks * 32,
            };
            off += le.signature.size;
        }
        le.end = off;
        le
    }

    fn signature_identifier(&self) -> String {
        let out = self
            .cfg
            .final_output
            .clone()
            .unwrap_or_else(|| self.cfg.output.display().to_string());
        out.rsplit('/').next().unwrap_or(&out).to_string()
    }

    /// The image and LINKEDIT are built side by side in two buffers; the file is written by
    /// helper threads while the code signature is computed, all but the first page (the
    /// UUID's) and the signature itself, which go last.
    pub fn write(&self, layout: &Layout, timer: &mut Timer) -> Result<()> {
        let li = layout.segments[layout.linkedit].fileoff as usize;
        let mut image = vec![0u8; li];
        let (header_end, linkedit) = rayon::join(
            || self.write_image(layout, &mut image),
            || -> Result<_> {
                let mut details = Vec::new();
                let prepared = self.prepare(layout, &mut details)?;
                let le = self.plan_linkedit(layout, &prepared);
                let mut buf = vec![0u8; le.end as usize - li];
                self.write_linkedit(layout, &mut buf, &le, &prepared, li as u64)?;
                Ok((prepared, le, buf, details))
            },
        );
        let header_end = header_end?;
        let (prepared, le, mut linkedit, details) = linkedit?;
        for d in details {
            timer.detail(d);
        }
        self.write_header(layout, &mut image[..header_end], &le, &prepared)?;
        if let Some((plan, fx)) = &prepared.chain {
            fixups::apply(&mut image, fx, plan, layout.page, |a| {
                self.file_off(layout, a)
            })?;
        }
        timer.phase("write sections and LINKEDIT");

        let path = self.output_path();
        let io = |e: std::io::Error| err!("cannot write '{}': {e}", path.display());
        let out = crate::fileio::PartsFile::create(path, le.end, 0o777).map_err(io)?;
        let sig_at = if layout.signed {
            (le.signature.off as usize) - li
        } else {
            linkedit.len()
        };
        // The first page holds the UUID; write everything after it now.
        let first = 4096
            .min(image.len())
            .max(align_up(self.uuid_offset(layout).unwrap_or(0) as u64 + 16, 4096) as usize)
            .min(image.len());
        let (body, sig) = linkedit.split_at_mut(sig_at);
        let (head, rest) = image.split_at_mut(first);
        let rest = &*rest;
        let body_ro = &*body;
        let (written, signed) = std::thread::scope(|s| {
            let writer = s.spawn(|| -> std::io::Result<()> {
                out.write_parallel(rest, first as u64)?;
                out.write_parallel(body_ro, li as u64)
            });
            let r = (|| -> Result<()> {
                if let Some(at) = self.uuid_offset(layout) {
                    let uuid = match self.cfg.uuid {
                        UuidMode::Random => random_uuid(),
                        _ => content_uuid(&[&*head, rest, body_ro]),
                    };
                    head[at..at + 16].copy_from_slice(&uuid);
                }
                if layout.signed {
                    self.sign(layout, &[&*head, rest, body_ro], sig)?;
                }
                Ok(())
            })();
            (writer.join().unwrap(), r)
        });
        written.map_err(io)?;
        signed?;
        out.write_at(head, 0).map_err(io)?;
        out.write_at(sig, (li + sig_at) as u64).map_err(io)?;
        timer.phase("UUID, code signature and file");
        out.commit().map_err(io)?;
        if crate::EXIT_AFTER_LINK.load(std::sync::atomic::Ordering::Relaxed) {
            std::mem::forget(image);
            std::mem::forget(linkedit);
        }
        Ok(())
    }

    fn uuid_offset(&self, layout: &Layout) -> Option<usize> {
        if self.cfg.uuid == UuidMode::None {
            return None;
        }
        // Mirrors write_load_commands: segments, dyld info, symtab, dysymtab, dylinker/id.
        let mut off = 32usize;
        for g in &layout.segments {
            off += 72 + 80 * g.sections.len();
        }
        off += if layout.chained { 32 } else { 48 };
        off += 24 + 80;
        match self.cfg.kind {
            OutputKind::Execute => {
                off += align_up(12 + layout::LC_DYLINKER_PATH.len() as u64 + 1, 8) as usize
            }
            OutputKind::Dylib => off += layout::dylib_cmd_size(&self.install_name()) as usize,
            OutputKind::Bundle => {}
        }
        Some(off + 8)
    }

    fn header_flags(&self, layout: &Layout, p: &Prepared) -> u32 {
        let mut f = MH_DYLDLINK;
        if !self.cfg.flat_namespace {
            f |= MH_TWOLEVEL | MH_NOUNDEFS;
        } else {
            f |= MH_FORCE_FLAT;
        }
        if self.cfg.kind == OutputKind::Execute && self.cfg.is_pie() {
            f |= MH_PIE;
        }
        if layout
            .sections
            .iter()
            .any(|s| s.flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES)
        {
            f |= MH_HAS_TLV_DESCRIPTORS;
        }
        if p.flags_weak_defines {
            f |= MH_WEAK_DEFINES;
        }
        if p.flags_binds_to_weak {
            f |= MH_BINDS_TO_WEAK;
        }
        if self.cfg.kind == OutputKind::Dylib
            && !self
                .dylibs
                .iter()
                .any(|d| d.ordinal != 0 && d.flags.reexport)
        {
            f |= MH_NO_REEXPORTED_DYLIBS;
        }
        if self.cfg.application_extension {
            f |= MH_APP_EXTENSION_SAFE;
        }
        f
    }

    fn write_header(
        &self,
        layout: &Layout,
        out: &mut [u8],
        le: &Linkedit,
        p: &Prepared,
    ) -> Result<()> {
        put32(out, 0, MH_MAGIC_64);
        put32(out, 4, self.arch.cputype());
        put32(out, 8, self.arch.cpusubtype());
        put32(
            out,
            12,
            match self.cfg.kind {
                OutputKind::Execute => MH_EXECUTE,
                OutputKind::Dylib => MH_DYLIB,
                OutputKind::Bundle => MH_BUNDLE,
            },
        );
        put32(out, 16, layout.ncmds);
        put32(out, 20, layout.sizeofcmds as u32);
        put32(out, 24, self.header_flags(layout, p));
        put32(out, 28, 0);
        let mut w = Cmds { out, at: 32, n: 0 };
        let linkedit_size = le.end - layout.segments[layout.linkedit].fileoff;
        for (gi, g) in layout.segments.iter().enumerate() {
            let (filesize, vmsize) = if gi == layout.linkedit {
                (linkedit_size, align_up(linkedit_size, layout.page))
            } else {
                (g.filesize, g.vmsize)
            };
            let start = w.begin(LC_SEGMENT_64, 72 + 80 * g.sections.len() as u32);
            w.name16(start + 8, &g.name);
            w.u64(start + 24, g.vmaddr);
            w.u64(start + 32, vmsize);
            w.u64(start + 40, g.fileoff);
            w.u64(start + 48, filesize);
            w.u32(start + 56, g.maxprot);
            w.u32(start + 60, g.initprot);
            w.u32(start + 64, g.sections.len() as u32);
            w.u32(start + 68, g.flags);
            for (k, &si) in g.sections.iter().enumerate() {
                let s = &layout.sections[si];
                let h = start + 72 + 80 * k;
                w.name16(h, &s.sectname);
                w.name16(h + 16, &s.segname);
                w.u64(h + 32, s.addr);
                w.u64(h + 40, s.size);
                w.u32(
                    h + 48,
                    if s.is_zerofill() {
                        0
                    } else {
                        s.file_off as u32
                    },
                );
                w.u32(h + 52, s.align as u32);
                w.u32(h + 64, s.flags);
                w.u32(h + 68, s.reserved1);
                w.u32(h + 72, s.reserved2);
            }
        }
        if layout.chained {
            let s = w.begin(LC_DYLD_CHAINED_FIXUPS, 16);
            w.u32(s + 8, le.chained.off as u32);
            w.u32(s + 12, le.chained.size as u32);
            let s = w.begin(LC_DYLD_EXPORTS_TRIE, 16);
            w.u32(
                s + 8,
                if le.exports.size > 0 {
                    le.exports.off as u32
                } else {
                    0
                },
            );
            w.u32(s + 12, le.exports.size as u32);
        } else {
            let s = w.begin(LC_DYLD_INFO_ONLY, 48);
            let piece = |p: Piece| {
                if p.size > 0 {
                    (p.off as u32, p.size as u32)
                } else {
                    (0, 0)
                }
            };
            let (ro, rs) = piece(le.rebase);
            let (bo, bs) = piece(le.bind);
            let (wo, ws) = piece(le.weak_bind);
            let (eo, es) = piece(le.exports);
            w.u32(s + 8, ro);
            w.u32(s + 12, rs);
            w.u32(s + 16, bo);
            w.u32(s + 20, bs);
            w.u32(s + 24, wo);
            w.u32(s + 28, ws);
            w.u32(s + 40, eo);
            w.u32(s + 44, es);
        }
        let st = &p.symtab;
        let s = w.begin(LC_SYMTAB, 24);
        w.u32(s + 8, le.symtab.off as u32);
        w.u32(s + 12, st.nsyms);
        w.u32(s + 16, le.strtab.off as u32);
        w.u32(s + 20, st.strsize as u32);
        let s = w.begin(LC_DYSYMTAB, 80);
        w.u32(s + 8, 0);
        w.u32(s + 12, st.nlocal);
        w.u32(s + 16, st.iextdef);
        w.u32(s + 20, st.nextdef);
        w.u32(s + 24, st.iundef);
        w.u32(s + 28, st.nundef);
        if !st.indirect.is_empty() {
            w.u32(s + 56, le.indirect.off as u32);
            w.u32(s + 60, st.indirect.len() as u32);
        }
        match self.cfg.kind {
            OutputKind::Execute => {
                let s = w.begin(
                    LC_LOAD_DYLINKER,
                    align_up(12 + layout::LC_DYLINKER_PATH.len() as u64 + 1, 8) as u32,
                );
                w.u32(s + 8, 12);
                w.bytes(s + 12, layout::LC_DYLINKER_PATH);
            }
            OutputKind::Dylib => {
                let name = self.install_name();
                let s = w.begin(LC_ID_DYLIB, layout::dylib_cmd_size(&name) as u32);
                w.u32(s + 8, 24);
                w.u32(s + 12, 1);
                w.u32(
                    s + 16,
                    if self.cfg.current_version == 0 {
                        0x1_0000
                    } else {
                        self.cfg.current_version
                    },
                );
                w.u32(
                    s + 20,
                    if self.cfg.compat_version == 0 {
                        0x1_0000
                    } else {
                        self.cfg.compat_version
                    },
                );
                w.bytes(s + 24, name.as_bytes());
            }
            OutputKind::Bundle => {}
        }
        if self.cfg.uuid != UuidMode::None {
            w.begin(LC_UUID, 24);
        }
        if layout.build_version {
            let s = w.begin(LC_BUILD_VERSION, 32);
            w.u32(s + 8, self.cfg.platform);
            w.u32(s + 12, self.cfg.min_version);
            w.u32(s + 16, self.cfg.sdk_version);
            w.u32(s + 20, 1);
            w.u32(s + 24, TOOL_LD);
            w.u32(s + 28, tool_version());
        } else {
            let cmd = match self.cfg.platform {
                PLATFORM_IOS | PLATFORM_IOSSIMULATOR => LC_VERSION_MIN_IPHONEOS,
                PLATFORM_TVOS | PLATFORM_TVOSSIMULATOR => LC_VERSION_MIN_TVOS,
                PLATFORM_WATCHOS | PLATFORM_WATCHOSSIMULATOR => LC_VERSION_MIN_WATCHOS,
                _ => LC_VERSION_MIN_MACOSX,
            };
            let s = w.begin(cmd, 16);
            w.u32(s + 8, self.cfg.min_version);
            w.u32(s + 12, self.cfg.sdk_version);
        }
        let s = w.begin(LC_SOURCE_VERSION, 16);
        w.u64(s + 8, self.cfg.source_version);
        if self.cfg.kind == OutputKind::Execute {
            let e = self.entry.ok_or_else(|| err!("no entry point"))?;
            let addr = self.sym_addr(layout, e).ok_or_else(|| {
                err!(
                    "entry point {} is not defined in the image",
                    crate::diag::symbol(self.symtab.get(e).name)
                )
            })?;
            let s = w.begin(LC_MAIN, 24);
            w.u64(s + 8, addr - layout.image_base);
            w.u64(s + 16, self.cfg.stack_size);
        }
        if let Some(u) = &self.cfg.umbrella {
            let s = w.begin(
                LC_SUB_FRAMEWORK,
                align_up(12 + u.len() as u64 + 1, 8) as u32,
            );
            w.u32(s + 8, 12);
            w.bytes(s + 12, u.as_bytes());
        }
        for c in &self.cfg.allowable_clients {
            let s = w.begin(LC_SUB_CLIENT, align_up(12 + c.len() as u64 + 1, 8) as u32);
            w.u32(s + 8, 12);
            w.bytes(s + 12, c.as_bytes());
        }
        for &d in &layout.dylib_cmds {
            let dl = &self.dylibs[d as usize];
            let cmd = if dl.flags.weak {
                LC_LOAD_WEAK_DYLIB
            } else if dl.flags.reexport {
                LC_REEXPORT_DYLIB
            } else if dl.flags.upward {
                LC_LOAD_UPWARD_DYLIB
            } else {
                LC_LOAD_DYLIB
            };
            let s = w.begin(cmd, layout::dylib_cmd_size(&dl.install_name) as u32);
            w.u32(s + 8, 24);
            w.u32(s + 12, 2);
            w.u32(s + 16, dl.current_version);
            w.u32(s + 20, dl.compat_version);
            w.bytes(s + 24, dl.install_name.as_bytes());
        }
        for r in &self.cfg.rpaths {
            let s = w.begin(LC_RPATH, align_up(12 + r.len() as u64 + 1, 8) as u32);
            w.u32(s + 8, 12);
            w.bytes(s + 12, r.as_bytes());
        }
        let s = w.begin(LC_FUNCTION_STARTS, 16);
        w.u32(s + 8, le.function_starts.off as u32);
        w.u32(s + 12, le.function_starts.size as u32);
        let s = w.begin(LC_DATA_IN_CODE, 16);
        w.u32(s + 8, le.data_in_code.off as u32);
        w.u32(s + 12, le.data_in_code.size as u32);
        if layout.signed {
            let s = w.begin(LC_CODE_SIGNATURE, 16);
            w.u32(s + 8, le.signature.off as u32);
            w.u32(s + 12, le.signature.size as u32);
        }
        if w.n != layout.ncmds || w.at as u64 != 32 + layout.sizeofcmds {
            bail!(
                "internal error: load commands take {} bytes in {} commands, planned {} in {}",
                w.at - 32,
                w.n,
                layout.sizeofcmds,
                layout.ncmds
            );
        }
        Ok(())
    }

    /// Everything before LINKEDIT: header, load commands and every section's contents.
    /// Every section's contents into `out` (the file before LINKEDIT); returns where the
    /// header and load commands end, for `write_header`.
    fn write_image(&self, layout: &Layout, out: &mut [u8]) -> Result<usize> {
        // (file offset, size, what)
        enum Item {
            Chunk(u32, u32),
            Synth(usize),
            Tail(usize),
        }
        let mut items: Vec<(u64, u64, Item)> = Vec::new();
        for (si, s) in layout.sections.iter().enumerate() {
            if s.is_zerofill() || s.size == 0 {
                continue;
            }
            match s.content {
                Content::Atoms => {
                    for &(oi, isec) in &s.chunks {
                        let sec = &self.objs[oi as usize].sections[isec as usize];
                        items.push((s.file_off + sec.out_off, 0, Item::Chunk(oi, isec)));
                    }
                    if s.tail > 0 {
                        items.push((s.file_off + s.size - s.tail, s.tail, Item::Tail(si)));
                    }
                }
                _ => items.push((s.file_off, s.size, Item::Synth(si))),
            }
        }
        // Chunk sizes: up to the next item's start (or the section's end).
        let mut ends: Vec<u64> = Vec::with_capacity(items.len());
        for (si, s) in layout.sections.iter().enumerate() {
            let _ = si;
            if s.is_zerofill() || s.size == 0 {
                continue;
            }
            if s.content == Content::Atoms {
                for (k, &(oi, isec)) in s.chunks.iter().enumerate() {
                    let _ = (oi, isec);
                    let next = s
                        .chunks
                        .get(k + 1)
                        .map(|&(o2, s2)| {
                            s.file_off + self.objs[o2 as usize].sections[s2 as usize].out_off
                        })
                        .unwrap_or(s.file_off + s.size - s.tail);
                    ends.push(next);
                }
                if s.tail > 0 {
                    ends.push(s.file_off + s.size);
                }
            } else {
                ends.push(s.file_off + s.size);
            }
        }
        for (it, end) in items.iter_mut().zip(ends) {
            it.1 = end - it.0;
        }
        items.sort_by_key(|i| i.0);
        let header_end = items.first().map_or(out.len() as u64, |i| i.0) as usize;
        let (_, mut rest) = out.split_at_mut(header_end);
        // Batches of roughly equal size, one slice of the output each.
        let total: u64 = items.iter().map(|i| i.1).sum();
        let target = (total / (rayon::current_num_threads() as u64 * 4).max(1)).max(256 * 1024);
        type Batch<'b> = (Vec<(u64, u64, Item)>, &'b mut [u8], u64);
        let mut batches: Vec<Batch> = Vec::new();
        let mut consumed = header_end as u64;
        let mut cur: Vec<(u64, u64, Item)> = Vec::new();
        let mut acc = 0u64;
        let mut start = consumed;
        let len = items.len();
        for (k, it) in items.into_iter().enumerate() {
            acc += it.1;
            let end = it.0 + it.1;
            cur.push(it);
            if acc >= target || k + 1 == len {
                let tail = std::mem::take(&mut rest);
                let (_, tail) = tail.split_at_mut((start - consumed) as usize);
                let (slice, tail) = tail.split_at_mut((end - start) as usize);
                rest = tail;
                consumed = end;
                batches.push((std::mem::take(&mut cur), slice, start));
                acc = 0;
                start = end;
            }
        }
        batches
            .into_par_iter()
            .map(|(items, slice, base)| -> Result<()> {
                for (off, size, what) in items {
                    let dst = &mut slice[(off - base) as usize..(off - base + size) as usize];
                    match what {
                        Item::Chunk(oi, si) => self.write_chunk(layout, oi, si, dst)?,
                        Item::Synth(si) => self.write_synth(layout, si, dst)?,
                        Item::Tail(si) => self.write_tail(layout, si, dst),
                    }
                }
                Ok(())
            })
            .collect::<Result<Vec<()>>>()?;
        Ok(header_end)
    }

    fn write_chunk(&self, layout: &Layout, oi: u32, si: u32, dst: &mut [u8]) -> Result<()> {
        let obj = &self.objs[oi as usize];
        let sec = &obj.sections[si as usize];
        let base = layout.sections[sec.out as usize].addr + sec.out_off;
        for ai in sec.atoms.clone() {
            let a = &obj.atoms[ai as usize];
            if !a.is_live() || a.flags & ATOM_DUPLICATE != 0 {
                continue;
            }
            let o = (a.addr - base) as usize;
            let buf = &mut dst[o..o + a.size as usize];
            if !sec.data.is_empty() {
                buf.copy_from_slice(&sec.data[a.off as usize..(a.off + a.size) as usize]);
            }
            if a.flags & ATOM_FDE != 0 {
                self.write_fde(layout, obj, oi, a, buf)?;
                continue;
            }
            if sec.kind == SecKind::NonLazyPointers {
                self.write_nl_pointer(layout, obj, oi, sec, a, buf)?;
            }
            self.relocate(layout, obj, oi, sec, a, buf)?;
        }
        Ok(())
    }

    fn ref_addr(&self, layout: &Layout, obj: &ObjFile, r: Ref) -> Option<u64> {
        match r {
            Ref::Atom { atom, off } => Some((obj.atoms[atom as usize].addr as i64 + off) as u64),
            Ref::Sym(i) => self.sym_addr(layout, obj.global(i)),
            Ref::Abs(v) => Some(v),
            Ref::None => None,
        }
    }

    fn write_fde(
        &self,
        layout: &Layout,
        obj: &ObjFile,
        _oi: u32,
        a: &Atom,
        buf: &mut [u8],
    ) -> Result<()> {
        let fde = &obj.fdes[a.aux as usize];
        let cie = &obj.cies[fde.cie as usize];
        let cie_addr = obj.atoms[cie.atom as usize].addr;
        let p = a.addr;
        put32(buf, 4, (p + 4 - cie_addr) as u32);
        let func = self
            .ref_addr(layout, obj, fde.func)
            .ok_or_else(|| err!("{}: __eh_frame FDE for a missing function", obj.name))?;
        write_signed(buf, 8, cie.fde_ptr_size, func as i64 - (p + 8) as i64);
        if fde.lsda != Ref::None && cie.lsda_ptr_size != 0 {
            let at = (fde.lsda_field - a.off) as usize;
            let lsda = self.ref_addr(layout, obj, fde.lsda).unwrap_or(0);
            write_signed(
                buf,
                at,
                cie.lsda_ptr_size,
                lsda as i64 - (p + at as u64) as i64,
            );
        }
        Ok(())
    }

    fn write_nl_pointer(
        &self,
        layout: &Layout,
        obj: &ObjFile,
        _oi: u32,
        sec: &Section,
        a: &Atom,
        buf: &mut [u8],
    ) -> Result<()> {
        let slot = sec.reserved1 as usize + (a.off / 8) as usize;
        let Some(idx) = obj
            .indirect
            .get(slot * 4..slot * 4 + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        else {
            return Ok(());
        };
        if idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
            return Ok(());
        }
        let (r, add) = obj.sym_ref(idx, 0);
        let v = match r {
            Ref::Sym(i) if self.symtab.get(obj.global(i)).def.is_imported() => 0,
            r => self
                .ref_addr(layout, obj, r)
                .unwrap_or(0)
                .wrapping_add(add as u64),
        };
        put64(buf, 0, v);
        Ok(())
    }

    /// Apply an atom's relocations to its bytes in `buf`.
    fn relocate(
        &self,
        layout: &Layout,
        obj: &ObjFile,
        _oi: u32,
        sec: &Section,
        a: &Atom,
        buf: &mut [u8],
    ) -> Result<()> {
        let arch = self.arch;
        let mut addend = 0i64;
        let mut i = a.rel_lo as usize;
        let hi = a.rel_hi as usize;
        while i < hi {
            let r = raw_reloc(sec.relocs, i);
            i += 1;
            let k = arch::kind(arch, r.ty);
            if k == Kind::Addend {
                addend = ((r.sym << 8) as i32 >> 8) as i64;
                continue;
            }
            let field = r.addr as usize;
            let off = field - a.off as usize;
            let p = a.addr + off as u64;
            let emb = arch::embedded_addend(arch, k, sec.data, field, r.len) + addend;
            addend = 0;
            let fail = |msg: String| {
                err!(
                    "{}: {msg} (relocation at {:#x} in {},{})",
                    obj.name,
                    field,
                    String::from_utf8_lossy(sec.segname),
                    String::from_utf8_lossy(sec.sectname)
                )
            };
            if k == Kind::Subtractor {
                let sub = if r.ext {
                    obj.sym_ref(r.sym, 0).0
                } else {
                    obj.section_ref(
                        r.sym,
                        obj.sections.get(r.sym as usize - 1).map_or(0, |s| s.addr),
                    )
                };
                if i >= hi {
                    return Err(fail("SUBTRACTOR without its UNSIGNED".into()));
                }
                let m = raw_reloc(sec.relocs, i);
                i += 1;
                let v = arch::embedded_addend(arch, Kind::Unsigned, sec.data, field, m.len);
                let min = if m.ext {
                    let (mr, ma) = obj.sym_ref(m.sym, v);
                    self.ref_addr(layout, obj, mr)
                        .map(|x| (x as i64 + ma) as u64)
                } else {
                    let mr = obj.section_ref(m.sym, v as u64);
                    self.ref_addr(layout, obj, mr)
                };
                let s_addr = self
                    .ref_addr(layout, obj, sub)
                    .ok_or_else(|| fail("SUBTRACTOR against a symbol with no address".into()))?;
                let m_addr =
                    min.ok_or_else(|| fail("difference against a symbol with no address".into()))?;
                let value = m_addr.wrapping_sub(s_addr);
                arch::apply(
                    arch,
                    Kind::Unsigned,
                    buf,
                    off,
                    m.len,
                    false,
                    p,
                    value,
                    false,
                )
                .map_err(fail)?;
                continue;
            }
            let (target, add) = if r.ext {
                obj.sym_ref(r.sym, emb)
            } else {
                let at = arch::section_target(arch, k, sec.addr + field as u64, emb, r.pcrel);
                (obj.section_ref(r.sym, at), 0)
            };
            let (value, relax) = match target {
                Ref::Sym(si) => {
                    let id = obj.global(si);
                    if id == NONE {
                        return Err(fail(format!(
                            "unresolved symbol {}",
                            crate::diag::symbol(obj.sym_name(si))
                        )));
                    }
                    let s = self.symtab.get(id);
                    let addr = || {
                        self.sym_addr(layout, id).ok_or_else(|| {
                            fail(format!(
                                "{} is imported and can't be referenced this way",
                                crate::diag::symbol(s.name)
                            ))
                        })
                    };
                    match k {
                        Kind::Branch if s.stub != u32::MAX => (
                            layout.sections[layout.stubs.unwrap()].addr
                                + s.stub as u64 * arch::stub_size(arch),
                            false,
                        ),
                        Kind::GotPage | Kind::GotPageOff | Kind::GotLoad | Kind::PointerToGot
                            if s.got != u32::MAX =>
                        {
                            (self.got_slot(layout, id).unwrap(), false)
                        }
                        Kind::GotPage | Kind::GotPageOff | Kind::GotLoad => {
                            (addr()?, k != Kind::GotPage)
                        }
                        Kind::TlvPage | Kind::TlvPageOff | Kind::Tlv if s.tlvp != u32::MAX => (
                            layout.sections[layout.tlvp.unwrap()].addr + 8 * s.tlvp as u64,
                            false,
                        ),
                        Kind::TlvPage | Kind::TlvPageOff | Kind::Tlv => {
                            (addr()?, k != Kind::TlvPage)
                        }
                        Kind::Unsigned | Kind::AuthPointer if s.def.is_imported() => (0, false),
                        Kind::Unsigned | Kind::AuthPointer
                            if sec.kind == SecKind::ThreadVars
                                && (field as u32 - a.off) % 24 == 16 =>
                        {
                            ((addr()? as i64 + add) as u64 - layout.tlv_start, false)
                        }
                        Kind::PointerToGot => {
                            return Err(fail(format!(
                                "{} has no GOT slot",
                                crate::diag::symbol(s.name)
                            )));
                        }
                        _ => ((addr()? as i64 + add) as u64, false),
                    }
                }
                Ref::Atom { atom, off: o } => {
                    let t = (obj.atoms[atom as usize].addr as i64 + o) as u64;
                    match k {
                        Kind::Unsigned
                            if sec.kind == SecKind::ThreadVars
                                && (field as u32 - a.off) % 24 == 16 =>
                        {
                            (t - layout.tlv_start, false)
                        }
                        Kind::GotPageOff | Kind::GotLoad | Kind::TlvPageOff | Kind::Tlv => {
                            (t, true)
                        }
                        Kind::PointerToGot => {
                            return Err(fail("pointer to a GOT slot of a local symbol".into()));
                        }
                        _ => (t, false),
                    }
                }
                Ref::Abs(v) => ((v as i64 + add) as u64, false),
                Ref::None => return Err(fail("relocation target not found".into())),
            };
            arch::apply(arch, k, buf, off, r.len, r.pcrel, p, value, relax).map_err(fail)?;
        }
        Ok(())
    }

    /// What the linker appends to an input section: selector names and references.
    fn write_tail(&self, layout: &Layout, si: usize, dst: &mut [u8]) {
        let Some(o) = layout.objc else { return };
        if si == o.methname {
            let mut p = 0;
            for (_, sel) in &self.objc_stubs {
                dst[p..p + sel.len()].copy_from_slice(sel);
                p += sel.len() + 1;
            }
        } else if si == o.selrefs {
            let mut name = layout.sections[o.methname].addr + o.methname_base;
            for (i, (_, sel)) in self.objc_stubs.iter().enumerate() {
                put64(dst, 8 * i, name);
                name += sel.len() as u64 + 1;
            }
        }
    }

    fn write_synth(&self, layout: &Layout, si: usize, dst: &mut [u8]) -> Result<()> {
        let s = &layout.sections[si];
        match s.content {
            Content::ObjcStubs => {
                let o = layout.objc.unwrap();
                let msg = self
                    .objc_msgsend
                    .and_then(|m| self.got_slot(layout, m))
                    .ok_or_else(|| err!("_objc_msgSend has no GOT slot"))?;
                let size = layout::objc_stub_size(self.arch) as usize;
                let refs = layout.sections[o.selrefs].addr + o.selrefs_base;
                for i in 0..self.objc_stubs.len() {
                    let at = s.addr + (i * size) as u64;
                    let selref = refs + 8 * i as u64;
                    arch::write_objc_stub(
                        self.arch,
                        &mut dst[i * size..(i + 1) * size],
                        at,
                        selref,
                        msg,
                    );
                }
            }
            Content::Stubs => {
                let size = arch::stub_size(self.arch) as usize;
                for (i, &id) in self.stubs.iter().enumerate() {
                    let addr = s.addr + (i * size) as u64;
                    let slot = self.stub_slot(layout, id).unwrap();
                    arch::write_stub(self.arch, &mut dst[i * size..(i + 1) * size], addr, slot);
                }
            }
            Content::Got => {
                for (i, &id) in self.got.iter().enumerate() {
                    let sym = self.symtab.get(id);
                    let v = if self.is_preemptible(sym) {
                        0
                    } else {
                        self.sym_addr(layout, id).unwrap_or(0)
                    };
                    put64(dst, i * 8, v);
                }
            }
            Content::ThreadPtrs => {}
            Content::AuthGot => {
                for (i, &id) in self.auth_got.iter().enumerate() {
                    let sym = self.symtab.get(id);
                    let v = if self.is_preemptible(sym) {
                        0
                    } else {
                        self.sym_addr(layout, id).unwrap_or(0)
                    };
                    put64(dst, i * 8, v);
                }
            }
            Content::UnwindInfo => {
                if let Some(plan) = &layout.unwind_plan {
                    self.write_unwind_info(plan, dst, layout.image_base, |p| {
                        let slot = if layout.auth_got.is_some() {
                            self.stub_slot(layout, p)
                        } else {
                            self.got_slot(layout, p)
                        };
                        slot.expect("personality routines have GOT slots")
                    });
                }
            }
            Content::Data(i) => dst.copy_from_slice(&layout.sectcreate[i]),
            Content::Atoms | Content::Empty => {}
        }
        Ok(())
    }

    fn write_linkedit(
        &self,
        layout: &Layout,
        out: &mut [u8],
        le: &Linkedit,
        p: &Prepared,
        base: u64,
    ) -> Result<()> {
        let at = |piece: Piece| {
            if piece.size == 0 {
                (0, 0)
            } else {
                ((piece.off - base) as usize, piece.size as usize)
            }
        };
        let pieces = [
            at(le.rebase),
            at(le.bind),
            at(le.weak_bind),
            at(le.chained),
            at(le.exports),
            at(le.function_starts),
            at(le.data_in_code),
            at(le.symtab),
            at(le.indirect),
            at(le.strtab),
        ];
        let mut slices = split_pieces(out, &pieces);
        let strtab = slices.pop().unwrap();
        let indirect = slices.pop().unwrap();
        let symtab = slices.pop().unwrap();
        let data_in_code = slices.pop().unwrap();
        let function_starts = slices.pop().unwrap();
        let exports = slices.pop().unwrap();
        let chained = slices.pop().unwrap();
        let weak_bind = slices.pop().unwrap();
        let bind = slices.pop().unwrap();
        let rebase = slices.pop().unwrap();
        rebase.copy_from_slice(&p.rebase);
        bind.copy_from_slice(&p.bind);
        weak_bind.copy_from_slice(&p.weak_bind);
        if let Some((plan, _)) = &p.chain {
            chained.copy_from_slice(&plan.blob);
        }
        exports.copy_from_slice(&p.exports);
        function_starts.copy_from_slice(&p.function_starts);
        data_in_code.copy_from_slice(&p.data_in_code);
        for (k, v) in p.symtab.indirect.iter().enumerate() {
            put32(indirect, k * 4, *v);
        }
        self.write_symtab(layout, &p.symtab, symtab, strtab);
        Ok(())
    }

    /// The ad-hoc, linker-signed code directory in `out`: SHA-256 of every 4 KiB page of
    /// `parts`, the file before it (each part but the last a multiple of 4 KiB).
    fn sign(&self, layout: &Layout, parts: &[&[u8]], out: &mut [u8]) -> Result<()> {
        let name = self.signature_identifier();
        let headers = align_up(CS_FIXED_HEADERS + name.len() as u64 + 1, 16);
        let limit: usize = parts.iter().map(|p| p.len()).sum();
        let nblocks = limit.div_ceil(4096);
        let sig_size = out.len() as u64;
        let sig = Piece {
            off: limit as u64,
            size: sig_size,
        };
        let be32 =
            |o: &mut [u8], at: usize, v: u32| o[at..at + 4].copy_from_slice(&v.to_be_bytes());
        let be64 =
            |o: &mut [u8], at: usize, v: u64| o[at..at + 8].copy_from_slice(&v.to_be_bytes());
        be32(out, 0, CSMAGIC_EMBEDDED_SIGNATURE);
        be32(out, 4, sig.size as u32);
        be32(out, 8, 1);
        be32(out, 12, CSSLOT_CODEDIRECTORY);
        be32(out, 16, 20);
        let cd = 20usize;
        be32(out, cd, CSMAGIC_CODEDIRECTORY);
        be32(out, cd + 4, (sig.size - 20) as u32);
        be32(out, cd + 8, CS_SUPPORTSEXECSEG);
        be32(out, cd + 12, CS_ADHOC | CS_LINKER_SIGNED);
        let hash_off = headers - 20;
        be32(out, cd + 16, hash_off as u32);
        be32(out, cd + 20, 88);
        be32(out, cd + 24, 0);
        be32(out, cd + 28, nblocks as u32);
        be32(out, cd + 32, limit as u32);
        out[cd + 36] = 32;
        out[cd + 37] = CS_HASHTYPE_SHA256;
        out[cd + 38] = 0;
        out[cd + 39] = CS_PAGE_SHIFT;
        let text = layout.text_seg();
        be64(out, cd + 64, text.fileoff);
        be64(out, cd + 72, text.filesize);
        be64(
            out,
            cd + 80,
            if self.cfg.kind == OutputKind::Execute {
                CS_EXECSEG_MAIN_BINARY
            } else {
                0
            },
        );
        out[cd + 88..cd + 88 + name.len()].copy_from_slice(name.as_bytes());
        let hashes = &mut out[headers as usize..headers as usize + nblocks * 32];
        let mut starts = Vec::with_capacity(parts.len());
        let mut acc = 0usize;
        for p in parts {
            starts.push(acc);
            acc += p.len();
        }
        let page = |b: usize| -> &[u8] {
            let at = b * 4096;
            let i = starts.partition_point(|&s| s <= at) - 1;
            let p = parts[i];
            let o = at - starts[i];
            &p[o..(o + 4096).min(p.len())]
        };
        // Two pages at a time: the hash unit then has two independent chains to overlap.
        hashes
            .par_chunks_mut(32 * 64)
            .enumerate()
            .for_each(|(ci, chunk)| {
                let base = ci * 64;
                for (k, pair) in chunk.chunks_mut(64).enumerate() {
                    let b = base + 2 * k;
                    if pair.len() == 64 && page(b).len() == 4096 && page(b + 1).len() == 4096 {
                        let (x, y) = crate::sha256::digest2(page(b), page(b + 1));
                        pair[..32].copy_from_slice(&x);
                        pair[32..].copy_from_slice(&y);
                    } else {
                        for (j, h) in pair.chunks_mut(32).enumerate() {
                            h.copy_from_slice(&crate::sha256::digest(page(b + j)));
                        }
                    }
                }
            });
        Ok(())
    }

    pub fn write_map(&self, layout: &Layout, path: &std::path::Path) -> Result<()> {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "# Path: {}", self.output_path().display());
        let _ = writeln!(s, "# Arch: {}", self.arch.name());
        let _ = writeln!(s, "# Object files:");
        let _ = writeln!(s, "[  0] linker synthesized");
        for (i, o) in self.objs.iter().enumerate() {
            let _ = writeln!(s, "[{:3}] {}", i + 1, o.name);
        }
        let _ = writeln!(s, "# Sections:\n# Address\tSize    \tSegment\tSection");
        for sec in &layout.sections {
            let _ = writeln!(
                s,
                "0x{:08X}\t0x{:08X}\t{}\t{}",
                sec.addr,
                sec.size,
                String::from_utf8_lossy(&sec.segname),
                String::from_utf8_lossy(&sec.sectname)
            );
        }
        let _ = writeln!(s, "# Symbols:\n# Address\tSize    \tFile  Name");
        let mut syms: Vec<(u64, u32, usize, &[u8])> = Vec::new();
        for id in 0..self.symtab.len() as SymId {
            let sym = self.symtab.get(id);
            if let Def::Defined { obj, atom, off } = sym.def {
                let a = &self.objs[obj as usize].atoms[atom as usize];
                if a.is_live() {
                    syms.push((
                        a.addr + off as u64,
                        a.size - off.min(a.size),
                        obj as usize + 1,
                        sym.name,
                    ));
                }
            }
        }
        syms.sort();
        for (addr, size, file, name) in syms {
            let _ = writeln!(
                s,
                "0x{addr:08X}\t0x{size:08X}\t[{file:3}] {}",
                String::from_utf8_lossy(name)
            );
        }
        std::fs::write(path, s).map_err(|e| err!("cannot write map file {}: {e}", path.display()))
    }

    /// `-dependency_info`: the binary format Xcode reads (version, inputs, output).
    pub fn write_dependency_info(&self, path: &std::path::Path) -> Result<()> {
        let mut v = Vec::new();
        v.push(0x00);
        v.extend_from_slice(format!("hyprlnk-{}", crate::VERSION).as_bytes());
        v.push(0);
        for o in &self.objs {
            if !o.from_archive {
                v.push(0x10);
                v.extend_from_slice(o.name.as_bytes());
                v.push(0);
            }
        }
        for a in &self.archives {
            v.push(0x10);
            v.extend_from_slice(a.path.as_bytes());
            v.push(0);
        }
        for d in &self.dylibs {
            v.push(0x10);
            v.extend_from_slice(d.path.as_bytes());
            v.push(0);
        }
        v.push(0x40);
        v.extend_from_slice(self.output_path().display().to_string().as_bytes());
        v.push(0);
        std::fs::write(path, v).map_err(|e| err!("cannot write {}: {e}", path.display()))
    }
}

struct Cmds<'o> {
    out: &'o mut [u8],
    at: usize,
    n: u32,
}

impl Cmds<'_> {
    fn begin(&mut self, cmd: u32, size: u32) -> usize {
        let s = self.at;
        put32(self.out, s, cmd);
        put32(self.out, s + 4, size);
        self.at += size as usize;
        self.n += 1;
        s
    }
    fn u32(&mut self, at: usize, v: u32) {
        put32(self.out, at, v);
    }
    fn u64(&mut self, at: usize, v: u64) {
        put64(self.out, at, v);
    }
    fn bytes(&mut self, at: usize, b: &[u8]) {
        self.out[at..at + b.len()].copy_from_slice(b);
    }
    fn name16(&mut self, at: usize, b: &[u8]) {
        let n = b.len().min(16);
        self.out[at..at + n].copy_from_slice(&b[..n]);
    }
}

fn write_signed(buf: &mut [u8], at: usize, size: u8, v: i64) {
    match size {
        2 => put16(buf, at, v as u16),
        4 => put32(buf, at, v as u32),
        _ => put64(buf, at, v as u64),
    }
}

fn tool_version() -> u32 {
    let mut parts = crate::VERSION
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let (a, b, c) = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    (a.min(0xffff) << 16) | (b.min(0xff) << 8) | c.min(0xff)
}

/// A name-based (version 3 style) UUID from the image's contents, hashed in parallel.
fn content_uuid(parts: &[&[u8]]) -> [u8; 16] {
    let chunk = 1 << 20;
    let hashes: Vec<u128> = parts
        .par_iter()
        .flat_map_iter(|p| p.chunks(chunk))
        .map(xxhash_rust::xxh3::xxh3_128)
        .collect();
    let mut all = Vec::with_capacity(hashes.len() * 16);
    for h in hashes {
        all.extend_from_slice(&h.to_le_bytes());
    }
    let mut u = xxhash_rust::xxh3::xxh3_128(&all).to_le_bytes();
    u[6] = (u[6] & 0x0f) | 0x30;
    u[8] = (u[8] & 0x3f) | 0x80;
    u
}

fn random_uuid() -> [u8; 16] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut u = xxhash_rust::xxh3::xxh3_128_with_seed(&t.to_le_bytes(), std::process::id() as u64)
        .to_le_bytes();
    u[6] = (u[6] & 0x0f) | 0x40;
    u[8] = (u[8] & 0x3f) | 0x80;
    u
}
