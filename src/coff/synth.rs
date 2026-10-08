//! Linker-made data: commons, import tables and thunks, local `__imp_` pointers, exports.

use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;

use super::resolve::Linker;
use super::symtab::{Def, SymId};
use super::*;
use crate::bail;
use crate::diag::Result;

// Synthetic chunks.
pub const COMMON: usize = 0;
pub const IDATA_DIR: usize = 1;
pub const IDATA_ILT: usize = 2;
pub const IDATA_IAT: usize = 3;
pub const IDATA_HINTS: usize = 4;
pub const IDATA_DLLS: usize = 5;
pub const THUNKS: usize = 6;
pub const LOCAL_IMPORTS: usize = 7;
pub const EDATA: usize = 8;
pub const SAFESEH: usize = 9;
pub const RSRC: usize = 10;
pub const DEBUG_DIR: usize = 11;
pub const NUM_CHUNKS: usize = 12;

#[derive(Debug, Clone, Copy, Default)]
pub struct SynthChunk {
    pub size: u32,
    pub align: u32,
    pub rva: u32,
    pub out: u32,
}

pub struct DllImports<'a> {
    pub name: &'a [u8],
    pub imports: Vec<u32>,
    pub table_off: u32,
    pub name_off: u32,
}

pub struct Edata {
    pub dll_name: String,
    pub base: u32,
    pub functions: Vec<Option<SymId>>,
    pub names: Vec<(String, u16)>,
    pub eat_off: u32,
    pub name_ptrs_off: u32,
    pub ordinals_off: u32,
    pub dll_name_off: u32,
    pub strings_off: u32,
}

impl Linker<'_> {
    pub fn create_synthetic(&mut self) -> Result<()> {
        self.synth = vec![SynthChunk::default(); NUM_CHUNKS];

        let mut commons: Vec<(u32, SymId, u32)> = Vec::new();
        for (id, s) in self.symtab.syms.iter().enumerate() {
            if let Def::Common { size, .. } = s.def {
                let align = size.next_power_of_two().min(32);
                commons.push((align, id as SymId, size));
            }
        }
        commons.sort_by_key(|&(align, id, _)| (std::cmp::Reverse(align), id));
        let mut off = 0u32;
        let mut max_align = 1;
        for (align, id, size) in commons {
            off = align_up(off as u64, align as u64) as u32;
            self.symtab.get_mut(id).def = Def::Synthetic {
                chunk: COMMON as u8,
                off,
            };
            off += size;
            max_align = max_align.max(align);
        }
        self.synth[COMMON] = SynthChunk {
            size: off,
            align: max_align,
            ..Default::default()
        };

        self.create_imports();
        let ptr = self.machine.ptr_size();
        self.synth[LOCAL_IMPORTS] = SynthChunk {
            size: self.local_imports.len() as u32 * ptr,
            align: ptr,
            ..Default::default()
        };
        self.create_exports()?;
        self.create_safeseh()?;
        self.create_resources()?;
        self.create_debug_directory();
        Ok(())
    }

    fn create_safeseh(&mut self) -> Result<()> {
        if self.machine != super::arch::Machine::X86 || self.cfg.safeseh == Some(false) {
            return Ok(());
        }
        let incompatible = self.objs.iter().find(|o| {
            o.machine == IMAGE_FILE_MACHINE_I386
                && o.feat00 & 1 == 0
                && o.sections
                    .iter()
                    .any(|s| s.is_live() && s.chars & IMAGE_SCN_CNT_CODE != 0)
        });
        if let Some(o) = incompatible {
            if self.cfg.safeseh == Some(true) {
                bail!("/SAFESEH: {} is not compatible with SafeSEH", o.name);
            }
            return Ok(());
        }
        let mut handlers = std::collections::BTreeSet::new();
        for (oi, o) in self.objs.iter().enumerate() {
            for idx in o.sxdata.as_chunks::<4>().0 {
                let idx = u32::from_le_bytes(*idx);
                let def = match o.sym_ids.get(idx as usize) {
                    Some(&id) if id != super::object::NONE => self.symtab.get(id).def,
                    _ => match o.raw_sym(idx) {
                        Some(r) if r.section > 0 => Def::Defined {
                            obj: oi as u32,
                            sec: (r.section - 1) as u32,
                            value: r.value,
                        },
                        _ => continue,
                    },
                };
                if let Def::Defined { obj, sec, value } = def
                    && self.objs[obj as usize].sections[sec as usize].is_live()
                {
                    handlers.insert((obj, sec, value));
                }
            }
        }
        self.seh_handlers = handlers.into_iter().collect();
        self.synth[SAFESEH] = SynthChunk {
            size: self.seh_handlers.len() as u32 * 4,
            align: 4,
            ..Default::default()
        };
        let count = self.seh_handlers.len() as u64;
        for (name, def) in [
            (
                "___safe_se_handler_table",
                Def::Synthetic {
                    chunk: SAFESEH as u8,
                    off: 0,
                },
            ),
            ("___safe_se_handler_count", Def::Absolute { va: count }),
        ] {
            if let Some(id) = self.symtab.find(name.as_bytes()) {
                let s = self.symtab.get_mut(id);
                if s.replaceable {
                    s.def = def;
                }
            }
        }
        Ok(())
    }

    fn create_imports(&mut self) {
        let mut by_dll: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut dlls: Vec<DllImports> = Vec::new();
        for (i, imp) in self.imports.iter().enumerate() {
            if !imp.live.load(Relaxed) {
                continue;
            }
            let key = imp.dll.to_ascii_lowercase();
            let d = *by_dll.entry(key).or_insert_with(|| {
                dlls.push(DllImports {
                    name: imp.dll,
                    imports: Vec::new(),
                    table_off: 0,
                    name_off: 0,
                });
                dlls.len() - 1
            });
            dlls[d].imports.push(i as u32);
        }

        for dll in &mut dlls {
            let imports = &self.imports;
            dll.imports.sort_by(|&a, &b| {
                let (a, b) = (&imports[a as usize], &imports[b as usize]);
                (a.name.is_none(), a.name, a.ordinal_or_hint).cmp(&(
                    b.name.is_none(),
                    b.name,
                    b.ordinal_or_hint,
                ))
            });
        }
        let ptr = self.machine.ptr_size();
        let thunk_size = self.machine.thunk_size();
        let mut table = 0u32;
        let mut hints = 0u32;
        let mut names = 0u32;
        let mut thunks = 0u32;
        for dll in &mut dlls {
            dll.table_off = table;
            dll.name_off = names;
            names += align_up(dll.name.len() as u64 + 1, 2) as u32;
            for (j, &i) in dll.imports.iter().enumerate() {
                let imp = &mut self.imports[i as usize];
                imp.iat_off = table + j as u32 * ptr;
                if let Some(name) = imp.name {
                    imp.hint_off = hints;
                    hints += align_up(2 + name.len() as u64 + 1, 2) as u32;
                }
                if imp.thunk_live.load(Relaxed) {
                    imp.thunk_off = thunks;
                    thunks = align_up((thunks + thunk_size) as u64, 8) as u32;
                }
            }
            table += (dll.imports.len() as u32 + 1) * ptr;
        }
        let chunk = |size: u32, align: u32| SynthChunk {
            size,
            align,
            ..Default::default()
        };
        if !dlls.is_empty() {
            self.synth[IDATA_DIR] = chunk((dlls.len() as u32 + 1) * 20, 4);
            self.synth[IDATA_ILT] = chunk(table, ptr);
            self.synth[IDATA_IAT] = chunk(table, ptr);
            self.synth[IDATA_HINTS] = chunk(hints, 2);
            self.synth[IDATA_DLLS] = chunk(names, 2);
        }
        self.synth[THUNKS] = chunk(thunks, 16);
        self.dlls = dlls;
    }

    fn create_exports(&mut self) -> Result<()> {
        if self.exports.is_empty() {
            return Ok(());
        }
        let mut order: Vec<usize> = (0..self.exports.len()).collect();
        order.sort_by(|&a, &b| self.exports[a].name.cmp(&self.exports[b].name));
        let mut max = self.exports.iter().map(|e| e.ordinal).max().unwrap_or(0);
        for &i in &order {
            if self.exports[i].ordinal == 0 {
                max = max
                    .checked_add(1)
                    .ok_or_else(|| crate::err!("too many exports"))?;
                self.exports[i].ordinal = max;
            }
        }
        let base = 1u32;
        let mut functions: Vec<Option<SymId>> = vec![None; max as usize];
        for e in &self.exports {
            let slot = &mut functions[(e.ordinal as u32 - base) as usize];
            if slot.is_some() {
                bail!("export ordinal {} is used twice", e.ordinal);
            }
            *slot = Some(e.sym);
        }
        let mut names: Vec<(String, u16)> = self
            .exports
            .iter()
            .filter(|e| !e.noname)
            .map(|e| (e.name.clone(), (e.ordinal as u32 - base) as u16))
            .collect();
        names.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let dll_name = self
            .output_path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let eat_off = 40;
        let name_ptrs_off = eat_off + functions.len() as u32 * 4;
        let ordinals_off = name_ptrs_off + names.len() as u32 * 4;
        let dll_name_off = ordinals_off + names.len() as u32 * 2;
        let strings_off = dll_name_off + dll_name.len() as u32 + 1;
        let size = strings_off + names.iter().map(|(n, _)| n.len() as u32 + 1).sum::<u32>();
        self.synth[EDATA] = SynthChunk {
            size,
            align: 4,
            ..Default::default()
        };
        self.edata = Some(Edata {
            dll_name,
            base,
            functions,
            names,
            eat_off,
            name_ptrs_off,
            ordinals_off,
            dll_name_off,
            strings_off,
        });
        Ok(())
    }
}

impl Linker<'_> {
    fn create_resources(&mut self) -> Result<()> {
        super::rsrc::create(self)
    }

    fn create_debug_directory(&mut self) {
        super::pdb::create_debug_directory(self);
    }
}
