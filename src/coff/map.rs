//! `/MAP`: a `link.exe`-style map file.

use std::fmt::Write as _;
use std::path::Path;

use rayon::prelude::*;

use super::layout::Layout;
use super::resolve::Linker;
use super::symtab::Def;
use super::*;
use crate::diag::Result;
use crate::err;

type MapEntry<'s> = (u32, u32, u64, bool, &'s [u8], String);

impl Linker<'_> {
    pub fn write_map(&self, layout: &Layout, path: &Path) -> Result<()> {
        let ib = self.image_base;
        let mut out = String::new();
        let name = self
            .output_path()
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = writeln!(out, " {name}\n");
        let _ = writeln!(out, " Preferred load address is {ib:016X}\n");
        let _ = writeln!(
            out,
            " Start         Length     Name                   Class"
        );
        for (i, s) in layout.sections.iter().enumerate() {
            let class = if s.chars & IMAGE_SCN_CNT_CODE != 0 {
                "CODE"
            } else {
                "DATA"
            };
            let _ = writeln!(
                out,
                " {:04X}:00000000 {:08X}H {:<23}{class}",
                i + 1,
                s.vsize,
                String::from_utf8_lossy(&s.name)
            );
        }

        let mut publics: Vec<MapEntry> = self
            .symtab
            .syms
            .par_iter()
            .enumerate()
            .filter_map(|(id, s)| {
                let t = self.sym_target(id as u32)?;
                let (sec, off) = if t.absolute || t.out == u32::MAX {
                    (0, t.va as u32)
                } else {
                    (
                        t.out + 1,
                        (t.va - ib) as u32 - self.out_rvas[t.out as usize],
                    )
                };
                let (function, file) = match s.def {
                    Def::Defined { obj, .. } => (s.function, self.objs[obj as usize].name.clone()),
                    Def::Thunk { imp } | Def::Import { imp } => (
                        matches!(s.def, Def::Thunk { .. }),
                        String::from_utf8_lossy(self.imports[imp as usize].dll).into_owned(),
                    ),
                    _ => (false, "<linker-defined>".to_string()),
                };
                Some((sec, off, t.va, function, s.name, file))
            })
            .collect();
        publics.par_sort_unstable_by(|a, b| (a.0, a.1, a.4).cmp(&(b.0, b.1, b.4)));
        let _ = writeln!(
            out,
            "\n  Address         Publics by Value              Rva+Base               Lib:Object\n"
        );
        for (sec, off, va, function, name, file) in &publics {
            let _ = writeln!(
                out,
                " {sec:04X}:{off:08X}       {:<26} {va:016X} {} {file}",
                String::from_utf8_lossy(name),
                if *function { "f" } else { " " }
            );
        }
        if let Some(id) = self.entry
            && let Some(t) = self.sym_target(id)
            && t.out != u32::MAX
        {
            let off = (t.va - ib) as u32 - self.out_rvas[t.out as usize];
            let _ = writeln!(out, "\n entry point at        {:04X}:{off:08X}", t.out + 1);
        }
        std::fs::write(path, out).map_err(|e| err!("cannot write '{}': {e}", path.display()))
    }
}
