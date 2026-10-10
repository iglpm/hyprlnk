//! `-Map=<file>`: where every output section, input section and symbol went, in lld's format.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;

use rayon::prelude::*;

use super::layout::{Layout, Synthetic};
use super::object::{Object, SecKind};
use super::resolve::Ctx;
use super::symbols::{CLASS_COMMON, UNDEF, def_class, def_index, def_prio};
use super::target::Target;
use super::*;
use crate::diag::Result;
use crate::err;

/// One input section's lines: (output section, offset in it, text).
type Entry = (u32, u64, String);

fn line(out: &mut String, vma: u64, size: u64, align: u64, indent: usize, text: &[u8]) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "{vma:16x} {vma:16x} {size:8x} {align:5} {:indent$}{}",
        "",
        String::from_utf8_lossy(text)
    );
}

impl<'a, T: Target> Ctx<'a, T> {
    pub fn write_map(&self, lay: &Layout, path: &Path) -> Result<()> {
        let mut entries: Vec<Entry> = self
            .objs
            .par_iter()
            .flat_map_iter(|o| self.map_object(lay, o))
            .collect();
        for m in &self.merged {
            if m.out == NONE {
                continue;
            }
            let os = &lay.outs[m.out as usize];
            let (vma, at) = if os.is_alloc() {
                (m.addr, m.addr - os.addr)
            } else {
                (0, m.file_off - os.offset)
            };
            let mut text = String::new();
            let name = [b"<merged>:(", m.name, b")"].concat();
            line(&mut text, vma, m.size, 1 << m.p2align, 8, &name);
            entries.push((m.out, at, text));
        }
        entries.par_sort_by_key(|e| (e.0, e.1));

        // `-M` prints the map: `-` is standard output.
        let sink: Box<dyn Write> = if path == Path::new("-") {
            Box::new(std::io::stdout().lock())
        } else {
            Box::new(
                std::fs::File::create(path)
                    .map_err(|e| err!("cannot create {}: {e}", path.display()))?,
            )
        };
        let mut file = std::io::BufWriter::new(sink);
        let mut head = format!(
            "{:>16} {:>16} {:>8} {:>5} Out     In      Symbol\n",
            "VMA", "LMA", "Size", "Align"
        );
        let mut order: Vec<usize> = (0..lay.outs.len())
            .filter(|&i| lay.outs[i].shndx != 0)
            .collect();
        order.sort_by_key(|&i| lay.outs[i].shndx);
        let mut next = 0;
        for i in order {
            let os = &lay.outs[i];
            let vma = if os.is_alloc() { os.addr } else { 0 };
            line(&mut head, vma, os.size, os.align, 0, &os.name);
            if os.synth != Synthetic::None {
                let name = [b"<internal>:(", &os.name[..], b")"].concat();
                line(&mut head, vma, os.size, os.align, 8, &name);
            }
            file.write_all(head.as_bytes())
                .map_err(|e| err!("cannot write {}: {e}", path.display()))?;
            head.clear();
            while next < entries.len() && (entries[next].0 as usize) < i {
                next += 1;
            }
            while next < entries.len() && entries[next].0 as usize == i {
                file.write_all(entries[next].2.as_bytes())
                    .map_err(|e| err!("cannot write {}: {e}", path.display()))?;
                next += 1;
            }
        }
        file.flush()
            .map_err(|e| err!("cannot write {}: {e}", path.display()))
    }

    /// An object's live input sections, each with the symbols defined in it.
    fn map_object(&self, lay: &Layout, o: &Object<'a>) -> Vec<Entry> {
        if !o.alive.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let mapped = |si: usize| {
            let s = &o.secs[si];
            s.is_live() && s.out != NONE && matches!(s.kind, SecKind::Alloc | SecKind::NonAlloc)
        };
        // Symbols by section: locals worth naming, and the globals this object defines.
        let mut syms: Vec<(u32, u64, &[u8])> = Vec::new();
        for i in 1..o.nsyms {
            let s = o.sym::<T>(i);
            let si = s.shndx as usize;
            if s.is_undef()
                || si >= o.secs.len()
                || !mapped(si)
                || matches!(s.ty(), STT_SECTION | STT_FILE)
                || (i >= o.first_global && self.map_owner(o, i))
            {
                continue;
            }
            let name = o.sym_name(&s);
            if name.is_empty() {
                continue;
            }
            syms.push((si as u32, self.local_value(i, o), name));
        }
        syms.sort_unstable_by_key(|&(si, v, _)| (si, v));
        let mut out = Vec::new();
        let mut k = 0;
        for (si, s) in o.secs.iter().enumerate() {
            if !mapped(si) {
                continue;
            }
            let os = &lay.outs[s.out as usize];
            let (vma, at) = if os.is_alloc() {
                (s.addr, s.addr - os.addr)
            } else {
                (0, s.addr)
            };
            let mut text = String::new();
            let name = [o.name.as_bytes(), b":(", o.sec_name::<T>(si as u32), b")"].concat();
            line(&mut text, vma, s.size as u64, 1 << s.p2align, 8, &name);
            while k < syms.len() && (syms[k].0 as usize) < si {
                k += 1;
            }
            while k < syms.len() && syms[k].0 as usize == si {
                let (_, v, n) = syms[k];
                line(&mut text, if os.is_alloc() { v } else { 0 }, 0, 1, 16, n);
                k += 1;
            }
            out.push((s.out, at, text));
        }
        out
    }

    /// A global this object references or loses to another definition: not listed under it.
    fn map_owner(&self, o: &Object<'a>, i: u32) -> bool {
        let id = o.global_id(i);
        if id == NONE {
            return false;
        }
        let d = self.syms.get(id).def();
        !(d != UNDEF && def_class(d) <= CLASS_COMMON && def_prio(d) == o.prio && def_index(d) == i)
    }
}
