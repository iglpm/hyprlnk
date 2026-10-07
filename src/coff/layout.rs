//! Output sections and addresses.
//!
//! Following the PE/COFF rules and what `link.exe`/`lld-link` do:
//!
//! * input sections are grouped by full name and output characteristics, and
//!   the groups sorted by name, so `.CRT$XCA` < `.CRT$XCU` < `.CRT$XCZ` (the
//!   C runtime finds its initializer tables between such markers);
//! * a group joins the output section named by the part before `$`;
//! * `/MERGE`s (and the default ones: `.bss` into `.data`, `.xdata`, `.idata`
//!   and `.edata` into `.rdata`) append whole output sections to others;
//! * output sections come in link.exe's order: `.text`, `.rdata`, `.data`,
//!   `.pdata`, the rest by name, `.rsrc`, then discardable ones (`.reloc`).

use std::collections::HashMap;

use super::object::NONE;
use super::resolve::Linker;
use super::synth::*;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkRef {
    Sec { obj: u32, sec: u32 },
    Synth(u8),
}

pub struct OutSection {
    pub name: Vec<u8>,
    pub chars: u32,
    pub chunks: Vec<ChunkRef>,
    pub rva: u32,
    pub vsize: u32,
    pub file_off: u32,
    pub raw_size: u32,
}

pub struct Layout {
    pub sections: Vec<OutSection>,
    pub header_size: u32,
    /// The RVA after the last section: where `.reloc` goes.
    pub end_rva: u32,
    /// The file size before `.reloc`.
    pub file_end: u32,
}

const CODE: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
const RDATA: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
const DATA: u32 = RDATA | IMAGE_SCN_MEM_WRITE;
const BSS: u32 = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

/// Size of the headers before the section table: DOS header and stub, PE
/// signature, COFF header, PE32+ optional header.
pub const HEADERS_BEFORE_SECTIONS: u32 = 120 + 4 + 20 + 240;

/// `.text$mn` → `.text`; `.text.unlikely` → `.text`.
fn output_name(name: &[u8]) -> &[u8] {
    let base = name.split(|&b| b == b'$').next().unwrap_or(name);
    match base.iter().skip(1).position(|&b| b == b'.') {
        Some(p) => &base[..p + 1],
        None => base,
    }
}

impl Linker<'_> {
    pub fn chunk_info(&self, c: ChunkRef) -> (u32, u32, bool) {
        match c {
            ChunkRef::Sec { obj, sec } => {
                let s = &self.objs[obj as usize].sections[sec as usize];
                (s.size, s.align, s.has_data())
            }
            ChunkRef::Synth(k) => {
                let s = &self.synth[k as usize];
                (s.size, s.align, k as usize != COMMON)
            }
        }
    }

    pub fn layout(&mut self) -> Layout {
        // Partial sections: (full name, characteristics) → chunks, in input
        // order. A small per-object cache saves most map lookups: objects
        // repeat `.text`, `.xdata`, `.pdata` for every function.
        let mut partials: Vec<(Vec<u8>, u32, Vec<ChunkRef>)> = Vec::new();
        let mut index: HashMap<(Vec<u8>, u32), usize> = HashMap::new();
        let mut tls_align = 0;
        for (oi, obj) in self.objs.iter().enumerate() {
            let mut cache: Vec<(&[u8], u32, usize)> = Vec::new();
            for (si, s) in obj.sections.iter().enumerate() {
                if !s.is_live() {
                    continue;
                }
                let chars = s.chars & OUTPUT_CHARS_MASK;
                let p = match cache.iter().find(|(n, c, _)| *n == s.name && *c == chars) {
                    Some(&(_, _, p)) => p,
                    None => {
                        let p = *index.entry((s.name.to_vec(), chars)).or_insert_with(|| {
                            partials.push((s.name.to_vec(), chars, Vec::new()));
                            partials.len() - 1
                        });
                        cache.push((s.name, chars, p));
                        p
                    }
                };
                partials[p].2.push(ChunkRef::Sec {
                    obj: oi as u32,
                    sec: si as u32,
                });
                if s.name.starts_with(b".tls") {
                    tls_align = tls_align.max(s.align);
                }
            }
        }
        self.tls_align = tls_align;
        for (name, chars, k) in [
            (".bss", BSS, COMMON),
            (".idata$2", RDATA, IDATA_DIR),
            (".idata$4", RDATA, IDATA_ILT),
            (".idata$5", RDATA, IDATA_IAT),
            (".idata$6", RDATA, IDATA_HINTS),
            (".idata$7", RDATA, IDATA_DLLS),
        ] {
            if self.synth[k].size > 0 {
                let p = *index
                    .entry((name.as_bytes().to_vec(), chars))
                    .or_insert_with(|| {
                        partials.push((name.as_bytes().to_vec(), chars, Vec::new()));
                        partials.len() - 1
                    });
                partials[p].2.push(ChunkRef::Synth(k as u8));
            }
        }
        let mut order: Vec<usize> = (0..partials.len()).collect();
        order.sort_by(|&a, &b| {
            (&partials[a].0, partials[a].1).cmp(&(&partials[b].0, partials[b].1))
        });

        // Output sections, link.exe's usual ones first.
        let mut sections: Vec<OutSection> = Vec::new();
        let find_or_create = |sections: &mut Vec<OutSection>, name: &[u8], chars: u32| -> usize {
            if let Some(i) = sections
                .iter()
                .position(|s| s.name == name && s.chars == chars)
            {
                return i;
            }
            sections.push(OutSection {
                name: name.to_vec(),
                chars,
                chunks: Vec::new(),
                rva: 0,
                vsize: 0,
                file_off: 0,
                raw_size: 0,
            });
            sections.len() - 1
        };
        for (name, chars) in [
            (".text", CODE),
            (".bss", BSS),
            (".rdata", RDATA),
            (".buildid", RDATA),
            (".data", DATA),
            (".pdata", RDATA),
            (".idata", RDATA),
            (".edata", RDATA),
            (".didat", RDATA),
            (".rsrc", RDATA),
            (".ctors", DATA),
            (".dtors", DATA),
        ] {
            find_or_create(&mut sections, name.as_bytes(), chars);
        }
        for p in order {
            let (name, chars, chunks) = std::mem::take(&mut partials[p]);
            let out = output_name(&name);
            let chars = if out == b".CRT" { RDATA } else { chars };
            let i = find_or_create(&mut sections, out, chars);
            sections[i].chunks.extend(chunks);
        }
        for (k, name, chars) in [
            (THUNKS, ".text", CODE),
            (LOCAL_IMPORTS, ".rdata", RDATA),
            (EDATA, ".edata", RDATA),
        ] {
            if self.synth[k].size > 0 {
                let i = find_or_create(&mut sections, name.as_bytes(), chars);
                sections[i].chunks.push(ChunkRef::Synth(k as u8));
            }
        }

        // Merges, following chains (`a=b`, `b=c`).
        for (from, to) in &self.merges {
            let mut to = to.as_str();
            for _ in 0..16 {
                match self.merges.get(to) {
                    Some(next) if next != to => to = next,
                    _ => break,
                }
            }
            if from == to {
                continue;
            }
            let Some(f) = sections.iter().position(|s| s.name == from.as_bytes()) else {
                continue;
            };
            match sections.iter().position(|s| s.name == to.as_bytes()) {
                Some(t) => {
                    let chunks = std::mem::take(&mut sections[f].chunks);
                    sections[t].chunks.extend(chunks);
                }
                None => sections[f].name = to.as_bytes().to_vec(),
            }
        }

        sections.retain(|s| s.chunks.iter().any(|&c| self.chunk_info(c).0 > 0));
        let rank = |s: &OutSection| {
            if s.chars & IMAGE_SCN_MEM_DISCARDABLE != 0 {
                if s.name.starts_with(b".debug_") { 3 } else { 2 }
            } else if s.name == b".rsrc" {
                1
            } else {
                0
            }
        };
        sections.sort_by_key(rank);

        // Addresses. One section header is reserved for `.reloc`.
        let file_align = self.cfg.file_align as u64;
        let sect_align = self.cfg.section_align as u64;
        let header_size = align_up(
            HEADERS_BEFORE_SECTIONS as u64 + 40 * (sections.len() as u64 + 1),
            file_align,
        );
        let mut rva = align_up(header_size, sect_align);
        let mut file_off = header_size;
        for (i, sec) in sections.iter_mut().enumerate() {
            sec.rva = rva as u32;
            let mut off = 0u64;
            let mut raw_end = 0u64;
            for &c in &sec.chunks {
                let (size, align, has_data) = self.chunk_info(c);
                off = align_up(off, align.max(1) as u64);
                let chunk_rva = (rva + off) as u32;
                match c {
                    ChunkRef::Sec { obj, sec } => {
                        let s = &mut self.objs[obj as usize].sections[sec as usize];
                        s.rva = chunk_rva;
                        s.out = i as u32;
                    }
                    ChunkRef::Synth(k) => {
                        let s = &mut self.synth[k as usize];
                        s.rva = chunk_rva;
                        s.out = i as u32;
                    }
                }
                off += size as u64;
                if has_data {
                    raw_end = off;
                }
            }
            sec.vsize = off as u32;
            sec.raw_size = align_up(raw_end, file_align) as u32;
            sec.file_off = if sec.raw_size > 0 { file_off as u32 } else { 0 };
            file_off += sec.raw_size as u64;
            rva = align_up(rva + off, sect_align);
            // Names are at most 8 bytes in an image without a string table.
            sec.name.truncate(8);
        }
        self.out_rvas = sections.iter().map(|s| s.rva).collect();
        for s in &mut self.synth {
            if s.size == 0 {
                s.out = NONE;
            }
        }
        Layout {
            sections,
            header_size: header_size as u32,
            end_rva: rva as u32,
            file_end: file_off as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_names() {
        assert_eq!(output_name(b".text$mn"), b".text");
        assert_eq!(output_name(b".CRT$XCU"), b".CRT");
        assert_eq!(output_name(b".text.unlikely"), b".text");
        assert_eq!(output_name(b".rdata"), b".rdata");
        assert_eq!(output_name(b".idata$5"), b".idata");
    }
}
