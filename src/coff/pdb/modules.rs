//! Module streams: each object's relocated `.debug$S`, one module per thread.

use super::super::arch;
use super::super::object::ObjFile;
use super::super::resolve::Linker;
use super::super::*;
use super::types::{LF_FUNC_ID, LF_MFUNC_ID, Merged};

// Symbol kinds.
pub const S_END: u16 = 0x0006;
pub const S_OBJNAME: u16 = 0x1101;
pub const S_THUNK32: u16 = 0x1102;
pub const S_BLOCK32: u16 = 0x1103;
pub const S_REGISTER: u16 = 0x1106;
pub const S_CONSTANT: u16 = 0x1107;
pub const S_UDT: u16 = 0x1108;
pub const S_BPREL32: u16 = 0x110b;
pub const S_LDATA32: u16 = 0x110c;
pub const S_GDATA32: u16 = 0x110d;
pub const S_PUB32: u16 = 0x110e;
pub const S_LPROC32: u16 = 0x110f;
pub const S_GPROC32: u16 = 0x1110;
pub const S_REGREL32: u16 = 0x1111;
pub const S_LTHREAD32: u16 = 0x1112;
pub const S_GTHREAD32: u16 = 0x1113;
pub const S_PROCREF: u16 = 0x1125;
pub const S_LPROCREF: u16 = 0x1127;
pub const S_SEPCODE: u16 = 0x1132;
pub const S_SECTION: u16 = 0x1136;
pub const S_CALLSITEINFO: u16 = 0x1139;
pub const S_COMPILE3: u16 = 0x113c;
pub const S_LOCAL: u16 = 0x113e;
pub const S_LPROC32_ID: u16 = 0x1146;
pub const S_GPROC32_ID: u16 = 0x1147;
pub const S_BUILDINFO: u16 = 0x114c;
pub const S_INLINESITE: u16 = 0x114d;
pub const S_INLINESITE_END: u16 = 0x114e;
pub const S_PROC_ID_END: u16 = 0x114f;
pub const S_FILESTATIC: u16 = 0x1153;
pub const S_LPROC32_DPC: u16 = 0x1155;
pub const S_LPROC32_DPC_ID: u16 = 0x1156;
pub const S_CALLERS: u16 = 0x115a;
pub const S_CALLEES: u16 = 0x115b;
pub const S_INLINESITE2: u16 = 0x115d;
pub const S_HEAPALLOCSITE: u16 = 0x115e;
pub const S_INLINEES: u16 = 0x1168;
pub const S_REGREL32_INDIR: u16 = 0x1171;

// Debug subsections.
const DEBUG_S_SYMBOLS: u32 = 0xF1;
const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_STRINGTABLE: u32 = 0xF3;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;
const DEBUG_S_INLINEELINES: u32 = 0xF6;
const DEBUG_S_IGNORE: u32 = 0x8000_0000;

fn u16at(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn set32(d: &mut [u8], o: usize, v: u32) {
    if let Some(b) = d.get_mut(o..o + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

fn symbol_refs(kind: u16, c: &[u8]) -> &'static [(u32, bool)] {
    let _ = c;
    match kind {
        S_GPROC32_ID | S_LPROC32_ID | S_LPROC32_DPC | S_LPROC32_DPC_ID => &[(24, true)],
        S_GPROC32 | S_LPROC32 => &[(24, false)],
        S_UDT | S_GDATA32 | S_GTHREAD32 | S_LTHREAD32 | S_LDATA32 | S_LOCAL | S_REGISTER
        | S_CONSTANT | S_FILESTATIC => &[(0, false)],
        S_BUILDINFO => &[(0, true)],
        S_BPREL32 | S_REGREL32 | S_REGREL32_INDIR => &[(4, false)],
        S_CALLSITEINFO | S_HEAPALLOCSITE => &[(8, false)],
        S_INLINESITE | S_INLINESITE2 => &[(8, true)],
        _ => &[],
    }
}

fn opens_scope(kind: u16) -> bool {
    matches!(
        kind,
        S_GPROC32
            | S_LPROC32
            | S_GPROC32_ID
            | S_LPROC32_ID
            | S_LPROC32_DPC
            | S_LPROC32_DPC_ID
            | S_BLOCK32
            | S_THUNK32
            | S_SEPCODE
            | S_INLINESITE
            | S_INLINESITE2
    )
}

fn closes_scope(kind: u16) -> bool {
    matches!(kind, S_END | S_PROC_ID_END | S_INLINESITE_END)
}

fn goes_in_module(kind: u16, depth: usize) -> bool {
    match kind {
        S_GDATA32 | S_GTHREAD32 | S_PROCREF | S_LPROCREF => false,
        S_UDT | S_CONSTANT => depth > 0,
        _ => true,
    }
}

fn goes_in_globals(kind: u16, depth: usize) -> bool {
    match kind {
        S_GDATA32 | S_GTHREAD32 | S_GPROC32 | S_LPROC32 | S_PROCREF | S_LPROCREF => true,
        S_UDT | S_LDATA32 | S_LTHREAD32 | S_CONSTANT => depth == 0,
        _ => false,
    }
}

pub fn symbol_name(rec: &[u8]) -> &[u8] {
    let kind = u16at(rec, 2);
    let c = &rec[4..];
    let at = match kind {
        S_GPROC32 | S_LPROC32 | S_GPROC32_ID | S_LPROC32_ID => 35,
        S_UDT => 4,
        S_GDATA32 | S_LDATA32 | S_GTHREAD32 | S_LTHREAD32 => 10,
        S_PROCREF | S_LPROCREF => 10,
        S_PUB32 => 10,
        S_CONSTANT => 4 + super::types::numeric_len(c.get(4..).unwrap_or(&[])),
        _ => return &[],
    };
    let rest = c.get(at..).unwrap_or(&[]);
    &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())]
}

#[derive(Default)]
pub struct ModuleOut {
    pub stream: Vec<u8>,
    pub sym_bytes: u32,
    pub c13_bytes: u32,
    pub files: Vec<Vec<u8>>,
    pub globals: Vec<u8>,
    pub string_patches: Vec<(u32, Vec<u8>)>,
}

impl ModuleOut {
    pub fn has_stream(&self) -> bool {
        !self.stream.is_empty()
    }
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

pub fn build(l: &Linker, oi: usize, obj: &ObjFile, merged: &Merged) -> ModuleOut {
    let sections: Vec<usize> = obj
        .debug_s
        .iter()
        .map(|&s| s as usize)
        .filter(|&s| {
            let sec = &obj.sections[s];
            if sec.discarded {
                return false;
            }
            match sec.comdat {
                Some(c) if c.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE => obj
                    .sections
                    .get(c.assoc as usize)
                    .is_some_and(|p| p.is_live()),
                _ => true,
            }
        })
        .collect();
    if sections.is_empty() {
        return ModuleOut::default();
    }

    let ctx = l.reloc_ctx();
    let relocated: Vec<Vec<u8>> = sections
        .iter()
        .map(|&si| {
            let sec = &obj.sections[si];
            let mut buf = sec.data.to_vec();
            for r in sec.relocs.as_chunks::<10>().0 {
                let ty = u16le(r, 8);
                if l.machine.is_absolute_reloc(ty) {
                    continue;
                }
                let off = u32le(r, 0).wrapping_sub(sec.va) as usize;
                if off + l.machine.reloc_width(ty) > buf.len() {
                    continue;
                }
                match l.reloc_target(obj, u32le(r, 4)) {
                    Some(t) => {
                        let _ = arch::apply(l.machine, &ctx, ty, &mut buf, off, t, 0);
                    }
                    None => {
                        let w = l.machine.reloc_width(ty);
                        buf[off..off + w].fill(0);
                    }
                }
            }
            buf
        })
        .collect();

    let mut subsections: Vec<(u32, &[u8])> = Vec::new();
    for buf in &relocated {
        if buf.len() < 4 || u32at(buf, 0) != 4 {
            continue;
        }
        let mut off = 4;
        while off + 8 <= buf.len() {
            let kind = u32at(buf, off);
            let len = u32at(buf, off + 4) as usize;
            if off + 8 + len > buf.len() {
                break;
            }
            subsections.push((kind, &buf[off + 8..off + 8 + len]));
            off = (off + 8 + len).next_multiple_of(4);
        }
    }
    let strtab: &[u8] = subsections
        .iter()
        .find(|(k, _)| *k == DEBUG_S_STRINGTABLE)
        .map_or(&[], |(_, d)| d);
    let string_at = |o: u32| -> Vec<u8> {
        let s = strtab.get(o as usize..).unwrap_or(&[]);
        s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())].to_vec()
    };

    let mut out = ModuleOut::default();
    let mut syms: Vec<u8> = 4u32.to_le_bytes().to_vec();
    let mut c13: Vec<u8> = Vec::new();
    let mut c13_patches: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let module_index = (oi + 1) as u16;
    let mut checksums_done = false;

    for &(kind, data) in &subsections {
        if kind & DEBUG_S_IGNORE != 0 {
            continue;
        }
        match kind {
            DEBUG_S_SYMBOLS => {
                let mut p = 0usize;
                while p + 4 <= data.len() {
                    let reclen = u16at(data, p) as usize;
                    if reclen < 2 || p + 2 + reclen > data.len() {
                        break;
                    }
                    let at = syms.len();
                    syms.extend_from_slice(&data[p..p + 2 + reclen]);
                    p += 2 + reclen;
                    pad4(&mut syms);
                    let len = syms.len() - at;
                    let rec = &mut syms[at..];
                    rec[..2].copy_from_slice(&((len - 2) as u16).to_le_bytes());
                    let mut kind = u16at(rec, 2);
                    for &(off, _) in symbol_refs(kind, &rec[4..]) {
                        let off = 4 + off as usize;
                        let ti = u32at(rec, off);
                        set32(rec, off, merged.map(oi, ti));
                    }
                    if let S_CALLERS | S_CALLEES | S_INLINEES = kind {
                        let n = u32at(rec, 4) as usize;
                        for k in 0..n {
                            let off = 8 + 4 * k;
                            let ti = u32at(rec, off);
                            set32(rec, off, merged.map(oi, ti));
                        }
                    }
                    if kind == S_GPROC32_ID || kind == S_LPROC32_ID {
                        let id = u32at(rec, 4 + 24);
                        if let Some(r) = merged.ipi_record(id)
                            && matches!(u16at(r, 2), LF_FUNC_ID | LF_MFUNC_ID)
                        {
                            set32(rec, 4 + 24, u32at(r, 4 + 4));
                            kind = if kind == S_GPROC32_ID {
                                S_GPROC32
                            } else {
                                S_LPROC32
                            };
                            rec[2..4].copy_from_slice(&kind.to_le_bytes());
                        }
                    } else if kind == S_PROC_ID_END {
                        kind = S_END;
                        rec[2..4].copy_from_slice(&kind.to_le_bytes());
                    }

                    let depth = stack.len();
                    if goes_in_globals(kind, depth) {
                        if kind == S_GPROC32 || kind == S_LPROC32 {
                            append_procref(
                                &mut out.globals,
                                kind,
                                module_index,
                                at as u32,
                                symbol_name(rec),
                            );
                        } else {
                            out.globals.extend_from_slice(rec);
                        }
                    }
                    if !goes_in_module(kind, depth) {
                        syms.truncate(at);
                        continue;
                    }
                    if kind == S_FILESTATIC {
                        let name = string_at(u32at(rec, 8));
                        out.string_patches.push((at as u32 + 8, name));
                    }
                    if opens_scope(kind) {
                        let parent = stack.last().copied().unwrap_or(0) as u32;
                        set32(rec, 4, parent);
                        set32(rec, 8, 0);
                        if matches!(
                            kind,
                            S_GPROC32 | S_LPROC32 | S_THUNK32 | S_GPROC32_ID | S_LPROC32_ID
                        ) {
                            set32(rec, 12, 0);
                        }
                        stack.push(at);
                    } else if closes_scope(kind)
                        && let Some(open) = stack.pop()
                    {
                        set32(&mut syms, open + 8, at as u32);
                    }
                }
            }
            DEBUG_S_FILECHKSMS if !checksums_done => {
                checksums_done = true;
                let base = c13.len() + 8;
                c13.extend_from_slice(&kind.to_le_bytes());
                c13.extend_from_slice(&(data.len() as u32).to_le_bytes());
                c13.extend_from_slice(data);
                let mut e = 0usize;
                while e + 6 <= data.len() {
                    let name = string_at(u32at(data, e));
                    c13_patches.push(((base + e) as u32, name.clone()));
                    out.files.push(name);
                    let size = data[e + 4] as usize;
                    e = (e + 6 + size).next_multiple_of(4);
                }
                pad4(&mut c13);
            }
            DEBUG_S_LINES => {
                c13.extend_from_slice(&kind.to_le_bytes());
                c13.extend_from_slice(&(data.len() as u32).to_le_bytes());
                c13.extend_from_slice(data);
                pad4(&mut c13);
            }
            DEBUG_S_INLINEELINES => {
                let start = c13.len() + 8;
                c13.extend_from_slice(&kind.to_le_bytes());
                c13.extend_from_slice(&(data.len() as u32).to_le_bytes());
                c13.extend_from_slice(data);
                let extra_files = u32at(data, 0) == 1;
                let mut e = 4usize;
                while e + 12 <= data.len() {
                    let ti = u32at(data, e);
                    set32(&mut c13, start + e, merged.map(oi, ti));
                    let mut size = 12;
                    if extra_files {
                        size += 4 + 4 * u32at(data, e + 12) as usize;
                    }
                    e += size;
                }
                pad4(&mut c13);
            }
            _ => {}
        }
    }

    out.sym_bytes = syms.len() as u32;
    out.c13_bytes = c13.len() as u32;
    let base = syms.len() as u32;
    out.string_patches
        .extend(c13_patches.into_iter().map(|(p, s)| (p + base, s)));
    out.stream = syms;
    out.stream.extend_from_slice(&c13);
    out.stream.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[cfg(test)]
pub fn procref(kind: u16, module: u16, offset: u32, name: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    append_procref(&mut r, kind, module, offset, name);
    r
}

pub fn append_procref(r: &mut Vec<u8>, kind: u16, module: u16, offset: u32, name: &[u8]) {
    let ref_kind = if kind == S_LPROC32 {
        S_LPROCREF
    } else {
        S_PROCREF
    };
    let start = r.len();
    r.extend_from_slice(&[0, 0]);
    r.extend_from_slice(&ref_kind.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes()); // SumName
    r.extend_from_slice(&offset.to_le_bytes());
    r.extend_from_slice(&module.to_le_bytes());
    r.extend_from_slice(name);
    r.push(0);
    pad4(r);
    let len = r.len() - start;
    r[start..start + 2].copy_from_slice(&((len - 2) as u16).to_le_bytes());
}

pub fn record(kind: u16, content: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(4 + content.len() + 3);
    r.extend_from_slice(&[0, 0]);
    r.extend_from_slice(&kind.to_le_bytes());
    r.extend_from_slice(content);
    pad4(&mut r);
    let len = r.len();
    r[..2].copy_from_slice(&((len - 2) as u16).to_le_bytes());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procrefs_and_names() {
        let r = procref(S_GPROC32, 3, 0x40, b"main");
        assert_eq!(u16at(&r, 2), S_PROCREF);
        assert_eq!(r.len() % 4, 0);
        assert_eq!(u16at(&r, 0) as usize, r.len() - 2);
        assert_eq!(symbol_name(&r), b"main");
        let udt = record(S_UDT, &[0x00, 0x10, 0, 0, b'T', 0]);
        assert_eq!(symbol_name(&udt), b"T");
        assert!(goes_in_globals(S_UDT, 0) && !goes_in_module(S_UDT, 0));
        assert!(goes_in_module(S_UDT, 1) && !goes_in_globals(S_UDT, 1));
        assert!(goes_in_module(S_LDATA32, 0) && goes_in_globals(S_LDATA32, 0));
        assert!(!goes_in_module(S_GDATA32, 0));
    }
}
