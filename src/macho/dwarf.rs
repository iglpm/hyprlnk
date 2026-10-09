//! Just enough DWARF to name a compile unit for the debug map: `DW_AT_name` and `DW_AT_comp_dir`.

use super::object::ObjFile;
use super::*;

const DW_AT_NAME: u64 = 0x03;
const DW_AT_COMP_DIR: u64 = 0x1b;
const DW_AT_STR_OFFSETS_BASE: u64 = 0x72;

fn section<'a>(obj: &ObjFile<'a>, name: &[u8]) -> &'a [u8] {
    obj.sections
        .iter()
        .find(|s| s.segname == b"__DWARF" && s.sectname == name)
        .map_or(&[], |s| s.data)
}

/// The compile unit's source path: `DW_AT_name`, under `DW_AT_comp_dir` unless absolute.
pub fn source_file(obj: &ObjFile) -> Option<Vec<u8>> {
    let info = section(obj, b"__debug_info");
    let abbrev = section(obj, b"__debug_abbrev");
    let strs = section(obj, b"__debug_str");
    let line_strs = section(obj, b"__debug_line_str");
    let str_offsets = section(obj, b"__debug_str_offs");
    let mut p = 0usize;
    let len = u32le(info.get(..4)?, 0);
    if len == 0xffff_ffff {
        return None;
    }
    p += 4;
    let version = u16le(info.get(p..p + 2)?, 0);
    p += 2;
    let (abbrev_off, addr_size) = if version >= 5 {
        let _unit_type = *info.get(p)?;
        let asz = *info.get(p + 1)?;
        let ao = u32le(info.get(p + 2..p + 6)?, 0);
        p += 6;
        (ao as usize, asz as usize)
    } else {
        let ao = u32le(info.get(p..p + 4)?, 0);
        let asz = *info.get(p + 4)?;
        p += 5;
        (ao as usize, asz as usize)
    };
    let code = read_uleb(info, &mut p)?;
    // Find the abbreviation.
    let mut a = abbrev_off;
    loop {
        let c = read_uleb(abbrev, &mut a)?;
        if c == 0 {
            return None;
        }
        let _tag = read_uleb(abbrev, &mut a)?;
        a += 1;
        if c == code {
            break;
        }
        loop {
            let at = read_uleb(abbrev, &mut a)?;
            let form = read_uleb(abbrev, &mut a)?;
            if form == 0x21 {
                read_sleb(abbrev, &mut a)?;
            }
            if at == 0 && form == 0 {
                break;
            }
        }
    }
    enum Str {
        Inline(usize),
        Strp(u64),
        LineStrp(u64),
        Strx(u64),
    }
    let mut name = None;
    let mut dir = None;
    let mut str_base = 8u64;
    loop {
        let at = read_uleb(abbrev, &mut a)?;
        let mut form = read_uleb(abbrev, &mut a)?;
        if at == 0 && form == 0 {
            break;
        }
        if form == 0x21 {
            read_sleb(abbrev, &mut a)?;
            continue;
        }
        if form == 0x16 {
            form = read_uleb(info, &mut p)?;
        }
        let mut value: Option<Str> = None;
        let mut num: Option<u64> = None;
        match form {
            0x08 => {
                value = Some(Str::Inline(p));
                p += cstr(info, p).len() + 1;
            }
            0x0e => {
                value = Some(Str::Strp(u32le(info.get(p..p + 4)?, 0) as u64));
                p += 4;
            }
            0x1f => {
                value = Some(Str::LineStrp(u32le(info.get(p..p + 4)?, 0) as u64));
                p += 4;
            }
            0x1a => value = Some(Str::Strx(read_uleb(info, &mut p)?)),
            0x25..=0x28 => {
                let n = (form - 0x24) as usize;
                let mut v = 0u64;
                for i in 0..n {
                    v |= (*info.get(p + i)? as u64) << (8 * i);
                }
                p += n;
                value = Some(Str::Strx(v));
            }
            0x01 => p += addr_size,
            0x0b | 0x11 | 0x0c | 0x29 => p += 1,
            0x05 | 0x12 | 0x2a => p += 2,
            0x2b => p += 3,
            0x06 | 0x13 | 0x10 | 0x2c => {
                num = Some(u32le(info.get(p..p + 4)?, 0) as u64);
                p += 4;
            }
            0x17 => {
                num = Some(u32le(info.get(p..p + 4)?, 0) as u64);
                p += 4;
            }
            0x07 | 0x14 | 0x20 => p += 8,
            0x1e => p += 16,
            0x0d => {
                read_sleb(info, &mut p)?;
            }
            0x0f | 0x15 | 0x1b | 0x22 | 0x23 => {
                num = Some(read_uleb(info, &mut p)?);
            }
            0x19 => {}
            0x18 | 0x09 => {
                let n = read_uleb(info, &mut p)? as usize;
                p += n;
            }
            0x0a => {
                let n = *info.get(p)? as usize;
                p += 1 + n;
            }
            0x03 => {
                let n = u16le(info.get(p..p + 2)?, 0) as usize;
                p += 2 + n;
            }
            0x04 => {
                let n = u32le(info.get(p..p + 4)?, 0) as usize;
                p += 4 + n;
            }
            _ => return None,
        }
        match at {
            DW_AT_NAME => name = value,
            DW_AT_COMP_DIR => dir = value,
            DW_AT_STR_OFFSETS_BASE => str_base = num.unwrap_or(8),
            _ => {}
        }
    }
    let get = |s: Option<Str>| -> Option<&[u8]> {
        Some(match s? {
            Str::Inline(o) => cstr(info, o),
            Str::Strp(o) => cstr(strs, o as usize),
            Str::LineStrp(o) => cstr(line_strs, o as usize),
            Str::Strx(i) => {
                let at = (str_base + 4 * i) as usize;
                let o = u32le(str_offsets.get(at..at + 4)?, 0);
                cstr(strs, o as usize)
            }
        })
    };
    let name = get(name)?;
    if name.starts_with(b"/") || (name.len() > 2 && name[1] == b':') {
        return Some(name.to_vec());
    }
    let mut out = get(dir).unwrap_or(b"").to_vec();
    if !out.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    Some(out)
}
