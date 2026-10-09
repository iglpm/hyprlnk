//! Mach-O dylibs as link inputs: their install name, versions, re-exports and exported symbols.

use std::borrow::Cow;

use super::tbd::{Export, Interface};
use super::*;
use crate::diag::Result;
use crate::{bail, err};

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;

pub fn parse<'a>(data: &'a [u8], path: &str) -> Result<(Interface<'a>, Vec<String>)> {
    if data.len() < 32 || u32le(data, 0) != MH_MAGIC_64 {
        bail!("{path}: not a 64-bit Mach-O dylib");
    }
    let ncmds = u32le(data, 16) as usize;
    let mut iface = Interface::default();
    let mut rpaths = Vec::new();
    let mut trie: Option<&[u8]> = None;
    let mut symtab: Option<(usize, usize, usize, usize)> = None;
    let mut sect_types: Vec<u32> = Vec::new();
    let mut id_seen = false;
    let mut off = 32;
    for _ in 0..ncmds {
        if off + 8 > data.len() {
            bail!("{path}: load commands run past the end");
        }
        let cmd = u32le(data, off);
        let size = u32le(data, off + 4) as usize;
        if size < 8 || off + size > data.len() {
            bail!("{path}: bad load command size");
        }
        let lc = &data[off..off + size];
        let str_at =
            |o: usize| String::from_utf8_lossy(cstr(lc, u32le(lc, o) as usize)).into_owned();
        match cmd {
            LC_ID_DYLIB => {
                iface.install_name = str_at(8);
                iface.current_version = u32le(lc, 16);
                iface.compat_version = u32le(lc, 20);
                id_seen = true;
            }
            LC_REEXPORT_DYLIB => iface.reexports.push(str_at(8)),
            LC_RPATH => rpaths.push(str_at(8)),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                let (o, n) = (u32le(lc, 40) as usize, u32le(lc, 44) as usize);
                if n > 0 {
                    trie = data.get(o..o + n);
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                let (o, n) = (u32le(lc, 8) as usize, u32le(lc, 12) as usize);
                if n > 0 {
                    trie = data.get(o..o + n);
                }
            }
            LC_SYMTAB => {
                symtab = Some((
                    u32le(lc, 8) as usize,
                    u32le(lc, 12) as usize,
                    u32le(lc, 16) as usize,
                    u32le(lc, 20) as usize,
                ))
            }
            LC_SEGMENT_64 => {
                let nsects = u32le(lc, 64) as usize;
                for i in 0..nsects {
                    let h = 72 + i * 80;
                    if h + 80 <= lc.len() {
                        sect_types.push(u32le(lc, h + 64) & SECTION_TYPE);
                    }
                }
            }
            _ => {}
        }
        off += size;
    }
    if !id_seen {
        bail!("{path}: dylib has no LC_ID_DYLIB");
    }
    if let Some(t) = trie {
        walk_trie(t, &mut iface.exports).map_err(|e| err!("{path}: {e}"))?;
    } else if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        let nl = data
            .get(symoff..symoff + nsyms * 16)
            .ok_or_else(|| err!("{path}: symbol table runs past the end"))?;
        let strtab = data
            .get(stroff..stroff + strsize)
            .ok_or_else(|| err!("{path}: string table runs past the end"))?;
        for i in 0..nsyms {
            let o = i * 16;
            let ty = nl[o + 4];
            let sect = nl[o + 5];
            let desc = u16le(nl, o + 6);
            if ty & N_STAB != 0 || ty & N_EXT == 0 || ty & N_PEXT != 0 {
                continue;
            }
            if !matches!(ty & N_TYPE, N_SECT | N_ABS) {
                continue;
            }
            let tlv = sect > 0
                && sect_types
                    .get(sect as usize - 1)
                    .is_some_and(|&t| t == S_THREAD_LOCAL_VARIABLES);
            iface.exports.push(Export {
                name: Cow::Borrowed(cstr(strtab, u32le(nl, o) as usize)),
                weak: desc & N_WEAK_DEF != 0,
                tlv,
            });
        }
    }
    Ok((iface, rpaths))
}

fn walk_trie<'a>(t: &[u8], out: &mut Vec<Export<'a>>) -> Result<()> {
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    let mut visited = 0usize;
    while let Some((node, prefix)) = stack.pop() {
        visited += 1;
        if visited > t.len() + 1 {
            bail!("export trie has a cycle");
        }
        let mut p = node;
        let term = read_uleb(t, &mut p).ok_or_else(|| err!("truncated export trie"))? as usize;
        let children_at = p + term;
        if term > 0 {
            let flags = read_uleb(t, &mut p).ok_or_else(|| err!("truncated export trie"))?;
            out.push(Export {
                name: Cow::Owned(prefix.clone()),
                weak: flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0,
                tlv: flags & EXPORT_SYMBOL_FLAGS_KIND_MASK == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
            });
        }
        let mut p = children_at;
        let n = *t.get(p).ok_or_else(|| err!("truncated export trie"))? as usize;
        p += 1;
        for _ in 0..n {
            let edge = cstr(t, p);
            p += edge.len() + 1;
            let child = read_uleb(t, &mut p).ok_or_else(|| err!("truncated export trie"))? as usize;
            if child >= t.len() {
                bail!("export trie child out of range");
            }
            let mut name = prefix.clone();
            name.extend_from_slice(edge);
            stack.push((child, name));
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn tests_walk(t: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    walk_trie(t, &mut out).unwrap();
    out.into_iter().map(|e| (e.name.to_vec(), e.weak)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_a_trie() {
        // root: no terminal, 2 children: "_a" → node A (terminal, flags 0, addr 0x10), "_b" → B (weak)
        let mut t = vec![0u8, 2];
        t.extend_from_slice(b"_a\0");
        let a_at = t.len();
        t.push(0);
        t.extend_from_slice(b"_b\0");
        let b_at = t.len();
        t.push(0);
        let a = t.len();
        t.extend_from_slice(&[2, 0, 0x10, 0]);
        let b = t.len();
        t.extend_from_slice(&[2, 4, 0x20, 0]);
        t[a_at] = a as u8;
        t[b_at] = b as u8;
        let mut out = Vec::new();
        walk_trie(&t, &mut out).unwrap();
        let mut names: Vec<(Vec<u8>, bool)> =
            out.iter().map(|e| (e.name.to_vec(), e.weak)).collect();
        names.sort();
        assert_eq!(names, [(b"_a".to_vec(), false), (b"_b".to_vec(), true)]);
    }
}
