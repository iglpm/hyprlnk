//! `.res` files → the `.rsrc` resource tree (what `cvtres.exe` does for `link.exe`).

use std::collections::BTreeMap;

use super::resolve::Linker;
use super::synth::{RSRC, SynthChunk};
use super::*;
use crate::diag::Result;
use crate::{bail, err};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResId {
    // Named entries come before numbered ones in a directory.
    Name(Vec<u16>),
    Id(u16),
}

pub struct Rsrc {
    pub bytes: Vec<u8>,
    pub data_entry_fields: Vec<usize>,
}

impl Rsrc {
    pub fn write(&self, dst: &mut [u8], rva: u32) {
        dst[..self.bytes.len()].copy_from_slice(&self.bytes);
        for &f in &self.data_entry_fields {
            put32(dst, f, u32le(dst, f) + rva);
        }
    }
}

type Tree<'a> = BTreeMap<ResId, BTreeMap<ResId, BTreeMap<u16, &'a [u8]>>>;

fn read_id(d: &[u8], off: &mut usize, file: &str) -> Result<ResId> {
    let word = |o: usize| -> Result<u16> {
        d.get(o..o + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| err!("{file}: truncated resource header"))
    };
    if word(*off)? == 0xFFFF {
        let id = word(*off + 2)?;
        *off += 4;
        return Ok(ResId::Id(id));
    }
    let mut name = Vec::new();
    loop {
        let c = word(*off)?;
        *off += 2;
        if c == 0 {
            break;
        }
        name.push(c);
    }
    Ok(ResId::Name(name))
}

fn parse<'a>(file: &str, d: &'a [u8], tree: &mut Tree<'a>) -> Result<()> {
    let mut off = 0usize;
    while off + 8 <= d.len() {
        let data_size = u32le(d, off) as usize;
        let header_size = u32le(d, off + 4) as usize;
        if header_size < 16 || off + header_size + data_size > d.len() {
            bail!("{file}: malformed resource entry at offset {off}");
        }
        let mut p = off + 8;
        let ty = read_id(d, &mut p, file)?;
        let name = read_id(d, &mut p, file)?;
        p = align_up(p as u64, 4) as usize;
        let lang = u16le(d, p + 6);
        let data = &d[off + header_size..off + header_size + data_size];
        let empty = data_size == 0 && ty == ResId::Id(0) && name == ResId::Id(0);
        if !empty {
            let langs = tree
                .entry(ty.clone())
                .or_default()
                .entry(name.clone())
                .or_default();
            if langs.insert(lang, data).is_some() {
                bail!("{file}: duplicate resource {ty:?}/{name:?} (language {lang:#x})");
            }
        }
        off = align_up((off + header_size + data_size) as u64, 4) as usize;
    }
    Ok(())
}

pub fn create(l: &mut Linker) -> Result<()> {
    if l.resources.is_empty() {
        return Ok(());
    }
    let mut tree: Tree = BTreeMap::new();
    for (file, data) in &l.resources {
        parse(file, data, &mut tree)?;
    }
    let rsrc = build(&tree);
    l.synth[RSRC] = SynthChunk {
        size: rsrc.bytes.len() as u32,
        align: 4,
        ..Default::default()
    };
    l.rsrc = Some(rsrc);
    Ok(())
}

fn build(tree: &Tree) -> Rsrc {
    let dir_size = |n: usize| 16 + 8 * n;
    let mut size = dir_size(tree.len());
    for names in tree.values() {
        size += dir_size(names.len());
    }
    for names in tree.values() {
        for langs in names.values() {
            size += dir_size(langs.len());
        }
    }
    let data_entries_off = size;
    let nleaves: usize = tree
        .values()
        .flat_map(|n| n.values())
        .map(|l| l.len())
        .sum();
    size += 16 * nleaves;
    let strings_off = size;
    let mut strings: Vec<u8> = Vec::new();
    let mut string_offsets: BTreeMap<Vec<u16>, u32> = BTreeMap::new();
    let mut intern = |s: &Vec<u16>| -> u32 {
        *string_offsets.entry(s.clone()).or_insert_with(|| {
            let o = (strings_off + strings.len()) as u32;
            strings.extend_from_slice(&(s.len() as u16).to_le_bytes());
            for c in s {
                strings.extend_from_slice(&c.to_le_bytes());
            }
            o
        })
    };
    for (ty, names) in tree {
        if let ResId::Name(n) = ty {
            intern(n);
        }
        for name in names.keys() {
            if let ResId::Name(n) = name {
                intern(n);
            }
        }
    }
    size += strings.len();
    let mut data_off = align_up(size as u64, 8) as usize;
    let mut out = vec![0u8; data_off];
    out[strings_off..strings_off + strings.len()].copy_from_slice(&strings);

    let mut fields = Vec::new();
    let id_field = |id: &ResId| -> u32 {
        match id {
            ResId::Id(n) => *n as u32,
            ResId::Name(n) => 0x8000_0000 | string_offsets[n],
        }
    };
    let write_dir = |out: &mut [u8], at: usize, ids: &[&ResId]| {
        let named = ids.iter().filter(|i| matches!(i, ResId::Name(_))).count();
        put16(out, at + 12, named as u16);
        put16(out, at + 14, (ids.len() - named) as u16);
    };

    let types: Vec<&ResId> = tree.keys().collect();
    write_dir(&mut out, 0, &types);
    let mut next_dir = dir_size(tree.len());
    let mut leaf = 0usize;
    let mut name_dirs = Vec::new();
    for (i, (ty, names)) in tree.iter().enumerate() {
        put32(&mut out, 16 + 8 * i, id_field(ty));
        put32(&mut out, 16 + 8 * i + 4, 0x8000_0000 | next_dir as u32);
        name_dirs.push((next_dir, names));
        next_dir += dir_size(names.len());
    }
    let mut lang_dirs = Vec::new();
    for (at, names) in name_dirs {
        let ids: Vec<&ResId> = names.keys().collect();
        write_dir(&mut out, at, &ids);
        for (j, (name, langs)) in names.iter().enumerate() {
            put32(&mut out, at + 16 + 8 * j, id_field(name));
            put32(&mut out, at + 16 + 8 * j + 4, 0x8000_0000 | next_dir as u32);
            lang_dirs.push((next_dir, langs));
            next_dir += dir_size(langs.len());
        }
    }
    let mut blobs = Vec::new();
    for (at, langs) in lang_dirs {
        put16(&mut out, at + 14, langs.len() as u16);
        for (k, (lang, data)) in langs.iter().enumerate() {
            let entry = data_entries_off + 16 * leaf;
            leaf += 1;
            put32(&mut out, at + 16 + 8 * k, *lang as u32);
            put32(&mut out, at + 16 + 8 * k + 4, entry as u32);
            put32(&mut out, entry, data_off as u32);
            put32(&mut out, entry + 4, data.len() as u32);
            fields.push(entry);
            blobs.push((data_off, *data));
            data_off = align_up((data_off + data.len()) as u64, 8) as usize;
        }
    }
    out.resize(data_off, 0);
    for (at, data) in blobs {
        out[at..at + data.len()].copy_from_slice(data);
    }
    Rsrc {
        bytes: out,
        data_entry_fields: fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ty: u16, name: &str, lang: u16, data: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&[0xFF, 0xFF]);
        h.extend_from_slice(&ty.to_le_bytes());
        for c in name.encode_utf16() {
            h.extend_from_slice(&c.to_le_bytes());
        }
        h.extend_from_slice(&[0, 0]);
        while (8 + h.len()) % 4 != 0 {
            h.push(0);
        }
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0x1030u16.to_le_bytes());
        h.extend_from_slice(&lang.to_le_bytes());
        h.extend_from_slice(&[0; 8]);
        let mut e = Vec::new();
        e.extend_from_slice(&(data.len() as u32).to_le_bytes());
        e.extend_from_slice(&((8 + h.len()) as u32).to_le_bytes());
        e.extend_from_slice(&h);
        e.extend_from_slice(data);
        while e.len() % 4 != 0 {
            e.push(0);
        }
        e
    }

    #[test]
    fn builds_a_resource_tree() {
        let mut res = vec![0u8; 0];
        res.extend_from_slice(&[
            0, 0, 0, 0, 0x20, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0,
        ]);
        res.extend_from_slice(&[0; 16]);
        res.extend(entry(24, "MANIFEST", 0x409, b"<assembly/>"));
        res.extend(entry(16, "VER", 0x409, b"version!"));
        let mut tree = Tree::new();
        parse("t.res", &res, &mut tree).unwrap();
        let r = build(&tree);
        assert_eq!(u16le(&r.bytes, 12), 0);
        assert_eq!(u16le(&r.bytes, 14), 2);
        assert_eq!(u32le(&r.bytes, 16), 16);
        assert_eq!(u32le(&r.bytes, 24), 24);
        assert_eq!(r.data_entry_fields.len(), 2);
        let mut out = vec![0u8; r.bytes.len()];
        r.write(&mut out, 0x5000);
        let first = r.data_entry_fields[0];
        let data_rva = u32le(&out, first) - 0x5000;
        assert_eq!(&out[data_rva as usize..data_rva as usize + 8], b"version!");
        let mut dup = Tree::new();
        let two = [entry(3, "X", 1, b"a"), entry(3, "X", 1, b"b")].concat();
        assert!(parse("d.res", &two, &mut dup).is_err());
    }
}
