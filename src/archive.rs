//! `ar` archives: rlibs, MSVC `.lib` files (static libraries and import
//! libraries alike) and Unix `.a` files.
//!
//! Only the symbol table is read up front. A member is parsed when the link
//! needs one of its symbols, by the offset the symbol table gives.

use crate::diag::Result;
use crate::{bail, err};

const MAGIC: &[u8] = b"!<arch>\n";
const THIN_MAGIC: &[u8] = b"!<thin>\n";
const HEADER: usize = 60;

/// One symbol-table entry: a name and the offset of the member header that
/// defines it.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveSymbol<'a> {
    pub name: &'a [u8],
    pub offset: u32,
}

pub struct Archive<'a> {
    data: &'a [u8],
    longnames: &'a [u8],
    /// Offset of the first member after the symbol table and name table.
    first_member: usize,
    pub symbols: Vec<ArchiveSymbol<'a>>,
    /// Whether the archive had a symbol table; without one, every member is
    /// read to build it.
    pub has_symbol_table: bool,
}

pub struct Member<'a> {
    pub name: String,
    pub data: &'a [u8],
    pub offset: u32,
}

pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub fn is_thin_archive(data: &[u8]) -> bool {
    data.starts_with(THIN_MAGIC)
}

struct RawHeader<'a> {
    name: &'a [u8],
    data_start: usize,
    size: usize,
}

impl<'a> Archive<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Archive<'a>> {
        if is_thin_archive(data) {
            bail!("thin archives are not supported yet");
        }
        if !is_archive(data) {
            bail!("not an archive");
        }
        let mut ar = Archive {
            data,
            longnames: &[],
            first_member: MAGIC.len(),
            symbols: Vec::new(),
            has_symbol_table: false,
        };
        // Leading special members: the symbol table(s) and the long-name table.
        let mut off = MAGIC.len();
        let mut seen_symtab = false;
        while off < data.len() {
            let h = ar.header_at(off)?;
            let body = &data[h.data_start..h.data_start + h.size];
            match h.name {
                b"/" if !seen_symtab => {
                    ar.symbols = parse_gnu_symtab(body, false)?;
                    seen_symtab = true;
                }
                // The COFF second linker member repeats the first, sorted.
                b"/" => {}
                b"/SYM64/" => {
                    ar.symbols = parse_gnu_symtab(body, true)?;
                    seen_symtab = true;
                }
                b"__.SYMDEF" | b"__.SYMDEF SORTED" => {
                    ar.symbols = parse_bsd_symtab(body)?;
                    seen_symtab = true;
                }
                b"//" => ar.longnames = body,
                // ARM64EC's extra symbol table.
                b"/<ECSYMBOLS>/" => {}
                _ => break,
            }
            off = h.data_start + h.size + (h.size & 1);
        }
        ar.first_member = off;
        ar.has_symbol_table = seen_symtab;
        Ok(ar)
    }

    fn header_at(&self, off: usize) -> Result<RawHeader<'a>> {
        let data = self.data;
        if off + HEADER > data.len() {
            bail!("truncated archive member header at offset {off}");
        }
        let h = &data[off..off + HEADER];
        if &h[58..60] != b"`\n" {
            bail!("bad archive member header at offset {off}");
        }
        let size = parse_decimal(&h[48..58])
            .ok_or_else(|| err!("bad archive member size at offset {off}"))?;
        let data_start = off + HEADER;
        if data_start + size > data.len() {
            bail!("archive member at offset {off} runs past the end of the file");
        }
        let name = trim_trailing(&h[..16], b' ');
        Ok(RawHeader {
            name,
            data_start,
            size,
        })
    }

    /// The member whose header is at `offset` (as the symbol table says).
    pub fn member_at(&self, offset: u32) -> Result<Member<'a>> {
        let h = self.header_at(offset as usize)?;
        let mut data = &self.data[h.data_start..h.data_start + h.size];
        let name = if let Some(len) = h.name.strip_prefix(b"#1/") {
            // BSD: the name follows the header and counts towards the size.
            let len = parse_decimal(len).ok_or_else(|| err!("bad BSD member name"))?;
            if len > data.len() {
                bail!("bad BSD member name length");
            }
            let (name, rest) = data.split_at(len);
            data = rest;
            String::from_utf8_lossy(trim_trailing(name, 0)).into_owned()
        } else if let Some(idx) = h.name.strip_prefix(b"/").and_then(parse_decimal) {
            // GNU/COFF long name: an offset into the `//` member, where names
            // end with "/\n" (GNU) or a NUL (COFF).
            let start = idx.min(self.longnames.len());
            let rest = &self.longnames[start..];
            let end = rest
                .iter()
                .position(|&b| b == 0 || b == b'\n')
                .unwrap_or(rest.len());
            let name = &rest[..end];
            String::from_utf8_lossy(name.strip_suffix(b"/").unwrap_or(name)).into_owned()
        } else {
            String::from_utf8_lossy(h.name.strip_suffix(b"/").unwrap_or(h.name)).into_owned()
        };
        Ok(Member { name, data, offset })
    }

    /// Every regular member, in order.
    pub fn members(&self) -> Result<Vec<Member<'a>>> {
        let mut out = Vec::new();
        let mut off = self.first_member;
        while off + HEADER <= self.data.len() {
            let h = self.header_at(off)?;
            out.push(self.member_at(off as u32)?);
            off = h.data_start + h.size + (h.size & 1);
        }
        Ok(out)
    }
}

fn parse_gnu_symtab(body: &[u8], wide: bool) -> Result<Vec<ArchiveSymbol<'_>>> {
    let w = if wide { 8 } else { 4 };
    let read = |off: usize| -> Option<u64> {
        let b = body.get(off..off + w)?;
        Some(if wide {
            u64::from_be_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap()) as u64
        })
    };
    let count = read(0).ok_or_else(|| err!("truncated archive symbol table"))? as usize;
    let names_start = w + count * w;
    if names_start > body.len() {
        bail!("truncated archive symbol table");
    }
    let mut names = &body[names_start..];
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let offset = read(w + i * w).unwrap() as u32;
        let end = names
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| err!("truncated archive symbol table names"))?;
        out.push(ArchiveSymbol {
            name: &names[..end],
            offset,
        });
        names = &names[end + 1..];
    }
    Ok(out)
}

fn parse_bsd_symtab(body: &[u8]) -> Result<Vec<ArchiveSymbol<'_>>> {
    let u32le = |off: usize| -> Option<usize> {
        Some(u32::from_le_bytes(body.get(off..off + 4)?.try_into().unwrap()) as usize)
    };
    let ranlib_size = u32le(0).ok_or_else(|| err!("truncated BSD symbol table"))?;
    let strtab_size = u32le(4 + ranlib_size).ok_or_else(|| err!("truncated BSD symbol table"))?;
    let strtab_start = 8 + ranlib_size;
    let strtab = body
        .get(strtab_start..strtab_start + strtab_size)
        .ok_or_else(|| err!("truncated BSD symbol table"))?;
    let mut out = Vec::with_capacity(ranlib_size / 8);
    for i in 0..ranlib_size / 8 {
        let strx = u32le(4 + i * 8).unwrap();
        let offset = u32le(8 + i * 8).unwrap() as u32;
        let rest = strtab.get(strx..).unwrap_or(&[]);
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        out.push(ArchiveSymbol {
            name: &rest[..end],
            offset,
        });
    }
    Ok(out)
}

fn parse_decimal(field: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(field).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    s.parse().ok()
}

fn trim_trailing(s: &[u8], c: u8) -> &[u8] {
    let end = s.iter().rposition(|&b| b != c).map_or(0, |p| p + 1);
    &s[..end]
}

/// Writes COFF-style archives (with both linker members), as `lib.exe` and
/// `llvm-lib` do: used for import libraries.
pub struct ArchiveWriter {
    members: Vec<(String, Vec<u8>, Vec<Vec<u8>>)>,
}

impl Default for ArchiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveWriter {
    pub fn new() -> ArchiveWriter {
        ArchiveWriter {
            members: Vec::new(),
        }
    }

    /// Add a member named `name` that defines `symbols`.
    pub fn add(&mut self, name: &str, data: Vec<u8>, symbols: Vec<Vec<u8>>) {
        self.members.push((name.to_string(), data, symbols));
    }

    pub fn finish(self) -> Vec<u8> {
        // Long names: members whose "name/" doesn't fit in 16 bytes.
        let mut longnames = Vec::new();
        let header_names: Vec<String> = self
            .members
            .iter()
            .map(|(name, _, _)| {
                if name.len() < 16 {
                    format!("{name}/")
                } else {
                    let off = longnames.len();
                    longnames.extend_from_slice(name.as_bytes());
                    longnames.push(0);
                    format!("/{off}")
                }
            })
            .collect();

        let nsyms: usize = self.members.iter().map(|m| m.2.len()).sum();
        let names_len: usize = self
            .members
            .iter()
            .flat_map(|m| m.2.iter())
            .map(|s| s.len() + 1)
            .sum();
        let first_size = 4 + 4 * nsyms + names_len;
        let second_size = 4 + 4 * self.members.len() + 4 + 2 * nsyms + names_len;
        let padded = |n: usize| n + (n & 1);

        // Member offsets, now that the sizes of what precedes them are known.
        let mut off = MAGIC.len() + HEADER + padded(first_size) + HEADER + padded(second_size);
        if !longnames.is_empty() {
            off += HEADER + padded(longnames.len());
        }
        let mut offsets = Vec::with_capacity(self.members.len());
        for (_, data, _) in &self.members {
            offsets.push(off as u32);
            off += HEADER + padded(data.len());
        }

        let mut out = Vec::with_capacity(off);
        out.extend_from_slice(MAGIC);

        // First linker member: big-endian, in member order.
        let mut first = Vec::with_capacity(first_size);
        first.extend_from_slice(&(nsyms as u32).to_be_bytes());
        for (i, m) in self.members.iter().enumerate() {
            for _ in &m.2 {
                first.extend_from_slice(&offsets[i].to_be_bytes());
            }
        }
        for s in self.members.iter().flat_map(|m| m.2.iter()) {
            first.extend_from_slice(s);
            first.push(0);
        }
        write_member(&mut out, "/", &first);

        // Second linker member: little-endian, symbols sorted by name.
        let mut sorted: Vec<(&[u8], u16)> = self
            .members
            .iter()
            .enumerate()
            .flat_map(|(i, m)| m.2.iter().map(move |s| (s.as_slice(), (i + 1) as u16)))
            .collect();
        sorted.sort();
        let mut second = Vec::with_capacity(second_size);
        second.extend_from_slice(&(self.members.len() as u32).to_le_bytes());
        for o in &offsets {
            second.extend_from_slice(&o.to_le_bytes());
        }
        second.extend_from_slice(&(nsyms as u32).to_le_bytes());
        for (_, idx) in &sorted {
            second.extend_from_slice(&idx.to_le_bytes());
        }
        for (s, _) in &sorted {
            second.extend_from_slice(s);
            second.push(0);
        }
        write_member(&mut out, "/", &second);

        if !longnames.is_empty() {
            write_member(&mut out, "//", &longnames);
        }
        for ((_, data, _), name) in self.members.iter().zip(&header_names) {
            write_member(&mut out, name, data);
        }
        out
    }
}

fn write_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        name,
        "0",
        "0",
        "0",
        "644",
        data.len()
    );
    debug_assert_eq!(header.len(), HEADER);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_archives_read_back() {
        let mut w = ArchiveWriter::new();
        w.add(
            "a.obj",
            b"first".to_vec(),
            vec![b"foo".to_vec(), b"bar".to_vec()],
        );
        w.add(
            "a-much-longer-member-name.obj",
            b"second!".to_vec(),
            vec![b"baz".to_vec()],
        );
        let bytes = w.finish();
        let ar = Archive::parse(&bytes).unwrap();
        assert!(ar.has_symbol_table);
        let names: Vec<_> = ar.symbols.iter().map(|s| s.name).collect();
        assert_eq!(names, [&b"foo"[..], b"bar", b"baz"]);
        let baz = ar.member_at(ar.symbols[2].offset).unwrap();
        assert_eq!(baz.name, "a-much-longer-member-name.obj");
        assert_eq!(baz.data, b"second!");
        let members = ar.members().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "a.obj");
        assert_eq!(members[0].data, b"first");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Archive::parse(b"not an archive").is_err());
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(b"short");
        assert!(Archive::parse(&bytes).is_err());
    }
}
