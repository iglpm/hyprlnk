//! Short import objects: the members of import libraries.

use super::*;
use crate::bail;
use crate::diag::Result;

#[derive(Debug, Clone, Copy)]
pub struct ShortImport<'a> {
    pub machine: u16,
    pub symbol: &'a [u8],
    pub dll: &'a [u8],
    pub kind: u8,
    pub name: Option<&'a [u8]>,
    pub ordinal_or_hint: u16,
}

impl<'a> ShortImport<'a> {
    pub fn parse(d: &'a [u8], file: &str) -> Result<ShortImport<'a>> {
        if d.len() < 20 {
            bail!("{file}: truncated import object");
        }
        let machine = u16le(d, 6);
        let size = u32le(d, 12) as usize;
        let ordinal_or_hint = u16le(d, 16);
        let info = u16le(d, 18);
        let kind = (info & 3) as u8;
        let name_type = ((info >> 2) & 7) as u8;
        let rest = d.get(20..20 + size).unwrap_or(&d[20..]);
        let mut strings = rest.split(|&b| b == 0);
        let symbol = strings.next().unwrap_or(&[]);
        let dll = strings.next().unwrap_or(&[]);
        if symbol.is_empty() || dll.is_empty() {
            bail!("{file}: malformed import object");
        }
        let name = match name_type {
            IMPORT_ORDINAL => None,
            IMPORT_NAME => Some(symbol),
            IMPORT_NAME_NOPREFIX => Some(strip_prefix(symbol)),
            IMPORT_NAME_UNDECORATE => {
                let s = strip_prefix(symbol);
                Some(s.split(|&b| b == b'@').next().unwrap_or(s))
            }
            IMPORT_NAME_EXPORTAS => {
                Some(strings.next().filter(|s| !s.is_empty()).unwrap_or(symbol))
            }
            _ => bail!("{file}: unknown import name type {name_type}"),
        };
        Ok(ShortImport {
            machine,
            symbol,
            dll,
            kind,
            name,
            ordinal_or_hint,
        })
    }
}

fn strip_prefix(s: &[u8]) -> &[u8] {
    match s.first() {
        Some(b'?' | b'@' | b'_') => &s[1..],
        _ => s,
    }
}

pub fn write_short_import(
    machine: u16,
    symbol: &str,
    dll: &str,
    kind: u8,
    name_type: u8,
    ordinal_or_hint: u16,
) -> Vec<u8> {
    let size = symbol.len() + 1 + dll.len() + 1;
    let mut out = Vec::with_capacity(20 + size);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&machine.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&ordinal_or_hint.to_le_bytes());
    out.extend_from_slice(&(((name_type as u16) << 2) | kind as u16).to_le_bytes());
    out.extend_from_slice(symbol.as_bytes());
    out.push(0);
    out.extend_from_slice(dll.as_bytes());
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = write_short_import(
            IMAGE_FILE_MACHINE_AMD64,
            "_foo@4",
            "a.dll",
            IMPORT_CODE,
            IMPORT_NAME_UNDECORATE,
            7,
        );
        let i = ShortImport::parse(&bytes, "x").unwrap();
        assert_eq!(i.symbol, b"_foo@4");
        assert_eq!(i.dll, b"a.dll");
        assert_eq!(i.name, Some(&b"foo"[..]));
        assert_eq!(i.ordinal_or_hint, 7);
        assert_eq!(i.kind, IMPORT_CODE);
        let bytes = write_short_import(
            IMAGE_FILE_MACHINE_AMD64,
            "bar",
            "b.dll",
            IMPORT_DATA,
            IMPORT_ORDINAL,
            3,
        );
        let i = ShortImport::parse(&bytes, "x").unwrap();
        assert_eq!(i.name, None);
        assert_eq!(i.kind, IMPORT_DATA);
    }
}
