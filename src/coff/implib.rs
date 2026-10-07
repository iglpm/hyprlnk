//! Import libraries: the `.lib` other images link against to call a DLL.
//!
//! Laid out like `lib.exe` and `llvm-lib` write them, so `link.exe`, `lld`
//! and hyprlnk all read them: an import descriptor object, the null import
//! descriptor, the null thunk, then a short import object per export.

use std::path::{Path, PathBuf};

use super::import::write_short_import;
use super::resolve::Linker;
use super::*;
use crate::archive::ArchiveWriter;
use crate::diag::Result;
use crate::err;

impl Linker<'_> {
    pub fn implib_path(&self) -> Option<PathBuf> {
        if self.cfg.no_implib {
            return None;
        }
        if let Some(p) = &self.cfg.implib {
            return Some(p.clone());
        }
        (self.cfg.dll && !self.exports.is_empty()).then(|| self.output_path().with_extension("lib"))
    }

    pub fn write_implib(&self, path: &Path) -> Result<()> {
        let dll = self
            .output_path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let lib = Path::new(&dll)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let descriptor = format!("__IMPORT_DESCRIPTOR_{lib}");
        let null_descriptor = "__NULL_IMPORT_DESCRIPTOR".to_string();
        let null_thunk = format!("\x7f{lib}_NULL_THUNK_DATA");

        let mut w = ArchiveWriter::new();
        w.add(
            &dll,
            import_descriptor(&dll, &descriptor, &null_descriptor, &null_thunk),
            vec![descriptor.clone().into_bytes()],
        );
        w.add(
            &dll,
            null_import_descriptor(&null_descriptor),
            vec![null_descriptor.clone().into_bytes()],
        );
        w.add(
            &dll,
            null_thunk_data(&null_thunk),
            vec![null_thunk.clone().into_bytes()],
        );

        let mut exports: Vec<_> = self.exports.iter().filter(|e| !e.private).collect();
        exports.sort_by(|a, b| a.name.cmp(&b.name));
        for e in exports {
            let kind = if e.data {
                IMPORT_DATA
            } else if e.constant {
                IMPORT_CONST
            } else {
                IMPORT_CODE
            };
            let name_type = if e.noname {
                IMPORT_ORDINAL
            } else {
                IMPORT_NAME
            };
            let member = write_short_import(
                IMAGE_FILE_MACHINE_AMD64,
                &e.name,
                &dll,
                kind,
                name_type,
                e.ordinal,
            );
            let mut syms = vec![format!("__imp_{}", e.name).into_bytes()];
            if kind != IMPORT_DATA {
                syms.push(e.name.clone().into_bytes());
            }
            w.add(&dll, member, syms);
        }
        std::fs::write(path, w.finish())
            .map_err(|e| err!("cannot write import library '{}': {e}", path.display()))
    }
}

fn coff_header(buf: &mut Vec<u8>, nsections: u16, symtab_off: u32, nsyms: u32) {
    buf.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    buf.extend_from_slice(&nsections.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&symtab_off.to_le_bytes());
    buf.extend_from_slice(&nsyms.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn section_header(
    buf: &mut Vec<u8>,
    name: &[u8],
    size: u32,
    data: u32,
    relocs: u32,
    nrelocs: u16,
    chars: u32,
) {
    let mut n = [0u8; 8];
    n[..name.len()].copy_from_slice(name);
    buf.extend_from_slice(&n);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&data.to_le_bytes());
    buf.extend_from_slice(&relocs.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&nrelocs.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&chars.to_le_bytes());
}

/// A symbol whose name is in the string table at `strx` (or short `name`).
fn symbol(buf: &mut Vec<u8>, name: Option<&[u8]>, strx: u32, value: u32, section: i16, class: u8) {
    match name {
        Some(n) => {
            let mut b = [0u8; 8];
            b[..n.len()].copy_from_slice(n);
            buf.extend_from_slice(&b);
        }
        None => {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&strx.to_le_bytes());
        }
    }
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&section.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(class);
    buf.push(0);
}

fn string_table(buf: &mut Vec<u8>, strings: &[&str]) {
    let size: usize = 4 + strings.iter().map(|s| s.len() + 1).sum::<usize>();
    buf.extend_from_slice(&(size as u32).to_le_bytes());
    for s in strings {
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
    }
}

const IDATA_CHARS_4: u32 =
    0x0030_0000 | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
const IDATA_CHARS_2: u32 =
    0x0020_0000 | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
const IDATA_CHARS_8: u32 =
    0x0040_0000 | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

fn import_descriptor(
    dll: &str,
    descriptor: &str,
    null_descriptor: &str,
    null_thunk: &str,
) -> Vec<u8> {
    let mut b = Vec::new();
    let headers = 20 + 2 * 40;
    let idata2 = headers;
    let relocs = idata2 + 20;
    let idata6 = relocs + 3 * 10;
    let symtab = idata6 + dll.len() as u32 + 1;
    coff_header(&mut b, 2, symtab, 7);
    section_header(&mut b, b".idata$2", 20, idata2, relocs, 3, IDATA_CHARS_4);
    section_header(
        &mut b,
        b".idata$6",
        dll.len() as u32 + 1,
        idata6,
        0,
        0,
        IDATA_CHARS_2,
    );
    b.extend_from_slice(&[0; 20]);
    // Name, lookup table and address table RVAs.
    for (off, sym) in [(12u32, 2u32), (0, 3), (16, 4)] {
        b.extend_from_slice(&off.to_le_bytes());
        b.extend_from_slice(&sym.to_le_bytes());
        b.extend_from_slice(&IMAGE_REL_AMD64_ADDR32NB.to_le_bytes());
    }
    b.extend_from_slice(dll.as_bytes());
    b.push(0);
    symbol(&mut b, None, 4, 0, 1, IMAGE_SYM_CLASS_EXTERNAL);
    symbol(&mut b, Some(b".idata$2"), 0, 0, 1, IMAGE_SYM_CLASS_SECTION);
    symbol(&mut b, Some(b".idata$6"), 0, 0, 2, IMAGE_SYM_CLASS_STATIC);
    symbol(&mut b, Some(b".idata$4"), 0, 0, 0, IMAGE_SYM_CLASS_SECTION);
    symbol(&mut b, Some(b".idata$5"), 0, 0, 0, IMAGE_SYM_CLASS_SECTION);
    let x1 = 4 + descriptor.len() as u32 + 1;
    symbol(&mut b, None, x1, 0, 0, IMAGE_SYM_CLASS_EXTERNAL);
    symbol(
        &mut b,
        None,
        x1 + null_descriptor.len() as u32 + 1,
        0,
        0,
        IMAGE_SYM_CLASS_EXTERNAL,
    );
    string_table(&mut b, &[descriptor, null_descriptor, null_thunk]);
    b
}

fn null_import_descriptor(name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let data = 20 + 40;
    coff_header(&mut b, 1, data + 20, 1);
    section_header(&mut b, b".idata$3", 20, data, 0, 0, IDATA_CHARS_4);
    b.extend_from_slice(&[0; 20]);
    symbol(&mut b, None, 4, 0, 1, IMAGE_SYM_CLASS_EXTERNAL);
    string_table(&mut b, &[name]);
    b
}

fn null_thunk_data(name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let data = 20 + 2 * 40;
    coff_header(&mut b, 2, data + 16, 1);
    section_header(&mut b, b".idata$5", 8, data, 0, 0, IDATA_CHARS_8);
    section_header(&mut b, b".idata$4", 8, data + 8, 0, 0, IDATA_CHARS_8);
    b.extend_from_slice(&[0; 16]);
    symbol(&mut b, None, 4, 0, 1, IMAGE_SYM_CLASS_EXTERNAL);
    string_table(&mut b, &[name]);
    b
}

#[cfg(test)]
mod tests {
    use super::super::object::ObjFile;
    use super::*;

    #[test]
    fn descriptor_objects_parse() {
        let d = import_descriptor(
            "foo.dll",
            "__IMPORT_DESCRIPTOR_foo",
            "__NULL_IMPORT_DESCRIPTOR",
            "\x7ffoo_NULL_THUNK_DATA",
        );
        let o = ObjFile::parse(&d, "d".into()).unwrap();
        assert_eq!(o.sections.len(), 2);
        assert_eq!(o.sections[0].nrelocs(), 3);
        assert_eq!(o.sections[1].data, b"foo.dll\0");
        let names: Vec<_> = o.externals.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            [
                &b"__IMPORT_DESCRIPTOR_foo"[..],
                b"__NULL_IMPORT_DESCRIPTOR",
                b"\x7ffoo_NULL_THUNK_DATA"
            ]
        );
        let nd = null_import_descriptor("__NULL_IMPORT_DESCRIPTOR");
        let n = ObjFile::parse(&nd, "n".into()).unwrap();
        assert_eq!(n.externals[0].name, b"__NULL_IMPORT_DESCRIPTOR");
        let td = null_thunk_data("\x7ffoo_NULL_THUNK_DATA");
        let t = ObjFile::parse(&td, "t".into()).unwrap();
        assert_eq!(t.sections.len(), 2);
    }
}
