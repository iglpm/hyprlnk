//! Import libraries, laid out like `lib.exe`/`llvm-lib` write them.

use std::path::{Path, PathBuf};

use super::arch::Machine;
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

        let m = self.machine;
        let mut w = ArchiveWriter::new();
        w.add(
            &dll,
            import_descriptor(m, &dll, &descriptor, &null_descriptor, &null_thunk),
            vec![descriptor.clone().into_bytes()],
        );
        w.add(
            &dll,
            null_import_descriptor(m, &null_descriptor),
            vec![null_descriptor.clone().into_bytes()],
        );
        w.add(
            &dll,
            null_thunk_data(m, &null_thunk),
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
            let symbol = self.import_symbol(e);
            let name_type = if e.noname {
                IMPORT_ORDINAL
            } else if m == Machine::X86 && e.name.starts_with('_') && e.name.contains('@') {
                IMPORT_NAME
            } else if symbol != e.name {
                IMPORT_NAME_UNDECORATE
            } else {
                IMPORT_NAME
            };
            let member = write_short_import(m.coff(), &symbol, &dll, kind, name_type, e.ordinal);
            let mut syms = vec![format!("__imp_{symbol}").into_bytes()];
            if kind != IMPORT_DATA {
                syms.push(symbol.clone().into_bytes());
            }
            w.add(&dll, member, syms);
        }
        std::fs::write(path, w.finish())
            .map_err(|e| err!("cannot write import library '{}': {e}", path.display()))
    }
}

impl Linker<'_> {
    fn import_symbol(&self, e: &super::resolve::Export) -> String {
        if self.machine != Machine::X86 || e.name.starts_with(['_', '?', '@']) {
            return e.name.clone();
        }
        let internal = String::from_utf8_lossy(self.symtab.get(e.sym).name);
        let undecorated = format!("_{}", e.name);
        if internal == undecorated || internal.starts_with(&format!("{undecorated}@")) {
            internal.into_owned()
        } else {
            undecorated
        }
    }
}

fn reloc_addr32nb(m: Machine) -> u16 {
    match m {
        Machine::X64 => IMAGE_REL_AMD64_ADDR32NB,
        Machine::Arm64 => super::arch::IMAGE_REL_ARM64_ADDR32NB,
        Machine::X86 => super::arch::IMAGE_REL_I386_DIR32NB,
    }
}

fn coff_header(buf: &mut Vec<u8>, m: Machine, nsections: u16, symtab_off: u32, nsyms: u32) {
    buf.extend_from_slice(&m.coff().to_le_bytes());
    buf.extend_from_slice(&nsections.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&symtab_off.to_le_bytes());
    buf.extend_from_slice(&nsyms.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    let chars: u16 = if m.is64() { 0 } else { 0x0100 };
    buf.extend_from_slice(&chars.to_le_bytes());
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
    m: Machine,
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
    coff_header(&mut b, m, 2, symtab, 7);
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
    for (off, sym) in [(12u32, 2u32), (0, 3), (16, 4)] {
        b.extend_from_slice(&off.to_le_bytes());
        b.extend_from_slice(&sym.to_le_bytes());
        b.extend_from_slice(&reloc_addr32nb(m).to_le_bytes());
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

fn null_import_descriptor(m: Machine, name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let data = 20 + 40;
    coff_header(&mut b, m, 1, data + 20, 1);
    section_header(&mut b, b".idata$3", 20, data, 0, 0, IDATA_CHARS_4);
    b.extend_from_slice(&[0; 20]);
    symbol(&mut b, None, 4, 0, 1, IMAGE_SYM_CLASS_EXTERNAL);
    string_table(&mut b, &[name]);
    b
}

fn null_thunk_data(m: Machine, name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let data = 20 + 2 * 40;
    let ptr = m.ptr_size();
    let chars = if m.is64() {
        IDATA_CHARS_8
    } else {
        IDATA_CHARS_4
    };
    coff_header(&mut b, m, 2, data + 2 * ptr, 1);
    section_header(&mut b, b".idata$5", ptr, data, 0, 0, chars);
    section_header(&mut b, b".idata$4", ptr, data + ptr, 0, 0, chars);
    b.extend_from_slice(&vec![0; 2 * ptr as usize]);
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
            Machine::X64,
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
        let nd = null_import_descriptor(Machine::X64, "__NULL_IMPORT_DESCRIPTOR");
        let n = ObjFile::parse(&nd, "n".into()).unwrap();
        assert_eq!(n.externals[0].name, b"__NULL_IMPORT_DESCRIPTOR");
        let td = null_thunk_data(Machine::X86, "\x7ffoo_NULL_THUNK_DATA");
        let t = ObjFile::parse(&td, "t".into()).unwrap();
        assert_eq!(t.sections.len(), 2);
    }
}
