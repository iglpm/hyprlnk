//! Finding and mapping the inputs: library search, archives (also thin), input scripts.
//! Everything is mapped in parallel; archives are expanded into their ELF members, which are
//! all parsed later (members that aren't needed are dropped by resolution).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::config::{Config, Input, InputFlags, InputKind};
use super::script;
use super::target::Machine;
use super::{ET_DYN, ET_REL};
use crate::archive;
use crate::diag::{self, Result};
use crate::fileio::{self, Arena};
use crate::{bail, err};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A relocatable object; `member`: from an archive (loaded only if needed), unless `whole`.
    Object {
        member: bool,
        whole: bool,
    },
    Dso {
        as_needed: bool,
    },
}

pub struct File<'a> {
    pub name: String,
    pub data: &'a [u8],
    pub kind: Kind,
}

pub struct Loaded<'a> {
    pub files: Vec<File<'a>>,
    pub machine: Option<Machine>,
    pub machine_source: String,
    pub script_entry: Option<String>,
    /// Every file read, for `--dependency-file` and `--reproduce`.
    pub paths: Vec<PathBuf>,
}

struct Pending {
    path: PathBuf,
    display: String,
    flags: InputFlags,
    /// Directory of the script that named it (for relative names).
    from_script: Option<PathBuf>,
}

pub fn load<'a>(cfg: &Config, arena: &'a Arena) -> Result<Loaded<'a>> {
    let mut search: Vec<PathBuf> = cfg.lib_paths.clone();
    let pending: Vec<Pending> = cfg
        .inputs
        .iter()
        .map(|i| resolve_input(cfg, i, &search))
        .collect::<Result<_>>()?;
    let mut out = Loaded {
        files: Vec::with_capacity(pending.len() * 4),
        machine: None,
        machine_source: String::new(),
        script_entry: None,
        paths: Vec::new(),
    };
    let mut seen = HashSet::new();
    load_batch(cfg, arena, pending, &mut out, &mut seen, &mut search, 0)?;
    Ok(out)
}

fn resolve_input(cfg: &Config, input: &Input, search: &[PathBuf]) -> Result<Pending> {
    Ok(match &input.kind {
        InputKind::Path(p) => Pending {
            path: PathBuf::from(p),
            display: p.clone(),
            flags: input.flags,
            from_script: None,
        },
        InputKind::Lib(name) => {
            let path = find_library(cfg, name, input.flags.link_static, search)?;
            Pending {
                display: path.display().to_string(),
                path,
                flags: input.flags,
                from_script: None,
            }
        }
    })
}

pub fn find_library(
    cfg: &Config,
    name: &str,
    link_static: bool,
    search: &[PathBuf],
) -> Result<PathBuf> {
    if let Some(file) = name.strip_prefix(':') {
        for dir in search {
            let p = dir.join(file);
            if p.is_file() {
                return Ok(p);
            }
        }
        bail!("unable to find library -l{name}");
    }
    let so = format!("lib{name}.so");
    let a = format!("lib{name}.a");
    for dir in search {
        if !link_static && !cfg.static_ {
            let p = dir.join(&so);
            if p.is_file() {
                return Ok(p);
            }
        }
        let p = dir.join(&a);
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!("unable to find library -l{name}");
}

fn identity(meta: &std::fs::Metadata, path: &Path) -> (u64, u64) {
    #[cfg(unix)]
    {
        let _ = path;
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        let h = xxhash_rust::xxh3::xxh3_64(path.to_string_lossy().as_bytes());
        (0, h)
    }
}

fn load_batch<'a>(
    cfg: &Config,
    arena: &'a Arena,
    pending: Vec<Pending>,
    out: &mut Loaded<'a>,
    seen: &mut HashSet<(u64, u64)>,
    search: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > 8 {
        bail!("linker scripts nest too deeply");
    }
    // Mapped and classified on all threads: listing an archive reads every member's header,
    // a page fault each the first time.
    let loaded: Vec<Result<Classified<'a>>> = pending
        .par_iter()
        .map(|p| {
            let (bytes, meta) = fileio::load_with_metadata(&p.path)
                .map_err(|e| err!("cannot open {}: {e}", p.display))?;
            let data = arena.keep(bytes);
            Ok((data, identity(&meta, &p.path), Shape::of(data, &p.display)?))
        })
        .collect();
    for (p, r) in pending.into_iter().zip(loaded) {
        let (data, id, shape) = r?;
        if cfg.trace {
            diag::note(&p.display);
        }
        out.paths.push(p.path.clone());
        if let Shape::Elf(ty, machine) = shape {
            match ty {
                ET_REL => {
                    note_machine(out, machine, &p.display)?;
                    out.files.push(File {
                        name: p.display,
                        data,
                        kind: Kind::Object {
                            member: false,
                            whole: true,
                        },
                    });
                }
                ET_DYN => {
                    if !seen.insert(id) {
                        continue;
                    }
                    out.files.push(File {
                        name: p.display,
                        data,
                        kind: Kind::Dso {
                            as_needed: p.flags.as_needed,
                        },
                    });
                }
                _ => bail!("{}: not a relocatable object or shared object", p.display),
            }
        } else if let Shape::Archive(thin, members) = shape {
            if !seen.insert(id) {
                continue;
            }
            let dir = p.path.parent().map(Path::to_path_buf).unwrap_or_default();
            if thin {
                let paths: Vec<PathBuf> = members
                    .iter()
                    .map(|(m, _)| {
                        let mp = Path::new(&m.name);
                        if mp.is_absolute() {
                            mp.to_path_buf()
                        } else {
                            dir.join(mp)
                        }
                    })
                    .collect();
                let datas: Vec<_> = paths.par_iter().map(|mp| fileio::load(mp)).collect();
                for (((m, _), mp), d) in members.iter().zip(&paths).zip(datas) {
                    let d = d.map_err(|e| {
                        err!("{}: cannot open member {}: {e}", p.display, mp.display())
                    })?;
                    let d = arena.keep(d);
                    let ty = d.starts_with(b"\x7fELF").then(|| elf_type(d)).flatten();
                    add_member(out, &p, &m.name, d, ty)?;
                }
            } else {
                for (m, ty) in &members {
                    add_member(out, &p, &m.name, m.data, *ty)?;
                }
            }
        } else if matches!(shape, Shape::Bitcode) {
            bail!(
                "{}: LLVM bitcode (LTO) inputs are not supported; build without linker-plugin LTO",
                p.display
            );
        } else {
            // An input script: libc.so, libgcc_s.so, or -T with only GROUP/INPUT.
            if !seen.insert(id) {
                continue;
            }
            let text =
                std::str::from_utf8(data).map_err(|_| err!("{}: unknown file type", p.display))?;
            let s = script::parse_input_script(text, &p.display)?;
            if s.entry.is_some() {
                out.script_entry = s.entry.clone();
            }
            let script_dir = p.path.parent().map(Path::to_path_buf).unwrap_or_default();
            for d in &s.search_dirs {
                search.push(PathBuf::from(d));
            }
            let mut sub = Vec::new();
            for si in &s.inputs {
                let flags = InputFlags {
                    as_needed: si.as_needed || p.flags.as_needed,
                    ..p.flags
                };
                let path = if si.is_lib {
                    find_library(cfg, &si.name, flags.link_static, search)?
                } else {
                    script_path(cfg, &si.name, &script_dir, search)?
                };
                sub.push(Pending {
                    display: path.display().to_string(),
                    path,
                    flags,
                    from_script: Some(script_dir.clone()),
                });
            }
            load_batch(cfg, arena, sub, out, seen, search, depth + 1)?;
        }
        let _ = p.from_script;
    }
    Ok(())
}

/// A file named in a linker script: sysroot-relative if absolute and under a sysroot, else
/// as written, else relative to the script, else in the search path.
fn script_path(cfg: &Config, name: &str, script_dir: &Path, search: &[PathBuf]) -> Result<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() {
        if let Some(root) = &cfg.sysroot {
            let r = root.join(name.trim_start_matches('/'));
            if r.is_file() {
                return Ok(r);
            }
        }
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    } else {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        let r = script_dir.join(p);
        if r.is_file() {
            return Ok(r);
        }
        for d in search {
            let r = d.join(p);
            if r.is_file() {
                return Ok(r);
            }
        }
    }
    bail!("cannot find {name}, named in a linker script")
}

/// An ELF file's type and machine.
type ElfType = (u16, Option<Machine>);

/// An input's contents, its identity (device, inode) and what it is.
type Classified<'a> = (&'a [u8], (u64, u64), Shape<'a>);

/// What an input file is, with the ELF type and machine of each archive member.
enum Shape<'a> {
    Elf(u16, Option<Machine>),
    Archive(bool, Vec<(archive::Member<'a>, Option<ElfType>)>),
    Bitcode,
    Script,
}

impl<'a> Shape<'a> {
    fn of(data: &'a [u8], display: &str) -> Result<Shape<'a>> {
        Ok(if data.starts_with(b"\x7fELF") {
            let (ty, machine) = elf_type(data).ok_or_else(|| err!("{display}: bad ELF header"))?;
            Shape::Elf(ty, machine)
        } else if archive::is_archive(data) || archive::is_thin_archive(data) {
            let (thin, members) =
                archive::list_members(data).map_err(|e| err!("{display}: {e}"))?;
            let typed = members
                .into_iter()
                .map(|m| {
                    let ty = m
                        .data
                        .starts_with(b"\x7fELF")
                        .then(|| elf_type(m.data))
                        .flatten();
                    (m, ty)
                })
                .collect();
            Shape::Archive(thin, typed)
        } else if data.starts_with(b"BC\xc0\xde") || data.starts_with(&[0xde, 0xc0, 0x17, 0x0b]) {
            Shape::Bitcode
        } else {
            Shape::Script
        })
    }
}

/// `ty`: the member's ELF type and machine, if it is an ELF file with a valid header.
fn add_member<'a>(
    out: &mut Loaded<'a>,
    ar: &Pending,
    name: &str,
    data: &'a [u8],
    ty: Option<(u16, Option<Machine>)>,
) -> Result<()> {
    if !data.starts_with(b"\x7fELF") {
        // lib.rmeta in rlibs, symbol definitions files, bitcode we can't use: skip.
        return Ok(());
    }
    let (ty, machine) = ty.ok_or_else(|| err!("{}({name}): bad ELF header", ar.display))?;
    if ty != ET_REL {
        return Ok(());
    }
    let display = format!("{}({name})", ar.display);
    note_machine(out, machine, &display)?;
    out.files.push(File {
        name: display,
        data,
        kind: Kind::Object {
            member: !ar.flags.whole_archive,
            whole: ar.flags.whole_archive,
        },
    });
    Ok(())
}

fn note_machine(out: &mut Loaded<'_>, m: Option<Machine>, name: &str) -> Result<()> {
    let m = m.ok_or_else(|| err!("{name}: unsupported machine"))?;
    match out.machine {
        None => {
            out.machine = Some(m);
            out.machine_source = name.to_string();
        }
        Some(prev) if prev != m => bail!(
            "{name} is for {}, but {} is for {}",
            m.name(),
            out.machine_source,
            prev.name()
        ),
        _ => {}
    }
    Ok(())
}

/// `e_type` and the machine of an ELF file.
pub fn elf_type(d: &[u8]) -> Option<(u16, Option<Machine>)> {
    if d.len() < 52 {
        return None;
    }
    let (class, data) = (d[4], d[5]);
    let rd16 = |o: usize| {
        let b = [d[o], d[o + 1]];
        if data == super::ELFDATA2MSB {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        }
    };
    let ty = rd16(16);
    let machine = Machine::from_header(rd16(18), class, data);
    Some((ty, machine))
}
