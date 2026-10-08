//! hyprlnk: a fast linker built into Rune. The COFF backend links x64/ARM64/x86 Windows images.

pub mod archive;
pub mod cmdline;
pub mod coff;
pub mod diag;
pub mod fileio;

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Makes the Rune executable act as this linker (`-C linker=<rune>`).
pub const EMBEDDED_ENV: &str = "RUNE_HYPRLNK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Coff,
    Gnu,
    Darwin,
}

pub fn supports_target(triple: &str) -> bool {
    matches!(
        triple,
        "x86_64-pc-windows-msvc"
            | "x86_64-uwp-windows-msvc"
            | "x86_64-win7-windows-msvc"
            | "aarch64-pc-windows-msvc"
            | "aarch64-uwp-windows-msvc"
            | "i686-pc-windows-msvc"
            | "i686-uwp-windows-msvc"
            | "i686-win7-windows-msvc"
            | "i586-pc-windows-msvc"
    )
}

static EXIT_AFTER_LINK: AtomicBool = AtomicBool::new(false);

/// Run the linker on a full command line and return the exit code. Memory is not freed:
/// only for processes that exit right after; use [`coff::link`] to link repeatedly.
pub fn main_with_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    EXIT_AFTER_LINK.store(true, Ordering::Relaxed);
    let mut args: Vec<String> = args
        .into_iter()
        .map(|a| a.into().to_string_lossy().into_owned())
        .collect();
    let argv0 = if args.is_empty() {
        String::new()
    } else {
        args.remove(0)
    };
    match run(&argv0, args) {
        Ok(()) => 0,
        Err(e) => {
            diag::error(e);
            1
        }
    }
}

fn run(argv0: &str, mut args: Vec<String>) -> diag::Result<()> {
    let mut flavor = None;
    if args.first().map(String::as_str) == Some("-flavor") && args.len() >= 2 {
        flavor = Some(parse_flavor(&args[1])?);
        args.drain(..2);
    }
    let flavor = flavor.unwrap_or_else(|| flavor_from_program_name(argv0));
    match flavor {
        Flavor::Coff => coff::link_main(args),
        Flavor::Gnu => bail!(
            "the GNU ld (ELF) flavor is not implemented yet: hyprlnk links PE/COFF \
             images for now (`-flavor link`)"
        ),
        Flavor::Darwin => bail!(
            "the ld64 (Mach-O) flavor is not implemented yet: hyprlnk links PE/COFF \
             images for now (`-flavor link`)"
        ),
    }
}

fn parse_flavor(name: &str) -> diag::Result<Flavor> {
    Ok(match name {
        "link" | "lld-link" | "coff" => Flavor::Coff,
        "gnu" | "ld" | "ld.lld" | "elf" => Flavor::Gnu,
        "darwin" | "ld64" | "ld64.lld" | "macho" => Flavor::Darwin,
        other => bail!("unknown flavor '{other}' (expected link, gnu or darwin)"),
    })
}

fn flavor_from_program_name(argv0: &str) -> Flavor {
    let stem = Path::new(argv0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if stem.starts_with("ld64") {
        Flavor::Darwin
    } else if stem == "ld" || stem.starts_with("ld.") {
        Flavor::Gnu
    } else {
        Flavor::Coff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavor_follows_the_program_name() {
        assert_eq!(flavor_from_program_name("hyprlnk"), Flavor::Coff);
        assert_eq!(flavor_from_program_name(r"C:\x\rune.exe"), Flavor::Coff);
        assert_eq!(flavor_from_program_name("/usr/bin/ld.hyprlnk"), Flavor::Gnu);
        assert_eq!(flavor_from_program_name("ld64.hyprlnk"), Flavor::Darwin);
        assert_eq!(flavor_from_program_name("lld-link"), Flavor::Coff);
    }

    #[test]
    fn unimplemented_flavors_fail_cleanly() {
        assert_eq!(main_with_args(["ld.hyprlnk", "a.o"]), 1);
        assert_eq!(main_with_args(["hyprlnk", "-flavor", "nope"]), 1);
    }
}
