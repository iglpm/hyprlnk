//! hyprlnk ("hyperlink") is a fast linker, developed together with Rune and
//! built into it.
//!
//! It is a library first: Rune links its users' binaries by running the
//! hyprlnk inside its own executable (see [`EMBEDDED_ENV`]), and the
//! `hyprlnk` binary is a thin wrapper around [`main_with_args`].
//!
//! The first backend links PE/COFF images (Windows executables and DLLs) for
//! x86-64 and takes the same command lines as `link.exe` and `lld-link`, which
//! is what `rustc` passes on `*-windows-msvc` targets. Where the time goes
//! and what makes it fast is described in `README.md`.

pub mod archive;
pub mod cmdline;
pub mod coff;
pub mod diag;
pub mod fileio;

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// hyprlnk's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Set (to any value) in the environment of a process to make the Rune
/// executable act as this linker when that process runs it: Rune sets it on
/// the compiler, so that `-C linker=<rune>` runs the embedded hyprlnk.
pub const EMBEDDED_ENV: &str = "RUNE_HYPRLNK";

/// The command-line conventions a linker can be driven with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// `link.exe` / `lld-link`: Windows PE/COFF images.
    Coff,
    /// GNU `ld` / `ld.lld`: ELF. Not implemented yet.
    Gnu,
    /// Apple `ld64`: Mach-O. Not implemented yet.
    Darwin,
}

/// Whether hyprlnk can link binaries for the Rust target `triple`.
pub fn supports_target(triple: &str) -> bool {
    matches!(triple, "x86_64-pc-windows-msvc" | "x86_64-uwp-windows-msvc")
}

/// Set by [`main_with_args`]: the process exits once the link is done, so the
/// link's memory is left to the OS rather than freed.
static EXIT_AFTER_LINK: AtomicBool = AtomicBool::new(false);

/// Run the linker on a full command line (the program name first) and return
/// the process exit code. Diagnostics go to stderr.
///
/// This is for processes that exit right after (the `hyprlnk` binary, Rune's
/// linker mode): what the link allocated is not freed. To link several times
/// in one process, use [`coff::link`].
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
    // `rust-lld -flavor link ...` style.
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

/// `ld.hyprlnk`, `ld` → GNU; `ld64.hyprlnk` → Darwin; anything else (`hyprlnk`,
/// `lld-link`, `link`, `rune`) → COFF.
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
