//! hyprlnk: a fast linker built into Rune. The COFF backend links x64/ARM64/x86 Windows images;
//! the Mach-O backend links arm64, arm64e and x86_64 macOS images.

pub mod archive;
pub mod cmdline;
pub mod coff;
pub mod diag;
pub mod fileio;
pub mod macho;
pub mod sha256;

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

/// The `-C linker-flavor` rustc needs to call hyprlnk with this target's native command line,
/// if not the default one (Apple targets would get `cc` arguments otherwise).
pub fn rustc_linker_flavor(triple: &str) -> Option<&'static str> {
    triple.contains("-apple-").then_some("ld64.lld")
}

pub fn supports_target(triple: &str) -> bool {
    matches!(
        triple,
        "aarch64-apple-darwin"
            | "arm64e-apple-darwin"
            | "x86_64-apple-darwin"
            | "x86_64h-apple-darwin"
    ) || matches!(
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
    let flavor = flavor
        .or_else(|| flavor_from_program_name(argv0))
        .unwrap_or_else(|| flavor_from_args(&args));
    match flavor {
        Flavor::Coff => coff::link_main(args),
        Flavor::Darwin => macho::link_main(args),
        Flavor::Gnu => bail!(
            "the GNU ld (ELF) flavor is not implemented yet: hyprlnk links PE/COFF and Mach-O \
             images (`-flavor link`, `-flavor darwin`)"
        ),
    }
}

/// Without a flavor or a telling program name: ld64's or clang's Darwin options mean Mach-O,
/// link.exe-style options mean COFF, anything else means the host's own format.
fn flavor_from_args(args: &[String]) -> Flavor {
    let darwin = args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-arch"
                | "-platform_version"
                | "-syslibroot"
                | "-dylib"
                | "-macos_version_min"
                | "-framework"
                | "-dynamiclib"
                | "-isysroot"
        ) || a.starts_with("-mmacosx-version-min")
            || a.starts_with("-mmacos-version-min")
            || a.starts_with("-Wl,")
    });
    if darwin {
        return Flavor::Darwin;
    }
    let coff = args.iter().any(|a| {
        let l = a.to_ascii_lowercase();
        let opt = l.strip_prefix('/').or_else(|| l.strip_prefix('-'));
        opt.is_some_and(|o| {
            [
                "out:",
                "machine:",
                "subsystem:",
                "libpath:",
                "defaultlib:",
                "nodefaultlib:",
                "dll",
                "debug",
                "nologo",
                "entry:",
                "opt:",
                "pdb:",
                "def:",
                "implib:",
                "wholearchive",
                "dynamicbase",
            ]
            .iter()
            .any(|p| o.starts_with(p))
        }) || l.ends_with(".obj")
            || l.ends_with(".lib")
            || l.ends_with(".res")
    });
    if coff || !cfg!(target_vendor = "apple") {
        Flavor::Coff
    } else {
        Flavor::Darwin
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

fn flavor_from_program_name(argv0: &str) -> Option<Flavor> {
    let stem = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let stem = stem.strip_suffix(".exe").unwrap_or(&stem);
    if stem.starts_with("ld64") {
        Some(Flavor::Darwin)
    } else if stem.starts_with("ld.") {
        Some(Flavor::Gnu)
    } else if stem == "ld" || stem.ends_with("-ld") {
        // What rustc and clang run on Apple platforms as "ld": ld64's command line there.
        Some(if cfg!(target_vendor = "apple") {
            Flavor::Darwin
        } else {
            Flavor::Gnu
        })
    } else if stem == "lld-link" || stem == "link" {
        Some(Flavor::Coff)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavor_follows_the_program_name() {
        assert_eq!(flavor_from_program_name("hyprlnk"), None);
        assert_eq!(flavor_from_program_name(r"C:\x\rune.exe"), None);
        assert_eq!(
            flavor_from_program_name("/usr/bin/ld.hyprlnk"),
            Some(Flavor::Gnu)
        );
        assert_eq!(
            flavor_from_program_name("ld64.hyprlnk"),
            Some(Flavor::Darwin)
        );
        assert_eq!(flavor_from_program_name("lld-link"), Some(Flavor::Coff));
        assert_eq!(flavor_from_program_name("lld-link.exe"), Some(Flavor::Coff));
    }

    #[test]
    fn flavor_follows_the_arguments() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(flavor_from_args(&v(&["/OUT:a.exe", "a.obj"])), Flavor::Coff);
        assert_eq!(
            flavor_from_args(&v(&["-arch", "arm64", "a.o"])),
            Flavor::Darwin
        );
        assert_eq!(flavor_from_args(&v(&["-out:a.exe"])), Flavor::Coff);
        assert_eq!(
            flavor_from_args(&v(&["a.o", "-nodefaultlibs", "-arch", "arm64"])),
            Flavor::Darwin
        );
    }

    #[test]
    fn unimplemented_flavors_fail_cleanly() {
        assert_eq!(main_with_args(["ld.hyprlnk", "a.o"]), 1);
        assert_eq!(main_with_args(["hyprlnk", "-flavor", "nope"]), 1);
    }

    #[test]
    fn apple_targets_are_supported() {
        assert!(supports_target("aarch64-apple-darwin"));
        assert!(supports_target("x86_64-apple-darwin"));
        assert_eq!(
            rustc_linker_flavor("aarch64-apple-darwin"),
            Some("ld64.lld")
        );
        assert_eq!(rustc_linker_flavor("x86_64-pc-windows-msvc"), None);
    }
}
