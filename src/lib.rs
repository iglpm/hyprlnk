//! hyprlnk: a fast linker built into Rune. The COFF backend links x64/ARM64/x86 Windows images;
//! the Mach-O backend links arm64, arm64e and x86_64 macOS images; the ELF backend links Linux
//! executables and shared libraries for x86-64, x86, AArch64, ARM, RISC-V, POWER, s390x and
//! LoongArch.

pub mod archive;
pub mod cmdline;
pub mod coff;
pub mod diag;
pub mod elf;
pub mod fileio;
pub mod macho;
pub mod sha256;

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Makes the Rune executable act as this linker (`-C linker=<rune>`).
pub const EMBEDDED_ENV: &str = "RUNE_HYPRLNK";

/// The C compiler hyprlnk runs for a `cc` command line on Linux (default `cc`), to find the C
/// runtime; hyprlnk is its `ld`.
pub const CC_ENV: &str = "HYPRLNK_CC";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Coff,
    Gnu,
    Darwin,
}

/// The `-C linker-flavor` rustc needs to call hyprlnk with this target's native command line,
/// if not the default one (Apple targets would get `cc` arguments otherwise).
pub fn rustc_linker_flavor(triple: &str) -> Option<&'static str> {
    if triple.contains("-apple-") {
        Some("ld64.lld")
    } else if cfg!(not(unix)) && (linux_target(triple) || triple.contains("-freebsd")) {
        Some("ld.lld")
    } else {
        None
    }
}

pub fn supports_target(triple: &str) -> bool {
    linux_target(triple)
        || matches!(
            triple,
            "aarch64-apple-darwin"
                | "arm64e-apple-darwin"
                | "x86_64-apple-darwin"
                | "x86_64h-apple-darwin"
        )
        || matches!(
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

/// Linux with glibc or musl on the architectures the ELF backend links: x86-64, x86, AArch64,
/// 32-bit ARM from ARMv5TE on (interworking needs `blx`), 64-bit RISC-V, little-endian POWER
/// (ELFv2), s390x and LoongArch.
fn linux_target(triple: &str) -> bool {
    let mut parts = triple.splitn(4, '-');
    let (Some(arch), Some(_vendor), Some("linux"), Some(env)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let arm = (arch == "arm" || arch.starts_with("armv") || arch.starts_with("thumbv"))
        && !arch.starts_with("armv4");
    let arch = arm
        || matches!(
            arch,
            "x86_64"
                | "i686"
                | "i586"
                | "aarch64"
                | "riscv64gc"
                | "powerpc64le"
                | "s390x"
                | "loongarch64"
        );
    arch && matches!(
        env,
        "gnu" | "musl" | "gnueabi" | "gnueabihf" | "musleabi" | "musleabihf"
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
        Ok(code) => code,
        Err(e) => {
            diag::error(e);
            1
        }
    }
}

fn run(argv0: &str, mut args: Vec<String>) -> diag::Result<i32> {
    let mut flavor = None;
    if args.first().map(String::as_str) == Some("-flavor") && args.len() >= 2 {
        flavor = Some(parse_flavor(&args[1])?);
        args.drain(..2);
    }
    let flavor = match flavor.or_else(|| flavor_from_program_name(argv0)) {
        Some(f) => f,
        None => match flavor_from_args(&args) {
            // A `cc` command line for an ELF target: the C compiler runs hyprlnk as `ld`.
            Flavor::Gnu if elf::driver::is_cc_command_line(&args) => {
                return elf::driver::run_cc(args);
            }
            f => f,
        },
    };
    match flavor {
        Flavor::Coff => coff::link_main(args),
        Flavor::Darwin => macho::link_main(args),
        Flavor::Gnu => elf::link_main(args),
    }
    .map(|()| 0)
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
    if coff {
        return Flavor::Coff;
    }
    let elf = args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--gc-sections"
                | "--eh-frame-hdr"
                | "-pie"
                | "-shared"
                | "-static"
                | "-static-pie"
                | "-soname"
                | "--as-needed"
                | "-Bstatic"
                | "-Bdynamic"
                | "-dynamic-linker"
                | "--no-dynamic-linker"
                | "--hash-style"
                | "-z"
        ) || a.starts_with("--version-script")
            || a.starts_with("--build-id")
            || a.starts_with("-melf")
            || a.starts_with("--hash-style=")
            || a.ends_with(".so")
            || a.contains(".so.")
    });
    if elf {
        return Flavor::Gnu;
    }
    // `cc`-style lines (`-Wl,...`) are what rustc writes for a linker it doesn't know.
    if cfg!(target_vendor = "apple") {
        Flavor::Darwin
    } else if cfg!(windows) && !args.iter().any(|a| a.starts_with("-Wl,")) {
        Flavor::Coff
    } else {
        Flavor::Gnu
    }
}

fn parse_flavor(name: &str) -> diag::Result<Flavor> {
    Ok(match name {
        "link" | "lld-link" | "coff" | "msvc" => Flavor::Coff,
        "gnu" | "ld" | "ld.lld" | "gnu-lld" | "elf" => Flavor::Gnu,
        "darwin" | "ld64" | "ld64.lld" | "darwin-lld" | "macho" => Flavor::Darwin,
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
    } else if stem.starts_with("ld.") || stem == "gnu-lld" {
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
        assert_eq!(
            flavor_from_args(&v(&[
                "crt1.o",
                "a.o",
                "--gc-sections",
                "-static",
                "-o",
                "a"
            ])),
            Flavor::Gnu
        );
        assert_eq!(
            flavor_from_args(&v(&["a.o", "-shared", "-soname", "libx.so"])),
            Flavor::Gnu
        );
    }

    #[test]
    fn unimplemented_flavors_fail_cleanly() {
        assert_eq!(main_with_args(["ld.hyprlnk", "a.o"]), 1);
        assert_eq!(main_with_args(["hyprlnk", "-flavor", "nope"]), 1);
    }

    #[test]
    fn linux_targets_are_supported() {
        for t in [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "i686-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
            "armv7-unknown-linux-gnueabihf",
            "arm-unknown-linux-gnueabi",
            "thumbv7neon-unknown-linux-gnueabihf",
            "riscv64gc-unknown-linux-gnu",
            "powerpc64le-unknown-linux-gnu",
            "s390x-unknown-linux-gnu",
            "loongarch64-unknown-linux-musl",
        ] {
            assert!(supports_target(t), "{t}");
            #[cfg(unix)]
            assert_eq!(rustc_linker_flavor(t), None, "{t}");
            #[cfg(not(unix))]
            assert_eq!(rustc_linker_flavor(t), Some("ld.lld"), "{t}");
        }
        for t in [
            "powerpc64-unknown-linux-gnu",
            "aarch64-linux-android",
            "x86_64-unknown-linux-gnux32",
            "armv4t-unknown-linux-gnueabi",
            "mips64-unknown-linux-gnuabi64",
            "x86_64-unknown-freebsd",
            "aarch64-unknown-linux-ohos",
        ] {
            assert!(!supports_target(t), "{t}");
        }
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
