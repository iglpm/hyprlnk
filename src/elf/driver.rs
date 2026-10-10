//! `cc` command lines. rustc runs a linker it doesn't recognize (`-C linker=hyprlnk`) the way it
//! runs `cc`, and on Linux only the C compiler knows where the C runtime's start files, libgcc
//! and the system's library directories are. So hyprlnk runs the C compiler ([`crate::CC_ENV`],
//! else `cc`) with a private `-B` directory whose `ld` is hyprlnk, and is then run again as `ld`.

use crate::diag::Result;

/// What a C compiler runs as the linker: `ld`, or `ld.<name>` for `-fuse-ld=<name>` (and for
/// a clang whose default is lld).
#[cfg(all(unix, not(target_vendor = "apple")))]
const LD_NAMES: [&str; 5] = ["ld", "ld.lld", "ld.bfd", "ld.gold", "ld.mold"];

/// Set for the C compiler's process tree, so hyprlnk configured as the C compiler fails instead
/// of running itself forever.
#[cfg(all(unix, not(target_vendor = "apple")))]
const NESTED_ENV: &str = "HYPRLNK_DRIVER";

/// Options only a compiler driver takes (`ld` has `-Bstatic` and `-m <emulation>`, not these).
pub fn is_cc_command_line(args: &[String]) -> bool {
    let cc = |a: &String| {
        let a = a.as_str();
        a.starts_with("-Wl,")
            || a.starts_with("-fuse-ld=")
            || a.starts_with("--ld-path=")
            || a.starts_with("--target=")
            || a.starts_with("-fsanitize")
            || a.starts_with("-fprofile")
            || a.starts_with("-flto")
            || (a.starts_with("-m") && a.contains('='))
            || (a.starts_with("-B") && a[2..].starts_with(['/', '.', '~']))
            || matches!(
                a,
                "-Xlinker"
                    | "-nodefaultlibs"
                    | "-nostartfiles"
                    | "-nostdlib"
                    | "-nolibc"
                    | "-m64"
                    | "-m32"
                    | "-m31"
                    | "-mx32"
                    | "-static-libgcc"
                    | "-shared-libgcc"
                    | "-static-libstdc++"
                    | "-pthread"
                    | "-rdynamic"
                    | "-target"
                    | "-fPIC"
                    | "-fpic"
                    | "-fPIE"
                    | "-fpie"
            )
    };
    if args.iter().any(cc) {
        return true;
    }
    // rustc moves a command line too long for the system into a response file.
    args.iter().any(|a| a.starts_with('@'))
        && crate::cmdline::expand_gnu_response_files(args.to_vec())
            .is_ok_and(|all| all.iter().any(cc))
}

/// Link through the C compiler; its exit code.
#[cfg(all(unix, not(target_vendor = "apple")))]
pub fn run_cc(args: Vec<String>) -> Result<i32> {
    use std::os::unix::process::ExitStatusExt;

    if std::env::var_os(NESTED_ENV).is_some() {
        crate::bail!(
            "hyprlnk was run as the C compiler it runs for a `cc` command line; set HYPRLNK_CC \
             to a C compiler"
        );
    }
    let exe = std::env::current_exe()
        .map_err(|e| crate::err!("cannot find hyprlnk's own executable: {e}"))?;
    let dir = LdDir::create(&exe)?;
    let cc = std::env::var_os(crate::CC_ENV)
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "cc".into());
    let mut prefix = std::ffi::OsString::from("-B");
    prefix.push(dir.0.as_os_str());
    prefix.push("/");
    // Our `-B` comes first, so its `ld` wins over any other; a `-fuse-ld=` would only pick
    // another of the names it holds.
    let status = std::process::Command::new(&cc)
        .arg(prefix)
        .args(
            args.iter()
                .filter(|a| !a.starts_with("-fuse-ld=") && !a.starts_with("--ld-path=")),
        )
        .env(NESTED_ENV, "1")
        .status()
        .map_err(|e| {
            crate::err!(
                "cannot run the C compiler `{}`: {e}. hyprlnk runs it for a `cc` command line, \
                 to find the C runtime; set HYPRLNK_CC to another, or pass `ld` arguments \
                 (`-C linker-flavor=ld` for rustc)",
                cc.to_string_lossy()
            )
        })?;
    drop(dir);
    Ok(match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        _ => 1,
    })
}

#[cfg(not(all(unix, not(target_vendor = "apple"))))]
pub fn run_cc(_args: Vec<String>) -> Result<i32> {
    crate::bail!(
        "a `cc` command line for an ELF target: on this host pass `ld` arguments instead \
         (`-flavor gnu`, or `-C linker-flavor=ld` for rustc)"
    )
}

/// A fresh directory of links to hyprlnk named like linkers, removed when dropped.
#[cfg(all(unix, not(target_vendor = "apple")))]
struct LdDir(std::path::PathBuf);

#[cfg(all(unix, not(target_vendor = "apple")))]
impl LdDir {
    fn create(exe: &std::path::Path) -> Result<LdDir> {
        use std::os::unix::fs::DirBuilderExt;

        let base = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        for i in 0..64u32 {
            let path = base.join(format!("hyprlnk-{pid}-{nanos:x}-{i}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let dir = LdDir(path);
                    for name in LD_NAMES {
                        std::os::unix::fs::symlink(exe, dir.0.join(name)).map_err(|e| {
                            crate::err!("cannot create {}: {e}", dir.0.join(name).display())
                        })?;
                    }
                    return Ok(dir);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => crate::bail!("cannot create a directory in {}: {e}", base.display()),
            }
        }
        crate::bail!("cannot create a directory in {}", base.display())
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
impl Drop for LdDir {
    fn drop(&mut self) {
        for name in LD_NAMES {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rustc_cc_lines_are_told_from_ld_lines() {
        // What rustc passes for x86_64-unknown-linux-gnu with a linker it doesn't know.
        assert!(is_cc_command_line(&v(&[
            "-m64",
            "a.o",
            "-Wl,--as-needed",
            "-fuse-ld=lld",
            "-nodefaultlibs",
            "-pie"
        ])));
        assert!(is_cc_command_line(&v(&["a.o", "-B/usr/lib/x", "-o", "a"])));
        assert!(is_cc_command_line(&v(&["a.o", "-march=rv64gc", "-o", "a"])));
        // What a C compiler passes to `ld`.
        assert!(!is_cc_command_line(&v(&[
            "-z",
            "relro",
            "--hash-style=gnu",
            "-m",
            "elf_x86_64",
            "-melf_x86_64",
            "-Bstatic",
            "-Bsymbolic",
            "-pie",
            "-dynamic-linker",
            "/lib64/ld-linux-x86-64.so.2",
            "Scrt1.o",
            "-L/usr/lib",
            "a.o",
            "-lgcc",
            "-o",
            "a"
        ])));
    }

    #[test]
    fn response_files_are_looked_into() {
        let dir = std::env::temp_dir().join(format!("hyprlnk-driver-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rsp = dir.join("args");
        std::fs::write(&rsp, "a.o\n-Wl,--gc-sections\n").unwrap();
        assert!(is_cc_command_line(&v(&[&format!("@{}", rsp.display())])));
        std::fs::write(&rsp, "a.o\n--gc-sections\n").unwrap();
        assert!(!is_cc_command_line(&v(&[&format!("@{}", rsp.display())])));
        std::fs::remove_dir_all(&dir).ok();
    }
}
