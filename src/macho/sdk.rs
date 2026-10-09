//! Finding libraries and frameworks: `-L`/`-F` directories re-rooted under `-syslibroot`, then the system ones.

use std::path::{Path, PathBuf};

use super::config::Config;

pub struct SearchPaths {
    pub libs: Vec<PathBuf>,
    pub frameworks: Vec<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub dylibs_first: bool,
}

impl SearchPaths {
    pub fn new(cfg: &Config) -> SearchPaths {
        let mut roots = cfg.syslibroots.clone();
        if roots.is_empty() {
            // The SDK is the only place libSystem's stubs live since macOS 11.
            roots.extend(default_sdk(cfg));
        }
        let reroot = |dirs: &[PathBuf], system: &[&str]| -> Vec<PathBuf> {
            let mut out = Vec::new();
            for d in dirs {
                let mut found = false;
                if d.is_absolute() {
                    for r in &roots {
                        let p = join_root(r, d);
                        if p.is_dir() {
                            out.push(p);
                            found = true;
                        }
                    }
                }
                if !found {
                    out.push(d.clone());
                }
            }
            if !cfg.no_default_paths {
                for s in system {
                    let mut found = false;
                    for r in &roots {
                        let p = join_root(r, Path::new(s));
                        if p.is_dir() {
                            out.push(p);
                            found = true;
                        }
                    }
                    if !found && cfg.syslibroots.is_empty() && Path::new(s).is_dir() {
                        out.push(PathBuf::from(s));
                    }
                }
            }
            out
        };
        SearchPaths {
            libs: reroot(&cfg.lib_paths, &["/usr/lib", "/usr/local/lib"]),
            frameworks: reroot(
                &cfg.framework_paths,
                &["/Library/Frameworks", "/System/Library/Frameworks"],
            ),
            roots,
            dylibs_first: cfg.search_dylibs_first,
        }
    }

    /// `-lname`: per directory `.tbd`, `.dylib`, `.so`, then `.a` (or all dylibs first).
    pub fn find_library(&self, name: &str) -> Option<PathBuf> {
        if name.contains('.') && (name.ends_with(".o") || name.ends_with(".a")) {
            // `-lfoo.o` / `-lfoo.a`: ld64 searches the exact file name.
            return self.libs.iter().map(|d| d.join(name)).find(|p| p.is_file());
        }
        let dylib = [".tbd", ".dylib", ".so"];
        let stem = format!("lib{name}");
        if self.dylibs_first {
            for d in &self.libs {
                if let Some(p) = first_existing(d, &stem, &dylib) {
                    return Some(p);
                }
            }
            for d in &self.libs {
                if let Some(p) = first_existing(d, &stem, &[".a"]) {
                    return Some(p);
                }
            }
            return None;
        }
        for d in &self.libs {
            if let Some(p) = first_existing(d, &stem, &[".tbd", ".dylib", ".so", ".a"]) {
                return Some(p);
            }
        }
        None
    }

    /// `-framework Name[,suffix]`: `Name.framework/Name[suffix]` (or its `.tbd`).
    pub fn find_framework(&self, spec: &str) -> Option<PathBuf> {
        let (name, suffix) = match spec.split_once(',') {
            Some((n, s)) => (n, Some(s)),
            None => (spec, None),
        };
        for d in &self.frameworks {
            let dir = d.join(format!("{name}.framework"));
            if !dir.is_dir() {
                continue;
            }
            if let Some(s) = suffix
                && let Some(p) = first_existing(&dir, &format!("{name}{s}"), &[".tbd", ""])
            {
                return Some(p);
            }
            if let Some(p) = first_existing(&dir, name, &[".tbd", ""]) {
                return Some(p);
            }
        }
        None
    }

    /// A re-exported or `$ld$previous$` library by install name, inside the SDK first.
    pub fn find_install_name(&self, install_name: &str) -> Option<PathBuf> {
        let p = Path::new(install_name);
        let tbd = p.with_extension("tbd");
        let mut candidates = Vec::new();
        for r in &self.roots {
            if install_name.ends_with(".dylib") {
                candidates.push(join_root(r, &tbd));
            } else {
                let mut t = join_root(r, p).into_os_string();
                t.push(".tbd");
                candidates.push(PathBuf::from(t));
            }
            candidates.push(join_root(r, p));
        }
        if install_name.ends_with(".dylib") {
            candidates.push(tbd);
        }
        candidates.push(p.to_path_buf());
        candidates.into_iter().find(|c| c.is_file())
    }

    pub fn describe(&self) -> String {
        let all: Vec<String> = self
            .libs
            .iter()
            .chain(&self.frameworks)
            .map(|p| p.display().to_string())
            .collect();
        if all.is_empty() {
            "no directories".to_string()
        } else {
            all.join(", ")
        }
    }
}

fn first_existing(dir: &Path, stem: &str, exts: &[&str]) -> Option<PathBuf> {
    exts.iter()
        .map(|e| dir.join(format!("{stem}{e}")))
        .find(|p| p.is_file())
}

fn join_root(root: &Path, p: &Path) -> PathBuf {
    let rel = p.strip_prefix("/").unwrap_or(p);
    root.join(rel)
}

/// `SDKROOT`, then the Command Line Tools' or Xcode's macOS SDK, when linking for macOS on a Mac.
fn default_sdk(cfg: &Config) -> Option<PathBuf> {
    if let Some(s) = std::env::var_os("SDKROOT").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(s));
    }
    if cfg.platform != super::PLATFORM_MACOS || !cfg!(target_os = "macos") {
        return None;
    }
    [
        "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.join("usr/lib").is_dir())
}

/// The SDK's version from `SDKSettings.json`, for `-platform_version` in `cc` mode.
pub fn sdk_version(sysroot: &str) -> Option<String> {
    let text = std::fs::read_to_string(Path::new(sysroot).join("SDKSettings.json")).ok()?;
    let at = text.find("\"Version\"")?;
    let rest = &text[at + 9..];
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    let v = &rest[start..end];
    v.chars()
        .all(|c| c.is_ascii_digit() || c == '.')
        .then(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_libraries_in_order() {
        let dir = std::env::temp_dir().join(format!("hyprlnk-sdk-{}", std::process::id()));
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("libx.a"), b"").unwrap();
        std::fs::write(b.join("libx.dylib"), b"").unwrap();
        std::fs::create_dir_all(b.join("F.framework")).unwrap();
        std::fs::write(b.join("F.framework/F.tbd"), b"").unwrap();
        let mut cfg = Config {
            lib_paths: vec![a.clone(), b.clone()],
            framework_paths: vec![b.clone()],
            no_default_paths: true,
            ..Config::default()
        };
        cfg.syslibroots = vec![PathBuf::from("/nonexistent-root")];
        let s = SearchPaths::new(&cfg);
        assert_eq!(s.find_library("x"), Some(a.join("libx.a")));
        cfg.search_dylibs_first = true;
        let s = SearchPaths::new(&cfg);
        assert_eq!(s.find_library("x"), Some(b.join("libx.dylib")));
        assert_eq!(s.find_framework("F"), Some(b.join("F.framework/F.tbd")));
        assert_eq!(s.find_library("nope"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
