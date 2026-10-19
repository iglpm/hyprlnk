//! Library search: `/LIBPATH`, `%LIB%`, else the newest installed MSVC toolset and Windows SDK.

use std::path::{Path, PathBuf};

use super::arch::Machine;

pub fn search_paths(lib_paths: &[PathBuf], machine: Machine) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::new()];
    out.extend(lib_paths.iter().cloned());
    if let Ok(sdk) = std::env::var("HYPRCROSS_SDK_PATH") {
        let p = PathBuf::from(sdk);
        let arch = machine.lib_dir();
        for sub in [
            p.join("lib").join(arch),
            p.join("lib"),
            p.join("ucrt").join(arch),
            p.join("um").join(arch),
            p.join("ucrt"),
            p.join("um"),
        ] {
            if sub.is_dir() && !out.contains(&sub) {
                out.push(sub);
            }
        }
    }
    match std::env::var_os("LIB") {
        Some(lib) if !lib.is_empty() => out.extend(std::env::split_paths(&lib)),
        _ => out.extend(installed_lib_dirs(machine)),
    }
    out
}

pub fn installed_lib_dirs(machine: Machine) -> Vec<PathBuf> {
    let arch = machine.lib_dir();
    if !cfg!(windows) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let program_files: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    let msvc = std::env::var_os("VCToolsInstallDir")
        .map(PathBuf::from)
        .or_else(|| {
            let mut tools = Vec::new();
            for pf in &program_files {
                for year in children(&pf.join("Microsoft Visual Studio")) {
                    for edition in children(&year) {
                        tools.extend(children(&edition.join("VC").join("Tools").join("MSVC")));
                    }
                }
            }
            newest(tools)
        });
    if let Some(dir) = msvc {
        out.push(dir.join("lib").join(arch));
    }
    for pf in &program_files {
        let versions = children(&pf.join("Windows Kits").join("10").join("Lib"));
        if let Some(v) = newest(
            versions
                .into_iter()
                .filter(|v| v.join("um").exists())
                .collect(),
        ) {
            out.push(v.join("ucrt").join(arch));
            out.push(v.join("um").join(arch));
            break;
        }
    }
    out.retain(|p| p.is_dir());
    out
}

fn children(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default()
}

fn newest(dirs: Vec<PathBuf>) -> Option<PathBuf> {
    dirs.into_iter().max_by_key(|p| version_key(p))
}

fn version_key(p: &Path) -> Vec<u64> {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_compares_versions_numerically() {
        let dirs = vec![
            PathBuf::from("x/14.9.1"),
            PathBuf::from("x/14.44.35207"),
            PathBuf::from("x/14.10"),
        ];
        assert_eq!(newest(dirs), Some(PathBuf::from("x/14.44.35207")));
    }
}
