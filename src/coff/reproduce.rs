//! `/REPRODUCE:<dir>` / `HYPRLNK_REPRODUCE`: save a link's inputs and a response file replaying it.

use std::path::{Path, PathBuf};

use super::config::Config;
use super::winsdk;
use crate::diag::Result;
use crate::err;

pub fn save(root: &Path, args: &[String], cfg: &Config) -> Result<()> {
    let stem = cfg
        .output
        .as_deref()
        .and_then(|o| o.file_stem())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "link".to_string());
    let dir = &root.join(format!("{stem}-{}", std::process::id()));
    let io = |e: std::io::Error| err!("/REPRODUCE: {}: {e}", dir.display());
    std::fs::create_dir_all(dir).map_err(io)?;
    let machine = cfg
        .machine
        .unwrap_or_else(|| super::resolve::detect_machine(cfg));
    let search = winsdk::search_paths(&cfg.lib_paths, machine);
    let find = |name: &str| -> Option<PathBuf> {
        let p = Path::new(name);
        if p.is_absolute() {
            return p.is_file().then(|| p.to_path_buf());
        }
        search.iter().map(|d| d.join(name)).find(|c| c.is_file())
    };
    let inputs: Vec<&str> = cfg.inputs.iter().map(|i| i.path.as_str()).collect();
    let quote = |s: &str| format!("\"{}\"", s.replace('"', "\\\""));
    let mut rsp = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        let lower = arg.to_ascii_lowercase();
        if lower.starts_with("/reproduce") || lower.starts_with("-reproduce") {
            continue;
        }
        if inputs.contains(&arg.as_str())
            && let Some(path) = find(arg)
        {
            let file = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let copy = dir.join(format!("{i:04}-{file}"));
            std::fs::copy(&path, &copy).map_err(io)?;
            rsp.push(quote(&copy.display().to_string()));
            continue;
        }
        if let Some(def) = lower
            .strip_prefix("/def:")
            .or_else(|| lower.strip_prefix("-def:"))
        {
            let src = &arg[arg.len() - def.len()..];
            let copy = dir.join(format!("{i:04}.def"));
            std::fs::copy(src, &copy).map_err(io)?;
            rsp.push(quote(&format!("/DEF:{}", copy.display())));
            continue;
        }
        rsp.push(quote(arg));
    }
    for p in search.iter().filter(|p| !p.as_os_str().is_empty()) {
        rsp.push(quote(&format!("/LIBPATH:{}", p.display())));
    }
    std::fs::write(dir.join("link.rsp"), rsp.join("\n")).map_err(io)?;
    Ok(())
}
