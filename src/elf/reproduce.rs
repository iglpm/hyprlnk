//! `--reproduce=<dir>` / `HYPRLNK_REPRODUCE`: save a link's inputs and a response file replaying it.

use std::path::Path;

use super::config::Config;
use crate::diag::Result;
use crate::err;

pub fn save(root: &Path, args: &[String], cfg: &Config) -> Result<()> {
    let stem = cfg
        .output
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "link".to_string());
    let dir = &root.join(format!("{stem}-{}", std::process::id()));
    let io = |e: std::io::Error| err!("--reproduce: {}: {e}", dir.display());
    std::fs::create_dir_all(dir).map_err(io)?;
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let mut rsp = Vec::new();
    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with("--reproduce") || arg == "-reproduce" {
            skip_next = arg == "-reproduce";
            continue;
        }
        let p = Path::new(arg);
        let is_output = i > 0 && (args[i - 1] == "-o" || args[i - 1] == "--output");
        if !is_output && !arg.starts_with('-') && p.is_file() {
            let file = p
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let copy = dir.join(format!("{i:04}-{file}"));
            std::fs::copy(p, &copy).map_err(io)?;
            rsp.push(quote(&copy.display().to_string()));
            continue;
        }
        rsp.push(quote(arg));
    }
    std::fs::write(dir.join("link.rsp"), rsp.join("\n")).map_err(io)?;
    Ok(())
}
