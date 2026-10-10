//! The parts of the linker script language real link lines use: input scripts (`GROUP`,
//! `INPUT`, `AS_NEEDED` — glibc's `libc.so` is one), version scripts and dynamic lists.

use crate::diag::Result;
use crate::macho::glob_match;
use crate::{bail, err};

fn tokenize(text: &str) -> Result<Vec<String>> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"/*") {
            let end = text[i + 2..]
                .find("*/")
                .ok_or_else(|| err!("unterminated comment"))?;
            i += end + 4;
        } else if c == b'#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'"' {
            let end = text[i + 1..]
                .find('"')
                .ok_or_else(|| err!("unterminated string"))?;
            out.push(text[i..i + end + 2].to_string());
            i += end + 2;
        } else if matches!(c, b'(' | b')' | b'{' | b'}' | b';' | b',' | b'=') {
            out.push((c as char).to_string());
            i += 1;
        } else {
            let start = i;
            while i < b.len()
                && !b[i].is_ascii_whitespace()
                && !matches!(b[i], b'(' | b')' | b'{' | b'}' | b';' | b',' | b'"')
                && !b[i..].starts_with(b"/*")
            {
                i += 1;
            }
            out.push(text[start..i].to_string());
        }
    }
    Ok(out)
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// An input named by a script: a path or `-l<name>`, possibly inside `AS_NEEDED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInput {
    pub name: String,
    pub is_lib: bool,
    pub as_needed: bool,
}

#[derive(Debug, Default)]
pub struct InputScript {
    pub inputs: Vec<ScriptInput>,
    pub search_dirs: Vec<String>,
    pub entry: Option<String>,
}

pub fn parse_input_script(text: &str, path: &str) -> Result<InputScript> {
    let toks = tokenize(text).map_err(|e| err!("{path}: {e}"))?;
    let mut s = InputScript::default();
    let mut i = 0;
    let expect = |i: usize, t: &str| -> Result<()> {
        if toks.get(i).map(String::as_str) != Some(t) {
            bail!(
                "{path}: expected '{t}', found '{}'",
                toks.get(i).map(String::as_str).unwrap_or("end of file")
            );
        }
        Ok(())
    };
    while i < toks.len() {
        let t = toks[i].as_str();
        match t {
            "GROUP" | "INPUT" => {
                expect(i + 1, "(")?;
                i += 2;
                let mut as_needed = false;
                while i < toks.len() && toks[i] != ")" || as_needed {
                    let t = toks
                        .get(i)
                        .ok_or_else(|| err!("{path}: unterminated {t}"))?
                        .as_str();
                    match t {
                        "AS_NEEDED" => {
                            expect(i + 1, "(")?;
                            as_needed = true;
                            i += 2;
                            continue;
                        }
                        ")" => as_needed = false,
                        "," => {}
                        name => {
                            let name = unquote(name);
                            let (name, is_lib) = match name.strip_prefix("-l") {
                                Some(l) => (l.to_string(), true),
                                None => (name.to_string(), false),
                            };
                            s.inputs.push(ScriptInput {
                                name,
                                is_lib,
                                as_needed,
                            });
                        }
                    }
                    i += 1;
                }
                i += 1;
            }
            "OUTPUT_FORMAT" | "OUTPUT_ARCH" | "TARGET" | "STARTUP" | "OUTPUT" | "SEARCH_DIR"
            | "ENTRY" | "VERSION" | "INCLUDE" => {
                if t == "INCLUDE" {
                    bail!("{path}: INCLUDE in linker scripts is not supported");
                }
                expect(i + 1, "(")?;
                let mut j = i + 2;
                let mut args = Vec::new();
                while j < toks.len() && toks[j] != ")" {
                    if toks[j] != "," {
                        args.push(unquote(&toks[j]).to_string());
                    }
                    j += 1;
                }
                match t {
                    "SEARCH_DIR" => s.search_dirs.extend(args),
                    "ENTRY" => s.entry = args.into_iter().next(),
                    "STARTUP" => s.inputs.extend(args.into_iter().map(|name| ScriptInput {
                        name,
                        is_lib: false,
                        as_needed: false,
                    })),
                    _ => {}
                }
                i = j + 1;
            }
            ";" => i += 1,
            "SECTIONS" | "MEMORY" | "PHDRS" => bail!(
                "{path}: linker scripts with {t} are not supported; hyprlnk lays out the output itself"
            ),
            _ => bail!("{path}: unexpected '{t}' in a linker script"),
        }
    }
    Ok(s)
}

/// A symbol name or a glob (`*`, `?`, `[...]`).
#[derive(Debug, Clone, Default)]
pub struct Patterns {
    pub literals: std::collections::HashSet<Vec<u8>>,
    pub globs: Vec<Vec<u8>>,
}

impl Patterns {
    pub fn is_empty(&self) -> bool {
        self.literals.is_empty() && self.globs.is_empty()
    }

    pub fn insert(&mut self, p: &str) {
        let p = unquote(p.trim());
        if p.is_empty() {
            return;
        }
        if p.contains(['*', '?', '[']) {
            self.globs.push(p.as_bytes().to_vec());
        } else {
            self.literals.insert(p.as_bytes().to_vec());
        }
    }

    pub fn literal_match(&self, name: &[u8]) -> bool {
        self.literals.contains(name)
    }

    pub fn glob_match(&self, name: &[u8]) -> bool {
        self.globs.iter().any(|g| glob_match(g, name))
    }

    pub fn matches(&self, name: &[u8]) -> bool {
        self.literal_match(name) || self.glob_match(name)
    }

    /// Matches every name (`*` alone).
    pub fn matches_all(&self) -> bool {
        self.globs.iter().any(|g| g == b"*")
    }
}

#[derive(Debug, Clone)]
pub struct VersionNode {
    /// Empty for the anonymous version.
    pub name: String,
    pub global: Patterns,
    pub local: Patterns,
}

#[derive(Debug, Clone, Default)]
pub struct VersionScript {
    pub nodes: Vec<VersionNode>,
}

impl VersionScript {
    pub fn is_anonymous(&self) -> bool {
        self.nodes.len() == 1 && self.nodes[0].name.is_empty()
    }

    /// Where `name` goes: `Some(Some(i))` global in node `i`, `Some(None)` local, `None`
    /// unmentioned. Exact names win over globs; among globs, `*` alone matters least.
    pub fn assign(&self, name: &[u8]) -> Option<Option<usize>> {
        for (i, n) in self.nodes.iter().enumerate() {
            if n.global.literal_match(name) {
                return Some(Some(i));
            }
        }
        for n in &self.nodes {
            if n.local.literal_match(name) {
                return Some(None);
            }
        }
        for (i, n) in self.nodes.iter().enumerate().rev() {
            if n.global
                .globs
                .iter()
                .any(|g| g != b"*" && glob_match(g, name))
            {
                return Some(Some(i));
            }
        }
        for n in &self.nodes {
            if n.local
                .globs
                .iter()
                .any(|g| g != b"*" && glob_match(g, name))
            {
                return Some(None);
            }
        }
        for (i, n) in self.nodes.iter().enumerate().rev() {
            if n.global.matches_all() {
                return Some(Some(i));
            }
        }
        if self.nodes.iter().any(|n| n.local.matches_all()) {
            return Some(None);
        }
        None
    }
}

pub fn parse_version_script(text: &str, path: &str) -> Result<VersionScript> {
    let toks = tokenize(text).map_err(|e| err!("{path}: {e}"))?;
    let mut vs = VersionScript::default();
    let mut i = 0;
    // `VERSION { ... }` wrapping is allowed.
    if toks.first().map(String::as_str) == Some("VERSION") {
        i = 2;
    }
    while i < toks.len() {
        if toks[i] == "}" || toks[i] == ";" {
            i += 1;
            continue;
        }
        let name = if toks[i] == "{" {
            String::new()
        } else {
            let n = toks[i].clone();
            i += 1;
            n
        };
        if toks.get(i).map(String::as_str) != Some("{") {
            bail!("{path}: expected '{{' after version '{name}'");
        }
        i += 1;
        let mut node = VersionNode {
            name,
            global: Patterns::default(),
            local: Patterns::default(),
        };
        let mut local = false;
        let mut cpp_warned = false;
        while i < toks.len() && toks[i] != "}" {
            let t = toks[i].as_str();
            if t == "global" && toks.get(i + 1).map(String::as_str) == Some(":") {
                local = false;
                i += 2;
                continue;
            }
            if t == "local" && toks.get(i + 1).map(String::as_str) == Some(":") {
                local = true;
                i += 2;
                continue;
            }
            if let Some(t) = t.strip_suffix(':')
                && (t == "global" || t == "local")
            {
                local = t == "local";
                i += 1;
                continue;
            }
            if t == "extern" {
                // `extern "C++" { ... };`: demangled patterns. Only plain names match here.
                let lang = toks
                    .get(i + 1)
                    .map(|s| unquote(s).to_string())
                    .unwrap_or_default();
                i += 3;
                while i < toks.len() && toks[i] != "}" {
                    if toks[i] != ";" {
                        if lang == "C" {
                            if local {
                                node.local.insert(&toks[i]);
                            } else {
                                node.global.insert(&toks[i]);
                            }
                        } else if !cpp_warned {
                            crate::diag::warn(format!(
                                "{path}: extern \"{lang}\" patterns in version scripts are not supported; ignored"
                            ));
                            cpp_warned = true;
                        }
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            if t != ";" {
                if local {
                    node.local.insert(t);
                } else {
                    node.global.insert(t);
                }
            }
            i += 1;
        }
        i += 1;
        // Optional parent version names, then `;`.
        while i < toks.len() && toks[i] != ";" {
            i += 1;
        }
        i += 1;
        vs.nodes.push(node);
    }
    Ok(vs)
}

/// `--dynamic-list` / `--export-dynamic-symbol-list`: `{ sym; pattern*; };`.
pub fn parse_dynamic_list(text: &str, path: &str, out: &mut Patterns) -> Result<()> {
    let toks = tokenize(text).map_err(|e| err!("{path}: {e}"))?;
    let mut depth = 0;
    let mut i = 0;
    while i < toks.len() {
        match toks[i].as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            ";" => {}
            "extern" => {
                // extern "C++" { ... } — demangled names: not supported, skip the block.
                let lang = toks
                    .get(i + 1)
                    .map(|s| unquote(s).to_string())
                    .unwrap_or_default();
                i += 3;
                while i < toks.len() && toks[i] != "}" {
                    if lang == "C" && toks[i] != ";" {
                        out.insert(&toks[i]);
                    }
                    i += 1;
                }
            }
            t if depth > 0 => out.insert(t),
            t => bail!("{path}: unexpected '{t}' in a dynamic list"),
        }
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_libc_so() {
        let text = "/* GNU ld script\n   Use the shared library, but some functions are only in\n   the static library.  */\nOUTPUT_FORMAT(elf64-x86-64)\nGROUP ( /usr/lib/libc.so.6 /usr/lib/libc_nonshared.a  AS_NEEDED ( /usr/lib/ld-linux-x86-64.so.2 ) )\n";
        let s = parse_input_script(text, "libc.so").unwrap();
        assert_eq!(s.inputs.len(), 3);
        assert_eq!(s.inputs[0].name, "/usr/lib/libc.so.6");
        assert!(!s.inputs[1].as_needed);
        assert!(s.inputs[2].as_needed);
        let s = parse_input_script("GROUP ( libgcc_s.so.1 -lgcc )", "x").unwrap();
        assert_eq!(s.inputs[1].name, "gcc");
        assert!(s.inputs[1].is_lib);
        assert!(parse_input_script("SECTIONS { }", "x").is_err());
    }

    #[test]
    fn rustc_version_scripts() {
        let text = "{\n  global:\n    rust_metadata_foo_123;\n    __rustc_proc_macro_decls_abc__;\n\n  local:\n    *;\n};\n";
        let vs = parse_version_script(text, "list").unwrap();
        assert!(vs.is_anonymous());
        assert_eq!(vs.assign(b"rust_metadata_foo_123"), Some(Some(0)));
        assert_eq!(vs.assign(b"other"), Some(None));
    }

    #[test]
    fn named_versions() {
        let text = "V1 { global: a; b*; local: *; };\nV2 { global: c; } V1;";
        let vs = parse_version_script(text, "v").unwrap();
        assert_eq!(vs.nodes.len(), 2);
        assert_eq!(vs.nodes[1].name, "V2");
        assert_eq!(vs.assign(b"c"), Some(Some(1)));
        assert_eq!(vs.assign(b"bar"), Some(Some(0)));
        assert_eq!(vs.assign(b"zzz"), Some(None));
    }

    #[test]
    fn dynamic_lists() {
        let mut p = Patterns::default();
        parse_dynamic_list("{ foo; bar*; extern \"C++\" { x::y; }; };", "l", &mut p).unwrap();
        assert!(p.matches(b"foo") && p.matches(b"barx") && !p.matches(b"x::y"));
    }
}
