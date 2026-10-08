//! `/EXPORT:` specifications and module-definition (`.def`) files.

use super::config::parse_number;
use crate::diag::Result;
use crate::{bail, err};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportSpec {
    pub name: String,
    pub internal: Option<String>,
    pub ordinal: Option<u16>,
    pub noname: bool,
    pub data: bool,
    pub private: bool,
    pub constant: bool,
    pub export_as: Option<String>,
}

impl ExportSpec {
    pub fn symbol(&self) -> &str {
        self.internal.as_deref().unwrap_or(&self.name)
    }
}

/// `name[=internal][,@ordinal[,NONAME]][,DATA][,PRIVATE][,CONSTANT]`
pub fn parse_export(spec: &str) -> Result<ExportSpec> {
    let mut parts = spec.split(',');
    let head = parts.next().unwrap_or("");
    let mut e = ExportSpec::default();
    match head.split_once('=') {
        Some((name, internal)) => {
            e.name = name.to_string();
            e.internal = Some(internal.to_string());
        }
        None => e.name = head.to_string(),
    }
    if e.name.is_empty() {
        bail!("invalid /EXPORT: '{spec}'");
    }
    let mut parts = parts.peekable();
    while let Some(part) = parts.next() {
        let p = part.trim();
        if p.eq_ignore_ascii_case("exportas") {
            let name = parts.next().map(str::trim).unwrap_or("");
            if name.is_empty() {
                bail!("invalid /EXPORT: '{spec}': EXPORTAS needs a name");
            }
            e.export_as = Some(name.to_string());
            continue;
        }
        if let Some(ord) = p.strip_prefix('@') {
            e.ordinal = Some(parse_ordinal(ord)?);
            continue;
        }
        match p.to_ascii_lowercase().as_str() {
            "noname" => e.noname = true,
            "data" => e.data = true,
            "private" => e.private = true,
            "constant" => e.constant = true,
            "" => {}
            _ => bail!("invalid /EXPORT: '{spec}'"),
        }
    }
    Ok(e)
}

fn parse_ordinal(s: &str) -> Result<u16> {
    let n: u16 = s
        .trim()
        .parse()
        .map_err(|_| err!("invalid export ordinal '{s}'"))?;
    if n == 0 {
        bail!("export ordinals start at 1");
    }
    Ok(n)
}

#[derive(Debug, Default)]
pub struct DefFile {
    pub name: Option<String>,
    pub base: Option<u64>,
    pub stack: Option<(u64, u64)>,
    pub heap: Option<(u64, u64)>,
    pub version: Option<(u16, u16)>,
    pub exports: Vec<ExportSpec>,
}

pub fn parse_def(text: &str) -> Result<DefFile> {
    let mut def = DefFile::default();
    let mut tokens = tokenize_def(text).into_iter().peekable();
    let is_keyword = |t: &str| {
        matches!(
            t.to_ascii_uppercase().as_str(),
            "LIBRARY"
                | "NAME"
                | "EXPORTS"
                | "HEAPSIZE"
                | "STACKSIZE"
                | "VERSION"
                | "SECTIONS"
                | "DESCRIPTION"
                | "STUB"
                | "IMPORTS"
        )
    };
    while let Some(tok) = tokens.next() {
        match tok.to_ascii_uppercase().as_str() {
            kw @ ("LIBRARY" | "NAME") => {
                if let Some(name) = tokens.next_if(|t| !is_keyword(t) && !t.contains('=')) {
                    let mut name = name;
                    if !name.contains('.') {
                        name.push_str(if kw == "LIBRARY" { ".dll" } else { ".exe" });
                    }
                    def.name = Some(name);
                }
                if let Some(base) = tokens.next_if(|t| t.to_ascii_uppercase().starts_with("BASE="))
                {
                    def.base = Some(parse_number(&base[5..])?);
                }
            }
            "EXPORTS" => {
                while let Some(name) = tokens.next_if(|t| !is_keyword(t)) {
                    let mut e = ExportSpec::default();
                    match name.split_once('=') {
                        Some((a, b)) => {
                            e.name = a.to_string();
                            e.internal = Some(b.to_string());
                        }
                        None => e.name = name.clone(),
                    }
                    if tokens.next_if(|t| t == "=").is_some() {
                        e.internal = tokens.next();
                    }
                    loop {
                        if let Some(ord) = tokens.next_if(|t| t.starts_with('@')) {
                            let ord = if ord.len() > 1 {
                                ord[1..].to_string()
                            } else {
                                tokens.next().unwrap_or_default()
                            };
                            e.ordinal = Some(parse_ordinal(&ord)?);
                            continue;
                        }
                        let attr = tokens.next_if(|t| {
                            matches!(
                                t.to_ascii_uppercase().as_str(),
                                "NONAME" | "DATA" | "PRIVATE" | "CONSTANT"
                            )
                        });
                        match attr.map(|a| a.to_ascii_uppercase()).as_deref() {
                            Some("NONAME") => e.noname = true,
                            Some("DATA") => e.data = true,
                            Some("PRIVATE") => e.private = true,
                            Some("CONSTANT") => e.constant = true,
                            _ => break,
                        }
                    }
                    def.exports.push(e);
                }
            }
            kw @ ("HEAPSIZE" | "STACKSIZE") => {
                let v = tokens
                    .next()
                    .ok_or_else(|| err!("{kw} needs a size in the .def file"))?;
                let pair = match v.split_once(',') {
                    Some((r, c)) => (parse_number(r)?, parse_number(c)?),
                    None => (parse_number(&v)?, 4096),
                };
                if kw == "HEAPSIZE" {
                    def.heap = Some(pair);
                } else {
                    def.stack = Some(pair);
                }
            }
            "VERSION" => {
                if let Some(v) = tokens.next() {
                    let (a, b) = v.split_once('.').unwrap_or((&v, "0"));
                    def.version = Some((
                        a.parse()
                            .map_err(|_| err!("invalid VERSION in .def file"))?,
                        b.parse()
                            .map_err(|_| err!("invalid VERSION in .def file"))?,
                    ));
                }
            }
            "DESCRIPTION" | "STUB" => {
                tokens.next();
            }
            "SECTIONS" | "IMPORTS" => while tokens.next_if(|t| !is_keyword(t)).is_some() {},
            other => bail!("unexpected '{other}' in .def file"),
        }
    }
    Ok(def)
}

fn tokenize_def(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("");
        let mut chars = line.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else if c == '"' {
                chars.next();
                let mut s = String::new();
                for c in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                    s.push(c);
                }
                out.push(s);
            } else if c == '=' {
                chars.next();
                out.push("=".to_string());
            } else {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_specs() {
        let e = parse_export("foo").unwrap();
        assert_eq!((e.name.as_str(), e.symbol()), ("foo", "foo"));
        let e = parse_export("foo=bar,@7,NONAME,DATA").unwrap();
        assert_eq!(e.symbol(), "bar");
        assert_eq!(e.ordinal, Some(7));
        assert!(e.noname && e.data && !e.private);
        assert!(parse_export(",DATA").is_err());
        let e = parse_export("_MAGIC,DATA,EXPORTAS,MAGIC").unwrap();
        assert_eq!(
            (e.name.as_str(), e.export_as.as_deref()),
            ("_MAGIC", Some("MAGIC"))
        );
        assert!(e.data);
        assert!(parse_export("x,@0").is_err());
    }

    #[test]
    fn def_files_as_rustc_writes_them() {
        let d = parse_def("LIBRARY\nEXPORTS\n    foo\n    bar\n").unwrap();
        assert_eq!(d.name, None);
        let names: Vec<_> = d.exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["foo", "bar"]);
    }

    #[test]
    fn def_file_statements() {
        let d = parse_def(
            "; comment\nLIBRARY mylib BASE=0x10000000\nSTACKSIZE 0x100000,0x2000\n\
             EXPORTS\n  a @1 NONAME\n  b = c DATA\n  d=e PRIVATE ; trailing\nVERSION 1.2\n",
        )
        .unwrap();
        assert_eq!(d.name.as_deref(), Some("mylib.dll"));
        assert_eq!(d.base, Some(0x1000_0000));
        assert_eq!(d.stack, Some((0x100000, 0x2000)));
        assert_eq!(d.version, Some((1, 2)));
        assert_eq!(d.exports.len(), 3);
        assert_eq!(d.exports[0].ordinal, Some(1));
        assert!(d.exports[0].noname);
        assert_eq!(d.exports[1].symbol(), "c");
        assert!(d.exports[1].data);
        assert_eq!(d.exports[2].symbol(), "e");
        assert!(d.exports[2].private);
    }
}
