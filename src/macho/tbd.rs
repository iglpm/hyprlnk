//! Text-based dylib stubs (`.tbd`): YAML v1–v4 and JSON v5, reduced to what the linker needs.

use std::borrow::Cow;

use super::config::Arch;
use super::*;
use crate::diag::Result;
use crate::{bail, err};

#[derive(Debug, Default)]
pub struct Interface<'a> {
    pub install_name: String,
    pub current_version: u32,
    pub compat_version: u32,
    pub reexports: Vec<String>,
    pub exports: Vec<Export<'a>>,
    /// `$ld$previous$` moves: (install name, compatibility version, symbol).
    pub previous: Vec<(String, u32, Cow<'a, [u8]>)>,
}

#[derive(Debug, Clone)]
pub struct Export<'a> {
    pub name: Cow<'a, [u8]>,
    pub weak: bool,
    pub tlv: bool,
}

pub fn is_tbd(d: &[u8]) -> bool {
    let d = trim_bom(d);
    d.starts_with(b"--- !tapi-tbd")
        || d.starts_with(b"---\narchs:")
        || d.starts_with(b"--- \narchs:")
        || (d.first() == Some(&b'{')
            && d[..d.len().min(256)]
                .windows(16)
                .any(|w| w == b"tapi_tbd_version"))
}

fn trim_bom(d: &[u8]) -> &[u8] {
    d.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(d)
}

pub struct Target {
    pub arch: Arch,
    pub platform: u32,
    pub min_version: u32,
}

/// Every library in the file: the main one first, then those documented inline (usually its re-exports).
pub fn parse<'a>(data: &'a [u8], t: &Target) -> Result<Vec<Interface<'a>>> {
    let data = trim_bom(data);
    let text = std::str::from_utf8(data).map_err(|_| err!("text stub is not UTF-8"))?;
    if text.starts_with('{') {
        let v = Json {
            s: text.as_bytes(),
            pos: 0,
        }
        .parse_document()?;
        return interpret_v5(&v, t);
    }
    let mut out = Vec::new();
    for doc in split_documents(text) {
        let mut p = Yaml {
            s: doc.body,
            pos: 0,
        };
        let root = p.node(0);
        let v = if doc.tag.contains("tapi-tbd-v3") {
            3
        } else if doc.tag.contains("tapi-tbd-v2") {
            2
        } else if doc.tag.contains("tapi-tbd") {
            root.get("tbd-version")
                .and_then(Y::as_str)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(4)
        } else {
            1
        };
        out.push(if v >= 4 {
            interpret_v4(&root, t)?
        } else {
            interpret_v1_3(&root, t, v)?
        });
    }
    if out.is_empty() {
        bail!("empty text stub");
    }
    Ok(out)
}

struct Doc<'a> {
    tag: &'a str,
    body: &'a str,
}

fn split_documents(text: &str) -> Vec<Doc<'_>> {
    let mut docs = Vec::new();
    let mut start: Option<(usize, &str)> = None;
    let mut off = 0;
    for line in text.split_inclusive('\n') {
        let l = line.trim_end();
        if let Some(tag) = l.strip_prefix("---") {
            if let Some((s, t)) = start.take() {
                docs.push(Doc {
                    tag: t,
                    body: &text[s..off],
                });
            }
            start = Some((off + line.len(), tag.trim()));
        } else if l == "..."
            && let Some((s, tag)) = start.take()
        {
            docs.push(Doc {
                tag,
                body: &text[s..off],
            });
        }
        off += line.len();
    }
    if let Some((s, tag)) = start {
        docs.push(Doc {
            tag,
            body: &text[s..],
        });
    }
    docs
}

#[derive(Debug)]
enum Y<'a> {
    Null,
    Str(Cow<'a, str>),
    Seq(Vec<Y<'a>>),
    Map(Vec<(Cow<'a, str>, Y<'a>)>),
}

impl<'a> Y<'a> {
    fn get(&self, key: &str) -> Option<&Y<'a>> {
        match self {
            Y::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Y::Str(s) => Some(s),
            _ => None,
        }
    }

    fn items(&self) -> &[Y<'a>] {
        match self {
            Y::Seq(v) => v,
            _ => &[],
        }
    }

    /// A scalar or a list of scalars, as a list.
    fn strs(&self) -> Vec<&Cow<'a, str>> {
        match self {
            Y::Str(s) => vec![s],
            Y::Seq(v) => v
                .iter()
                .filter_map(|y| match y {
                    Y::Str(s) => Some(s),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// The block-and-flow YAML subset TAPI writes.
struct Yaml<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Yaml<'a> {
    fn bytes(&self) -> &'a [u8] {
        self.s.as_bytes()
    }

    /// Skip blank and comment lines; return the indentation of the next content line.
    fn next_line(&mut self) -> Option<usize> {
        let b = self.bytes();
        loop {
            let start = self.pos;
            let mut i = start;
            while i < b.len() && b[i] == b' ' {
                i += 1;
            }
            if i >= b.len() {
                self.pos = b.len();
                return None;
            }
            match b[i] {
                b'\n' | b'\r' => {
                    self.pos = i + 1;
                }
                b'#' => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                    self.pos = i;
                }
                _ => return Some(i - start),
            }
        }
    }

    fn node(&mut self, min_indent: usize) -> Y<'a> {
        let Some(indent) = self.next_line() else {
            return Y::Null;
        };
        if indent < min_indent {
            return Y::Null;
        }
        let at = self.pos + indent;
        if self.is_dash(at) {
            self.seq(indent)
        } else {
            self.pos = at;
            self.map(indent)
        }
    }

    fn is_dash(&self, at: usize) -> bool {
        let b = self.bytes();
        b.get(at) == Some(&b'-') && matches!(b.get(at + 1), None | Some(b' ' | b'\n' | b'\r'))
    }

    fn seq(&mut self, indent: usize) -> Y<'a> {
        let mut items = Vec::new();
        while let Some(i) = self.next_line() {
            let at = self.pos + i;
            if i != indent || !self.is_dash(at) {
                break;
            }
            self.pos = at + 1;
            let b = self.bytes();
            let mut col = indent + 1;
            while self.pos < b.len() && b[self.pos] == b' ' {
                self.pos += 1;
                col += 1;
            }
            if self.pos >= b.len() || b[self.pos] == b'\n' || b[self.pos] == b'\r' {
                items.push(self.node(indent + 1));
            } else if self.line_has_key() {
                items.push(self.map(col));
            } else {
                items.push(self.inline_value());
                self.skip_to_eol();
            }
        }
        Y::Seq(items)
    }

    /// Whether the rest of this line is `key: ...` (outside quotes and brackets).
    fn line_has_key(&self) -> bool {
        let b = self.bytes();
        let mut i = self.pos;
        if matches!(b.get(i), Some(b'[' | b'\'' | b'"' | b'{')) {
            return false;
        }
        while i < b.len() && b[i] != b'\n' {
            if b[i] == b':' && matches!(b.get(i + 1), None | Some(b' ' | b'\n' | b'\r')) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// A block map whose first key starts at `self.pos`, in column `indent`.
    fn map(&mut self, indent: usize) -> Y<'a> {
        let mut entries = Vec::new();
        let mut first = true;
        loop {
            if !first {
                let Some(i) = self.next_line() else { break };
                if i != indent || self.is_dash(self.pos + i) {
                    break;
                }
                self.pos += i;
            }
            first = false;
            let b = self.bytes();
            let ks = self.pos;
            while self.pos < b.len() && b[self.pos] != b':' && b[self.pos] != b'\n' {
                self.pos += 1;
            }
            if self.pos >= b.len() || b[self.pos] != b':' {
                self.skip_to_eol();
                continue;
            }
            let key = unquote(self.s[ks..self.pos].trim());
            self.pos += 1;
            while self.pos < b.len() && b[self.pos] == b' ' {
                self.pos += 1;
            }
            let value = if self.pos >= b.len() || b[self.pos] == b'\n' || b[self.pos] == b'\r' {
                // A nested block: deeper, or a sequence at the same indentation.
                let save = self.pos;
                match self.next_line() {
                    Some(i) if i > indent || (i == indent && self.is_dash(self.pos + i)) => {
                        self.node(i)
                    }
                    _ => {
                        self.pos = save;
                        self.skip_to_eol();
                        Y::Null
                    }
                }
            } else {
                let v = self.inline_value();
                self.skip_to_eol();
                v
            };
            entries.push((key, value));
        }
        Y::Map(entries)
    }

    fn skip_to_eol(&mut self) {
        let b = self.bytes();
        while self.pos < b.len() && b[self.pos] != b'\n' {
            self.pos += 1;
        }
        if self.pos < b.len() {
            self.pos += 1;
        }
    }

    fn skip_ws(&mut self) {
        let b = self.bytes();
        while self.pos < b.len() && matches!(b[self.pos], b' ' | b'\n' | b'\r' | b'\t') {
            self.pos += 1;
        }
    }

    fn inline_value(&mut self) -> Y<'a> {
        let b = self.bytes();
        match b.get(self.pos) {
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match b.get(self.pos) {
                        None => break,
                        Some(b']') => {
                            self.pos += 1;
                            break;
                        }
                        Some(b',') => {
                            self.pos += 1;
                        }
                        _ => items.push(Y::Str(self.scalar(true))),
                    }
                }
                Y::Seq(items)
            }
            _ => Y::Str(self.scalar(false)),
        }
    }

    fn scalar(&mut self, in_flow: bool) -> Cow<'a, str> {
        let b = self.bytes();
        match b.get(self.pos) {
            Some(b'\'') => {
                let start = self.pos + 1;
                let mut i = start;
                let mut escaped = false;
                while i < b.len() {
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            escaped = true;
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                self.pos = (i + 1).min(b.len());
                let raw = &self.s[start..i.min(b.len())];
                if escaped {
                    Cow::Owned(raw.replace("''", "'"))
                } else {
                    Cow::Borrowed(raw)
                }
            }
            Some(b'"') => {
                let start = self.pos + 1;
                let mut i = start;
                let mut out: Option<String> = None;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        let o = out.get_or_insert_with(|| self.s[start..i].to_string());
                        o.push(match b[i + 1] {
                            b'n' => '\n',
                            b't' => '\t',
                            c => c as char,
                        });
                        i += 2;
                        continue;
                    }
                    if let Some(o) = &mut out {
                        o.push(b[i] as char);
                    }
                    i += 1;
                }
                self.pos = (i + 1).min(b.len());
                match out {
                    Some(o) => Cow::Owned(o),
                    None => Cow::Borrowed(&self.s[start..i.min(b.len())]),
                }
            }
            _ => {
                let start = self.pos;
                let mut i = start;
                while i < b.len() {
                    let c = b[i];
                    if c == b'\n' || (in_flow && (c == b',' || c == b']')) {
                        break;
                    }
                    if c == b'#' && i > start && b[i - 1] == b' ' {
                        break;
                    }
                    i += 1;
                }
                self.pos = i;
                Cow::Borrowed(self.s[start..i].trim())
            }
        }
    }
}

fn unquote(s: &str) -> Cow<'_, str> {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')))
    {
        Cow::Borrowed(&t[1..t.len() - 1])
    } else {
        Cow::Borrowed(t)
    }
}

fn arch_cpu(name: &str) -> Option<u32> {
    if name.starts_with("arm64_32") {
        None
    } else if name.starts_with("arm64") {
        Some(CPU_TYPE_ARM64)
    } else if name.starts_with("x86_64") {
        Some(CPU_TYPE_X86_64)
    } else {
        None
    }
}

fn platform_of(name: &str) -> Option<u32> {
    Some(match name {
        "macos" | "macosx" => PLATFORM_MACOS,
        "ios" => PLATFORM_IOS,
        "tvos" => PLATFORM_TVOS,
        "watchos" => PLATFORM_WATCHOS,
        "bridgeos" => PLATFORM_BRIDGEOS,
        "maccatalyst" | "iosmac" => PLATFORM_MACCATALYST,
        "ios-simulator" => PLATFORM_IOSSIMULATOR,
        "tvos-simulator" => PLATFORM_TVOSSIMULATOR,
        "watchos-simulator" => PLATFORM_WATCHOSSIMULATOR,
        "driverkit" => PLATFORM_DRIVERKIT,
        "xros" => PLATFORM_XROS,
        "xros-simulator" => PLATFORM_XROS_SIMULATOR,
        _ => return None,
    })
}

/// `arm64e-macos`: the CPU type must match (arm64 links against arm64e stubs) and the platform too.
fn target_matches(s: &str, t: &Target) -> bool {
    let Some((arch, plat)) = s.split_once('-') else {
        return false;
    };
    arch_cpu(arch) == Some(t.arch.cputype())
        && platform_of(plat).is_some_and(|p| same_platform(p, t.platform))
}

fn same_platform(a: u32, b: u32) -> bool {
    a == b
}

fn any_target(list: Option<&Y>, t: &Target) -> bool {
    match list {
        // No `targets` key: everything the document covers.
        None => true,
        Some(y) => y.strs().iter().any(|s| target_matches(s, t)),
    }
}

fn arch_matches(list: Option<&Y>, t: &Target) -> bool {
    match list {
        None => true,
        Some(y) => y
            .strs()
            .iter()
            .any(|s| arch_cpu(s) == Some(t.arch.cputype())),
    }
}

fn version_of(y: Option<&Y>) -> u32 {
    y.and_then(Y::as_str).and_then(parse_version).unwrap_or(0)
}

fn bytes_of<'a>(s: &Cow<'a, str>) -> Cow<'a, [u8]> {
    match s {
        Cow::Borrowed(b) => Cow::Borrowed(b.as_bytes()),
        Cow::Owned(o) => Cow::Owned(o.as_bytes().to_vec()),
    }
}

fn prefixed<'a>(prefix: &str, name: &str) -> Cow<'a, [u8]> {
    let mut v = Vec::with_capacity(prefix.len() + name.len());
    v.extend_from_slice(prefix.as_bytes());
    v.extend_from_slice(name.as_bytes());
    Cow::Owned(v)
}

struct Builder<'a, 't> {
    t: &'t Target,
    iface: Interface<'a>,
}

impl<'a> Builder<'a, '_> {
    fn symbol(&mut self, name: Cow<'a, [u8]>, weak: bool, tlv: bool) {
        if name.starts_with(b"$ld$") {
            self.ld_directive(&name);
            return;
        }
        self.iface.exports.push(Export { name, weak, tlv });
    }

    fn objc_class(&mut self, name: &str) {
        self.iface.exports.push(Export {
            name: prefixed("_OBJC_CLASS_$_", name),
            weak: false,
            tlv: false,
        });
        self.iface.exports.push(Export {
            name: prefixed("_OBJC_METACLASS_$_", name),
            weak: false,
            tlv: false,
        });
    }

    /// `$ld$hide$`, `$ld$add$`, `$ld$install_name$` and `$ld$previous$` adjust a dylib per deployment target.
    fn ld_directive(&mut self, name: &[u8]) {
        let Ok(s) = std::str::from_utf8(name) else {
            return;
        };
        let rest = &s[4..];
        let Some((action, rest)) = rest.split_once('$') else {
            return;
        };
        let at_version = |cond: &str| -> bool {
            cond.strip_prefix("os")
                .and_then(parse_version)
                .is_some_and(|v| v == self.t.min_version)
        };
        match action {
            "hide" => {
                if let Some((cond, sym)) = rest.split_once('$')
                    && at_version(cond)
                {
                    self.iface
                        .exports
                        .retain(|e| e.name.as_ref() != sym.as_bytes());
                    self.iface.exports.push(Export {
                        name: Cow::Owned(format!("$ld$hidden${sym}").into_bytes()),
                        weak: false,
                        tlv: false,
                    });
                }
            }
            "add" => {
                if let Some((cond, sym)) = rest.split_once('$')
                    && at_version(cond)
                {
                    self.iface.exports.push(Export {
                        name: Cow::Owned(sym.as_bytes().to_vec()),
                        weak: false,
                        tlv: false,
                    });
                }
            }
            "install_name" => {
                if let Some((cond, path)) = rest.split_once('$')
                    && at_version(cond)
                {
                    self.iface.install_name = path.to_string();
                }
            }
            "previous" => {
                // <install>$<compat>$<platform>$<start>$<end>$<symbol>$
                let parts: Vec<&str> = rest.splitn(6, '$').collect();
                if parts.len() < 6 {
                    return;
                }
                let platform: u32 = parts[2].parse().unwrap_or(0);
                if platform != self.t.platform {
                    return;
                }
                let start = parse_version(parts[3]).unwrap_or(0);
                let end = parse_version(parts[4]).unwrap_or(u32::MAX);
                if self.t.min_version < start || self.t.min_version >= end {
                    return;
                }
                let compat = parse_version(parts[1]).unwrap_or(0);
                let sym = parts[5].trim_end_matches('$');
                if sym.is_empty() {
                    self.iface.install_name = parts[0].to_string();
                    if compat != 0 {
                        self.iface.compat_version = compat;
                    }
                } else {
                    self.iface.previous.push((
                        parts[0].to_string(),
                        compat,
                        Cow::Owned(sym.as_bytes().to_vec()),
                    ));
                }
            }
            _ => {}
        }
    }

    /// Symbols hidden by `$ld$hide$` leave a marker so a later plain entry doesn't revive them.
    fn finish(mut self) -> Interface<'a> {
        let hidden: Vec<Vec<u8>> = self
            .iface
            .exports
            .iter()
            .filter_map(|e| e.name.strip_prefix(b"$ld$hidden$").map(<[u8]>::to_vec))
            .collect();
        if !hidden.is_empty() {
            self.iface.exports.retain(|e| {
                !e.name.starts_with(b"$ld$hidden$") && !hidden.iter().any(|h| h == e.name.as_ref())
            });
        }
        self.iface
    }
}

fn interpret_v4<'a>(root: &Y<'a>, t: &Target) -> Result<Interface<'a>> {
    let mut b = Builder {
        t,
        iface: Interface::default(),
    };
    b.iface.install_name = root
        .get("install-name")
        .and_then(Y::as_str)
        .ok_or_else(|| err!("text stub without an install-name"))?
        .to_string();
    b.iface.current_version = version_of(root.get("current-version")).max(0x1_0000);
    b.iface.compat_version = version_of(root.get("compatibility-version")).max(0x1_0000);
    if !any_target(root.get("targets"), t) {
        b.iface.exports.clear();
        return Ok(b.finish());
    }
    for block in root.get("reexported-libraries").map_or(&[][..], Y::items) {
        if any_target(block.get("targets"), t) {
            for lib in block.get("libraries").map(Y::strs).unwrap_or_default() {
                b.iface.reexports.push(lib.to_string());
            }
        }
    }
    for key in ["exports", "reexports"] {
        for block in root.get(key).map_or(&[][..], Y::items) {
            if !any_target(block.get("targets"), t) {
                continue;
            }
            for (k, weak, tlv) in [
                ("symbols", false, false),
                ("weak-symbols", true, false),
                ("thread-local-symbols", false, true),
            ] {
                for s in block.get(k).map(Y::strs).unwrap_or_default() {
                    b.symbol(bytes_of(s), weak, tlv);
                }
            }
            for s in block.get("objc-classes").map(Y::strs).unwrap_or_default() {
                b.objc_class(s);
            }
            for s in block.get("objc-eh-types").map(Y::strs).unwrap_or_default() {
                b.symbol(prefixed("_OBJC_EHTYPE_$_", s), false, false);
            }
            for s in block.get("objc-ivars").map(Y::strs).unwrap_or_default() {
                b.symbol(prefixed("_OBJC_IVAR_$_", s), false, false);
            }
        }
    }
    Ok(b.finish())
}

fn interpret_v1_3<'a>(root: &Y<'a>, t: &Target, version: u32) -> Result<Interface<'a>> {
    let mut b = Builder {
        t,
        iface: Interface::default(),
    };
    b.iface.install_name = root
        .get("install-name")
        .and_then(Y::as_str)
        .ok_or_else(|| err!("text stub without an install-name"))?
        .to_string();
    b.iface.current_version = version_of(root.get("current-version")).max(0x1_0000);
    b.iface.compat_version = version_of(root.get("compatibility-version")).max(0x1_0000);
    let platform = root.get("platform").and_then(Y::as_str).unwrap_or("macosx");
    let platform_ok = match platform {
        "zippered" => matches!(t.platform, PLATFORM_MACOS | PLATFORM_MACCATALYST),
        p => platform_of(p).is_some_and(|p| same_platform(p, t.platform)),
    };
    if !platform_ok || !arch_matches(root.get("archs"), t) {
        return Ok(b.finish());
    }
    for block in root.get("exports").map_or(&[][..], Y::items) {
        if !arch_matches(block.get("archs"), t) {
            continue;
        }
        for lib in block.get("re-exports").map(Y::strs).unwrap_or_default() {
            b.iface.reexports.push(lib.to_string());
        }
        for (k, weak, tlv) in [
            ("symbols", false, false),
            ("weak-def-symbols", true, false),
            ("thread-local-symbols", false, true),
        ] {
            for s in block.get(k).map(Y::strs).unwrap_or_default() {
                b.symbol(bytes_of(s), weak, tlv);
            }
        }
        for s in block.get("objc-classes").map(Y::strs).unwrap_or_default() {
            // v1 and v2 spell classes with the leading underscore of the old ABI's symbol.
            let name: &str = if version < 3 {
                s.strip_prefix('_').unwrap_or(s)
            } else {
                s
            };
            b.objc_class(name);
        }
        for s in block.get("objc-eh-types").map(Y::strs).unwrap_or_default() {
            b.symbol(prefixed("_OBJC_EHTYPE_$_", s), false, false);
        }
        for s in block.get("objc-ivars").map(Y::strs).unwrap_or_default() {
            let name: &str = if version < 3 {
                s.strip_prefix('_').unwrap_or(s)
            } else {
                s
            };
            b.symbol(prefixed("_OBJC_IVAR_$_", name), false, false);
        }
    }
    Ok(b.finish())
}

/// A JSON reader for TBD v5, producing the same tree as the YAML one.
struct Json<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Json<'a> {
    fn parse_document(&mut self) -> Result<Y<'a>> {
        let v = self.value()?;
        Ok(v)
    }

    fn ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Y<'a>> {
        self.ws();
        match self.s.get(self.pos) {
            Some(b'{') => {
                self.pos += 1;
                let mut m = Vec::new();
                loop {
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Y::Map(m));
                        }
                        Some(b',') => self.pos += 1,
                        Some(b'"') => {
                            let k = self.string()?;
                            self.ws();
                            if self.s.get(self.pos) != Some(&b':') {
                                bail!("malformed JSON text stub at byte {}", self.pos);
                            }
                            self.pos += 1;
                            let v = self.value()?;
                            m.push((k, v));
                        }
                        _ => bail!("malformed JSON text stub at byte {}", self.pos),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut v = Vec::new();
                loop {
                    self.ws();
                    match self.s.get(self.pos) {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Y::Seq(v));
                        }
                        Some(b',') => self.pos += 1,
                        Some(_) => v.push(self.value()?),
                        None => bail!("truncated JSON text stub"),
                    }
                }
            }
            Some(b'"') => Ok(Y::Str(self.string()?)),
            Some(_) => {
                let start = self.pos;
                while self.pos < self.s.len()
                    && !matches!(self.s[self.pos], b',' | b'}' | b']')
                    && !self.s[self.pos].is_ascii_whitespace()
                {
                    self.pos += 1;
                }
                let raw = std::str::from_utf8(&self.s[start..self.pos]).unwrap_or("");
                Ok(if raw == "null" {
                    Y::Null
                } else {
                    Y::Str(Cow::Borrowed(raw))
                })
            }
            None => bail!("truncated JSON text stub"),
        }
    }

    fn string(&mut self) -> Result<Cow<'a, str>> {
        self.pos += 1;
        let start = self.pos;
        let mut owned: Option<String> = None;
        while self.pos < self.s.len() && self.s[self.pos] != b'"' {
            if self.s[self.pos] == b'\\' {
                let o = owned.get_or_insert_with(|| {
                    String::from_utf8_lossy(&self.s[start..self.pos]).into_owned()
                });
                let c = self.s.get(self.pos + 1).copied().unwrap_or(b'\\');
                o.push(match c {
                    b'n' => '\n',
                    b't' => '\t',
                    b'u' => {
                        let hex = std::str::from_utf8(
                            self.s.get(self.pos + 2..self.pos + 6).unwrap_or(b"003f"),
                        )
                        .unwrap_or("003f");
                        self.pos += 4;
                        char::from_u32(u32::from_str_radix(hex, 16).unwrap_or(0x3f)).unwrap_or('?')
                    }
                    c => c as char,
                });
                self.pos += 2;
                continue;
            }
            if let Some(o) = &mut owned {
                o.push(self.s[self.pos] as char);
            }
            self.pos += 1;
        }
        let end = self.pos;
        self.pos += 1;
        Ok(match owned {
            Some(o) => Cow::Owned(o),
            None => Cow::Borrowed(
                std::str::from_utf8(&self.s[start..end])
                    .map_err(|_| err!("text stub is not UTF-8"))?,
            ),
        })
    }
}

fn interpret_v5<'a>(root: &Y<'a>, t: &Target) -> Result<Vec<Interface<'a>>> {
    let mut out = Vec::new();
    if let Some(main) = root.get("main_library") {
        out.push(interpret_v5_library(main, t)?);
    }
    for lib in root.get("libraries").map_or(&[][..], Y::items) {
        out.push(interpret_v5_library(lib, t)?);
    }
    if out.is_empty() {
        bail!("text stub without a main_library");
    }
    Ok(out)
}

fn first_field<'y, 'a>(y: &'y Y<'a>, list: &str, field: &str) -> Option<&'y str> {
    y.get(list)?.items().first()?.get(field)?.as_str()
}

fn interpret_v5_library<'a>(lib: &Y<'a>, t: &Target) -> Result<Interface<'a>> {
    let mut b = Builder {
        t,
        iface: Interface::default(),
    };
    b.iface.install_name = first_field(lib, "install_names", "name")
        .ok_or_else(|| err!("text stub without an install name"))?
        .to_string();
    b.iface.current_version = first_field(lib, "current_versions", "version")
        .and_then(parse_version)
        .unwrap_or(0x1_0000);
    b.iface.compat_version = first_field(lib, "compatibility_versions", "version")
        .and_then(parse_version)
        .unwrap_or(0x1_0000);
    let targets: Vec<&str> = lib
        .get("target_info")
        .map_or(&[][..], Y::items)
        .iter()
        .filter_map(|ti| ti.get("target").and_then(Y::as_str))
        .collect();
    if !targets.is_empty() && !targets.iter().any(|s| target_matches(s, t)) {
        return Ok(b.finish());
    }
    for block in lib.get("reexported_libraries").map_or(&[][..], Y::items) {
        if any_target(block.get("targets"), t) {
            for n in block.get("names").map(Y::strs).unwrap_or_default() {
                b.iface.reexports.push(n.to_string());
            }
        }
    }
    for key in ["exported_symbols", "reexported_symbols"] {
        for block in lib.get(key).map_or(&[][..], Y::items) {
            if !any_target(block.get("targets"), t) {
                continue;
            }
            for section in ["data", "text"] {
                let Some(sec) = block.get(section) else {
                    continue;
                };
                for (k, weak, tlv) in [
                    ("global", false, false),
                    ("weak", true, false),
                    ("thread_local", false, true),
                ] {
                    for s in sec.get(k).map(Y::strs).unwrap_or_default() {
                        b.symbol(bytes_of(s), weak, tlv);
                    }
                }
                for s in sec.get("objc_class").map(Y::strs).unwrap_or_default() {
                    b.objc_class(s);
                }
                for s in sec.get("objc_eh_type").map(Y::strs).unwrap_or_default() {
                    b.symbol(prefixed("_OBJC_EHTYPE_$_", s), false, false);
                }
                for s in sec.get("objc_ivar").map(Y::strs).unwrap_or_default() {
                    b.symbol(prefixed("_OBJC_IVAR_$_", s), false, false);
                }
            }
        }
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(arch: Arch, min: &str) -> Target {
        Target {
            arch,
            platform: PLATFORM_MACOS,
            min_version: parse_version(min).unwrap(),
        }
    }

    fn names(i: &Interface) -> Vec<String> {
        i.exports
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect()
    }

    const V4: &str = "--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, x86_64-maccatalyst, arm64e-macos, arm64e-maccatalyst,
                   arm64e.x1-macos ]
install-name:    '/usr/lib/libSystem.B.dylib'
current-version: 1359
reexported-libraries:
  - targets:         [ x86_64-macos, arm64e-macos ]
    libraries:       [ '/usr/lib/system/libcache.dylib',
                       '/usr/lib/system/libsystem_c.dylib' ]
exports:
  - targets:         [ x86_64-macos, x86_64-maccatalyst ]
    symbols:         [ 'R8289209$_close', _x86_only ]
  - targets:         [ x86_64-macos, arm64e-macos ]
    symbols:         [ ___crashreporter_info__, _mach_init_routine,
                       '$ld$hide$os11.0$_hidden_at_11', _hidden_at_11 ]
    weak-symbols:    [ _weakling ]
    thread-local-symbols: [ _tlv ]
    objc-classes:    [ NSObject ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64e-macos ]
install-name:    '/usr/lib/system/libcache.dylib'
current-version: 95
parent-umbrella:
  - targets:         [ x86_64-macos, arm64e-macos ]
    umbrella:        System
exports:
  - targets:         [ arm64e-macos ]
    symbols:         [ _cache_create, _cache_destroy ]
...
";

    #[test]
    fn reads_v4_with_inline_documents() {
        let docs = parse(V4.as_bytes(), &target(Arch::Arm64, "11.0")).unwrap();
        assert_eq!(docs.len(), 2);
        let sys = &docs[0];
        assert_eq!(sys.install_name, "/usr/lib/libSystem.B.dylib");
        assert_eq!(sys.current_version, 1359 << 16);
        assert_eq!(
            sys.reexports,
            [
                "/usr/lib/system/libcache.dylib",
                "/usr/lib/system/libsystem_c.dylib"
            ]
        );
        assert_eq!(
            names(sys),
            [
                "___crashreporter_info__",
                "_mach_init_routine",
                "_weakling",
                "_tlv",
                "_OBJC_CLASS_$_NSObject",
                "_OBJC_METACLASS_$_NSObject"
            ]
        );
        assert!(sys.exports[2].weak && sys.exports[3].tlv);
        assert_eq!(names(&docs[1]), ["_cache_create", "_cache_destroy"]);

        let x86 = parse(V4.as_bytes(), &target(Arch::X86_64, "10.13")).unwrap();
        assert!(names(&x86[0]).contains(&"_x86_only".to_string()));
        assert!(names(&x86[0]).contains(&"_hidden_at_11".to_string()));
        assert!(names(&x86[1]).is_empty());
    }

    #[test]
    fn reads_v3_and_previous_symbols() {
        let v3 = "--- !tapi-tbd-v3
archs:           [ x86_64, arm64 ]
platform:        macosx
install-name:    /usr/lib/libfoo.dylib
current-version: 1.2.3
exports:
  - archs:           [ arm64 ]
    re-exports:      [ /usr/lib/libbar.dylib ]
    symbols:         [ _a, '$ld$previous$/usr/lib/libold.dylib$$1$10.0$12.0$_a$' ]
    weak-def-symbols: [ _w ]
...
";
        let d = parse(v3.as_bytes(), &target(Arch::Arm64, "11.0")).unwrap();
        assert_eq!(d[0].current_version, 0x0001_0203);
        assert_eq!(d[0].reexports, ["/usr/lib/libbar.dylib"]);
        assert_eq!(names(&d[0]), ["_a", "_w"]);
        assert_eq!(d[0].previous.len(), 1);
        assert_eq!(d[0].previous[0].0, "/usr/lib/libold.dylib");
        assert_eq!(d[0].previous[0].2.as_ref(), b"_a");
        let d = parse(v3.as_bytes(), &target(Arch::Arm64, "12.0")).unwrap();
        assert!(d[0].previous.is_empty());
    }

    #[test]
    fn reads_v5_json() {
        let v5 = r#"{
  "tapi_tbd_version": 5,
  "main_library": {
    "target_info": [ { "target": "arm64-macos", "min_deployment": "11" } ],
    "install_names": [ { "name": "/S/L/F/Foo.framework/Foo" } ],
    "current_versions": [ { "version": "2.5" } ],
    "reexported_libraries": [ { "names": [ "/usr/lib/libz.1.dylib" ] } ],
    "exported_symbols": [
      { "targets": [ "arm64-macos" ],
        "data": { "global": [ "_d" ], "objc_class": [ "C" ], "thread_local": [ "_t" ] },
        "text": { "global": [ "_f" ], "weak": [ "_w" ] } },
      { "targets": [ "x86_64-macos" ], "text": { "global": [ "_x" ] } }
    ]
  }
}"#;
        let d = parse(v5.as_bytes(), &target(Arch::Arm64, "11.0")).unwrap();
        assert_eq!(d[0].install_name, "/S/L/F/Foo.framework/Foo");
        assert_eq!(d[0].current_version, 0x0002_0500);
        assert_eq!(d[0].reexports, ["/usr/lib/libz.1.dylib"]);
        assert_eq!(
            names(&d[0]),
            [
                "_d",
                "_t",
                "_OBJC_CLASS_$_C",
                "_OBJC_METACLASS_$_C",
                "_f",
                "_w"
            ]
        );
        assert!(is_tbd(v5.as_bytes()) && is_tbd(V4.as_bytes()) && !is_tbd(b"\xcf\xfa\xed\xfe"));
    }

    #[test]
    fn reads_the_sdk() {
        let Ok(out) = std::process::Command::new("xcrun")
            .arg("--show-sdk-path")
            .output()
        else {
            return;
        };
        let sdk = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let path = std::path::Path::new(&sdk).join("usr/lib/libSystem.tbd");
        let Ok(data) = std::fs::read(&path) else {
            return;
        };
        let docs = parse(&data, &target(Arch::Arm64, "11.0")).unwrap();
        assert!(docs.len() > 10);
        assert!(
            docs.iter()
                .any(|d| d.exports.iter().any(|e| e.name.as_ref() == b"_malloc"))
        );
        assert!(
            docs.iter()
                .any(|d| d.exports.iter().any(|e| e.name.as_ref() == b"_printf"))
        );
    }
}
