//! Response files and Windows-style command-line quoting.

use crate::diag::Result;
use crate::{bail, err};

pub fn expand_response_files(args: Vec<String>) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(args.len());
    expand_into(args, &mut out, 0)?;
    Ok(out)
}

fn expand_into(args: Vec<String>, out: &mut Vec<String>, depth: usize) -> Result<()> {
    for arg in args {
        match arg.strip_prefix('@') {
            Some(path) if !path.is_empty() => {
                if depth > 16 {
                    bail!("response files nest too deeply at '{path}'");
                }
                let bytes = std::fs::read(path)
                    .map_err(|e| err!("cannot read response file '{path}': {e}"))?;
                let mut inner = Vec::new();
                tokenize_windows(&decode_text(&bytes), &mut inner);
                expand_into(inner, out, depth + 1)?;
            }
            _ => out.push(arg),
        }
    }
    Ok(())
}

pub fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// Split `s` like the MSVC runtime does (backslash/quote rules included).
pub fn tokenize_windows(s: &str, out: &mut Vec<String>) {
    let mut chars = s.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            return;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            match c {
                '\\' => {
                    let mut n = 0;
                    while chars.next_if_eq(&'\\').is_some() {
                        n += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        arg.extend(std::iter::repeat_n('\\', n / 2));
                        if n % 2 == 1 {
                            arg.push('"');
                            chars.next();
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', n));
                    }
                }
                '"' => {
                    chars.next();
                    if quoted && chars.peek() == Some(&'"') {
                        arg.push('"');
                        chars.next();
                    } else {
                        quoted = !quoted;
                    }
                }
                c if c.is_whitespace() && !quoted => break,
                c => {
                    arg.push(c);
                    chars.next();
                }
            }
        }
        out.push(arg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(s: &str) -> Vec<String> {
        let mut v = Vec::new();
        tokenize_windows(s, &mut v);
        v
    }

    #[test]
    fn splits_like_the_crt() {
        assert_eq!(split(r#"a b  "c d" e"f g"h"#), ["a", "b", "c d", "ef gh"]);
        assert_eq!(
            split(r#"/LIBPATH:"C:\Program Files\x""#),
            [r"/LIBPATH:C:\Program Files\x"]
        );
        assert_eq!(
            split(r#"a\\\"b c\\"d e" f\g"#),
            [r#"a\"b"#, r"c\d e", r"f\g"]
        );
        assert_eq!(split(r##""a""b" """"##), [r#"a"b"#, "\""]);
        assert_eq!(split("  \r\n\t "), Vec::<String>::new());
        assert_eq!(split(r#""""#), [""]);
    }

    #[test]
    fn decodes_utf16_and_utf8_response_files() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("/OUT:ä.exe".encode_utf16().flat_map(|u| u.to_le_bytes()))
            .collect();
        assert_eq!(decode_text(&utf16), "/OUT:ä.exe");
        assert_eq!(decode_text(b"\xEF\xBB\xBFa b"), "a b");
        assert_eq!(decode_text(b"a b"), "a b");
    }

    #[test]
    fn expands_nested_response_files() {
        let dir = std::env::temp_dir().join(format!("hyprlnk-rsp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let inner = dir.join("inner.rsp");
        let outer = dir.join("outer.rsp");
        std::fs::write(&inner, "c \"d e\"").unwrap();
        std::fs::write(&outer, format!("b \"@{}\"\r\nf", inner.display())).unwrap();
        let args = vec!["a".to_string(), format!("@{}", outer.display())];
        assert_eq!(
            expand_response_files(args).unwrap(),
            ["a", "b", "c", "d e", "f"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
