//! Errors, warnings and the `/TIME` report.

use std::fmt;
use std::time::{Duration, Instant};

/// A fatal error: the link stops and nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Return early with a formatted [`Error`].
#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::diag::Error(format!($($t)*)))
    };
}

/// Build a formatted [`Error`].
#[macro_export]
macro_rules! err {
    ($($t:tt)*) => {
        $crate::diag::Error(format!($($t)*))
    };
}

pub fn warn(msg: impl fmt::Display) {
    eprintln!("hyprlnk: warning: {msg}");
}

pub fn error(msg: impl fmt::Display) {
    eprintln!("hyprlnk: error: {msg}");
}

pub fn note(msg: impl fmt::Display) {
    eprintln!("hyprlnk: {msg}");
}

/// A symbol name as a person reads it: Rust symbols demangled, with the
/// mangled name alongside so it can still be searched for.
pub fn symbol(name: &[u8]) -> String {
    let raw = String::from_utf8_lossy(name);
    match rustc_demangle::try_demangle(&raw) {
        Ok(d) => format!("{d:#} ({raw})"),
        Err(_) => raw.into_owned(),
    }
}

/// Wall-clock time per phase, printed by `/TIME`.
pub struct Timer {
    enabled: bool,
    start: Instant,
    last: Instant,
    phases: Vec<(&'static str, Duration)>,
    details: Vec<String>,
}

impl Timer {
    pub fn new(enabled: bool) -> Timer {
        let now = Instant::now();
        Timer {
            enabled,
            start: now,
            last: now,
            phases: Vec::new(),
            details: Vec::new(),
        }
    }

    /// Close the phase that just ended.
    pub fn phase(&mut self, name: &'static str) {
        if self.enabled {
            let now = Instant::now();
            self.phases.push((name, now - self.last));
            self.last = now;
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// A line printed under the phase that ends next.
    pub fn detail(&mut self, text: String) {
        if self.enabled {
            self.details.push(text);
        }
    }

    pub fn report(&self) {
        if !self.enabled {
            return;
        }
        for d in &self.details {
            eprintln!("hyprlnk:              {d}");
        }
        for (name, d) in &self.phases {
            eprintln!("hyprlnk: {:>9.2} ms  {name}", d.as_secs_f64() * 1e3);
        }
        eprintln!(
            "hyprlnk: {:>9.2} ms  total",
            self.start.elapsed().as_secs_f64() * 1e3
        );
    }
}
