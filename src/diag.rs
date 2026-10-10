//! Errors, warnings and the `/TIME` report.

use std::fmt;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::diag::Error(format!($($t)*)))
    };
}

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

pub fn symbol(name: &[u8]) -> String {
    let raw = String::from_utf8_lossy(name);
    match rustc_demangle::try_demangle(&raw) {
        Ok(d) => format!("{d:#} ({raw})"),
        Err(_) => raw.into_owned(),
    }
}

pub struct Timer {
    enabled: bool,
    start: Instant,
    last: Instant,
    phases: Vec<(&'static str, Duration)>,
    details: Vec<String>,
    /// With `HYPRLNK_PROF`: CPU time (all threads) and page faults per phase.
    cpu: Option<(Usage, Vec<Usage>)>,
}

/// User and system milliseconds, and minor page faults.
#[derive(Clone, Copy, Default)]
struct Usage(f64, f64, i64);

fn usage() -> Usage {
    #[cfg(unix)]
    {
        // SAFETY: getrusage fills the struct.
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
        let ms = |t: libc::timeval| t.tv_sec as f64 * 1e3 + t.tv_usec as f64 / 1e3;
        Usage(ms(r.ru_utime), ms(r.ru_stime), r.ru_minflt as i64)
    }
    #[cfg(not(unix))]
    {
        Usage::default()
    }
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
            cpu: (enabled && std::env::var_os("HYPRLNK_PROF").is_some())
                .then(|| (usage(), Vec::new())),
        }
    }

    pub fn phase(&mut self, name: &'static str) {
        if self.enabled {
            let now = Instant::now();
            self.phases.push((name, now - self.last));
            self.last = now;
            if let Some((last, v)) = &mut self.cpu {
                let c = usage();
                v.push(Usage(c.0 - last.0, c.1 - last.1, c.2 - last.2));
                *last = c;
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

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
        for (i, (name, d)) in self.phases.iter().enumerate() {
            match &self.cpu {
                Some((_, v)) => eprintln!(
                    "hyprlnk: {:>9.2} ms  {name:<32} user {:>7.1} sys {:>6.1} ms ({:4.1} cores) {:>7} faults",
                    d.as_secs_f64() * 1e3,
                    v[i].0,
                    v[i].1,
                    (v[i].0 + v[i].1) / (d.as_secs_f64() * 1e3),
                    v[i].2
                ),
                None => eprintln!("hyprlnk: {:>9.2} ms  {name}", d.as_secs_f64() * 1e3),
            }
        }
        eprintln!(
            "hyprlnk: {:>9.2} ms  total",
            self.start.elapsed().as_secs_f64() * 1e3
        );
    }
}
