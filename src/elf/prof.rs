//! Developer profiling: with `HYPRLNK_PROF` set, wall times of sub-steps, CPU time summed over
//! threads for hot loops, and page faults. Off, it costs a relaxed load per call.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("HYPRLNK_PROF").is_some())
}

/// Run `f`, reporting its wall time.
pub fn time<R>(name: &str, f: impl FnOnce() -> R) -> R {
    if !enabled() {
        return f();
    }
    let t = Instant::now();
    let r = f();
    eprintln!("prof: {name}: {:.2} ms", t.elapsed().as_secs_f64() * 1e3);
    r
}

/// CPU time summed over threads, per counter.
pub struct Counters(pub [AtomicU64; 8]);

pub static SUM: Counters = Counters([const { AtomicU64::new(0) }; 8]);

pub fn start() -> Option<Instant> {
    enabled().then(Instant::now)
}

pub fn add(i: usize, t: Option<Instant>) {
    if let Some(t) = t {
        SUM.0[i].fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
}

pub fn report_sums(names: &[&str]) {
    if !enabled() {
        return;
    }
    for (i, n) in names.iter().enumerate() {
        let v = SUM.0[i].swap(0, Ordering::Relaxed);
        if v > 0 {
            eprintln!("prof: {n}: {:.1} ms cpu", v as f64 / 1e6);
        }
    }
}

#[cfg(unix)]
pub fn usage() -> (i64, i64, i64) {
    // SAFETY: getrusage fills the struct.
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    // `tv_usec` is 32 bits on macOS.
    let ms = |t: libc::timeval| (t.tv_sec as f64 * 1e3 + t.tv_usec as f64 / 1e3) as i64;
    (r.ru_minflt as i64, ms(r.ru_utime), ms(r.ru_stime))
}

#[cfg(not(unix))]
pub fn usage() -> (i64, i64, i64) {
    (0, 0, 0)
}

pub fn report_usage(name: &str, since: (i64, i64, i64)) {
    if enabled() {
        let now = usage();
        eprintln!(
            "prof: {name}: {} faults, user {} ms, sys {} ms",
            now.0 - since.0,
            now.1 - since.1,
            now.2 - since.2
        );
    }
}

/// Wall time between successive marks, and how many cores were busy.
pub struct Marks(Option<(Instant, (i64, i64, i64))>);

impl Marks {
    pub fn new() -> Marks {
        Marks(start().map(|t| (t, usage())))
    }

    pub fn mark(&mut self, name: &str) {
        if let Some((t, u)) = &mut self.0 {
            let (wall, now) = (t.elapsed().as_secs_f64() * 1e3, usage());
            let cpu = (now.1 - u.1 + now.2 - u.2) as f64;
            eprintln!(
                "prof:   {name}: {wall:.2} ms ({:.1} cores)",
                cpu / wall.max(0.01)
            );
            *t = Instant::now();
            *u = now;
        }
    }
}
