//! End-to-end: `rustc -C linker=hyprlnk`, then run what it linked.
//!
//! Windows only (hyprlnk links PE/COFF), and only where rustc can link for
//! `x86_64-pc-windows-msvc` at all (the MSVC libraries are installed).
#![cfg(all(windows, target_arch = "x86_64", target_env = "msvc"))]

use std::path::{Path, PathBuf};
use std::process::Command;

const HYPRLNK: &str = env!("CARGO_BIN_EXE_hyprlnk");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hyprlnk-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Compile `src` with rustc, linking with hyprlnk; panics with the compiler's
/// output on failure.
fn rustc(dir: &Path, file: &str, src: &str, extra: &[&str]) {
    std::fs::write(dir.join(file), src).unwrap();
    let out = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .current_dir(dir)
        .arg(file)
        .arg(format!("-Clinker={HYPRLNK}"))
        .args(extra)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rustc failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn run(exe: &Path) -> String {
    let out = Command::new(exe).output().unwrap();
    assert!(
        out.status.success(),
        "{} failed: {:?}\n{}",
        exe.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

const STRESS: &str = r#"
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);
struct Guard(usize);
impl Drop for Guard {
    fn drop(&mut self) { DROPS.fetch_add(self.0, Ordering::SeqCst); }
}
thread_local! {
    static TLS: RefCell<Vec<u64>> = RefCell::new(Vec::new());
    static G: Guard = Guard(10);
}
#[inline(never)]
fn deep(n: u32) -> u32 {
    let _g = Guard(1);
    if n == 0 { panic!("bottom"); }
    deep(n - 1) + 1
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    assert!(std::panic::catch_unwind(|| deep(30)).is_err());
    assert_eq!(DROPS.load(Ordering::SeqCst), 31);
    let sums: Vec<u64> = (0..6)
        .map(|i| std::thread::spawn(move || {
            G.with(|g| assert_eq!(g.0, 10));
            TLS.with(|t| t.borrow_mut().extend(0..i));
            TLS.with(|t| t.borrow().iter().sum())
        }))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(sums, [0, 0, 1, 3, 6, 10]);
    assert_eq!(DROPS.load(Ordering::SeqCst), 31 + 60);
    let x: f64 = (1..100).map(|i| (i as f64).sqrt()).sum();
    println!("ok {x:.3}");
}
"#;

#[test]
fn unwinding_threads_and_thread_locals() {
    let dir = scratch("stress");
    for (opt, exe) in [("0", "o0"), ("3", "o3")] {
        let opt = format!("-Copt-level={opt}");
        rustc(
            &dir,
            "stress.rs",
            STRESS,
            &[&opt, "-o", &format!("{exe}.exe")],
        );
        assert_eq!(run(&dir.join(format!("{exe}.exe"))), "ok 661.463\n");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_dll_and_a_program_that_imports_from_it() {
    let dir = scratch("dll");
    rustc(
        &dir,
        "mylib.rs",
        r#"
        #[unsafe(no_mangle)]
        pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 { a + b }
        #[unsafe(no_mangle)]
        pub static MAGIC: i32 = 1234;
        "#,
        &["--crate-type", "cdylib"],
    );
    assert!(dir.join("mylib.dll").is_file());
    assert!(dir.join("mylib.dll.lib").is_file());
    rustc(
        &dir,
        "user.rs",
        r#"
        #[link(name = "mylib.dll", kind = "dylib")]
        unsafe extern "C" {
            fn add_numbers(a: i32, b: i32) -> i32;
            static MAGIC: i32;
        }
        fn main() { unsafe { println!("{} {}", add_numbers(40, 2), MAGIC); } }
        "#,
        &["-L", "."],
    );
    assert_eq!(run(&dir.join("user.exe")), "42 1234\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn undefined_symbols_are_reported_with_their_referrer() {
    let dir = scratch("undefined");
    std::fs::write(
        dir.join("bad.rs"),
        r#"
        unsafe extern "C" { fn hyprlnk_test_missing(); }
        fn main() { unsafe { hyprlnk_test_missing() } }
        "#,
    )
    .unwrap();
    let out = Command::new("rustc")
        .current_dir(&dir)
        .args(["bad.rs", &format!("-Clinker={HYPRLNK}")])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("undefined symbol: hyprlnk_test_missing"),
        "{stderr}"
    );
    assert!(stderr.contains(">>> referenced by bad."), "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reproduce_saves_a_link_that_replays() {
    let dir = scratch("reproduce");
    let saved = dir.join("saved");
    std::fs::write(
        dir.join("hello.rs"),
        r#"fn main() { println!("replayed"); }"#,
    )
    .unwrap();
    let out = Command::new("rustc")
        .current_dir(&dir)
        .args([
            "hello.rs",
            &format!("-Clinker={HYPRLNK}"),
            &format!("-Clink-arg=/REPRODUCE:{}", saved.display()),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = std::fs::read_dir(&saved)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let replayed = dir.join("replayed.exe");
    let status = Command::new(HYPRLNK)
        .arg(format!("@{}", link.join("link.rsp").display()))
        .arg(format!("/OUT:{}", replayed.display()))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(run(&replayed), "replayed\n");
    // The same inputs give the same image, byte for byte.
    assert_eq!(
        std::fs::read(&replayed).unwrap(),
        std::fs::read(dir.join("hello.exe")).unwrap()
    );
    std::fs::remove_dir_all(&dir).ok();
}
