//! End-to-end: `rustc -C linker=hyprlnk`, then run the result. Windows/MSVC only.
#![cfg(all(windows, target_env = "msvc"))]

use std::path::{Path, PathBuf};
use std::process::Command;

const HYPRLNK: &str = env!("CARGO_BIN_EXE_hyprlnk");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hyprlnk-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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
    let replay = |name: &str| -> (Vec<u8>, Vec<u8>) {
        let out = dir.join(name).join("replayed.exe");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        let status = Command::new(HYPRLNK)
            .arg(format!("@{}", link.join("link.rsp").display()))
            .arg(format!("/OUT:{}", out.display()))
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(run(&out), "replayed\n");
        let pdb = std::fs::read(out.with_extension("pdb")).unwrap();
        (std::fs::read(&out).unwrap(), pdb)
    };
    let (a, a_pdb) = replay("a");
    let (b, b_pdb) = replay("b");
    assert!(a == b, "the image changed between identical links");
    assert!(a_pdb == b_pdb, "the PDB changed between identical links");
    std::fs::remove_dir_all(&dir).ok();
}

fn has_target(target: &str) -> bool {
    Command::new("rustc")
        .args(["--print", "target-libdir", "--target", target])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        .is_some_and(|dir| {
            dir.join("..").join("lib").is_dir()
                && std::fs::read_dir(&dir)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
        })
}

#[test]
fn pdbs_give_debuggers_names_and_lines() {
    let dir = scratch("pdb");
    rustc(
        &dir,
        "bt.rs",
        "#[inline(never)]\nfn inner(v: &[u32]) -> u32 { v[10] }\n#[inline(never)]\nfn outer() -> u32 { let v = vec![1, 2, 3]; inner(&v) + 1 }\nfn main() { println!(\"{}\", outer()); }\n",
        &["-g"],
    );
    assert!(dir.join("bt.pdb").is_file());
    let out = Command::new(dir.join("bt.exe"))
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bt::inner"), "{stderr}");
    assert!(stderr.contains("bt.rs:2"), "{stderr}");
    assert!(stderr.contains("bt::outer"), "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

fn res_file(data: &[u8]) -> Vec<u8> {
    let mut out = vec![
        0, 0, 0, 0, 0x20, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0,
    ];
    out.extend_from_slice(&[0; 16]);
    let mut header = Vec::new();
    header.extend_from_slice(&[0xFF, 0xFF, 10, 0]); // type: RT_RCDATA
    for c in "GREETING".encode_utf16() {
        header.extend_from_slice(&c.to_le_bytes());
    }
    header.extend_from_slice(&[0, 0]);
    while (8 + header.len()) % 4 != 0 {
        header.push(0);
    }
    header.extend_from_slice(&0u32.to_le_bytes()); // data version
    header.extend_from_slice(&0x0030u16.to_le_bytes()); // memory flags
    header.extend_from_slice(&0x0409u16.to_le_bytes()); // language
    header.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&((8 + header.len()) as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    out
}

#[test]
fn resources_are_found_at_run_time() {
    let dir = scratch("rsrc");
    std::fs::write(dir.join("app.res"), res_file(b"hello from a resource")).unwrap();
    rustc(
        &dir,
        "res.rs",
        r#"
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn FindResourceW(m: *mut u8, name: *const u16, ty: *const u16) -> *mut u8;
            fn LoadResource(m: *mut u8, r: *mut u8) -> *mut u8;
            fn LockResource(h: *mut u8) -> *const u8;
            fn SizeofResource(m: *mut u8, r: *mut u8) -> u32;
        }
        fn main() {
            let name: Vec<u16> = "GREETING\0".encode_utf16().collect();
            unsafe {
                let r = FindResourceW(std::ptr::null_mut(), name.as_ptr(), 10 as *const u16);
                assert!(!r.is_null(), "resource not found");
                let n = SizeofResource(std::ptr::null_mut(), r) as usize;
                let p = LockResource(LoadResource(std::ptr::null_mut(), r));
                let s = std::slice::from_raw_parts(p, n);
                println!("{}", String::from_utf8_lossy(s));
            }
        }
        "#,
        &["-Clink-arg=app.res"],
    );
    assert_eq!(run(&dir.join("res.exe")), "hello from a resource\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn x86_programs_run() {
    if !has_target("i686-pc-windows-msvc") {
        eprintln!("skipped: no i686-pc-windows-msvc standard library");
        return;
    }
    let dir = scratch("x86");
    rustc(
        &dir,
        "stress.rs",
        STRESS,
        &["--target", "i686-pc-windows-msvc", "-Copt-level=1"],
    );
    assert_eq!(run(&dir.join("stress.exe")), "ok 661.463\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arm64_images_match_lld() {
    let lld = Command::new("lld-link").arg("--version").output();
    if !has_target("aarch64-pc-windows-msvc") || lld.is_err() {
        eprintln!("skipped: needs the aarch64-pc-windows-msvc target and lld-link");
        return;
    }
    let dir = scratch("arm64");
    let src = r#"
        #![no_std]
        #![no_main]
        #[link(name = "kernel32")]
        unsafe extern "system" { fn ExitProcess(code: u32) -> !; }
        static TABLE: [fn(u32) -> u32; 3] = [|x| x + 1, |x| x * 3, |x| x ^ 5];
        #[inline(never)]
        fn fib(n: u32) -> u32 { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } }
        #[unsafe(no_mangle)]
        pub extern "C" fn mainCRTStartup() -> ! {
            let mut acc = fib(15);
            for f in TABLE.iter() { acc = f(acc); }
            unsafe { ExitProcess(acc) }
        }
        #[panic_handler]
        fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { ExitProcess(1) } }
        #[unsafe(no_mangle)]
        pub extern "C" fn __CxxFrameHandler3() -> i32 { 1 }
    "#;
    let saved = dir.join("saved");
    rustc(
        &dir,
        "app.rs",
        src,
        &[
            "--target",
            "aarch64-pc-windows-msvc",
            "-Cpanic=abort",
            "-Copt-level=2",
            "-Clink-arg=-NODEFAULTLIB",
            "-Clink-arg=-ENTRY:mainCRTStartup",
            "-Clink-arg=-SUBSYSTEM:CONSOLE",
            "-Clink-arg=-DEBUG:NONE",
            &format!("-Clink-arg=-REPRODUCE:{}", saved.display()),
        ],
    );
    let link = std::fs::read_dir(&saved)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let theirs = dir.join("lld.exe");
    let status = Command::new("lld-link")
        .arg(format!("@{}", link.join("link.rsp").display()))
        .arg(format!("-out:{}", theirs.display()))
        .status()
        .unwrap();
    assert!(status.success());
    let sections = |p: &Path| -> Vec<(String, Vec<u8>)> {
        let d = std::fs::read(p).unwrap();
        let u16at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]) as usize;
        let u32at = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) as usize;
        let pe = u32at(0x3C);
        let table = pe + 24 + u16at(pe + 20);
        (0..u16at(pe + 6))
            .map(|i| {
                let h = table + 40 * i;
                let name = String::from_utf8_lossy(&d[h..h + 8])
                    .trim_end_matches('\0')
                    .to_string();
                let (vsize, raw, ptr) = (u32at(h + 8), u32at(h + 16), u32at(h + 20));
                (name, d[ptr..ptr + vsize.min(raw)].to_vec())
            })
            .collect()
    };
    let ours = sections(&dir.join("app.exe"));
    let lld = sections(&theirs);
    assert_eq!(ours.len(), lld.len());
    for ((n1, a), (n2, b)) in ours.iter().zip(&lld) {
        assert_eq!(n1, n2);
        assert!(a == b, "section {n1} differs from lld's");
    }
    std::fs::remove_dir_all(&dir).ok();
}
