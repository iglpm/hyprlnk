//! End-to-end on Linux: rustc, cc and c++ link with hyprlnk, then the result runs. hyprlnk
//! is found as `ld` through `-B` (as Rune does it), or run directly with `ld` command lines.
//! Parts skip when a target, compiler or emulator is missing.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const HYPRLNK: &str = env!("CARGO_BIN_EXE_hyprlnk");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hyprlnk-elf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A directory with hyprlnk as `ld` (and the names `-fuse-ld=` looks for): `cc -B<dir>`.
fn ld_dir(dir: &Path) -> PathBuf {
    let bin = dir.join("ldbin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["ld", "ld.lld", "ld.bfd", "ld.gold", "ld.mold"] {
        let _ = std::os::unix::fs::symlink(HYPRLNK, bin.join(name));
    }
    bin
}

fn ok(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed: {:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(!out.status.success(), "{cmd:?} should have failed");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn host() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        let out = Command::new("rustc").arg("-vV").output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("host: "))
            .unwrap_or("")
            .to_string()
    })
}

/// rustc linking through `cc -B<hyprlnk as ld>`.
fn rustc_cmd(dir: &Path) -> Command {
    let mut c = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()));
    c.current_dir(dir)
        .arg(format!("-Clink-arg=-B{}", ld_dir(dir).display()));
    if host() == "x86_64-unknown-linux-gnu" {
        // Its default links with the bundled lld instead of `cc`'s linker.
        c.arg("-Clinker-features=-lld");
    }
    c
}

fn rustc(dir: &Path, file: &str, src: &str, extra: &[&str]) {
    std::fs::write(dir.join(file), src).unwrap();
    ok(rustc_cmd(dir).arg(file).args(extra));
}

fn run(dir: &Path, exe: &str, env: &[(&str, &str)]) -> String {
    ok(Command::new(dir.join(exe))
        .current_dir(dir)
        .envs(env.iter().copied()))
}

fn has_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn has_target(target: &str) -> bool {
    static SYSROOT: OnceLock<String> = OnceLock::new();
    let sysroot = SYSROOT.get_or_init(|| {
        let out = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    });
    Path::new(sysroot)
        .join("lib/rustlib")
        .join(target)
        .join("lib")
        .is_dir()
}

fn readelf(args: &[&str], file: &Path) -> String {
    ok(Command::new("readelf").args(args).arg(file))
}

/// The output names its linker in `.comment`: hyprlnk linked it, not a system linker.
fn linked_by_hyprlnk(file: &Path) {
    let comment = readelf(&["-p", ".comment"], file);
    assert!(
        comment.contains(concat!("Linker: hyprlnk ", env!("CARGO_PKG_VERSION"))),
        "{} wasn't linked by hyprlnk:\n{comment}",
        file.display()
    );
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
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    assert!(bt.contains("stress.rs"), "no file names in the backtrace:\n{bt}");
    let x: f64 = (1..100).map(|i| (i as f64).sqrt()).sum();
    println!("ok {x:.3}");
}
"#;

#[test]
fn unwinding_threads_thread_locals_and_backtraces() {
    let dir = scratch("stress");
    for opt in ["0", "3"] {
        let exe = format!("o{opt}");
        rustc(
            &dir,
            "stress.rs",
            STRESS,
            &["-g", &format!("-Copt-level={opt}"), "-o", &exe],
        );
        assert_eq!(run(&dir, &exe, &[]), "ok 661.463\n");
        // Linked by hyprlnk, as a PIE with RELRO and a build ID.
        let headers = readelf(&["-lWn"], &dir.join(&exe));
        assert!(
            headers.contains("GNU_RELRO") && headers.contains("Build ID"),
            "{headers}"
        );
        assert!(headers.contains("GNU_EH_FRAME"), "{headers}");
        linked_by_hyprlnk(&dir.join(&exe));
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cc_style_command_lines_work_without_a_flavor() {
    // rustc's default command line for a linker named `hyprlnk`: `cc`'s.
    let dir = scratch("cc");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    ok(Command::new("rustc")
        .current_dir(&dir)
        .args(["stress.rs", "-g", "-o", "cc"])
        .arg(format!("-Clinker={HYPRLNK}")));
    assert_eq!(run(&dir, "cc", &[]), "ok 661.463\n");
    linked_by_hyprlnk(&dir.join("cc"));
    std::fs::remove_dir_all(&dir).ok();
}

/// `.tbss` is aligned within the TLS block but takes no room in its segment: what follows it
/// there (`.init_array`, `.dynamic`, `.got`) must keep the distance from the segment start its
/// file offset says. A 4-byte `.tdata` before an 8-aligned `.tbss` once moved them 4 bytes
/// in memory but not in the file, and the dynamic loader crashed reading `.dynamic` (ARM
/// binaries, where 4-byte thread-locals are common, hit it first).
#[test]
fn sections_after_an_aligned_tbss_stay_where_the_file_puts_them() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("tbss");
    std::fs::write(
        dir.join("tls.c"),
        r#"
#include <stdio.h>
__thread int small __attribute__((aligned(8))) = 1;
__thread long long wide __attribute__((aligned(8)));
static int ran;
__attribute__((constructor)) static void init(void) { ran = 1; }
int main(void) {
    wide = 41;
    printf("%lld %d\n", wide + small, ran);
    return 0;
}
"#,
    )
    .unwrap();
    ok(Command::new("cc")
        .current_dir(&dir)
        .arg(format!("-B{}", ld_dir(&dir).display()))
        .args(["-fPIE", "-pie", "tls.c", "-o", "tls"]));
    linked_by_hyprlnk(&dir.join("tls"));
    assert_eq!(run(&dir, "tls", &[]), "42 1\n");
    std::fs::remove_dir_all(&dir).ok();
}

/// A symbol defined in an input `.eh_frame` is where that object's records went. GCC's
/// crtbegin defines `__EH_FRAME_BEGIN__` so, in an empty `.eh_frame`, and where glibc isn't the
/// C library (musl) passes it to libgcc's `__register_frame_info`, which walks the records from
/// there to the zero terminator. It once resolved to 0, the ELF header, and every dynamically
/// linked musl program that loaded libgcc_s crashed before `main`.
#[test]
fn symbols_in_eh_frame_point_at_the_records() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("ehsym");
    // crtbegin's marker, static in an object linked first: its code reaches it through a local
    // symbol (or the section symbol, as x86-64's assembler writes it).
    std::fs::write(
        dir.join("begin.c"),
        "static const char eh_begin[] __attribute__((section(\".eh_frame\"), aligned(4), used)) = {};\n\
         const char *eh_frame_begin(void) { return eh_begin; }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("main.c"),
        r#"
#include <stdio.h>
#include <string.h>
const char *eh_frame_begin(void);
int main(void) {
    /* What __register_frame_info does with it: records up to a zero length. */
    const char *p = eh_frame_begin();
    unsigned len;
    int n = 0;
    for (memcpy(&len, p, 4); len != 0; memcpy(&len, p, 4)) {
        if (len == 0xffffffff || ++n > 1000000) return 2;
        p += 4 + len;
    }
    printf("%s\n", n > 0 ? "records" : "none");
    return 0;
}
"#,
    )
    .unwrap();
    ok(Command::new("cc").current_dir(&dir).args([
        "-c",
        "-fno-asynchronous-unwind-tables",
        "begin.c",
    ]));
    ok(Command::new("cc")
        .current_dir(&dir)
        .arg(format!("-B{}", ld_dir(&dir).display()))
        .args(["-fPIE", "-pie", "begin.o", "main.c", "-o", "eh"]));
    linked_by_hyprlnk(&dir.join("eh"));
    assert_eq!(run(&dir, "eh", &[]), "records\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_cdylib_and_a_program_that_imports_from_it() {
    let dir = scratch("cdylib");
    rustc(
        &dir,
        "mylib.rs",
        r#"
        #[unsafe(no_mangle)]
        pub extern "C" fn add_numbers(a: i32, b: i32) -> i32 { a + b }
        #[unsafe(no_mangle)]
        pub static MAGIC: i32 = 1234;
        thread_local!(static T: std::cell::Cell<i32> = std::cell::Cell::new(5));
        #[unsafe(no_mangle)]
        pub extern "C" fn tls_bump() -> i32 { T.with(|t| { t.set(t.get() + 1); t.get() }) }
        "#,
        &["--crate-type", "cdylib"],
    );
    linked_by_hyprlnk(&dir.join("libmylib.so"));
    let dynsym = readelf(&["--dyn-syms", "-W"], &dir.join("libmylib.so"));
    assert!(
        dynsym.contains("add_numbers") && dynsym.contains("MAGIC"),
        "{dynsym}"
    );
    rustc(
        &dir,
        "user.rs",
        r#"
        #[link(name = "mylib", kind = "dylib")]
        unsafe extern "C" { fn add_numbers(a: i32, b: i32) -> i32; static MAGIC: i32; fn tls_bump() -> i32; }
        fn main() { unsafe { println!("{} {} {} {}", add_numbers(40, 2), MAGIC, tls_bump(), tls_bump()); } }
        "#,
        &["-L", "."],
    );
    let here = dir.display().to_string();
    assert_eq!(
        run(&dir, "user", &[("LD_LIBRARY_PATH", &here)]),
        "42 1234 6 7\n"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn proc_macros_load_into_rustc() {
    let dir = scratch("pm");
    rustc(
        &dir,
        "pm.rs",
        r#"
        extern crate proc_macro;
        #[proc_macro]
        pub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream { "42".parse().unwrap() }
        "#,
        &["--crate-type", "proc-macro"],
    );
    rustc(
        &dir,
        "usepm.rs",
        r#"fn main() { println!("pm {}", pm::answer!()); }"#,
        &["--extern", "pm=libpm.so"],
    );
    assert_eq!(run(&dir, "usepm", &[]), "pm 42\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rust_dylibs_and_prefer_dynamic() {
    let dir = scratch("dylib");
    rustc(
        &dir,
        "rdy.rs",
        r#"pub fn greet(n: &str) -> String { format!("hi {n}") }"#,
        &["--crate-type", "dylib", "-Cprefer-dynamic"],
    );
    rustc(
        &dir,
        "userdy.rs",
        r#"fn main() { println!("{}", rdy::greet("dylib")); }"#,
        &["--extern", "rdy=librdy.so", "-L", ".", "-Cprefer-dynamic"],
    );
    let sysroot = ok(Command::new("rustc").args(["--print", "sysroot"]));
    let path = format!(
        "{}:{}/lib/rustlib/{}/lib",
        dir.display(),
        sysroot.trim(),
        host()
    );
    assert_eq!(
        run(&dir, "userdy", &[("LD_LIBRARY_PATH", &path)]),
        "hi dylib\n"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn static_executables_with_musl() {
    let target = format!("{}-unknown-linux-musl", host().split('-').next().unwrap());
    if !has_target(&target) {
        return;
    }
    let dir = scratch("musl");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    // static-pie is musl's default; the second link is a classic static executable.
    for (exe, extra) in [
        ("pie", &[][..]),
        ("nopie", &["-Crelocation-model=static"][..]),
    ] {
        ok(Command::new("rustc")
            .current_dir(&dir)
            .args(["stress.rs", "-g", "--target", &target, "-o", exe])
            .arg(format!("-Clinker={HYPRLNK}"))
            .arg("-Clinker-flavor=ld")
            .args(extra));
        assert_eq!(run(&dir, exe, &[]), "ok 661.463\n");
        let headers = readelf(&["-lW"], &dir.join(exe));
        assert!(!headers.contains("INTERP"), "{headers}");
        linked_by_hyprlnk(&dir.join(exe));
    }
    std::fs::remove_dir_all(&dir).ok();
}

fn cc(dir: &Path, compiler: &str, args: &[&str], out: &str) {
    ok(Command::new(compiler)
        .current_dir(dir)
        .arg(format!("-B{}", ld_dir(dir).display()))
        .args(args)
        .arg("-o")
        .arg(out));
}

#[test]
fn c_with_commons_thread_locals_and_constructors() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("c");
    std::fs::write(
        dir.join("a.c"),
        r#"
        #include <stdio.h>
        int common_var;
        __thread int tls_var = 3;
        static int ctor_ran;
        __attribute__((constructor)) static void init(void) { ctor_ran = 7; }
        int helper(int);
        int main(void) {
            common_var += helper(tls_var);
            printf("%d %d %d\n", common_var, tls_var, ctor_ran);
            return 0;
        }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.c"),
        "int common_var;\nint helper(int x) { return x * 14; }\nint unused(void) { return 1; }\n",
    )
    .unwrap();
    cc(
        &dir,
        "cc",
        &[
            "-fcommon",
            "-O1",
            "a.c",
            "b.c",
            "-Wl,--gc-sections",
            "-ffunction-sections",
        ],
        "c",
    );
    assert_eq!(run(&dir, "c", &[]), "42 3 7\n");
    linked_by_hyprlnk(&dir.join("c"));
    let syms = readelf(&["-sW"], &dir.join("c"));
    assert!(
        !syms.contains(" unused"),
        "--gc-sections kept `unused`:\n{syms}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cxx_exceptions_rtti_and_weak_definitions() {
    let cxx = ["c++", "g++", "clang++"].into_iter().find(|c| has_tool(c));
    let Some(cxx) = cxx else {
        return;
    };
    let dir = scratch("cxx");
    std::fs::write(
        dir.join("a.cc"),
        r#"
        #include <cstdio>
        #include <stdexcept>
        #include <string>
        template <class T> T twice(T v) { return v + v; }
        int other();
        struct Base { virtual ~Base() {} virtual int f() { return 1; } };
        struct Derived : Base { int f() override { return 2; } };
        int main() {
            try { throw std::runtime_error("boom"); }
            catch (const std::exception &e) { std::printf("caught %s\n", e.what()); }
            Base *b = new Derived;
            std::printf("%d %d %d %s\n", b->f(), twice(21), other(), dynamic_cast<Derived *>(b) ? "rtti" : "no");
            delete b;
        }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.cc"),
        "template <class T> T twice(T v) { return v + v; }\nint other() { return twice(4); }\n",
    )
    .unwrap();
    cc(&dir, cxx, &["-O1", "a.cc", "b.cc"], "x");
    assert_eq!(run(&dir, "x", &[]), "caught boom\n2 42 8 rtti\n");
    linked_by_hyprlnk(&dir.join("x"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn version_scripts_define_symbol_versions() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("ver");
    std::fs::write(
        dir.join("v.c"),
        "int vfun(void) { return 5; }\nint hidden_fun(void) { return 6; }\n",
    )
    .unwrap();
    std::fs::write(dir.join("v.map"), "VERS_1 { global: vfun; local: *; };\n").unwrap();
    cc(
        &dir,
        "cc",
        &[
            "-shared",
            "-fPIC",
            "v.c",
            "-Wl,--version-script=v.map",
            "-Wl,-soname,libv.so.1",
        ],
        "libv.so",
    );
    let lib = dir.join("libv.so");
    let vers = readelf(&["-VW"], &lib);
    assert!(vers.contains("VERS_1"), "{vers}");
    let dynsym = readelf(&["--dyn-syms", "-W"], &lib);
    assert!(
        dynsym.contains("vfun@@VERS_1") && !dynsym.contains("hidden_fun"),
        "{dynsym}"
    );
    assert!(readelf(&["-dW"], &lib).contains("libv.so.1"));
    std::fs::write(
        dir.join("m.c"),
        "#include <stdio.h>\nint vfun(void);\nint main(void) { printf(\"%d\\n\", vfun()); }\n",
    )
    .unwrap();
    cc(&dir, "cc", &["m.c", "-L.", "-lv"], "m");
    std::fs::rename(&lib, dir.join("libv.so.1")).unwrap();
    let here = dir.display().to_string();
    assert_eq!(run(&dir, "m", &[("LD_LIBRARY_PATH", &here)]), "5\n");
    // The program asks for the version.
    assert!(readelf(&["-VW"], &dir.join("m")).contains("VERS_1"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn debug_info_is_valid_dwarf() {
    if !has_tool("llvm-dwarfdump") {
        return;
    }
    let dir = scratch("dwarf");
    rustc(
        &dir,
        "dbg.rs",
        "#[inline(never)]\nfn inner(v: &[u32]) -> u32 { v.iter().sum() }\nfn main() { println!(\"{}\", inner(&[1, 2, 3])); }\n",
        &["-g", "-o", "dbg"],
    );
    let out = Command::new("llvm-dwarfdump")
        .args(["--verify", "--quiet"])
        .arg(dir.join("dbg"))
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    // Rust's own DWARF has overlapping ranges for code it drops; anything else is ours.
    for line in text.lines().filter(|l| l.contains("error:")) {
        assert!(
            line.contains("overlapping address ranges")
                || line.contains("not contained by parent")
                || line.contains("Errors detected")
                || line.contains("Aggregated"),
            "{text}"
        );
    }
    let lines = ok(Command::new("llvm-dwarfdump")
        .arg("--debug-line")
        .arg(dir.join("dbg")));
    assert!(lines.contains("dbg.rs"), "no line table for dbg.rs");
    std::fs::remove_dir_all(&dir).ok();
}

/// The `ld` arguments of a link, saved by `--reproduce`.
fn saved_link(dir: &Path, src: &str, exe: &str) -> PathBuf {
    let saved = dir.join("saved");
    std::fs::write(dir.join("p.rs"), src).unwrap();
    ok(rustc_cmd(dir)
        .args(["p.rs", "-g", "-o", exe])
        .env("HYPRLNK_REPRODUCE", &saved));
    std::fs::read_dir(&saved)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[test]
fn output_is_reproducible() {
    let dir = scratch("repro");
    let link = saved_link(&dir, STRESS, "s");
    let mut outputs = Vec::new();
    for i in 0..2 {
        let out = dir.join(format!("out{i}"));
        std::fs::create_dir_all(&out).unwrap();
        ok(Command::new(HYPRLNK)
            .current_dir(&link)
            .args(["-flavor", "gnu", "@link.rsp", "-o"])
            .arg(out.join("app")));
        outputs.push(std::fs::read(out.join("app")).unwrap());
    }
    assert!(
        outputs[0] == outputs[1],
        "two links of the same inputs differ"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn reproduce_saves_a_link_that_replays() {
    let dir = scratch("reproduce");
    let link = saved_link(&dir, "fn main() { println!(\"replayed\"); }", "hi");
    assert!(link.join("link.rsp").is_file());
    ok(Command::new(HYPRLNK)
        .current_dir(&link)
        .args(["-flavor", "gnu", "@link.rsp", "-o"])
        .arg(dir.join("again")));
    assert_eq!(run(&dir, "again", &[]), "replayed\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn undefined_symbols_are_reported_with_their_referrer() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("undef");
    std::fs::write(
        dir.join("u.c"),
        "int missing_function(void);\nint main(void) { return missing_function(); }\n",
    )
    .unwrap();
    let err = fails(
        Command::new("cc")
            .current_dir(&dir)
            .arg(format!("-B{}", ld_dir(&dir).display()))
            .args(["u.c", "-o", "u"]),
    );
    assert!(err.contains("undefined symbol: missing_function"), "{err}");
    assert!(err.contains("referenced by") && err.contains(".o"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// A user-mode emulator for a target's architecture, if one is installed.
fn qemu(arch: &str) -> Option<String> {
    [format!("qemu-{arch}-static"), format!("qemu-{arch}")]
        .into_iter()
        .find(|q| {
            Command::new(q)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
}

#[test]
fn other_architectures_run_under_qemu() {
    let targets = [
        ("aarch64-unknown-linux-musl", "aarch64"),
        ("armv7-unknown-linux-musleabihf", "arm"),
        ("arm-unknown-linux-musleabihf", "arm"),
        ("i686-unknown-linux-musl", "i386"),
        ("riscv64gc-unknown-linux-musl", "riscv64"),
        ("powerpc64le-unknown-linux-musl", "ppc64le"),
        ("loongarch64-unknown-linux-musl", "loongarch64"),
        ("x86_64-unknown-linux-musl", "x86_64"),
    ];
    // CI installs every target and emulator, and asks for all of them to run.
    let all = std::env::var_os("HYPRLNK_TEST_ALL_ARCHES").is_some();
    let dir = scratch("cross");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    let mut tested = Vec::new();
    for (target, arch) in targets {
        if !has_target(target) {
            assert!(!all, "the Rust target {target} is not installed");
            continue;
        }
        let Some(q) = qemu(arch) else {
            assert!(!all, "no qemu-{arch}-static or qemu-{arch}");
            continue;
        };
        let exe = format!("s-{target}");
        ok(Command::new("rustc")
            .current_dir(&dir)
            .args(["stress.rs", "-g", "--target", target, "-o", &exe])
            .args(["-Ctarget-feature=+crt-static", "-Clinker-flavor=ld"])
            .arg(format!("-Clinker={HYPRLNK}")));
        let out = ok(Command::new(&q).arg(dir.join(&exe)).current_dir(&dir));
        assert_eq!(out, "ok 661.463\n", "{target}");
        tested.push(target);
    }
    eprintln!("ran under qemu: {tested:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ld_flavor_options_are_honored() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("opts");
    std::fs::write(
        dir.join("o.c"),
        "#include <stdio.h>\nint main(void) { puts(\"opts\"); return 0; }\n",
    )
    .unwrap();
    cc(
        &dir,
        "cc",
        &[
            "o.c",
            "-Wl,-z,now,-z,relro,--build-id=sha1,-rpath,/opt/x,--hash-style=both",
        ],
        "o",
    );
    assert_eq!(run(&dir, "o", &[]), "opts\n");
    let d = readelf(&["-dW"], &dir.join("o"));
    assert!(d.contains("BIND_NOW") && d.contains("/opt/x"), "{d}");
    assert!(d.contains("(GNU_HASH)") && d.contains("(HASH)"), "{d}");
    let s = readelf(&["-SW"], &dir.join("o"));
    assert!(!s.contains(".interp") || readelf(&["-lW"], &dir.join("o")).contains("INTERP"));
    // Stripped: no symbol table, no debug info.
    cc(&dir, "cc", &["-g", "o.c", "-Wl,-s"], "os");
    let s = readelf(&["-SW"], &dir.join("os"));
    assert!(!s.contains(".symtab") && !s.contains(".debug_info"), "{s}");
    assert_eq!(run(&dir, "os", &[]), "opts\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn outputs_are_written_in_place_only_when_that_is_safe() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("reuse");
    // Over a megabyte, so the old output is worth reusing; reads a line, then prints its data.
    std::fs::write(
        dir.join("big.c"),
        "#include <stdio.h>\nstatic char big[2 << 20] = {VALUE};\n\
         int main(void) { char l[8]; if (!fgets(l, sizeof l, stdin)) return 1; printf(\"%d\\n\", big[0]); return 0; }\n",
    )
    .unwrap();
    let link = |value: &str| cc(&dir, "cc", &[&format!("-DVALUE={value}"), "big.c"], "big");
    let ino = |name: &str| std::fs::metadata(dir.join(name)).unwrap().ino();
    let feed = |name: &str| {
        let mut c = Command::new(dir.join(name))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(b"go\n").unwrap();
        String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap()
    };
    link("1");
    let first = ino("big");
    link("2");
    assert_eq!(ino("big"), first, "an executable is relinked in place");
    assert_eq!(feed("big"), "2\n");

    // A second link to it (Rune's store) is never written into.
    std::fs::hard_link(dir.join("big"), dir.join("kept")).unwrap();
    link("3");
    assert_ne!(ino("big"), ino("kept"));
    assert_eq!((feed("big"), feed("kept")), ("3\n".into(), "2\n".into()));
    std::fs::remove_file(dir.join("kept")).unwrap();

    // Relinking a running program works and leaves the running one alone.
    let mut running = Command::new(dir.join("big"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    link("4");
    running.stdin.take().unwrap().write_all(b"go\n").unwrap();
    let out = running.wait_with_output().unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "3\n");
    assert_eq!(feed("big"), "4\n");

    // A shared library always becomes a new file: a running process may have it mapped.
    let so = |value: &str| {
        cc(
            &dir,
            "cc",
            &["-shared", "-fPIC", &format!("-DVALUE={value}"), "big.c"],
            "libbig.so",
        )
    };
    so("1");
    let first = ino("libbig.so");
    so("2");
    assert_ne!(ino("libbig.so"), first);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn compressed_debug_sections_are_decompressed() {
    if !has_tool("cc") || !has_tool("addr2line") || !has_tool("nm") {
        return;
    }
    let dir = scratch("gz");
    std::fs::write(
        dir.join("gz.c"),
        "#include <stdio.h>\nint main(void) {\n  puts(\"gz\");\n  return 0;\n}\n",
    )
    .unwrap();
    for z in ["zlib", "zstd"] {
        let obj = format!("gz-{z}.o");
        let compiled = Command::new("cc")
            .current_dir(&dir)
            .args(["-g", &format!("-gz={z}"), "-c", "gz.c", "-o", &obj])
            .output()
            .is_ok_and(|o| o.status.success());
        if !compiled {
            continue; // a compiler or assembler without this compression
        }
        let exe = format!("gz-{z}");
        cc(&dir, "cc", &[&obj], &exe);
        assert_eq!(run(&dir, &exe, &[]), "gz\n");
        let syms = ok(Command::new("nm").arg(dir.join(&exe)));
        let main = syms
            .lines()
            .find_map(|l| l.strip_suffix(" T main"))
            .unwrap_or_else(|| panic!("no global main:\n{syms}"));
        let line = ok(Command::new("addr2line")
            .arg("-e")
            .arg(dir.join(&exe))
            .arg(main));
        assert!(line.trim().ends_with("gz.c:2"), "{z}: {line}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn symbol_table_bindings_follow_gnu_ld() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("bind");
    std::fs::write(
        dir.join("b.c"),
        "static int local_fn(void) { return 1; }\n\
         __attribute__((visibility(\"hidden\"))) int hidden_fn(void) { return local_fn(); }\n\
         __attribute__((weak)) int weak_fn(void) { return 2; }\n\
         int main(void) { return hidden_fn() + weak_fn() - 3; }\n",
    )
    .unwrap();
    cc(&dir, "cc", &["-O0", "b.c"], "b");
    run(&dir, "b", &[]);
    let syms = readelf(&["-sW"], &dir.join("b"));
    let bind = |name: &str| {
        syms.lines()
            .find(|l| l.split_whitespace().last() == Some(name))
            .and_then(|l| l.split_whitespace().nth(4))
            .unwrap_or_else(|| panic!("no {name}:\n{syms}"))
            .to_string()
    };
    // Not exported from an executable, but still global; hidden ones become local, as lld does.
    assert_eq!(bind("main"), "GLOBAL");
    assert_eq!(bind("weak_fn"), "WEAK");
    assert_eq!(bind("hidden_fn"), "LOCAL");
    assert_eq!(bind("local_fn"), "LOCAL");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn map_and_dependency_files() {
    if !has_tool("cc") {
        return;
    }
    let dir = scratch("map");
    std::fs::write(
        dir.join("m.c"),
        "int answer(void) { return 42; }\nint main(void) { return answer() - 42; }\n",
    )
    .unwrap();
    cc(
        &dir,
        "cc",
        &["m.c", "-Wl,-Map=m.map", "-Wl,--dependency-file=m.d"],
        "m",
    );
    run(&dir, "m", &[]);
    let map = std::fs::read_to_string(dir.join("m.map")).unwrap();
    assert!(map.starts_with("             VMA"), "{map}");
    assert!(
        map.contains(" .text\n") && map.lines().any(|l| l.trim_end().ends_with(" answer")),
        "{map}"
    );
    let dep = std::fs::read_to_string(dir.join("m.d")).unwrap();
    assert!(
        dep.starts_with("m: \\\n") && dep.contains(".o \\\n"),
        "{dep}"
    );
    // `-M` prints the map.
    let out = ok(Command::new("cc")
        .current_dir(&dir)
        .arg(format!("-B{}", ld_dir(&dir).display()))
        .args(["m.c", "-Wl,-M", "-o", "m2"]));
    assert!(out.contains("<internal>:(.interp)"), "{out}");
    assert!(!dir.join("-").exists());
    std::fs::remove_dir_all(&dir).ok();
}
