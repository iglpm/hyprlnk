//! End-to-end on macOS: rustc and clang link with hyprlnk, then the result runs. Parts skip
//! when a target or tool is missing.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const HYPRLNK: &str = env!("CARGO_BIN_EXE_hyprlnk");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hyprlnk-macho-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `ld64.hyprlnk` next to the tests' files, so clang's `-fuse-ld=<path>` runs it as ld64.
fn ld64(dir: &Path) -> PathBuf {
    let link = dir.join("ld64.hyprlnk");
    let _ = std::os::unix::fs::symlink(HYPRLNK, &link);
    link
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

fn rustc(dir: &Path, file: &str, src: &str, extra: &[&str]) {
    std::fs::write(dir.join(file), src).unwrap();
    ok(
        Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .current_dir(dir)
            .arg(file)
            .arg(format!("-Clinker={HYPRLNK}"))
            .arg("-Clinker-flavor=ld64.lld")
            .args(extra),
    );
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
    static INSTALLED: OnceLock<String> = OnceLock::new();
    let sysroot = INSTALLED.get_or_init(|| {
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
        ok(Command::new("codesign").arg("-v").arg(dir.join(&exe)));
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn chained_fixups_from_macos_13() {
    let dir = scratch("chained");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    ok(Command::new("rustc")
        .current_dir(&dir)
        .args(["stress.rs", "-g", "-o", "c14", "-Clinker-flavor=ld64.lld"])
        .arg(format!("-Clinker={HYPRLNK}"))
        .env("MACOSX_DEPLOYMENT_TARGET", "14.0"));
    let lcs = ok(Command::new("otool").arg("-l").arg(dir.join("c14")));
    assert!(lcs.contains("LC_DYLD_CHAINED_FIXUPS"), "{lcs}");
    assert_eq!(run(&dir, "c14", &[]), "ok 661.463\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cc_style_command_lines_work_without_a_flavor() {
    let dir = scratch("cc");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    ok(Command::new("rustc")
        .current_dir(&dir)
        .args(["stress.rs", "-g", "-o", "cc"])
        .arg(format!("-Clinker={HYPRLNK}")));
    assert_eq!(run(&dir, "cc", &[]), "ok 661.463\n");
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
        run(&dir, "user", &[("DYLD_LIBRARY_PATH", &here)]),
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
        &["--extern", "pm=libpm.dylib"],
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
        &[
            "--extern",
            "rdy=librdy.dylib",
            "-L",
            ".",
            "-Cprefer-dynamic",
        ],
    );
    let sysroot = ok(Command::new("rustc").args(["--print", "sysroot"]));
    let host = ok(Command::new("rustc").args(["--print", "host-tuple"]));
    let path = format!(
        "{}:{}/lib/rustlib/{}/lib",
        dir.display(),
        sysroot.trim(),
        host.trim()
    );
    assert_eq!(
        run(&dir, "userdy", &[("DYLD_LIBRARY_PATH", &path)]),
        "hi dylib\n"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_debug_map_feeds_dsymutil_and_lldb() {
    if !has_tool("dsymutil") {
        return;
    }
    let dir = scratch("dsym");
    rustc(
        &dir,
        "dbg.rs",
        "#[inline(never)]\nfn inner(v: &[u32]) -> u32 { v.iter().sum() }\nfn main() { println!(\"{}\", inner(&[1, 2, 3])); }\n",
        &["-g", "-Csplit-debuginfo=packed", "-o", "dbg"],
    );
    assert!(dir.join("dbg.dSYM").is_dir());
    let lookup = ok(Command::new("dwarfdump")
        .arg("--statistics")
        .arg(dir.join("dbg.dSYM")));
    assert!(lookup.contains("\"#functions\""), "{lookup}");
    let funcs: u64 = lookup
        .lines()
        .find(|l| l.contains("\"#functions\""))
        .and_then(|l| {
            l.trim()
                .trim_end_matches(',')
                .rsplit(' ')
                .next()?
                .parse()
                .ok()
        })
        .unwrap();
    assert!(funcs > 100, "{funcs} functions in the dSYM");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn output_is_reproducible() {
    let dir = scratch("repro");
    let saved = dir.join("saved");
    std::fs::write(dir.join("stress.rs"), STRESS).unwrap();
    ok(Command::new("rustc")
        .current_dir(&dir)
        .args(["stress.rs", "-g", "-o", "s", "-Clinker-flavor=ld64.lld"])
        .arg(format!("-Clinker={HYPRLNK}"))
        .env("HYPRLNK_REPRODUCE", &saved));
    let link = std::fs::read_dir(&saved)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut outputs = Vec::new();
    for i in 0..2 {
        let out = dir.join(format!("out{i}"));
        std::fs::create_dir_all(&out).unwrap();
        ok(Command::new(HYPRLNK)
            .current_dir(&link)
            .args(["-flavor", "darwin", "@link.rsp", "-o"])
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
    let saved = dir.join("saved");
    std::fs::write(dir.join("hi.rs"), "fn main() { println!(\"replayed\"); }").unwrap();
    ok(Command::new("rustc")
        .current_dir(&dir)
        .args(["hi.rs", "-o", "hi", "-Clinker-flavor=ld64.lld"])
        .arg(format!("-Clinker={HYPRLNK}"))
        .env("HYPRLNK_REPRODUCE", &saved));
    let link = std::fs::read_dir(&saved)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(link.join("link.rsp").is_file());
    ok(Command::new(HYPRLNK)
        .current_dir(&link)
        .args(["-flavor", "darwin", "@link.rsp", "-o"])
        .arg(dir.join("again")));
    assert_eq!(run(&dir, "again", &[]), "replayed\n");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn x86_64_images_link() {
    if !has_target("x86_64-apple-darwin") {
        return;
    }
    let dir = scratch("x86");
    rustc(
        &dir,
        "stress.rs",
        STRESS,
        &["--target", "x86_64-apple-darwin", "-o", "x"],
    );
    let head = ok(Command::new("otool").arg("-hv").arg(dir.join("x")));
    assert!(head.contains("X86_64"), "{head}");
    // Without Rosetta x86_64 can't run on Apple silicon; with it, it must.
    if Command::new("arch")
        .args(["-x86_64", "/usr/bin/true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        assert_eq!(run(&dir, "x", &[]), "ok 661.463\n");
    }
    std::fs::remove_dir_all(&dir).ok();
}

const C_MAIN: &str = r#"
#include <stdio.h>
#include <string.h>
int common_a; int common_b[100];
__thread int tv = 7;
__thread char tb[64];
static int inited;
__attribute__((constructor)) static void init(void) { inited = 42; }
__attribute__((destructor)) static void fini(void) { printf("bye\n"); }
const char *names[] = {"alpha", "beta", "alpha"};
int add(int a, int b) { return a + b; }
int (*ops[])(int, int) = {add};
extern int helper(void);
int main(void) {
  common_a = 3; common_b[99] = 4;
  tv++; strcpy(tb, "tls");
  printf("%d %d %d %d %s %s %d %d\n", inited, common_a + common_b[99], tv, ops[0](2, 3), tb, names[2], names[0] == names[2], helper());
  return 0;
}
"#;

const C_HELPER: &str = "int common_a;\nint helper(void) { static const char s[] = \"alpha\"; return (int)sizeof(s) + common_a; }\n";

const CXX_A: &str = r#"
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <map>
struct Base { virtual ~Base() {} virtual int f() const { return 1; } };
struct Derived : Base { int f() const override { return 2; } };
inline int shared_inline(int x) { return x * 3; }
int other();
static std::map<std::string, int> table = {{"a", 1}, {"b", 2}};
thread_local int tls_counter = 5;
int main() {
  try { throw std::runtime_error("boom"); }
  catch (const std::exception& e) { std::printf("caught %s\n", e.what()); }
  std::unique_ptr<Base> b(new Derived);
  std::vector<int> v{1,2,3};
  tls_counter += 1;
  std::printf("%d %d %d %d %d %d\n", b->f(), shared_inline(4), other(), (int)v.size(), table["b"], tls_counter);
  Derived& d = dynamic_cast<Derived&>(*b);
  std::printf("dyncast %d\n", d.f());
  return 0;
}
"#;

const CXX_B: &str = "inline int shared_inline(int x) { return x * 3; }\nint other() { try { throw 7; } catch (int x) { return shared_inline(x); } }\n";

const OBJC: &str = r#"
#import <Foundation/Foundation.h>
@interface Greeter : NSObject
@property (nonatomic, copy) NSString *name;
- (NSString *)greet;
@end
@implementation Greeter
- (NSString *)greet { return [NSString stringWithFormat:@"hello %@", self.name]; }
@end
@interface Greeter (Loud)
- (NSString *)shout;
@end
@implementation Greeter (Loud)
- (NSString *)shout { return [[self greet] uppercaseString]; }
@end
int main(void) {
  @autoreleasepool {
    Greeter *g = [Greeter new]; g.name = @"objc";
    NSArray *a = @[@1, @2, @3];
    @try { [a objectAtIndex:10]; } @catch (NSException *e) { printf("caught %s\n", e.name.UTF8String); }
    printf("%s %s %lu\n", g.greet.UTF8String, g.shout.UTF8String, (unsigned long)a.count);
  }
  return 0;
}
"#;

fn clang(dir: &Path, driver: &str, args: &[&str], out: &str) {
    let ld = ld64(dir);
    ok(Command::new(driver)
        .current_dir(dir)
        .args(args)
        .arg(format!("-fuse-ld={}", ld.display()))
        .args(["-o", out]));
}

#[test]
fn c_with_commons_thread_locals_and_constructors() {
    if !has_tool("clang") {
        return;
    }
    let dir = scratch("c");
    std::fs::write(dir.join("c1.c"), C_MAIN).unwrap();
    std::fs::write(dir.join("c2.c"), C_HELPER).unwrap();
    for (min, exe) in [("11.0", "c11"), ("14.0", "c14")] {
        clang(
            &dir,
            "clang",
            &[
                "-O1",
                "-fcommon",
                &format!("-mmacosx-version-min={min}"),
                "c1.c",
                "c2.c",
            ],
            exe,
        );
        assert_eq!(run(&dir, exe, &[]), "42 7 8 5 tls alpha 1 9\nbye\n");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cxx_exceptions_rtti_and_weak_definitions() {
    if !has_tool("clang++") {
        return;
    }
    let dir = scratch("cxx");
    std::fs::write(dir.join("a.cpp"), CXX_A).unwrap();
    std::fs::write(dir.join("b.cpp"), CXX_B).unwrap();
    let want = "caught boom\n2 12 21 3 2 6\ndyncast 2\n";
    for (min, exe) in [("11.0", "x11"), ("14.0", "x14")] {
        clang(
            &dir,
            "clang++",
            &[
                "-std=c++17",
                "-O1",
                &format!("-mmacosx-version-min={min}"),
                "a.cpp",
                "b.cpp",
            ],
            exe,
        );
        assert_eq!(run(&dir, exe, &[]), want);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn objective_c_with_selector_stubs() {
    if !has_tool("clang") {
        return;
    }
    let dir = scratch("objc");
    std::fs::write(dir.join("o.m"), OBJC).unwrap();
    clang(
        &dir,
        "clang",
        &["-fobjc-arc", "o.m", "-framework", "Foundation"],
        "o",
    );
    assert_eq!(
        run(&dir, "o", &[]),
        "caught NSRangeException\nhello objc HELLO OBJC 3\n"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arm64e_pointer_authentication() {
    if !has_tool("clang") || !cfg!(target_arch = "aarch64") {
        return;
    }
    let dir = scratch("arm64e");
    std::fs::write(dir.join("c1.c"), C_MAIN).unwrap();
    std::fs::write(dir.join("c2.c"), C_HELPER).unwrap();
    std::fs::write(dir.join("a.cpp"), CXX_A).unwrap();
    std::fs::write(dir.join("b.cpp"), CXX_B).unwrap();
    clang(
        &dir,
        "clang",
        &["-arch", "arm64e", "-O1", "-fcommon", "c1.c", "c2.c"],
        "c",
    );
    clang(
        &dir,
        "clang++",
        &["-arch", "arm64e", "-std=c++17", "-O1", "a.cpp", "b.cpp"],
        "x",
    );
    let head = ok(Command::new("otool").arg("-hv").arg(dir.join("c")));
    assert!(head.contains("ARM64") && head.contains(" E "), "{head}");
    // arm64e user code runs only where the system allows it (macOS 26 and later).
    if Command::new(dir.join("c"))
        .output()
        .is_ok_and(|o| o.status.success())
    {
        assert_eq!(run(&dir, "c", &[]), "42 7 8 5 tls alpha 1 9\nbye\n");
        assert_eq!(
            run(&dir, "x", &[]),
            "caught boom\n2 12 21 3 2 6\ndyncast 2\n"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn undefined_symbols_are_reported_with_their_referrer() {
    let dir = scratch("undefined");
    std::fs::write(
        dir.join("bad.rs"),
        "unsafe extern \"C\" { fn hyprlnk_test_missing(); }\nfn main() { unsafe { hyprlnk_test_missing() } }\n",
    )
    .unwrap();
    let out = Command::new("rustc")
        .current_dir(&dir)
        .args(["bad.rs", "-Clinker-flavor=ld64.lld"])
        .arg(format!("-Clinker={HYPRLNK}"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("undefined symbol: _hyprlnk_test_missing"),
        "{stderr}"
    );
    assert!(stderr.contains("referenced by"), "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}
