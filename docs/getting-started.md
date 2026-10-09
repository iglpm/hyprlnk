# Getting started

hyprlnk takes the same command lines as the platform linkers — Microsoft's
`link.exe` and LLVM's `lld-link` on Windows, Apple's `ld` and LLVM's
`ld64.lld` on macOS — so anything that can run one of those can run hyprlnk.

## Installing

### With Rune: nothing to install

[Rune](https://runepm.com) has hyprlnk built in. Turn it on for a project in
`Rune.toml`, for every project in `~/.rune/config.toml`, or for one build
with an environment variable:

```toml
[build]
linker = "hyprlnk"
```

```sh
RUNE_BUILD_LINKER=hyprlnk rune build                 # macOS, Linux shells
$env:RUNE_BUILD_LINKER = "hyprlnk"; rune build       # PowerShell
```

Rune then links binaries, tests, build scripts, proc-macros and dynamic
libraries with hyprlnk for `x86_64`, `aarch64` and `i686` `*-pc-windows-msvc`
targets and for `aarch64`, `arm64e` and `x86_64` `*-apple-darwin` targets, and
keeps the platform linker for other targets. The setting takes precedence
over `target.<triple>.linker` in `.cargo/config.toml`. Linked artifacts are
cached under a key that names the hyprlnk version, so switching linkers back
and forth is instant and upgrading hyprlnk relinks.

### Building the standalone executable

hyprlnk is a self-contained Rust crate. From the `hyprlnk/` directory:

```sh
rune build --release        # or: cargo build --release
# → target/release/hyprlnk (with Cargo) or .rune/target/release/hyprlnk
```

Copy it anywhere; it needs nothing but the libraries your programs link
against (the Windows SDK and MSVC libraries, or the macOS SDK). On macOS,
also make an `ld64.hyprlnk` link to it for clang's `-fuse-ld=`:

```sh
cp target/release/hyprlnk /usr/local/bin/
ln -s hyprlnk /usr/local/bin/ld64.hyprlnk
```

### Finding libraries

On macOS, `-l` and `-framework` are looked up in the `-L` and `-F`
directories and then in the SDK (`-syslibroot`, else `SDKROOT`, else the
Command Line Tools' or Xcode's SDK), as ld64 does. On Windows, like
`lld-link`, hyprlnk searches for libraries in the current directory,
then each `/LIBPATH:`, then the directories in `%LIB%`. `rustc` and Visual
Studio developer prompts set `%LIB%`. When it isn't set, hyprlnk looks up the
newest installed MSVC toolset and Windows SDK itself (`%VCToolsInstallDir%`,
then the default `Program Files` locations), for the machine being linked.

## Using it on macOS

### Cargo

In `.cargo/config.toml` (in the project, or `~/.cargo`):

```toml
[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"

[target.x86_64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"
```

rustc hands a linker it doesn't know a `cc`-style command line; hyprlnk
translates it. To skip that step (and `cc` entirely), add
`rustflags = ["-C", "linker-flavor=ld64.lld"]` to the same tables.

### rustc

```sh
rustc -C linker=hyprlnk main.rs
rustc -C linker=hyprlnk -C linker-flavor=ld64.lld main.rs
rustc --target x86_64-apple-darwin -C linker=hyprlnk main.rs
```

Debug info stays in the object files, as with every macOS linker; hyprlnk
writes the debug map pointing at them. With `-C split-debuginfo=packed`
(Cargo's default for release builds with debug info), rustc runs `dsymutil`
on it to make a `.dSYM`.

### C, C++ and Objective-C

```sh
clang -fuse-ld=/usr/local/bin/ld64.hyprlnk main.c -o app
clang++ -fuse-ld=/usr/local/bin/ld64.hyprlnk -std=c++20 *.cpp -o app
clang -fobjc-arc -fuse-ld=/usr/local/bin/ld64.hyprlnk app.m -framework Foundation -o app
cmake -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk ..
```

Or call it directly with ld64's options:

```sh
hyprlnk -arch arm64 -platform_version macos 13.0 15.0 \
        -syslibroot "$(xcrun --show-sdk-path)" main.o util.o -lSystem -o app
```

More in [macOS](macos.md).

## Using it on Windows

### Cargo

In `.cargo/config.toml` (in the project, or `%USERPROFILE%\.cargo`):

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"

[target.aarch64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"

[target.i686-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"
```

Or for one build: `$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "hyprlnk.exe"`.

### rustc

```powershell
rustc -C linker=hyprlnk.exe main.rs
rustc --target aarch64-pc-windows-msvc -C linker=hyprlnk.exe main.rs
```

`rustc` passes `/DEBUG` (and natvis files) whenever any linked code has debug
info — which includes the standard library — so you get a PDB by default.
Add `-C link-arg=/DEBUG:NONE` to skip it.

### C and C++

hyprlnk links objects from clang-cl and MSVC. Call it directly:

```powershell
clang-cl /c /O2 main.c util.c
hyprlnk /OUT:app.exe /DEBUG main.obj util.obj user32.lib
```

With CMake and the Ninja generator, point `CMAKE_LINKER` at it:

```powershell
cmake -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
      -DCMAKE_LINKER=C:/tools/hyprlnk.exe ..
```

With MSBuild, set the linker path in a `Directory.Build.props`:

```xml
<Project>
  <PropertyGroup>
    <LinkToolExe>hyprlnk.exe</LinkToolExe>
    <LinkToolPath>C:\tools</LinkToolPath>
  </PropertyGroup>
</Project>
```

## As a library

hyprlnk is a Rust library first. Link from your own program with a parsed
configuration, or a whole command line:

```rust
// Exits-after style (what the hyprlnk binary does):
let code = hyprlnk::main_with_args(["hyprlnk", "/OUT:app.exe", "main.obj"]);
let code = hyprlnk::main_with_args(["ld64.hyprlnk", "-arch", "arm64", "main.o", "-lSystem", "-o", "app"]);

// Repeatable, in-process:
let cfg = hyprlnk::coff::Config::parse(&["/OUT:app.exe".into(), "main.obj".into()])?;
hyprlnk::coff::link(cfg)?;
let cfg = hyprlnk::macho::Config::parse(&["-o".into(), "app".into(), "main.o".into()])?;
hyprlnk::macho::link(cfg)?;
```

`main_with_args` leaves the link's memory to the operating system (it is meant
for processes that exit right after); `coff::link` and `macho::link` free
everything.

## Checking it works

```sh
hyprlnk /OUT:hello.exe /TIME hello.obj            # Windows: a per-phase timing table
hyprlnk -flavor darwin hello.o -lSystem -o hello --time   # macOS
hyprlnk --version
```

If something goes wrong, see [troubleshooting](troubleshooting.md).
