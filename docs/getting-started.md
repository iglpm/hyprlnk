# Getting started

hyprlnk takes the same command lines as the platform linkers — Microsoft's
`link.exe` and LLVM's `lld-link` on Windows, Apple's `ld` and LLVM's
`ld64.lld` on macOS, GNU `ld`, `ld.lld`, mold and wild on Linux — so anything
that can run one of those can run hyprlnk.

## Installing

### With Rune: nothing to install

[Rune](https://runepm.com) has hyprlnk built in, and links with it by default.
It links binaries, tests, build scripts, proc-macros and dynamic libraries
for:

- Linux: `*-unknown-linux-gnu*` and `*-unknown-linux-musl*` on x86-64, x86,
  AArch64, ARM (ARMv5TE and later, Thumb-2 included), RISC-V 64,
  POWER little-endian, s390x and LoongArch;
- Windows: `x86_64`, `aarch64` and `i686` `*-pc-windows-msvc`;
- macOS: `aarch64`, `arm64e` and `x86_64` `*-apple-darwin`.

Other targets keep their platform linker. The setting takes precedence over
`target.<triple>.linker` in `.cargo/config.toml`; on Linux, a C compiler
named there (`aarch64-linux-gnu-gcc` for a cross build, say) is still the one
hyprlnk links through, for the C runtime. Linked artifacts are cached under a
key that names the hyprlnk version, so switching linkers back and forth is
instant and upgrading hyprlnk relinks.

To use the linker `rustc` and Cargo would choose instead — for a project in
`Rune.toml`, for every project in `~/.rune/config.toml`, or for one build:

```toml
[build]
linker = "default"
```

```sh
RUNE_BUILD_LINKER=default rune build                 # macOS, Linux shells
$env:RUNE_BUILD_LINKER = "default"; rune build       # PowerShell
```

### Building the standalone executable

hyprlnk is a self-contained Rust crate. From the `hyprlnk/` directory:

```sh
rune build --release        # or: cargo build --release
# → target/release/hyprlnk (with Cargo) or .rune/target/release/hyprlnk
```

Copy it anywhere; it needs nothing but the libraries your programs link
against (the Windows SDK and MSVC libraries, the macOS SDK, or a Linux
system's C library). On macOS, also make an `ld64.hyprlnk` link to it for
clang's `-fuse-ld=`; on Linux, `ld.hyprlnk` for clang's `-fuse-ld=`, and a
directory whose `ld` is hyprlnk for gcc's `-B`:

```sh
cp target/release/hyprlnk /usr/local/bin/
ln -s hyprlnk /usr/local/bin/ld64.hyprlnk                    # macOS
ln -s hyprlnk /usr/local/bin/ld.hyprlnk                      # Linux
mkdir -p /usr/local/libexec/hyprlnk && ln -s /usr/local/bin/hyprlnk /usr/local/libexec/hyprlnk/ld
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

## Using it on Linux

### Cargo

In `.cargo/config.toml` (in the project, or `~/.cargo`):

```toml
[target.x86_64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"

[target.aarch64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"
```

rustc hands a linker it doesn't know the command line it would give `cc`.
Only the C compiler knows where the C runtime's start files, libgcc and the
system's library directories are, so hyprlnk runs it — `cc`, or the one in
`HYPRLNK_CC` — with itself as the C compiler's `ld`. (On
`x86_64-unknown-linux-gnu`, it also drops the `-fuse-ld=lld` rustc adds to
use its bundled lld.)

For a cross build, keep the cross compiler as the linker and give it
hyprlnk as `ld` with `-B`:

```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
rustflags = ["-C", "link-arg=-B/usr/local/libexec/hyprlnk"]
```

### rustc

```sh
rustc -C linker=hyprlnk main.rs                                    # through cc
rustc -C link-arg=-B/usr/local/libexec/hyprlnk -C linker-features=-lld main.rs
rustc --target x86_64-unknown-linux-musl -C linker=hyprlnk -C linker-flavor=ld main.rs
```

The second line keeps `cc` as rustc's linker and gives it hyprlnk as `ld`
(`-C linker-features=-lld` stops rustc's own lld from winning on
`x86_64-unknown-linux-gnu`). The third needs no C compiler at all: musl
targets bring their own C runtime, and `-C linker-flavor=ld` makes rustc pass
`ld` arguments directly.

### C and C++

```sh
gcc -B/usr/local/libexec/hyprlnk main.c -o app
g++ -B/usr/local/libexec/hyprlnk -O2 *.cpp -o app
clang -fuse-ld=hyprlnk main.c -o app                        # finds ld.hyprlnk
clang --ld-path=/usr/local/bin/hyprlnk main.c -o app
cmake -DCMAKE_EXE_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk ..
```

Or call it directly with GNU ld's options:

```sh
hyprlnk -flavor gnu -pie -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o app \
        $(cc -print-file-name=Scrt1.o) $(cc -print-file-name=crti.o) main.o \
        -L/usr/lib -lc $(cc -print-file-name=crtn.o)
```

Like lld and unlike GNU ld, hyprlnk has no library directories of its own:
`-l` looks in the `-L` directories only.

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
let code = hyprlnk::main_with_args(["ld.hyprlnk", "main.o", "-lc", "-o", "app"]);

// Repeatable, in-process:
let cfg = hyprlnk::coff::Config::parse(&["/OUT:app.exe".into(), "main.obj".into()])?;
hyprlnk::coff::link(cfg)?;
let cfg = hyprlnk::macho::Config::parse(&["-o".into(), "app".into(), "main.o".into()])?;
hyprlnk::macho::link(cfg)?;
```

`main_with_args` leaves the link's memory to the operating system (it is meant
for processes that exit right after); `coff::link` and `macho::link` free
everything. ELF links run through `main_with_args` only.

## Checking it works

```sh
hyprlnk /OUT:hello.exe /TIME hello.obj            # Windows: a per-phase timing table
hyprlnk -flavor darwin hello.o -lSystem -o hello --time   # macOS
cc -B/usr/local/libexec/hyprlnk -Wl,--time hello.c -o hello   # Linux
readelf -p .comment hello                                 # Linux: "Linker: hyprlnk …"
hyprlnk --version
```

If something goes wrong, see [troubleshooting](troubleshooting.md).
