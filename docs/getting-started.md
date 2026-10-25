# Getting Started with hyprlnk

hyprlnk is a drop-in replacement for standard platform linkers: Microsoft's `link.exe` and LLVM's `lld-link` on Windows, Apple's `ld` and `ld64.lld` on macOS, and GNU `ld`, `ld.lld`, `mold`, and `wild` on Linux. 

Any tool or build system that invokes one of these linkers can run hyprlnk directly without modifying flags or linker scripts.

## Installation

### Built Into Igel (Zero Setup Required)

If you use [Igel](https://runepm.com), hyprlnk is already installed and enabled by default for:
- **Linux**: `*-unknown-linux-gnu*` and `*-unknown-linux-musl*` on x86-64, x86, AArch64, ARM (ARMv5TE and later, including Thumb-2), RISC-V 64, POWER (little-endian), s390x, and LoongArch.
- **Windows**: `x86_64`, `aarch64`, and `i686` on `*-pc-windows-msvc`.
- **macOS**: `aarch64`, `arm64e`, and `x86_64` on `*-apple-darwin`.

To switch back to your platform's default linker at any time:

```toml
# In Igel.toml or ~/.igel/config.toml
[build]
linker = "default"
```

Or set the environment variable for a single build:

```sh
IGEL_BUILD_LINKER=default igl build
```

### Standalone Executable Installation

hyprlnk is a self-contained Rust crate with zero external dependencies. To build the standalone binary:

```sh
cd hyprlnk
cargo build --release    # or: igl build --release
# Executable located at target/release/hyprlnk
```

Install it into your system path:

```sh
# Copy binary
cp target/release/hyprlnk /usr/local/bin/

# Set up toolchain symlinks
ln -s hyprlnk /usr/local/bin/ld64.hyprlnk                    # macOS Clang support
ln -s hyprlnk /usr/local/bin/ld.hyprlnk                      # Linux Clang support
mkdir -p /usr/local/libexec/hyprlnk
ln -s /usr/local/bin/hyprlnk /usr/local/libexec/hyprlnk/ld   # Linux GCC -B support
```

### Automatic System Library Discovery

- **macOS**: `-l` and `-framework` search in `-L` and `-F` paths, then query the macOS SDK (`-syslibroot`, `SDKROOT`, or Xcode / Command Line Tools SDKs) matching ld64.
- **Windows**: Searches the current working directory, explicit `/LIBPATH:` flags, and directories declared in the `%LIB%` environment variable. If `%LIB%` is unset, hyprlnk automatically discovers the newest installed MSVC toolset and Windows SDK under standard `Program Files` locations.

## Using hyprlnk on Linux

### With Cargo

Configure your `.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"

[target.aarch64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"
```

Because `rustc` passes C-compiler-style flags to unfamiliar linkers, hyprlnk invokes your C compiler (`cc` or `HYPRLNK_CC`) with itself as the compiler's `ld` to locate glibc start files and runtime libraries automatically.

### With rustc Directly

```sh
# Invoke through system C runtime
rustc -C linker=hyprlnk main.rs

# Direct linking for musl targets (no C compiler needed)
rustc --target x86_64-unknown-linux-musl -C linker=hyprlnk -C linker-flavor=ld main.rs
```

### With GCC and Clang

```sh
# GCC
gcc -B/usr/local/libexec/hyprlnk main.c -o app
g++ -B/usr/local/libexec/hyprlnk -O2 *.cpp -o app

# Clang
clang -fuse-ld=hyprlnk main.c -o app
clang --ld-path=/usr/local/bin/hyprlnk main.c -o app

# CMake projects
cmake -DCMAKE_EXE_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk ..
```

## Using hyprlnk on macOS

### With Cargo

Configure your `.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"
rustflags = ["-C", "linker-flavor=ld64.lld"]

[target.x86_64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"
rustflags = ["-C", "linker-flavor=ld64.lld"]
```

### With rustc

```sh
rustc -C linker=hyprlnk main.rs
rustc -C linker=hyprlnk -C linker-flavor=ld64.lld main.rs
```

hyprlnk emits standard Mach-O debug maps. When you specify `-C split-debuginfo=packed` (Cargo's default for release builds with debuginfo), `dsymutil` processes hyprlnk's debug maps to generate standard `.dSYM` bundles.

### With Clang and CMake

```sh
clang -fuse-ld=/usr/local/bin/ld64.hyprlnk main.c -o app
clang++ -fuse-ld=/usr/local/bin/ld64.hyprlnk -std=c++20 *.cpp -o app
clang -fobjc-arc -fuse-ld=/usr/local/bin/ld64.hyprlnk app.m -framework Foundation -o app

cmake -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk ..
```

## Using hyprlnk on Windows

### With Cargo

Configure `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"

[target.aarch64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"
```

Or enable for an active terminal session:

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = "C:\tools\hyprlnk.exe"
```

### With rustc

```powershell
rustc -C linker=hyprlnk.exe main.rs
```

`rustc` automatically passes `/DEBUG` whenever linked code contains debug symbols, producing a full PDB file by default.

### With MSVC, clang-cl, and CMake

```powershell
# Direct MSVC-style invocation
clang-cl /c /O2 main.c util.c
hyprlnk /OUT:app.exe /DEBUG main.obj util.obj user32.lib

# CMake with Ninja
cmake -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
      -DCMAKE_LINKER=C:/tools/hyprlnk.exe ..
```

## Using hyprlnk as a Rust Library

hyprlnk is designed as a modular Rust library. You can link binaries programmatically directly from in-process Rust code:

```rust
// In-process library execution
let config = hyprlnk::coff::Config::parse(&["/OUT:app.exe".into(), "main.obj".into()])?;
hyprlnk::coff::link(config)?;

let config = hyprlnk::macho::Config::parse(&["-o".into(), "app".into(), "main.o".into()])?;
hyprlnk::macho::link(config)?;
```

## Verifying Your Setup

Run a link with built-in profiling to verify execution:

```sh
# Windows: Detailed phase timing table
hyprlnk /OUT:hello.exe /TIME hello.obj

# macOS
hyprlnk -flavor darwin hello.o -lSystem -o hello --time

# Linux
cc -B/usr/local/libexec/hyprlnk -Wl,--time hello.c -o hello
```
