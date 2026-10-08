# Getting started

hyprlnk takes the same command lines as Microsoft's `link.exe` and LLVM's
`lld-link`, so anything that can run one of those can run hyprlnk.

## Installing

### With Rune: nothing to install

[Rune](https://runepm.com) has hyprlnk built in. Turn it on for a project in
`Rune.toml`, for every project in `~/.rune/config.toml`, or for one build
with an environment variable:

```toml
[build]
linker = "hyprlnk"
```

```powershell
$env:RUNE_BUILD_LINKER = "hyprlnk"; rune build
```

Rune then links binaries, tests, build scripts and `cdylib`s for
`x86_64`, `aarch64` and `i686` `*-pc-windows-msvc` targets with hyprlnk, and
keeps the platform linker for other targets. The setting takes precedence
over `target.<triple>.linker` in `.cargo/config.toml`. Linked artifacts are
cached under a key that names the hyprlnk version, so switching linkers back
and forth is instant and upgrading hyprlnk relinks.

### Building the standalone executable

hyprlnk is a self-contained Rust crate. From the `hyprlnk/` directory:

```powershell
rune build --release        # or: cargo build --release
# → target/release/hyprlnk.exe (with Cargo) or .rune/target/release/hyprlnk.exe
```

Copy `hyprlnk.exe` anywhere; it needs nothing but the Windows SDK and MSVC
libraries your programs link against.

### Finding libraries

Like `lld-link`, hyprlnk searches for libraries in the current directory,
then each `/LIBPATH:`, then the directories in `%LIB%`. `rustc` and Visual
Studio developer prompts set `%LIB%`. When it isn't set, hyprlnk looks up the
newest installed MSVC toolset and Windows SDK itself (`%VCToolsInstallDir%`,
then the default `Program Files` locations), for the machine being linked.

## Using it

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

### As a library

hyprlnk is a Rust library first. Link from your own program with a parsed
configuration, or a whole command line:

```rust
// Exits-after style (what the hyprlnk binary does):
let code = hyprlnk::main_with_args(["hyprlnk", "/OUT:app.exe", "main.obj"]);

// Repeatable, in-process:
let cfg = hyprlnk::coff::Config::parse(&["/OUT:app.exe".into(), "main.obj".into()])?;
hyprlnk::coff::link(cfg)?;
```

`main_with_args` leaves the link's memory to the operating system (it is meant
for processes that exit right after); `coff::link` frees everything.

## Checking it works

```powershell
hyprlnk /OUT:hello.exe /TIME hello.obj    # prints a per-phase timing table
hyprlnk --version
```

If something goes wrong, see [troubleshooting](troubleshooting.md).
