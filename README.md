<div align="center">

# hyprlnk

**The next-generation, high-performance linker for Windows, macOS, and Linux.**

A drop-in replacement for Microsoft's `link.exe` and `lld-link` on Windows (x64, ARM64, x86 with full PDB support), for Apple's `ld` and `ld64.lld` on macOS (arm64, arm64e, x86_64 with code-signing and debug maps) — running roughly **twice as fast** as the fastest alternatives — and for GNU `ld`, `ld.lld`, and `mold` on Linux.

Integrated directly into [Igel](https://runepm.com), and fully usable as a standalone tool by any Rust, C, or C++ project.

```sh
igl build                                                 # Igel links with hyprlnk by default
rustc -C linker=hyprlnk main.rs                            # Any toolchain that invokes a linker
clang -fuse-ld=/path/to/ld64.hyprlnk main.c                # C, C++, Objective-C on macOS
gcc -B/path/to/dir-with-hyprlnk-as-ld main.c               # C and C++ on Linux
```

</div>

## Why Linker Speed Matters

Every build cycle ends at the same bottleneck: the linker must read hundreds of megabytes of object files, resolve hundreds of thousands of symbols, and write an executable. The linker runs after every single edit, blocking test execution and debugging until it finishes.

hyprlnk is built from the ground up to make that wait as brief as physically possible.

### Real-World Benchmarks

**macOS (Apple Silicon M5)** — Linking Igel (dev profile: 460 inputs, 609 MB input data, 90 MB output binary):

| Linker | Median Wall Time | Relative Speed |
| :--- | :---: | :---: |
| **hyprlnk** | **75 ms** | **Baseline (Fastest)** |
| Apple `ld` (ld-prime) | 172 ms | 2.3× slower |
| ld64.lld 23 | 310 ms | 4.1× slower |

**Windows (Intel Core i5-10400F)** — Linking Igel (dev profile: 2,337 object files, 715 MB input data):

| Scenario | hyprlnk | lld-link 22 | Speedup |
| :--- | :---: | :---: | :---: |
| Executable only (`/DEBUG:NONE`) | **440 ms** | 845 ms | **1.9× faster** |
| Executable + PDB (Standard rustc default) | **1.09 s** | 1.93 s | **1.8× faster** |
| Executable + PDB (Single-threaded) | 1.95 s | — | |

**Linux (Intel Core i5-10400F, tmpfs output)** — Median of 11 interleaved benchmark runs:

| Workload | hyprlnk | wild 0.10 | mold 3.0 | lld 23 |
| :--- | :---: | :---: | :---: | :---: |
| Igel, dev build (3,640 objects, 600 MB in, 308 MB out) | 258 ms | **255 ms** | 427 ms | 478 ms |
| hyprlnk, dev build (716 MB in, 381 MB out) | 267 ms | **253 ms** | 386 ms | 409 ms |
| Igel without debug info (`-S`) | 138 ms | **100 ms** | 256 ms | 311 ms |

Outputs match `lld` in byte size, guarantee byte-for-byte reproducibility, and pass Igel's complete test suite across all three operating systems. Read our full [Performance Analysis & Methodology](docs/performance.md).

## Architectural Innovations: Why hyprlnk Is So Fast

- **Zero-Copy Memory-Mapped I/O**: Object files, static libraries, and text stubs are mapped into memory and parsed in-place. Symbol strings are hashed once on parallel parsing threads.
- **Deep Concurrency Everywhere**: Input archives parse in concurrent waves across all CPU cores; dead-code elimination uses lock-free work-stealing marking; sections are copied and relocated in batches; symbol tables, export tries, and unwind data construct concurrently.
- **Single-Pass Relocation Scanning**: On macOS, live-atom marking classifies every dynamic stub, GOT entry, rebase, and bind in a single pass. Relocations are visited twice per link (mark and write) and never re-scanned.
- **Concurrent Debug Generation**: On Windows, PDB generation (type records, module streams, symbol records) executes concurrently alongside PE image writing, rather than sequentially after image emission.
- **Pipelined Code Signing**: On macOS, disk writes stream via helper threads while code signatures hash across hardware SHA acceleration units.
- **Instant Process Teardown**: Leaves memory unmapping to OS process exit rather than expending millions of CPU cycles tearing down individual memory allocations.

## Comprehensive Platform Capabilities

### Windows (PE/COFF)

| Feature | x64 | ARM64 | x86 |
| :--- | :---: | :---: | :---: |
| Executables, DLLs, import libraries | Supported | Supported | Supported |
| Toolchains: Rust (`*-pc-windows-msvc`), MSVC, clang-cl | Supported | Supported | Supported |
| Debug info: Full PDB (symbols, types, line tables, Natvis) | Supported | Supported | Supported |
| Optimization: `/OPT:REF` garbage collection, `/OPT:ICF` folding | Supported | Supported | Supported |
| Resources, exceptions, TLS, export directives, `.def` files | Supported | Supported | Supported (SafeSEH) |

### Linux (ELF)

| Feature | x86-64 | x86 | AArch64 | ARM | RISC-V 64 | ppc64le | s390x | LoongArch |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Executables (PIE, static, static-pie), shared objects | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Supported |
| Toolchains: Rust (`*-linux-gnu*`, `*-linux-musl*`), C, C++ | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Supported |
| Relaxations: TLS model relaxations | Supported | Supported | Supported | — | — | — | Supported | — |
| Relaxations: GOT-load relaxations | Supported | — | — | — | — | — | — | — |
| Optimization: `--gc-sections`, symbol versions, IFUNC, RELRO | Supported | Supported | Supported | Supported | Supported | Supported | Supported | Supported |

### macOS (Mach-O)

| Feature | arm64 | arm64e | x86_64 |
| :--- | :---: | :---: | :---: |
| Executables, dylibs, bundles | Supported | Supported | Supported |
| Toolchains: Rust (`*-apple-darwin`), C, C++, Objective-C | Supported | Supported | Supported |
| Debug info: Debug map for `dsymutil`, lldb, and Rust backtraces | Supported | Supported | Supported |
| Unwinding: Compact unwind info + DWARF CFI, C++/Rust exceptions | Supported | Supported (signed) | Supported |
| Fixups: Classic dyld info and modern chained fixups | Supported | Chained fixups | Supported |
| Security: Ad-hoc code signatures, `-dead_strip`, weak coalescing | Supported | Supported | Supported |

## Production Reliability

- **Deterministic & Reproducible**: Identical inputs always emit identical bytes. Timestamps, PDB GUIDs, Mach-O UUIDs, and ELF build IDs are cryptographic content hashes.
- **First-Class Debugging**: PDBs load cleanly in WinDbg, Visual Studio, and `dbghelp`. Mach-O debug maps integrate seamlessly with `dsymutil`, lldb, and Rust backtraces.
- **Built-In Profiling**: Passing `/TIME` or `--time` outputs a precise breakdown of every linking phase. Passing `/REPRODUCE` or setting `HYPRLNK_REPRODUCE` bundles all link inputs into a self-contained archive for instant bug reproduction.

## Quickstart & Integration

### With Igel

Zero setup needed. `igl` embeds hyprlnk and uses it as the default linker on Linux, macOS, and Windows. To fall back to platform default linkers, configure `linker = "default"` in `Igel.toml`.

### With Cargo

Build hyprlnk, then configure `.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"

[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"

[target.x86_64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"
```

### Standalone CLI Invocations

hyprlnk seamlessly parses platform-native linker flags:

```sh
# MSVC link.exe syntax (Windows)
hyprlnk /OUT:app.exe /DEBUG main.obj util.obj user32.lib

# Apple ld64 syntax (macOS)
hyprlnk -arch arm64 -platform_version macos 11.0 15.0 \
        -syslibroot "$(xcrun --show-sdk-path)" main.o -lSystem -o app

# Invocation through Clang
clang -fuse-ld=/usr/local/bin/ld64.hyprlnk main.c -o app

# Invocation through GCC (Linux)
gcc -B/usr/local/libexec/hyprlnk main.c -o app
```

Build the release binary directly with `cargo build --release` (or `igl build --release`). Check our complete [Getting Started Guide](docs/getting-started.md).

## Documentation

| Guide | Description |
| :--- | :--- |
| [Getting Started](docs/getting-started.md) | Setup instructions for Igel, Cargo, rustc, GCC, Clang, and CMake |
| [Linux ELF Linker](docs/linux.md) | ELF architecture support, dynamic loader tables, and glibc/musl details |
| [macOS Mach-O Linker](docs/macos.md) | Mach-O binary formats, chained fixups, signing, and Apple Silicon tuning |
| [Command Line Options](docs/command-line.md) | Complete CLI reference for MSVC, ld64, and GNU ld flag flavors |
| [Windows PDB Debug Info](docs/pdb.md) | Fast PDB generation, Natvis visualizers, and determinism |
| [Performance Analysis](docs/performance.md) | Benchmarking methodology, phase profiling, and memory scaling |
| [Compatibility Matrix](docs/compatibility.md) | Input file formats, architecture support, and platform parity |
| [Linker Architecture](docs/architecture.md) | Internal pipeline design, threading model, and codebase tour |
| [Troubleshooting](docs/troubleshooting.md) | Diagnostic options, phase profiling with `/TIME`, and bug reporting |
| [Roadmap](docs/roadmap.md) | Upcoming platform features, optimizations, and roadmap goals |

## Project Status

hyprlnk links production PE/COFF images on Windows, Mach-O binaries on macOS, and ELF executables and shared libraries on Linux across all primary architectures. It is validated against Igel's entire test suite and production builds.

## Contributing

We welcome benchmark results on real-world projects, bug reports with reproducible `/REPRODUCE` bundles, and pull requests. Check out [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Dual-licensed under either the [Apache License, Version 2.0](LICENSE-APACHE.md) or the [MIT License](LICENSE-MIT.md), at your option.
