<div align="center">

# hyprlnk

**The fastest linker for Windows and macOS.**

A drop-in replacement for `link.exe` and `lld-link` on Windows (x64, ARM64,
x86, PDBs included) and for Apple's `ld` and `ld64.lld` on macOS (arm64,
arm64e, x86_64, code-signed, debug map included) — about twice as fast as
the fastest of them.

Built for [Rune](https://runepm.com), usable by everyone.

```sh
rune build                                                 # with build.linker = "hyprlnk"
rustc -C linker=hyprlnk main.rs                            # any toolchain that runs a linker
clang -fuse-ld=/path/to/ld64.hyprlnk main.c                # C, C++, Objective-C on macOS
```

</div>

---

## Why hyprlnk

Every Rust, C and C++ build ends the same way: the linker reads hundreds of
megabytes of objects and writes one executable. It runs after every edit,
and nothing else can start until it is done. hyprlnk makes that wait as short
as possible.

**macOS** — linking Rune itself (dev build: 460 inputs, 609 MB, a 90 MB
executable), Apple M5:

| | hyprlnk | Apple `ld` (ld-prime) | ld64.lld 23 |
| --- | ---: | ---: | ---: |
| Wall time, median | **75 ms** | 172 ms | 310 ms |

**Windows** — linking Rune itself (dev build: 2,337 objects, 715 MB of input),
Core i5-10400F:

| | hyprlnk | lld-link 22 |
| --- | ---: | ---: |
| Executable only | **440 ms** | 845 ms |
| Executable + PDB (what `rustc` asks for by default) | **1.09 s** | 1.93 s |
| … on a single thread | 1.95 s | — |

The output is the same size as lld's, byte-for-byte reproducible, and passes
Rune's whole test suite on both systems. [How it was measured →](docs/performance.md)

## What makes it fast

- **Zero-copy inputs.** Objects, libraries and text stubs are memory-mapped
  and parsed in place; symbol names are hashed once, on the parsing threads.
- **Parallel everywhere.** Inputs are parsed in waves on all cores; dead code
  is found by work-stealing marking; sections are copied and relocated in
  batches; the symbol table, export trie, fixups and unwind info are built
  side by side.
- **One walk over relocations.** On macOS, marking what is live also decides
  every stub, GOT slot, rebase and bind, so relocations are read twice per
  link (mark, write) and never more.
- **The debug info is built while the image is written** — a PDB on Windows,
  the stabs debug map on macOS — not after it.
- **Writing overlaps signing.** On macOS the file is written by helper
  threads while the code signature is hashed, two pages at a time on the SHA
  unit.
- **No wasted copies, no teardown.** The process exits without unmapping its
  inputs or freeing millions of small allocations one by one.

## Everything a build needs

| Windows | x64 | ARM64 | x86 |
| --- | :---: | :---: | :---: |
| Executables, DLLs, import libraries | ✅ | ✅ | ✅ |
| Rust (`*-pc-windows-msvc`), C and C++ (clang-cl, MSVC objects) | ✅ | ✅ | ✅ |
| PDB: symbols, types, line tables, natvis visualizers | ✅ | ✅ | ✅ |
| `/OPT:REF` garbage collection, `/OPT:ICF` code folding | ✅ | ✅ | ✅ |
| Resources, exceptions, TLS, load config, exports, `.def` files | ✅ | ✅ | ✅ (SafeSEH) |

| macOS | arm64 | arm64e | x86_64 |
| --- | :---: | :---: | :---: |
| Executables, dylibs, bundles | ✅ | ✅ | ✅ |
| Rust (`*-apple-darwin`), C, C++, Objective-C | ✅ | ✅ | ✅ |
| Debug map for `dsymutil`, lldb and Rust backtraces | ✅ | ✅ | ✅ |
| Compact unwind info + DWARF CFI, C++ and Rust exceptions | ✅ | ✅ (signed) | ✅ |
| Classic dyld info and chained fixups | ✅ | chained | ✅ |
| Ad-hoc code signature, `-dead_strip`, TLS, weak coalescing | ✅ | ✅ | ✅ |

It reads what each platform's toolchains produce — COFF and Mach-O objects,
rlibs and static libraries, import libraries, dylibs and `.tbd` text stubs
(also universal files), resource and `.def` files — and finds the Windows SDK
and MSVC libraries, or the macOS SDK, by itself.

- **Reproducible.** The same inputs give the same output, byte for byte; the
  timestamp, PDB GUID and Mach-O UUID are content hashes.
- **Debuggable.** PDBs that `dbghelp`, WinDbg and Visual Studio read; on
  macOS, a debug map that `dsymutil` turns into a dSYM and lldb and Rust's
  backtraces follow to the objects' DWARF.
- **Explains itself.** `/TIME` or `--time` shows where every millisecond went,
  and `/REPRODUCE` or `HYPRLNK_REPRODUCE` packs a link into a directory you
  can replay — or attach to a bug report.

## Get started

**With Rune** — in `Rune.toml`, `~/.rune/config.toml`, or `RUNE_BUILD_LINKER`:

```toml
[build]
linker = "hyprlnk"
```

Nothing to install: the linker is built into `rune`, for Windows and macOS
targets alike.

**With Cargo** — build hyprlnk, then in `.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"

[target.x86_64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"
```

**Anywhere else** — it takes the platform linker's command lines:

```sh
hyprlnk /OUT:app.exe /DEBUG main.obj util.obj user32.lib       # link.exe style
hyprlnk -arch arm64 -platform_version macos 11.0 15.0 \
        -syslibroot "$(xcrun --show-sdk-path)" main.o -lSystem -o app   # ld64 style
clang -fuse-ld=/usr/local/bin/ld64.hyprlnk main.c -o app         # through clang
```

**Build it**: `rune build -p hyprlnk --release` (or `cargo build --release`)
in this directory. [Installation and integration guide →](docs/getting-started.md)

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | install, use with Rune, Cargo, rustc, CMake, clang, clang-cl |
| [macOS](docs/macos.md) | the Mach-O linker: what it writes, debug info, signing, arm64e |
| [Command line](docs/command-line.md) | every option, `link.exe` and ld64 style |
| [Debug info (PDB)](docs/pdb.md) | what goes in, how it's built, natvis, determinism |
| [Performance](docs/performance.md) | benchmarks, methodology, where the time goes |
| [Compatibility](docs/compatibility.md) | inputs, features, differences from the platform linkers |
| [Architecture](docs/architecture.md) | how the linker is put together |
| [Troubleshooting](docs/troubleshooting.md) | errors, `--time`, `/REPRODUCE`, reporting bugs |
| [Roadmap](docs/roadmap.md) | what's next: ELF, and more |

## Status

hyprlnk links PE/COFF images for Windows on x64, ARM64 and x86, and Mach-O
images for macOS on arm64, arm64e and x86_64. It links Rune — 250 crates,
build scripts, proc-macros, tests — and Rune's test suite passes with every
binary linked by it, on both systems. ELF (Linux) is next on the
[roadmap](docs/roadmap.md).

## Contributing

Bug reports with a `/REPRODUCE` archive, benchmarks on your projects, and pull
requests are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md).

## License

Dual-licensed under [MIT](LICENSE-MIT.md) or [Apache 2.0](LICENSE-APACHE.md), at
your option.
