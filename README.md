<div align="center">

# hyprlnk

**The fastest linker for Windows.**

A drop-in replacement for `link.exe` and `lld-link`: x64, ARM64 and x86,
executables and DLLs, PDB debug info included — about twice as fast as lld.

Built for [Rune](https://runepm.com), usable by everyone.

```powershell
rune build                          # with build.linker = "hyprlnk"
rustc -C linker=hyprlnk main.rs     # or with any toolchain that runs link.exe
```

</div>

---

## Why hyprlnk

Every Rust, C and C++ build on Windows ends the same way: the linker reads
hundreds of megabytes of objects and writes an executable and a PDB. It runs
after every edit, and nothing else can start until it is done. hyprlnk makes
that wait as short as possible.

| Linking Rune itself (dev build: 2,337 objects, 715 MB of input) | hyprlnk | lld-link 22 |
| --- | ---: | ---: |
| Executable only | **440 ms** | 845 ms |
| Executable + PDB (what `rustc` asks for by default) | **1.09 s** | 1.93 s |
| … on a single thread | 1.95 s | — |

hyprlnk on **one** thread keeps pace with lld on twelve. The output is the
same size as lld's (the PDB 0.15 % smaller), byte-for-byte reproducible, and
passes Rune's whole test suite. [How it was measured →](docs/performance.md)

## What makes it fast

- **Zero-copy inputs.** Objects and libraries are memory-mapped and parsed in
  place; only section headers and external symbols are decoded up front.
- **Parallel everywhere.** Inputs are parsed in waves on all cores, symbol
  names are hashed and looked up on the parsing threads, garbage collection
  marks frontier by frontier, sections are copied and relocated in batches,
  and the exception table is sorted in parallel.
- **The PDB is built while the image is written** — not after it.
- **Type merging without locks.** Every type record gets a content hash on its
  own object's thread; duplicates collapse in a lock-free table; final
  indices come from prefix sums. 2.4 million type records from 2,335 objects
  merge in about 110 ms.
- **No wasted copies, no teardown.** The output is built inside a
  memory-mapped file, and the process exits without unmapping its inputs or
  freeing millions of small allocations one by one.

## Everything a Windows build needs

| | x64 | ARM64 | x86 |
| --- | :---: | :---: | :---: |
| Executables, DLLs, import libraries | ✅ | ✅ | ✅ |
| Rust (`*-pc-windows-msvc`), C and C++ (clang-cl, MSVC objects) | ✅ | ✅ | ✅ |
| PDB: symbols, types, line tables, natvis visualizers | ✅ | ✅ | ✅ |
| `/OPT:REF` garbage collection, `/OPT:ICF` code folding | ✅ | ✅ | ✅ |
| Resources (`.res`: icons, manifests, version info) | ✅ | ✅ | ✅ |
| Exceptions & unwinding, thread-local storage, load config | ✅ | ✅ | ✅ (SafeSEH) |
| Exports, `.def` files, `/WHOLEARCHIVE`, `/ALTERNATENAME`, … | ✅ | ✅ | ✅ |

It reads what Windows toolchains produce — COFF objects (including
`/bigobj`), rlibs and static libraries, short and long import libraries,
`.res` and `.def` files, UTF-8 and UTF-16 response files — and finds the MSVC
and Windows SDK libraries by itself when `%LIB%` isn't set.

- **Reproducible.** The same inputs give the same image and PDB, byte for
  byte; the timestamp and PDB GUID are content hashes.
- **Debuggable.** PDBs follow the layout Microsoft's tools read: `dbghelp`
  (the engine behind WinDbg and Rust's backtraces) resolves names, files and
  lines from them, LLVM's PDB tools read every record, and Rust's natvis
  visualizers are embedded for Visual Studio and VS Code.
- **Explains itself.** `/TIME` shows where every millisecond went, `/VERBOSE`
  what was loaded and folded, and `/REPRODUCE:<dir>` packs a link into a
  directory you can replay — or attach to a bug report.

## Get started

**With Rune** — in `Rune.toml`, `~/.rune/config.toml`, or `RUNE_BUILD_LINKER`:

```toml
[build]
linker = "hyprlnk"
```

Nothing to install: the linker is built into `rune`.

**With Cargo** — build hyprlnk, then in `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"

[target.aarch64-pc-windows-msvc]
linker = "C:\\tools\\hyprlnk.exe"
```

**Anywhere else** — it takes `link.exe` command lines:

```powershell
hyprlnk /OUT:app.exe /DEBUG main.obj util.obj user32.lib
cmake -G Ninja -DCMAKE_LINKER=hyprlnk.exe ..
```

**Build it**: `rune build -p hyprlnk --release` (or `cargo build --release`)
in this directory. [Installation and integration guide →](docs/getting-started.md)

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | install, use with Rune, Cargo, rustc, CMake, clang-cl |
| [Command line](docs/command-line.md) | every option |
| [Debug info (PDB)](docs/pdb.md) | what goes in, how it's built, natvis, determinism |
| [Performance](docs/performance.md) | benchmarks, methodology, where the time goes |
| [Compatibility](docs/compatibility.md) | inputs, features, differences from `link.exe`/`lld-link` |
| [Architecture](docs/architecture.md) | how the linker is put together |
| [Troubleshooting](docs/troubleshooting.md) | errors, `/VERBOSE`, `/REPRODUCE`, reporting bugs |
| [Roadmap](docs/roadmap.md) | what's next: ELF, Mach-O, and more |

## Status

hyprlnk links PE/COFF images for Windows on x64, ARM64 and x86. It links
Rune — 250 crates, build scripts, tests — and Rune's test suite
passes with every binary linked by it. ELF (Linux) and Mach-O (macOS)
backends are next on the [roadmap](docs/roadmap.md).

## Contributing

Bug reports with a `/REPRODUCE` archive, benchmarks on your projects, and pull
requests are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md).

## License

Dual-licensed under [MIT](LICENSE-MIT.md) or [Apache 2.0](LICENSE-APACHE.md), at
your option.
