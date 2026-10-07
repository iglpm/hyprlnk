# hyprlnk

**hyprlnk** ("hyperlink") is a linker developed together with Rune and built
into it. The goal is to link faster than lld, and to need nothing installed
beyond the platform's libraries.

It is a Rust library first (`hyprlnk::main_with_args`, `hyprlnk::coff::link`)
with a small `hyprlnk` executable on top. Rune links with the copy compiled
into its own executable.

## Status

The first backend links **PE/COFF for x86-64 Windows**: executables and DLLs,
from `link.exe`/`lld-link` command lines, which is what `rustc` passes on
`*-windows-msvc` targets. It links Rust (debug and release, unwinding,
thread-locals, proc-macros, `cdylib`s with import libraries), C and C++ (MSVC
exceptions, static constructors, the static and DLL C runtimes). Rune's own
test suite passes with every test binary linked by it.

| | |
| --- | --- |
| Inputs | COFF objects (regular and `/bigobj`), archives (rlibs, `.lib`, GNU/BSD `.a`), short and long import libraries, `.def` files, `@response` files (UTF-8/UTF-16) |
| Resolution | lazy archive members, COMDAT selection (any, no-duplicates, largest, associative), weak externals, `/ALTERNATENAME`, common symbols, `/DEFAULTLIB` and the rest of `.drectve`, locally defined `__imp_` symbols, `/FAILIFMISMATCH` |
| Output | `/OPT:REF` garbage collection, link.exe's section grouping and ordering, import tables and thunks, exports and import libraries, base relocations, sorted exception table, TLS and load configuration directories, deterministic timestamp, `/RELEASE` checksum |
| Diagnostics | undefined and duplicate symbols with the files involved (Rust names demangled), `/TIME`, `/VERBOSE`, `/REPRODUCE` |

Not yet: PDB debug info, identical code folding (`/OPT:ICF` is accepted and
ignored, so release binaries are somewhat larger than lld's), resources
(`.res`), delay-loaded imports, LTO inputs (bitcode), x86 and ARM64, and the
ELF and Mach-O backends. See [the roadmap](#roadmap).

## Using it

**From Rune** (`Rune.toml`, `~/.rune/config.toml` or `RUNE_BUILD_LINKER`):

```toml
[build]
linker = "hyprlnk"
```

Rune then passes its own executable to `rustc` as the linker and sets
`RUNE_HYPRLNK` on the compiler, so that executable links. The cache key of
everything it links names the hyprlnk version, so updating hyprlnk relinks,
and switching linkers back and forth comes from the cache. Targets hyprlnk
can't link yet keep their usual linker. `rune __hyprlnk <args>` runs the
built-in linker by hand.

**Standalone**, build it with Rune and point `rustc` (or anything that runs
`link.exe`) at it:

```sh
rune build -p hyprlnk --release
rustc -C linker=.rune/target/release/hyprlnk.exe main.rs
hyprlnk /OUT:app.exe main.obj util.obj kernel32.lib
```

When `%LIB%` isn't set, hyprlnk finds the newest installed MSVC toolset and
Windows SDK by itself.

## Speed

Linking Rune itself (dev profile: 2,337 objects from 221 archives, 715 MB of
input, a 32 MB executable) on a 12-thread Windows machine, best of 7, wall
time including about 70 ms of process startup each:

| Linker | Time |
| --- | ---: |
| **hyprlnk** | **339 ms** |
| hyprlnk `/THREADS:1` | 599 ms |
| lld-link 22, `/DEBUG:NONE` | 781 ms |
| rust-lld, `/DEBUG:NONE` | 791 ms |
| lld-link 22 writing a PDB (what `rustc` asks for by default) | 1,835 ms |

The fair comparison is against lld without a PDB, since hyprlnk doesn't write
one. Reproduce it with `/REPRODUCE:<dir>` (below) and
`hyprlnk @<dir>/link.rsp` vs `lld-link @<dir>/link.rsp /DEBUG:NONE`; `/TIME`
shows where the time goes.

Where the speed comes from:

- **Nothing is copied that needn't be.** Inputs are memory-mapped and parsed
  in place; only section headers and external symbols are decoded up front.
  The output is built directly in a memory-mapped file.
- **Parallel waves.** Everything waiting to be loaded is parsed on all
  threads at once, then merged in a fixed order (deterministic output). Each
  name is hashed (xxh3) and looked up in the global table on the parsing
  threads, so the one sequential step only handles genuinely new symbols.
- **Parallel everywhere else that counts:** garbage collection marks
  frontier by frontier, sections are copied and relocated in batches on all
  threads, and the exception table is sorted in parallel.
- **No teardown.** As a process (or inside Rune's), hyprlnk exits without
  unmapping its inputs or freeing its memory piece by piece: on Rune's link
  that alone was a quarter of the wall time.

## Layout

| | |
| --- | --- |
| `src/lib.rs` | public API, flavor dispatch (`-flavor`, program name) |
| `src/fileio.rs` | input mapping, the arena that owns inputs, the output file |
| `src/cmdline.rs` | response files and Windows command-line quoting |
| `src/archive.rs` | `ar` reader (symbol tables, long names) and writer |
| `src/coff/config.rs` | `link.exe` options |
| `src/coff/object.rs` | COFF objects |
| `src/coff/import.rs` | short import objects |
| `src/coff/symtab.rs` | the global symbol table |
| `src/coff/resolve.rs` | loading inputs, symbol resolution, COMDATs, directives |
| `src/coff/gc.rs` | which sections are written (`/OPT:REF`) |
| `src/coff/synth.rs` | import tables, thunks, exports, common symbols |
| `src/coff/layout.rs` | output sections and addresses |
| `src/coff/write.rs` | relocation, base relocations, PE headers |
| `src/coff/implib.rs` | import libraries for DLLs |
| `src/coff/def.rs` | `/EXPORT` and `.def` files |
| `src/coff/reproduce.rs` | `/REPRODUCE` |
| `src/coff/winsdk.rs` | library search paths, MSVC/SDK discovery |

## Testing

`rune test -p hyprlnk` runs the unit tests everywhere and, on Windows with
the MSVC libraries installed, end-to-end tests that link programs with
`rustc -C linker=hyprlnk` and run them (unwinding, threads, thread-locals,
DLLs and import libraries, error messages, reproducible output).

For a real-world check, build Rune with itself and run its test suite:

```sh
RUNE_BUILD_LINKER=hyprlnk rune test --workspace
```

`/REPRODUCE:<dir>` (or `HYPRLNK_REPRODUCE=<dir>`, which also reaches links
run by `rustc` under Rune) copies a link's inputs to
`<dir>/<output>-<pid>/` with a `link.rsp` that repeats it: the way to keep
a link that misbehaves, and to benchmark against other linkers.

## Roadmap

1. **ELF** (`ld.hyprlnk`, GNU flavor), so Rune's main platforms get it:
   static and dynamic executables and shared objects for x86-64 and AArch64
   Linux, driven through `cc -fuse-ld`.
2. **Identical code folding** for smaller release binaries.
3. **PDB** output, so debuggers see hyprlnk-linked binaries' symbols.
4. Resources, delay-loading, ARM64 Windows.
5. **Mach-O.**
6. Faster still: parallel symbol resolution and section layout, and
   incremental relinking inside Rune (keeping the previous link's state
   between builds).
