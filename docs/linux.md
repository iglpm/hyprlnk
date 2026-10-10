# Linux

hyprlnk links ELF executables and shared objects for **x86-64**, **x86**,
**AArch64**, **32-bit ARM** (ARMv5TE and later, ARM and Thumb-2), **RISC-V**
(64- and 32-bit), **POWER** (little-endian ppc64, ELFv2), **s390x** and
**LoongArch64**, against glibc or musl. It takes the command lines of GNU
`ld`, `ld.lld`, mold and wild — what gcc's `collect2`, clang and rustc
write — and the `cc`-style command line rustc writes for a linker it doesn't
recognize.

## Using it

### With Rune

Rune links with hyprlnk by default: binaries, tests, build scripts,
proc-macros and dynamic libraries, for every `*-unknown-linux-gnu*` and
`*-unknown-linux-musl*` target on the architectures above. rustc runs the
`rune` executable as its linker, which runs the target's C compiler (the
`target.<triple>.linker` named in `.cargo/config.toml`, else `cc`) with
hyprlnk as that compiler's `ld`. The C compiler contributes what only it
knows — the C runtime's start files, libgcc, the system's library
directories — and hyprlnk does the linking.

To use the linker rustc and Cargo would choose instead:

```toml
[build]
linker = "default"
```

### With Cargo or rustc

Name hyprlnk as the linker:

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
linker = "/usr/local/bin/hyprlnk"
```

rustc then passes the command line it would give `cc`. hyprlnk recognizes it
and runs `cc` (or the compiler in `HYPRLNK_CC`) with a private directory
holding itself as `ld` in front of `-B`, and drops the `-fuse-ld=lld` rustc
adds on `x86_64-unknown-linux-gnu`. For a cross build, keep the cross
compiler as the linker and hand it hyprlnk:

```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
rustflags = ["-C", "link-arg=-B/usr/local/libexec/hyprlnk"]
```

(`/usr/local/libexec/hyprlnk/ld` is a link to `hyprlnk`; a program name of
`ld` or `ld.*` selects the GNU command line, as does `-flavor gnu`.) musl
targets need no C compiler at all — they bring their own C runtime:

```sh
rustc --target x86_64-unknown-linux-musl -C linker=hyprlnk -C linker-flavor=ld main.rs
```

### C and C++

```sh
gcc -B/usr/local/libexec/hyprlnk main.c util.c -o app
clang -fuse-ld=hyprlnk main.c -o app        # runs ld.hyprlnk from PATH
clang --ld-path=/usr/local/bin/hyprlnk main.c -o app
cmake -DCMAKE_EXE_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-B/usr/local/libexec/hyprlnk ..
```

### Finding libraries

Like lld and unlike GNU ld, hyprlnk has no library directories of its own:
`-l` looks in the `-L` directories, which compiler drivers pass. `-lfoo`
prefers `libfoo.so` to `libfoo.a` unless `-Bstatic` or `-static` is in
effect; `-l:file` finds a file by name. Input linker scripts — glibc's
`libc.so`, `libgcc_s.so` — are followed (`GROUP`, `INPUT`, `AS_NEEDED`,
`SEARCH_DIR`), with `--sysroot` applied to their absolute paths.

## What it writes

| | |
| --- | --- |
| Outputs | position-independent executables (what compilers ask for by default), `-no-pie` executables, static executables (`-static`, `-static-pie`) and shared objects (`-shared`) |
| Dynamic linking | `.dynamic`, `.dynsym`, `.gnu.hash` and/or `.hash` (`--hash-style`), symbol versions (`.gnu.version`, `_r`, `_d`) from version scripts and from the shared objects linked against, `DT_NEEDED` with `--as-needed`, `DT_RUNPATH`/`DT_RPATH`, `DT_SONAME` |
| Relocations | GOT and PLT; copy relocations and canonical PLT entries in non-PIC executables; IFUNC through `R_*_IRELATIVE`, in static executables too (`__rela_iplt_start`/`_end`); RELRO (`-z relro`, `-z now`) |
| Thread locals | the general-dynamic, local-dynamic, initial-exec and local-exec models and TLS descriptors, relaxed to initial-exec or local-exec in executables where the architecture defines how (x86-64, x86, AArch64, s390x) |
| Unwinding | `.eh_frame` without the entries of removed code, and `.eh_frame_hdr`'s search table (`--eh-frame-hdr`); on 32-bit ARM, `.ARM.exidx` sorted by address and closed by an `EXIDX_CANTUNWIND` entry |
| Debug info | DWARF sections copied and relocated; `.debug_str`, `.debug_line_str` and every other mergeable section deduplicated; references to removed code get tombstone values, as lld writes them; sections compressed with zlib or zstd (`-gz`, the default of some distributions' assemblers) decompressed |
| Identity | `--build-id` hashed from the contents (sized like the named algorithm: `sha1` 20 bytes, `md5` 16, `fast` 8; tools only compare build IDs), or `uuid` / `0x…`; a `Linker: hyprlnk <version>` line in `.comment` |
| Garbage collection | `--gc-sections`, keeping `.init_array`/`.fini_array`, notes, `SHF_GNU_RETAIN` sections and sections whose names are C identifiers that `__start_`/`__stop_` symbols refer to; `--print-gc-sections` |
| Also | `-Map` (in lld's format), `--version-script`, `--dynamic-list`, `--export-dynamic`, `-Bsymbolic`, `--wrap`, `--defsym`, `--exclude-libs`, `-z noexecstack`, `--build-id`, `-s`/`-S` |

It rewrites GOT loads of symbols defined in the image into address
computations (on x86-64 `mov` → `lea` and indirect calls and jumps into
direct ones), switches ARM code to Thumb and back with `blx` or a small
thunk, and calls through the TOC and stubs ppc64's ABI requires.

## Linking, the parts that matter

- **Symbol resolution.** As in GNU ld: strong definitions beat weak ones,
  which beat common symbols, which beat shared objects; the first file wins a
  tie. Every archive is searched as if in one `--start-group`, so the order
  of libraries doesn't matter. COMDAT groups: the first copy loaded wins.
- **Archive members** load in parallel waves: each wave loads the members
  that define what the previous wave left undefined.
- **Shared objects.** Their definitions are bound with the version they
  carry, references from them export the symbols they need, and
  `--as-needed` libraries are recorded only if something used them.
- **Executables are written in place.** If the output exists, is a regular
  file of yours with no other links, and isn't running, hyprlnk overwrites
  it, as mold and wild do: on Linux, reusing a file's pages is much cheaper
  than allocating new ones. Otherwise — a file hard-linked into Rune's store,
  a running program, any shared library (a running process may have it
  mapped) — the output is a new file, renamed into place.
- **Reproducible.** The same inputs give the same output, byte for byte.

## Debugging what it wrote

```sh
cc -B/usr/local/libexec/hyprlnk -Wl,--time …   # where the time went
readelf -p .comment app                        # which linker wrote it
readelf -lSdW app                              # segments, sections, dynamic entries
readelf -VW app                                # symbol versions
cc … -Wl,-Map=app.map                          # where every section and symbol went
HYPRLNK_REPRODUCE=/tmp/links cargo build       # save each link to replay it
```

## Not supported (yet)

- Linker scripts that lay out the output (`SECTIONS`, `MEMORY`, `PHDRS`):
  hyprlnk decides the layout itself. Scripts naming inputs work.
- `-r` (relocatable output), `--emit-relocs`, `-R`/`--just-symbols`.
- LTO through LLVM bitcode or GCC's LTO objects (`-C lto` without
  `-C linker-plugin-lto` works: rustc does the LTO itself).
- Range-extension thunks: an AArch64 branch more than 128 MiB away, or an
  ARM one beyond its range, is reported as an error.
- Linker relaxation on RISC-V and LoongArch: the code stays as the compiler
  wrote it, which is correct, only not shortened.
- `--compress-debug-sections`: debug sections are written uncompressed.
- `-z pack-relative-relocs` is accepted, but relative relocations are written
  as ordinary `RELA` entries; `--icf` is accepted and ignored.
- ppc64 ELFv1 (`powerpc64-unknown-linux-gnu`), big-endian AArch64 and ARM,
  MIPS, SPARC, 32-bit PowerPC and x32. Rune keeps the platform linker for
  those targets, and for Android.
