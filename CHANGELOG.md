# Changelog

All notable changes to hyprlnk are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
Igel's (`YEAR.MINOR.PATCH`).

## [2027.0.0] - Unreleased

The first release.

### Added

- A PE/COFF linker for Windows taking `link.exe`/`lld-link` command lines:
  executables, DLLs and import libraries for **x64, ARM64 and x86**.
- **PDB** output with types, ids, module symbols, line tables, globals,
  publics and embedded natvis files; built in parallel and concurrently with
  the image.
- `/OPT:REF` garbage collection and `/OPT:ICF` identical code folding
  (including shared unwind data).
- Resources from `.res` files; exports, `.def` files, `/WHOLEARCHIVE`,
  `/ALTERNATENAME`, `/MERGE`, SafeSEH, TLS, load configuration, base
  relocations, the image checksum.
- Inputs: COFF objects (also `/bigobj`), archives (rlibs, `.lib`, `.a`),
  short and long import libraries, response files.
- Library search through `/LIBPATH`, `%LIB%`, or the installed MSVC toolset
  and Windows SDK.
- Reproducible output: content-hash timestamps and PDB GUIDs.
- `/TIME`, `/VERBOSE`, `/REPRODUCE` (and `HYPRLNK_REPRODUCE`), `/THREADS`.
- Built into Igel (`build.linker = "hyprlnk"`); usable as a library and as
  the standalone `hyprlnk` executable.
- A **Mach-O linker for macOS** taking ld64/`ld64.lld` command lines (and
  the `cc`-style ones rustc writes): executables, dylibs and bundles for
  **arm64, arm64e and x86_64**, about twice as fast as Apple's ld-prime and
  four times as fast as ld64.lld on Igel's own build.
  - Inputs: Mach-O objects, rlibs and `.a` archives (BSD and GNU symbol
    tables), dylibs, `.tbd` text stubs v1–v5 with re-exports and `$ld$`
    directives, universal files, `LC_LINKER_OPTION` auto-linking.
  - Output: classic dyld info or chained fixups (from macOS 13, and arm64e
    with signed pointers), export trie, compact unwind info with DWARF CFI,
    the stabs debug map for `dsymutil`/lldb/backtraces, ad-hoc code
    signatures, `LC_UUID` from the contents, function starts, data in code.
  - `-dead_strip`, literal deduplication, weak-definition coalescing, thread
    locals, Objective-C (selector stubs, `-ObjC`), `-exported_symbols_list`,
    `-sectcreate`, `-map`, `-dependency_info`, `--reproduce`, `--time`.
- The flavor comes from `-flavor`, the program name (`ld64.*`, `lld-link`)
  or the arguments.
- Igel passes `-C linker-flavor=ld64.lld` for Apple targets, so the built-in
  hyprlnk links them too.
- An **ELF linker for Linux** taking GNU ld/`ld.lld` command lines:
  executables (PIE, `-no-pie`, static, static-pie) and shared objects for
  **x86-64, x86, AArch64, ARM, RISC-V, POWER (ppc64le), s390x and
  LoongArch**, against glibc or musl; 1.5–2.3 times as fast as lld and
  1.45–1.85 times as fast as mold on Igel's and hyprlnk's own builds.
  - Inputs: ELF objects (debug sections may be zlib- or zstd-compressed),
    archives (also thin), shared objects with symbol versions, input linker
    scripts, response files.
  - Output: dynamic sections, `.gnu.hash`/`.hash`, symbol versions from
    version scripts, GOT/PLT, copy relocations and canonical PLT entries,
    IFUNC, RELRO, all TLS models with relaxation (x86-64, x86, AArch64,
    s390x), GOT-load relaxation on x86-64, ARM/Thumb interworking, ppc64
    TOC and call stubs, `.eh_frame_hdr`, `.ARM.exidx`, build IDs, a
    `Linker: hyprlnk` line in `.comment`.
  - `--gc-sections`, deduplicated mergeable sections (`.debug_str`),
    `--wrap`, `--defsym`, `--exclude-libs`, `-Map`, `--dependency-file`,
    `--reproduce`, `--time`.
  - A `cc` command line (`-C linker=hyprlnk`) runs the C compiler
    (`HYPRLNK_CC`, else `cc`) with hyprlnk as its `ld`.
  - Executables are written into the previous output's file when that is
    safe (not hard-linked, not running), as mold and wild do.
- `rustc -C linker=hyprlnk` on Linux, `cc -B<dir with hyprlnk as ld>`, and
  `clang -fuse-ld=hyprlnk` (with `ld.hyprlnk` on `PATH`) all work.
