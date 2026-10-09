# Changelog

All notable changes to hyprlnk are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
Rune's (`YEAR.MINOR.PATCH`).

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
- Built into Rune (`build.linker = "hyprlnk"`); usable as a library and as
  the standalone `hyprlnk` executable.
- A **Mach-O linker for macOS** taking ld64/`ld64.lld` command lines (and
  the `cc`-style ones rustc writes): executables, dylibs and bundles for
  **arm64, arm64e and x86_64**, about twice as fast as Apple's ld-prime and
  four times as fast as ld64.lld on Rune's own build.
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
- Rune passes `-C linker-flavor=ld64.lld` for Apple targets, so the built-in
  hyprlnk links them too.
