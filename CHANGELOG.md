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
