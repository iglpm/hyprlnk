# Compatibility

## Machines and outputs

| | x64 | ARM64 | x86 |
| --- | :---: | :---: | :---: |
| Executables and DLLs (PE32+ / PE32) | ✅ | ✅ | ✅ |
| Import libraries for DLLs | ✅ | ✅ | ✅ |
| PDB | ✅ | ✅ | ✅ (no FPO data) |
| Exception data | `.pdata` (sorted) | `.pdata` (sorted) | SafeSEH table |

ARM64EC, ARM64X and 32-bit ARM are not supported. ARM64 output is checked
byte-for-byte against `lld-link`.

## Inputs

- COFF objects, regular and `/bigobj`, from LLVM (`rustc`, clang, clang-cl)
  and MSVC; machine-independent objects.
- Archives: rlibs, MSVC static libraries, GNU and BSD `.a` files, with or
  without a symbol table. Thin archives are not supported.
- Import libraries: short import objects (all name types, including
  `EXPORTAS`) and long-format import libraries.
- `.res` resource files, merged into one `.rsrc` tree; objects that carry
  `.rsrc` sections themselves are linked as they are.
- Module-definition (`.def`) files.
- Response files, UTF-8 or UTF-16.

Not supported: LLVM bitcode (linker-plugin LTO), MSVC `/GL` objects, CLR
(managed) objects. hyprlnk says so when it meets one.

## Features

| | |
| --- | --- |
| Symbol resolution | lazy archive members; COMDAT selection (any, no duplicates, same size, exact match, largest, associative); weak externals; `/ALTERNATENAME`; common symbols; `__imp_` references to symbols defined in the image |
| Directives | `/DEFAULTLIB`, `/NODEFAULTLIB`, `/INCLUDE`, `/INCLUDEOPTIONAL`, `/ALTERNATENAME`, `/EXPORT`, `/MERGE`, `/FAILIFMISMATCH`, `/ENTRY`, `/SUBSYSTEM` |
| Layout | link.exe's section grouping (`$` suffixes sorted), merging, and order |
| Optimization | `/OPT:REF`, `/OPT:ICF` |
| Image | imports and thunks, exports, base relocations, TLS (with alignment), load configuration, resources, debug directory, checksum |
| Determinism | content-hash timestamp and PDB GUID, always |

## Differences from link.exe and lld-link

- **Always reproducible**: the timestamp is a hash, as with `/Brepro`.
- **No manifest files**: `/MANIFEST` options are ignored (embed manifests
  as resources instead).
- **No incremental linking**: `/INCREMENTAL` is ignored; a full link is
  usually faster than link.exe's incremental one anyway.
- **Not yet**: `/DELAYLOAD` (warned about, imported normally), `/GUARD:CF`,
  `/CETCOMPAT`'s debug entry, `/ORDER`, x86 FPO data in PDBs.
- **Within a DLL, imports are in name order** (as lld), and DLLs in the order
  they are first used.
- **Import thunks** each start 8-byte aligned (8 bytes on x64 and x86, 16 on ARM64).
- Diagnostics name both files for duplicate symbols and the first referrer
  for undefined ones, with Rust names demangled.

## Tested with

Rust 1.98 (`x86_64`, `aarch64`, `i686` `pc-windows-msvc`), clang-cl 22,
MSVC 14.44 runtime libraries, Windows SDK 10.0.26100. Rune's test suite
passes with every test binary and build script linked by hyprlnk.
