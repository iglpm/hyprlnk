# Compatibility

- [Windows](#windows)
- [macOS](#macos)

## Windows

### Machines and outputs

| | x64 | ARM64 | x86 |
| --- | :---: | :---: | :---: |
| Executables and DLLs (PE32+ / PE32) | ✅ | ✅ | ✅ |
| Import libraries for DLLs | ✅ | ✅ | ✅ |
| PDB | ✅ | ✅ | ✅ (no FPO data) |
| Exception data | `.pdata` (sorted) | `.pdata` (sorted) | SafeSEH table |

ARM64EC, ARM64X and 32-bit ARM are not supported. ARM64 output is checked
byte-for-byte against `lld-link`.

### Inputs

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

### Features

| | |
| --- | --- |
| Symbol resolution | lazy archive members; COMDAT selection (any, no duplicates, same size, exact match, largest, associative); weak externals; `/ALTERNATENAME`; common symbols; `__imp_` references to symbols defined in the image |
| Directives | `/DEFAULTLIB`, `/NODEFAULTLIB`, `/INCLUDE`, `/INCLUDEOPTIONAL`, `/ALTERNATENAME`, `/EXPORT`, `/MERGE`, `/FAILIFMISMATCH`, `/ENTRY`, `/SUBSYSTEM` |
| Layout | link.exe's section grouping (`$` suffixes sorted), merging, and order |
| Optimization | `/OPT:REF`, `/OPT:ICF` |
| Image | imports and thunks, exports, base relocations, TLS (with alignment), load configuration, resources, debug directory, checksum |
| Determinism | content-hash timestamp and PDB GUID, always |

### Differences from link.exe and lld-link

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

### Tested with

Rust 1.98 (`x86_64`, `aarch64`, `i686` `pc-windows-msvc`), clang-cl 22,
MSVC 14.44 runtime libraries, Windows SDK 10.0.26100. Rune's test suite
passes with every test binary and build script linked by hyprlnk.

## macOS

### Architectures and outputs

| | arm64 | arm64e | x86_64 / x86_64h |
| --- | :---: | :---: | :---: |
| Executables (`MH_EXECUTE`, PIE) | ✅ | ✅ | ✅ |
| Dylibs, bundles | ✅ | ✅ | ✅ |
| Classic dyld info (rebase/bind/weak bind opcodes) | ✅ | — | ✅ |
| Chained fixups | ✅ | ✅ (USERLAND24, signed) | ✅ |
| Ad-hoc code signature | ✅ (default) | ✅ (default) | with `-adhoc_codesign` |
| Compact unwind + DWARF CFI | ✅ | ✅ | ✅ |

Platforms: macOS, and Mac Catalyst through the macOS SDK; the other Apple
platforms get the right load commands but are not tested. 32-bit Mach-O
(i386, armv7, arm64_32) is not supported.

### Inputs

- Mach-O objects from LLVM (rustc, clang) and Apple's assembler, with or
  without `MH_SUBSECTIONS_VIA_SYMBOLS`.
- Archives: rlibs and `.a` files, BSD (`__.SYMDEF`, `__.SYMDEF_64`) or GNU
  symbol tables, or none; universal archives.
- Dylibs (export trie or symbol table) and text stubs (`.tbd` v1–v5), with
  re-exports, inline documents, and `$ld$hide$`, `$ld$add$`,
  `$ld$install_name$` and `$ld$previous$` directives; universal dylibs.
- `LC_LINKER_OPTION` auto-linking (`-l`, `-framework`) from objects.
- Response files and `-filelist`.

Not supported: LLVM bitcode (linker-plugin LTO), `-r`, `-static`,
`-preload`, thin archives.

### Features

| | |
| --- | --- |
| Symbol resolution | lazy archive members in any order; dylib/archive precedence by command-line position; weak definitions coalesced (strong over weak, first weak wins); `.weak_def_can_be_hidden`; common symbols; `N_INDR` aliases; `-alias`; `section$start$`, `section$end$`, `segment$start$`, `segment$end$`; `__mh_*_header`, `___dso_handle` |
| Dead stripping | atoms split at symbols, roots from the entry point, exports, `-u`, `no_dead_strip`, initializers; FDEs kept with their functions |
| Literals | C strings and 4/8/16-byte literals deduplicated per output section |
| Relocations | all arm64 and x86_64 types, arm64e authenticated pointers; GOT and TLV loads of local symbols relaxed |
| Imports | stubs and GOT bound at load (no lazy binding); weak imports; weak-definition coalescing (weak binds or weak-lookup binds); Objective-C selector stubs |
| Thread locals | TLV descriptors, template, `__thread_ptrs` for imported ones |
| Unwind | `__unwind_info` with folding, common encodings, compressed pages, personalities, LSDAs; `__eh_frame` pruned to the functions that need it |
| Debug | stabs debug map for `dsymutil`, lldb and Rust backtraces |
| Determinism | content-hash UUID; the same inputs give the same bytes |

### Differences from Apple's ld and ld64.lld

- **No lazy binding.** Imports are bound when the image loads (as with
  chained fixups); there is no `__stub_helper`/`__la_symbol_ptr`.
- **Initializers stay pointers** (`__mod_init_func`); ld-prime turns them into
  `__init_offsets` with chained fixups. dyld runs both.
- **Literal sections** keep their names (`__literal4/8/16`); ld-prime merges
  them into `__const`, ld64.lld into `__literals`.
- **Compact unwind entries in DWARF mode** carry no LSDA index entry (the
  unwinder takes the LSDA from the FDE).
- **Not yet**: branch islands for arm64 `__text` over 128 MiB, `-order_file`,
  identical code folding (`-deduplicate`), Objective-C category merging,
  `-bitcode_bundle`, `-sectalign`/`-segprot`, `-why_live`.
- Outputs are written to a temporary file and renamed, never in place: a
  running program or a hard link in Rune's store is never modified.

### Tested with

Rust 1.98 (`aarch64-apple-darwin`, `x86_64-apple-darwin`), Apple clang 21
(C, C++ with libc++, Objective-C, arm64e), macOS 27 SDK, on an Apple M5.
Rune's test suite passes with every test binary, build script and proc-macro
linked by hyprlnk; on Rune's own build, every function's unwind encoding and
the whole `__eh_frame` match ld64.lld's; on the x86_64 test programs, every
function matches lld's instruction for instruction.
