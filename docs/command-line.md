# Command line

hyprlnk speaks two command-line dialects: `link.exe`'s for Windows images and
ld64's for macOS images. It picks one from `-flavor link|darwin` as the first
argument, from its program name (`ld64.*` and `ld` on a Mac mean ld64,
`lld-link` and `link` mean link.exe), or from the arguments themselves
(`/OUT:` and friends, or `-arch`, `-platform_version`, `-Wl,…`); otherwise it
follows the host. [macOS (ld64)](#macos-ld64-command-line) options are below
the Windows ones.

## Windows (link.exe command line)

```text
hyprlnk [options] <inputs...>
```

Options follow `link.exe`: case-insensitive, introduced by `/` or `-`, values
after a colon (`/OUT:app.exe`, `-out:app.exe`). `@file` reads more arguments
from a response file (UTF-8, or UTF-16 with a byte-order mark), with the
quoting rules of the Windows command line. `-flavor link` as the first
argument (as `rust-lld` takes it) is accepted.

Inputs are recognized by their contents, not their names: COFF objects,
`/bigobj` objects, archives (`.lib`, `.rlib`, `.a`), import libraries, short
import objects and `.res` resource files.

### Output

| Option | Default | |
| --- | --- | --- |
| `/OUT:<file>` | first input's name | the image to write |
| `/DLL` | | build a DLL (default image base 0x180000000 on 64-bit, 0x10000000 on x86) |
| `/ENTRY:<symbol>` | from `main`/`wmain`/`WinMain`/`wWinMain`, or `_DllMainCRTStartup` | entry point (x86: the `_` is added) |
| `/NOENTRY` | | no entry point (resource-only DLLs) |
| `/SUBSYSTEM:<name>[,<major>.<minor>]` | console, or windows when only `WinMain` exists | `console`, `windows`, `native`, `posix`, `efi_application`, `efi_boot_service_driver`, `efi_runtime_driver`, `efi_rom`, `boot_application`, `windowsce` |
| `/MACHINE:<x64\|arm64\|x86>` | the first object's machine | |
| `/BASE:<address>` | 0x140000000 (64-bit) / 0x400000 (x86) | preferred load address |
| `/STACK:<reserve>[,<commit>]` | 1 MiB, 4 KiB | |
| `/HEAP:<reserve>[,<commit>]` | 1 MiB, 4 KiB | |
| `/VERSION:<major>.<minor>` | 0.0 | image version |
| `/OSVERSION:<major>.<minor>` | 6.0 | minimum Windows version |
| `/ALIGN:<n>`, `/FILEALIGN:<n>` | 4096, 512 | section and file alignment |
| `/TIMESTAMP:<n>` | a hash of the image | the header timestamp |
| `/RELEASE` | | compute the image checksum (drivers need it) |

### Security and loader flags

| Option | Default | |
| --- | --- | --- |
| `/DYNAMICBASE[:NO]` | on | address-space layout randomization |
| `/HIGHENTROPYVA[:NO]` | on (64-bit) | 64-bit ASLR |
| `/NXCOMPAT[:NO]` | on | data execution prevention |
| `/LARGEADDRESSAWARE[:NO]` | on for 64-bit, off for x86 | |
| `/TSAWARE[:NO]` | on for executables | terminal-server aware |
| `/FIXED[:NO]` | off | no base relocations |
| `/SAFESEH[:NO]` | on when every object supports it (x86) | the table of valid exception handlers; `/SAFESEH` makes an incompatible object an error |
| `/APPCONTAINER[:NO]`, `/INTEGRITYCHECK[:NO]` | off | |

### Libraries and symbols

| Option | |
| --- | --- |
| `/LIBPATH:<dir>` | search here for libraries (before `%LIB%`) |
| `/DEFAULTLIB:<lib>` | link `<lib>` (`.lib` is added when there is no extension) |
| `/NODEFAULTLIB[:<lib>]` | ignore default libraries (all, or one) requested by objects |
| `/WHOLEARCHIVE[:<lib>]` | load every member of an archive (all archives without a name) |
| `/INCLUDE:<symbol>` | link `<symbol>` even if nothing refers to it |
| `/ALTERNATENAME:<from>=<to>` | use `<to>` wherever `<from>` stays undefined |
| `/FORCE[:UNRESOLVED\|MULTIPLE]` | write the image despite undefined (or duplicate) symbols |

### Optimization

| Option | Default | |
| --- | --- | --- |
| `/OPT:REF` / `/OPT:NOREF` | `REF`, unless `/DEBUG` | drop COMDAT sections nothing refers to |
| `/OPT:ICF` / `/OPT:NOICF` | `ICF` when `REF` is on without `/DEBUG` | fold identical code and unwind data (and read-only data not marked address-significant) |
| `/MERGE:<from>=<to>` | `.bss=.data`, `.xdata`, `.idata`, `.edata`, `.didat`, `.00cfg` into `.rdata` | merge output sections |

`rustc` passes `/OPT:REF,NOICF` for debug builds and `/OPT:REF,ICF` for
optimized ones.

### Exports and DLLs

| Option | |
| --- | --- |
| `/EXPORT:<name>[=<internal>][,@<ordinal>[,NONAME]][,DATA][,PRIVATE][,EXPORTAS,<name>]` | export a symbol |
| `/DEF:<file>` | a module-definition file (`LIBRARY`, `EXPORTS`, `STACKSIZE`, `HEAPSIZE`, `VERSION`) |
| `/IMPLIB:<file>` | where to write the import library (default: the DLL's name with `.lib`) |
| `/NOIMPLIB` | don't write one |

### Debug info

| Option | Default | |
| --- | --- | --- |
| `/DEBUG[:FULL\|FASTLINK\|GHASH]` | off | write a PDB |
| `/DEBUG:NONE` | | don't |
| `/PDB:<file>` | the output's name with `.pdb` | |
| `/PDBALTPATH:<path>` | the PDB's absolute path | what the image calls its PDB; `%_PDB%` is the PDB's file name, `%_EXT%` the output's extension |
| `/NATVIS:<file>` | | embed a debugger visualizer in the PDB |

See [Debug info](pdb.md).

### Diagnostics

| Option | |
| --- | --- |
| `/TIME` | print how long each phase took, with details (objects, symbols, PDB sub-phases) |
| `/VERBOSE` | print each file read and loaded, and every section folded |
| `/MAP[:<file>]` | write a map file: output sections, then every public symbol by address with its object (default: the output's name with `.map`) |
| `/REPRODUCE:<dir>` | copy the inputs to `<dir>/<output>-<pid>/` with a `link.rsp` that repeats the link; also `HYPRLNK_REPRODUCE=<dir>` |
| `/THREADS:<n>` | worker threads (default: one per logical CPU) |
| `--version`, `/HELP` | |

### Accepted and ignored

For compatibility, these are accepted and have no effect: `/NOLOGO`,
`/INCREMENTAL`, `/MANIFEST*`, `/GUARD`, `/ERRORREPORT`, `/IGNORE`, `/WX`,
`/BREPRO` (hyprlnk is always reproducible), `/DEMANGLE`, `/ERRORLIMIT`,
`/FAILIFMISMATCH` (checked in object directives), `/LTCG`, `/CETCOMPAT`,
`/DEPENDENTLOADFLAG`, `/PDBPAGESIZE`, `/WINSYSROOT` and a few others.

These print a warning and are ignored: `/DELAYLOAD` (the DLL is imported
normally), `/ORDER`, `/DRIVER`, `/SECTION`, `/STUB`,
`/FUNCTIONPADMIN`. Anything unknown prints a warning too.

### Object directives

Objects can carry options in a `.drectve` section. hyprlnk honors
`/DEFAULTLIB`, `/NODEFAULTLIB`, `/INCLUDE`, `/INCLUDEOPTIONAL`,
`/ALTERNATENAME`, `/EXPORT`, `/MERGE`, `/FAILIFMISMATCH`, `/ENTRY` and
`/SUBSYSTEM` there.

### Environment

| Variable | |
| --- | --- |
| `LIB` | library search directories, after `/LIBPATH` |
| `VCToolsInstallDir` | the MSVC toolset to use when `LIB` is unset |
| `HYPRLNK_REPRODUCE` | as `/REPRODUCE` |
| `RUNE_HYPRLNK` | set by Rune on the compiler: makes the `rune` executable act as hyprlnk |


## macOS (ld64 command line)

```text
hyprlnk [-flavor darwin] [options] <inputs...>
```

Options follow Apple's `ld` (ld64): introduced by `-`, values in the next
arguments (`-o app`, `-platform_version macos 13.0 15.0`). `@file` reads more
arguments from a response file with shell-like quoting. Inputs are recognized
by their contents: Mach-O objects, archives (`.a`, `.rlib`), dylibs, `.tbd`
text stubs, and universal (fat) files of any of these.

`cc`-style command lines — what rustc passes to a linker it doesn't recognize
— are translated first: `-Wl,a,b` and `-Xlinker` are unwrapped,
`-mmacosx-version-min=`/`--target=` become `-platform_version` (with the SDK's
version from `SDKSettings.json`), `-isysroot` becomes `-syslibroot`,
`-dynamiclib`/`-shared` become `-dylib`, `-lSystem` is added unless
`-nodefaultlibs`/`-nostdlib`, and `-fuse-ld=`, `-m64`, `-O…`, `-g…` and other
compiler-driver flags are ignored.

### Output

| Option | Default | |
| --- | --- | --- |
| `-o <file>` | `a.out` | the image to write |
| `-execute` / `-dylib` / `-bundle` | `-execute` | executable, dynamic library or loadable bundle |
| `-arch <arm64\|arm64e\|x86_64\|x86_64h>` | the first object's | |
| `-platform_version <platform> <min> <sdk>` | macOS 11.0 (x86_64: 10.13) | `macos`, `ios`, `tvos`, `watchos`, `xros`, `driverkit`, `mac-catalyst`, simulators, or a number |
| `-macos_version_min <v>` (and `-ios_version_min` …) | | the older spelling |
| `-e <symbol>` | `_main` | entry point (`LC_MAIN`) |
| `-install_name <path>` | the output path | a dylib's install name |
| `-current_version <v>`, `-compatibility_version <v>` | 1.0 | a dylib's versions |
| `-rpath <path>` | | adds an `LC_RPATH` |
| `-headerpad <hex>`, `-headerpad_max_install_names` | 0x20 | room after the load commands |
| `-pagezero_size <hex>`, `-image_base <hex>`, `-stack_size <hex>` | 4 GiB, 0, default | |
| `-fixup_chains`, `-no_fixup_chains` | chained from macOS 13, iOS 13.4, and always on arm64e | dyld fixup format |
| `-data_const`, `-no_data_const` | on from macOS 10.15 | `__DATA_CONST` for data dyld only writes once |
| `-adhoc_codesign`, `-no_adhoc_codesign` | signed on arm64/arm64e | ad-hoc code signature |
| `-no_uuid`, `-random_uuid` | content hash | `LC_UUID` |
| `-sectcreate <seg> <sect> <file>` | | a section with a file's contents |
| `-source_version <A.B.C.D.E>` | 0 | `LC_SOURCE_VERSION` |
| `-umbrella <name>`, `-allowable_client <name>` | | `LC_SUB_FRAMEWORK`, `LC_SUB_CLIENT` |
| `-final_output <name>` | | the name in the code signature |

### Libraries and symbols

| Option | |
| --- | --- |
| `-l<name>`, `-framework <name>[,<suffix>]` | link a library or framework (`.tbd`, `.dylib`, `.a` per directory, in that order) |
| `-L<dir>`, `-F<dir>`, `-Z`, `-syslibroot <dir>` | search directories; `-Z` drops the system ones |
| `-search_paths_first`, `-search_dylibs_first` | per directory (default), or all dylibs before archives |
| `-weak-l<name>`, `-weak_framework`, `-weak_library` | `LC_LOAD_WEAK_DYLIB`; also imports weakly |
| `-needed-l<name>`, `-needed_framework`, `-needed_library` | keep the load command under `-dead_strip_dylibs` |
| `-reexport-l<name>`, `-reexport_framework`, `-reexport_library` | `LC_REEXPORT_DYLIB` |
| `-upward-l<name>`, `-upward_framework`, `-upward_library` | `LC_LOAD_UPWARD_DYLIB` |
| `-force_load <archive>`, `-all_load`, `-ObjC` | load whole archives, or the members with Objective-C classes |
| `-filelist <file>[,<dir>]` | inputs listed in a file |
| `-dead_strip`, `-dead_strip_dylibs` | drop unreferenced code and data; drop unused dylibs |
| `-u <symbol>`, `-U <symbol>` | must be defined; may stay undefined (dynamic lookup) |
| `-undefined error\|warning\|suppress\|dynamic_lookup` | what undefined symbols become |
| `-flat_namespace` | flat-namespace binding |
| `-exported_symbols_list <file>`, `-exported_symbol <glob>` | export only these |
| `-unexported_symbols_list <file>`, `-unexported_symbol <glob>` | don't export these |
| `-no_exported_symbols`, `-export_dynamic` | export nothing; keep every global under `-dead_strip` |
| `-alias <from> <to>`, `-alias_list <file>` | another name for a symbol |
| `-interposable` | bind every exported global through dyld |
| `-x`, `-S`, `-oso_prefix <dir>` | no local symbols; no debug map; shorter debug-map paths |

### Diagnostics

| Option | |
| --- | --- |
| `-print_statistics`, `--time` | per-phase timing |
| `-t` | print each input as it is loaded |
| `-map <file>` | sections and symbols by address |
| `-dependency_info <file>` | the binary dependency list Xcode reads |
| `--reproduce=<dir>`, `HYPRLNK_REPRODUCE` | save the inputs and a `link.rsp` |
| `--threads=<n>` | worker threads |
| `-w`, `-fatal_warnings`, `-v`, `--version` | |

Accepted and ignored, for compatibility: `-demangle`, `-dynamic`, `-pie`,
`-no_deduplicate`, `-no_compact_unwind`, `-lto_library`, `-mllvm`,
`-object_path_lto`, `-ld_classic`, `-ld_new`, `-bind_at_load` and other ld64
options without an effect here. Unknown options are warned about and
skipped.
