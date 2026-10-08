# Command line

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

## Output

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

## Security and loader flags

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

## Libraries and symbols

| Option | |
| --- | --- |
| `/LIBPATH:<dir>` | search here for libraries (before `%LIB%`) |
| `/DEFAULTLIB:<lib>` | link `<lib>` (`.lib` is added when there is no extension) |
| `/NODEFAULTLIB[:<lib>]` | ignore default libraries (all, or one) requested by objects |
| `/WHOLEARCHIVE[:<lib>]` | load every member of an archive (all archives without a name) |
| `/INCLUDE:<symbol>` | link `<symbol>` even if nothing refers to it |
| `/ALTERNATENAME:<from>=<to>` | use `<to>` wherever `<from>` stays undefined |
| `/FORCE[:UNRESOLVED\|MULTIPLE]` | write the image despite undefined (or duplicate) symbols |

## Optimization

| Option | Default | |
| --- | --- | --- |
| `/OPT:REF` / `/OPT:NOREF` | `REF`, unless `/DEBUG` | drop COMDAT sections nothing refers to |
| `/OPT:ICF` / `/OPT:NOICF` | `ICF` when `REF` is on without `/DEBUG` | fold identical code and unwind data (and read-only data not marked address-significant) |
| `/MERGE:<from>=<to>` | `.bss=.data`, `.xdata`, `.idata`, `.edata`, `.didat`, `.00cfg` into `.rdata` | merge output sections |

`rustc` passes `/OPT:REF,NOICF` for debug builds and `/OPT:REF,ICF` for
optimized ones.

## Exports and DLLs

| Option | |
| --- | --- |
| `/EXPORT:<name>[=<internal>][,@<ordinal>[,NONAME]][,DATA][,PRIVATE][,EXPORTAS,<name>]` | export a symbol |
| `/DEF:<file>` | a module-definition file (`LIBRARY`, `EXPORTS`, `STACKSIZE`, `HEAPSIZE`, `VERSION`) |
| `/IMPLIB:<file>` | where to write the import library (default: the DLL's name with `.lib`) |
| `/NOIMPLIB` | don't write one |

## Debug info

| Option | Default | |
| --- | --- | --- |
| `/DEBUG[:FULL\|FASTLINK\|GHASH]` | off | write a PDB |
| `/DEBUG:NONE` | | don't |
| `/PDB:<file>` | the output's name with `.pdb` | |
| `/PDBALTPATH:<path>` | the PDB's absolute path | what the image calls its PDB; `%_PDB%` is the PDB's file name, `%_EXT%` the output's extension |
| `/NATVIS:<file>` | | embed a debugger visualizer in the PDB |

See [Debug info](pdb.md).

## Diagnostics

| Option | |
| --- | --- |
| `/TIME` | print how long each phase took, with details (objects, symbols, PDB sub-phases) |
| `/VERBOSE` | print each file read and loaded, and every section folded |
| `/MAP[:<file>]` | write a map file: output sections, then every public symbol by address with its object (default: the output's name with `.map`) |
| `/REPRODUCE:<dir>` | copy the inputs to `<dir>/<output>-<pid>/` with a `link.rsp` that repeats the link; also `HYPRLNK_REPRODUCE=<dir>` |
| `/THREADS:<n>` | worker threads (default: one per logical CPU) |
| `--version`, `/HELP` | |

## Accepted and ignored

For compatibility, these are accepted and have no effect: `/NOLOGO`,
`/INCREMENTAL`, `/MANIFEST*`, `/GUARD`, `/ERRORREPORT`, `/IGNORE`, `/WX`,
`/BREPRO` (hyprlnk is always reproducible), `/DEMANGLE`, `/ERRORLIMIT`,
`/FAILIFMISMATCH` (checked in object directives), `/LTCG`, `/CETCOMPAT`,
`/DEPENDENTLOADFLAG`, `/PDBPAGESIZE`, `/WINSYSROOT` and a few others.

These print a warning and are ignored: `/DELAYLOAD` (the DLL is imported
normally), `/ORDER`, `/DRIVER`, `/SECTION`, `/STUB`,
`/FUNCTIONPADMIN`. Anything unknown prints a warning too.

## Object directives

Objects can carry options in a `.drectve` section. hyprlnk honors
`/DEFAULTLIB`, `/NODEFAULTLIB`, `/INCLUDE`, `/INCLUDEOPTIONAL`,
`/ALTERNATENAME`, `/EXPORT`, `/MERGE`, `/FAILIFMISMATCH`, `/ENTRY` and
`/SUBSYSTEM` there.

## Environment

| Variable | |
| --- | --- |
| `LIB` | library search directories, after `/LIBPATH` |
| `VCToolsInstallDir` | the MSVC toolset to use when `LIB` is unset |
| `HYPRLNK_REPRODUCE` | as `/REPRODUCE` |
| `RUNE_HYPRLNK` | set by Rune on the compiler: makes the `rune` executable act as hyprlnk |
