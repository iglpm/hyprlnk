# Architecture

hyprlnk is a library (`hyprlnk`) with a thin binary on top, and one backend
per object format: PE/COFF in `src/coff/`, Mach-O in `src/macho/`, ELF in
`src/elf/`. `lib.rs` picks one from `-flavor`, the program's name (`ld64.*` →
Mach-O, `lld-link` → COFF, `ld` and `ld.*` → ELF on Linux) or the arguments
themselves. Each backend is organized as phases of one link, each a module
adding methods to the linker context in its `resolve.rs`.

## PE/COFF

```text
command line ─▶ config ─▶ resolve ─▶ gc ─▶ icf ─▶ synth ─▶ layout ─▶ write ─┬─▶ image
                (args,     (inputs,   (live   (fold    (imports,  (output    (relocate,  │
                 .def)      symbols)   COMDATs) dupes)   exports,   sections,  headers)   └─▶ PDB
                                                         resources) addresses)  (pdb/, in parallel)
```

### Source map

| File | |
| --- | --- |
| `lib.rs` | public API (`main_with_args`, `supports_target`), flavor dispatch |
| `main.rs` | the `hyprlnk` executable |
| `fileio.rs` | input mapping, the arena that owns inputs, the memory-mapped output |
| `cmdline.rs` | response files and Windows command-line quoting |
| `archive.rs` | `ar` reader (symbol tables, long names) and writer |
| `diag.rs` | errors, warnings, demangling, `/TIME` |
| `coff/config.rs` | `link.exe` options → `Config` |
| `coff/def.rs` | `/EXPORT` specifications, `.def` files |
| `coff/arch.rs` | everything machine-specific: relocations, thunks, sizes |
| `coff/object.rs` | COFF object parsing (zero-copy) |
| `coff/import.rs` | short import objects |
| `coff/symtab.rs` | the global symbol table |
| `coff/resolve.rs` | the `Linker`; inputs, symbol resolution, COMDATs, directives |
| `coff/gc.rs` | `/OPT:REF` |
| `coff/icf.rs` | `/OPT:ICF` |
| `coff/synth.rs` | linker-made data: import tables, thunks, exports, commons, SafeSEH |
| `coff/rsrc.rs` | `.res` files → `.rsrc` |
| `coff/layout.rs` | output sections and addresses |
| `coff/write.rs` | copying and relocating sections, base relocations, PE headers |
| `coff/implib.rs` | import libraries |
| `coff/reproduce.rs` | `/REPRODUCE` |
| `coff/winsdk.rs` | library search paths, MSVC/SDK discovery |
| `coff/pdb/` | the PDB writer: `types` (merging), `modules`, `gsi` (globals and publics), `strtab`, `msf` (the container), `hash` |

## Mach-O

```text
command line ─▶ config ─▶ resolve ─▶ gc ──────▶ scan ─▶ layout ─▶ write ─┬─▶ sections (relocated, in batches)
                (ld64 or   (inputs,   (live atoms, (slots,   (sections,  │   ∥ LINKEDIT: fixups, export trie,
                 cc args)   symbols,   and per       literals, addresses, │     symbol table + debug map
                            dylibs)    relocation:   commons)  unwind     └─▶ UUID, then signature ∥ file write
                                       stub/GOT/              info)
                                       rebase/bind)
```

| File | |
| --- | --- |
| `macho/config.rs` | ld64 options → `Config`; `cc`-driver lines translated first; response files |
| `macho/sdk.rs` | `-l`/`-framework` search, `-syslibroot` re-rooting, finding the SDK |
| `macho/object.rs` | Mach-O objects (zero-copy), atoms, per-atom relocation ranges, symbol lookups |
| `macho/tbd.rs` | text stubs: YAML v1–v4 and JSON v5, `$ld$` directives |
| `macho/dylib.rs` | Mach-O dylibs as inputs: install name, re-exports, export trie |
| `macho/symtab.rs` | the global symbol table and per-symbol slots |
| `macho/resolve.rs` | the `Linker`; inputs, waves, precedence, re-exports, auto-linking, Objective-C stubs |
| `macho/gc.rs` | `-dead_strip`; classifying each relocation (stub, GOT, TLV pointer, rebase, bind, signed) |
| `macho/scan.rs` | slots, literal deduplication, commons, dylib ordinals |
| `macho/layout.rs` | output sections and segments, load-command sizes, addresses |
| `macho/unwind.rs` | `__compact_unwind` and `__eh_frame` in objects; `__unwind_info` |
| `macho/arch.rs` | arm64 and x86_64 relocations, instruction encodings, stubs |
| `macho/write.rs` | header, load commands, sections, the pipelined file write, code signature |
| `macho/linkedit.rs` | symbol table with the debug map, function starts, data in code |
| `macho/dyldinfo.rs` | rebase, bind and weak-bind opcodes; the export trie |
| `macho/fixups.rs` | chained fixups (64-bit and arm64e) |
| `macho/dwarf.rs` | compile-unit names for the debug map |
| `macho/reproduce.rs` | `--reproduce` |
| `sha256.rs` | SHA-256 with the ARMv8 and x86 SHA extensions, two messages at a time |

The Mach-O backend keeps each object's sections split into **atoms** (at
symbols, by literal content, or by `__eh_frame` record): the unit of dead
stripping, deduplication and placement. Liveness is computed by work-stealing
marking, and the same walk classifies every relocation of every live atom,
so no later pass needs to look at relocations until they are applied.
Writing splits the file in two buffers built side by side — everything
before `__LINKEDIT`, and `__LINKEDIT` — then hands both to helper threads to
write while the UUID and the code signature are computed; the first page
(with the UUID) and the signature go last.

## ELF

```text
command line ─▶ config ─▶ input ─▶ parse ─▶ intern ─▶ resolve ─▶ gc ─▶ scan ─▶ merge ─▶ layout ─▶ write ─┬─▶ sections, relocated
(cc line: the    (GNU ld   (map,    (objects,  (names,   (archive   (live   (GOT,  (strings,  (output    (in    │   ∥ merged strings
 C compiler       options)  archives, sections) hashes,   waves,     sections) PLT,  constants) sections,  parallel)│   ∥ .eh_frame ∥ symtab
 runs hyprlnk               scripts)            ranks)    COMDATs)          TLS,             segments,          └─▶ build ID from the
 as its ld)                                                                 copies)           addresses)              writers' hashes
```

| File | |
| --- | --- |
| `elf/mod.rs` | entry point (`link_main`), the forked early exit, the pipeline, small helpers |
| `elf/driver.rs` | `cc` command lines: running the C compiler with hyprlnk as its `ld` |
| `elf/config.rs` | GNU ld options → `Config` |
| `elf/script.rs` | input scripts (`GROUP`, `INPUT`, `AS_NEEDED`), version scripts, dynamic lists |
| `elf/input.rs` | library search, mapping and classifying inputs in parallel, archives and thin archives |
| `elf/target.rs` | `Machine` and the `Target` trait: everything machine-specific is behind it |
| `elf/object.rs` | ELF objects (one pass over the section table) and shared objects |
| `elf/symbols.rs` | the global symbol table: sharded, deterministic interning by 128-bit name hashes; definition ranks |
| `elf/resolve.rs` | the `Ctx`; parsing, interning, archive waves, COMDAT groups, undefined and duplicate symbols, symbol properties |
| `elf/ehframe.rs` | `.eh_frame` records in objects; the output `.eh_frame` and `.eh_frame_hdr` |
| `elf/gc.rs` | `--gc-sections`: roots, work-stealing marking, `.ARM.exidx` |
| `elf/scan.rs` | what each relocation needs: GOT, PLT, TLS slots, copy relocations, dynamic relocations |
| `elf/thunks.rs` | ARM/Thumb interworking thunks and ppc64 call stubs |
| `elf/merge.rs` | SHF_MERGE sections: split, deduplicate by shard, fill in each input's table |
| `elf/layout.rs` | output sections, the linker's own sections, order, segments, addresses |
| `elf/dynamic.rs` | `.dynamic`, `.dynsym`, `.gnu.hash`/`.hash`, symbol versions |
| `elf/write.rs` | copying and relocating sections, the symbol table, GOT and PLT, headers, the build ID |
| `elf/mapfile.rs` | `-Map` |
| `elf/reproduce.rs` | `--reproduce` |
| `elf/prof.rs` | developer profiling (`HYPRLNK_PROF`) |
| `elf/x86_64.rs`, `i386.rs`, `aarch64.rs`, `arm.rs`, `riscv.rs`, `ppc64.rs`, `s390x.rs`, `loongarch.rs` | each machine: relocations, relaxations, TLS models, PLT entries |

The ELF backend keeps sections whole (the unit of garbage collection) and
reads symbols and relocations from the mapped files when it needs them.
Names are interned in two parallel passes: per group of files, names are
hashed and bucketed by shard; per shard, they are inserted in file order,
which also keeps each symbol's best definition. Archive members load in
waves, each parsing its members in parallel. Writing copies and relocates
sections into the memory-mapped output on all threads while merged strings,
`.eh_frame`, the symbol table, the GOT and the headers are written
alongside; each writer hashes what it wrote, and the build ID combines those
hashes. A link run as a program forks first: the parent exits as soon as the
output is complete, and the child tears the process down.

## Principles

**Borrow, don't copy.** Inputs are memory-mapped into an `Arena` that lives
as long as the link, and parsed structures borrow from it (`'a`
everywhere). An object's symbols and relocations are read from the raw
tables when needed rather than decoded into new structures.

**Parallel where it pays, deterministic always.** Work is parallel per object,
per section batch or per record, with `rayon`. Wherever parallel work makes
choices — which copy of a COMDAT or a type to keep — the choice is made by a
fixed order (input order), never by thread timing. The same inputs give the
same bytes.

**Sequential where it must be, and short.** Symbol resolution is inherently
ordered. hyprlnk keeps it short: names are hashed and looked up on the
parsing threads, and the sequential merge only handles names it hasn't
seen.

**Machine differences in one place.** In each backend, `arch.rs` holds what
differs between machines — for COFF, between x64, ARM64 and x86: relocation semantics, thunk code, pointer and header
sizes, exception-table formats. The rest of the linker asks it.

## A COFF link, step by step

1. **Config** parses the command line (and `.def` files) into a `Config`.
2. **Resolve** maps the inputs in parallel and registers archive symbols as
   lazy. Then it loads in waves: everything pending is parsed in parallel,
   then merged into the symbol table in order; undefined symbols that an
   archive offers queue that member for the next wave; `/DEFAULTLIB`
   directives queue libraries. Afterwards: the entry point is inferred, the
   C runtime's load configuration is pulled in, `/ALTERNATENAME`s apply,
   weak externals fall back, and what is still undefined is reported.
3. **GC** marks, from every non-COMDAT section and the roots (entry, exports,
   `/INCLUDE`s, TLS and load configuration), everything reachable through
   relocations and associations.
4. **ICF** folds identical sections (see `icf.rs` for the algorithm).
5. **Synth** sizes what the linker makes: common symbols, import tables and
   thunks, `__imp_` pointers for local symbols, exports, the SafeSEH table,
   resources, the debug directory.
6. **Layout** groups sections the way link.exe does and assigns addresses.
7. **Write** builds the image in a memory-mapped file: sections are copied
   and relocated in batches on all threads while the PDB is built on the
   others; base relocations, the sorted exception table and the headers
   follow; the image and the PDB are committed together.

## Rune integration

Rune passes `-C linker=<rune>` to `rustc` (and, for Apple targets,
`-C linker-flavor=ld64.lld`) and sets `RUNE_HYPRLNK` on the compiler; `rune`'s
`main` sees the variable and runs `hyprlnk::main_with_args` instead of its own
command line. On Linux, rustc hands it a `cc` command line: hyprlnk runs the
target's C compiler (`HYPRLNK_CC`, which Rune sets from
`target.<triple>.linker`, else `cc`) with a directory holding `rune` as `ld`,
and the compiler runs `rune` again as the linker. The linker setting a unit
is cached under is `rune:hyprlnk@<version>` (plus the C compiler, on Linux),
independent of where `rune` is installed. See
`crates/rune-common/src/linker.rs` in the Rune repository.

## Testing

- Unit tests next to the code (`cargo test` / `rune test -p hyprlnk`).
- `tests/macho.rs`: end-to-end on macOS with rustc and clang — unwinding,
  threads and thread locals, backtraces, chained fixups, `cc`-style command
  lines, cdylibs and Rust dylibs, proc-macros loaded by rustc, the debug map
  through `dsymutil`, C with commons and TLS, C++ exceptions and weak
  definitions, Objective-C, arm64e, x86_64, reproducible output.
- `tests/link.rs`: end-to-end links with `rustc -C linker=hyprlnk` that run
  what they link — unwinding, threads and TLS, DLLs, resources, PDBs read by
  `dbghelp`, x86 programs, ARM64 images compared byte-for-byte with
  `lld-link`, reproducible output. Parts skip when a target or tool is
  missing.
- `tests/elf.rs`: end-to-end on Linux with rustc, gcc/clang and g++ —
  unwinding, threads and thread locals, backtraces, `cc`-style command lines,
  cdylibs and Rust dylibs, proc-macros loaded by rustc, static musl
  executables, C with commons, TLS and constructors, C++ exceptions and RTTI,
  version scripts, valid DWARF, `ld` options, reproducible output, writing
  outputs in place only when safe, and every other architecture under
  qemu-user when the emulator and the Rust target are installed.
- At scale: Rune's own test suite, which Rune links with hyprlnk by default.
