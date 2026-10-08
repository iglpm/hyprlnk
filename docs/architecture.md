# Architecture

hyprlnk is a library (`hyprlnk`) with a thin binary on top. The PE/COFF
backend lives in `src/coff/`; everything there is organized as phases of
one link, each a module adding methods to the `Linker` in `resolve.rs`.

```text
command line ─▶ config ─▶ resolve ─▶ gc ─▶ icf ─▶ synth ─▶ layout ─▶ write ─┬─▶ image
                (args,     (inputs,   (live   (fold    (imports,  (output    (relocate,  │
                 .def)      symbols)   COMDATs) dupes)   exports,   sections,  headers)   └─▶ PDB
                                                         resources) addresses)  (pdb/, in parallel)
```

## Source map

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

**Machine differences in one place.** `arch.rs` holds what differs between
x64, ARM64 and x86: relocation semantics, thunk code, pointer and header
sizes, exception-table formats. The rest of the linker asks it.

## A link, step by step

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

Rune passes `-C linker=<rune.exe>` to `rustc` and sets `RUNE_HYPRLNK` on the
compiler; `rune`'s `main` sees the variable and runs
`hyprlnk::main_with_args` instead of its own command line. The linker
setting a unit is cached under is `rune:hyprlnk@<version>`, independent of
where `rune` is installed. See `crates/rune-common/src/linker.rs` in the
Rune repository.

## Testing

- Unit tests next to the code (`cargo test` / `rune test -p hyprlnk`).
- `tests/link.rs`: end-to-end links with `rustc -C linker=hyprlnk` that run
  what they link — unwinding, threads and TLS, DLLs, resources, PDBs read by
  `dbghelp`, x86 programs, ARM64 images compared byte-for-byte with
  `lld-link`, reproducible output. Parts skip when a target or tool is
  missing.
- At scale: Rune's own test suite with `RUNE_BUILD_LINKER=hyprlnk`.
