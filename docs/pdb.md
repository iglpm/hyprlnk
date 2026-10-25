# Debug info (PDB)

With `/DEBUG`, hyprlnk writes a PDB next to the image and points the image's
debug directory at it. `rustc` asks for one whenever linked code has debug
info, which includes the standard library.

## What's in it

| | |
| --- | --- |
| **Types** (TPI) and **ids** (IPI) | every distinct type and function id of every object, merged |
| **Module streams** | each object's symbols — functions, blocks, inlined calls, locals and parameters with their locations — and line tables |
| **Globals** | global data, typedefs, constants, and a reference to every function, with a hash table to find them by name |
| **Publics** | every external symbol, with a name hash table and an address map |
| **DBI** | the module list, section contributions (which module each piece of the image came from), section map, source file list, image section headers |
| **Natvis** | `/NATVIS` files, embedded as injected sources (`/src/headerblock`, `/src/files/…`) — where Visual Studio and VS Code look for visualizers |

Object debug info that refers to code the link dropped (unreferenced
COMDATs, folded functions) is left out, along with the line tables that
went with it.

## Compatibility

The streams follow the format Microsoft's DIA SDK and `dbghelp` read, and
`lld-link` writes: same stream layout, same hash functions (`hashStringV1`,
the CRC-32 type hashes), same hash table growth, same record translations
(for example `S_GPROC32_ID` becomes `S_GPROC32` with the function's type).
On Igel's own build the PDB has exactly as many type and id records as
lld's, and is within 0.2 % of its size.

What hyprlnk checks itself against:

- `dbghelp`: Rust backtraces of hyprlnk-linked programs resolve function
  names and `file:line` for user code and the standard library (x64, x86).
- `llvm-pdbutil dump --all` reads every stream and record without error.
- Stream-by-stream comparison with lld's PDB for the same link.

Not written yet: x86 frame-pointer-omission data (`DEBUG_S_FRAMEDATA`, used
by debuggers to walk x86 stacks without frame pointers), and type-server
(`/Zi` + `vc140.pdb`) or precompiled-header types — modules whose types live
outside their object keep their symbols, with "no type".

## How it is built so fast

PDB writing is where `lld-link` spends most of its time. hyprlnk:

1. **Builds it while writing the image.** Sections are relocated on some
   threads while the PDB is assembled on the others; only the final
   identity stamp waits for both.
2. **Merges types without locks.** Each object's type records are hashed on
   that object's thread: a record's hash covers its bytes with every type
   index it contains replaced by the referenced type's hash, so equal types
   hash equally wherever they come from. All hashes go into one lock-free
   table where the earliest copy of each type wins (a compare-and-swap on
   its location), which keeps the result deterministic. Final indices come
   from prefix sums over what each object keeps, and the kept records are
   copied and rewritten on all threads.
3. **Builds every module stream in parallel**, rewriting records in place.
4. **Builds the global and public tables in parallel**, deduplicating
   typedefs by sorting content hashes rather than through a shared set.
5. **Never copies the big streams.** The type streams are written with room
   for their headers; the MSF container is laid out and copied into a
   memory-mapped file block by block on all threads.

Run with `/TIME` to see each sub-phase.

## Identity and determinism

A PDB is tied to its image by a GUID and an age in both. hyprlnk derives the
GUID from a hash of the PDB's contents, and the image timestamp from a hash
of the image (which contains the GUID), so the same inputs always give the
same image and the same PDB — useful for caching (Igel stores linked
binaries by content) and for reproducible builds.

`/PDBALTPATH:%_PDB%` (which `rustc` passes) records only the PDB's file name
in the image, so debuggers look for it next to the executable.
