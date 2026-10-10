# Performance

- [Linux](#linux) · [macOS](#macos) · [Windows](#windows) · [Measuring your own links](#measuring-your-own-links)

## Linux

Three links, captured with `HYPRLNK_REPRODUCE` and replayed with each linker:
Rune's own `rune` and hyprlnk's own `hyprlnk` in the dev profile (full debug
info), and Rune's link again with `-S` (no debug info, like a release build).
Intel Core i5-10400F (6 cores, 12 threads), Linux 7.2, inputs in the file
cache, outputs on tmpfs; the linkers take turns, 11 rounds after a warm-up,
wall-clock time including process startup.

| | hyprlnk | wild 0.10 | mold 3.0 | lld 23.1 |
| --- | ---: | ---: | ---: | ---: |
| Rune, dev (3,640 objects, 600 MB in, 308 MB out) | 258 ms | **255 ms** | 427 ms | 478 ms |
| hyprlnk, dev (716 MB in, 381 MB out) | 267 ms | **253 ms** | 386 ms | 409 ms |
| Rune, `-S` (77 MB out) | 138 ms | **100 ms** | 256 ms | 311 ms |

hyprlnk links in 55–70 % of mold's time and 45–65 % of lld's. wild is ahead:
by 1–5 % with debug info and by a third without it. The outputs are
equivalent; hyprlnk's are the smallest (wild's are up to 2 %, lld's 1–4 % and
mold's 9–34 % larger).

On a disk the picture is the same with more noise: Linux throttles writers
once a few hundred megabytes are waiting to be written back, and a relink
writes a whole executable. hyprlnk, like mold and wild, writes an executable
into the previous one's file when that is safe, which spares the kernel
allocating fresh pages (see [Linux](linux.md#linking-the-parts-that-matter)).

`--time` for Rune's dev link (`HYPRLNK_PROF=1` adds CPU time and busy cores):

```text
hyprlnk:      3.85 ms  open inputs
hyprlnk:     10.86 ms  parse inputs
hyprlnk:     14.54 ms  intern symbols
hyprlnk:      5.85 ms  load archive members
hyprlnk:     13.36 ms  resolve symbols
hyprlnk:      3.28 ms  parse .eh_frame
hyprlnk:     24.00 ms  gc sections
hyprlnk:      1.58 ms  scan relocations
hyprlnk:      2.35 ms  GOT, PLT, dynamic symbols
hyprlnk:     49.40 ms  merge strings and constants
hyprlnk:      9.70 ms  output sections
hyprlnk:     16.17 ms  layout
hyprlnk:     98.33 ms  write sections
hyprlnk:      0.55 ms  build ID
hyprlnk:      4.97 ms  commit output
```

| Phase | What happens | What makes it fast |
| --- | --- | --- |
| Open inputs | map files, list archive members, follow input scripts | parallel; archive members' headers read on all threads |
| Parse, intern | sections and symbols of every object; names to the symbol table | big files first; names hashed (128-bit) on the parsing threads and bucketed by shard; each shard keeps each symbol's best definition, no locks |
| Load archive members | waves of members defining what is undefined | each wave parsed and ranked in parallel |
| gc sections | mark from the roots; decide what each relocation needs | work-stealing marking with atomic flags; each section's relocations scanned (GOT, PLT, TLS, copies) right after it is marked, while they are in cache |
| Merge strings | `.debug_str`, `.rodata.str*` and friends deduplicated | split and hashed per section, deduplicated per shard, offsets filled in per section in order; the debug ones run beside resolution and gc |
| Layout, write | addresses; sections copied and relocated | all in parallel into the mapped output; each writer hashes what it wrote, so the build ID costs half a millisecond |
| Exit | | the process forks first: the parent exits once the output is complete, the child tears down |

## macOS

Linking Rune's own `rune` (dev profile): 258 objects and 202 rlibs on the
command line (2,561 objects loaded, 445,000 atoms), libSystem, Security and
CoreFoundation from the SDK's text stubs, 609 MB of input, a 90 MB
executable with a 9.8 MB export trie and a 450,000-entry symbol table with
its debug map. Apple M5 (10 cores, MacBook Air), macOS 27, inputs in the file
cache; the three linkers take turns, 7 rounds, wall-clock time including
process startup.

| | hyprlnk | Apple `ld` (ld-prime, ld-27037) | ld64.lld 23.1 |
| --- | ---: | ---: | ---: |
| Median | **75 ms** | 172 ms | 310 ms |
| Fastest | **73 ms** | 171 ms | 309 ms |
| Output | 90.3 MB | 94.3 MB | 89.8 MB |
| hyprlnk on 1 thread | 234 ms | | |

The outputs are equivalent: the same sections with the same sizes as lld's
(`__text`, `__eh_frame` and `__unwind_info` identical), the same symbols, and
an export trie a few bytes smaller. On x86_64, hyprlnk's code is
instruction-for-instruction lld's once addresses are factored out. (A
MacBook Air throttles under sustained load; measure with the linkers
interleaved, as above.)

`--time` (or ld-prime's `-print_statistics`) for this link:

```text
hyprlnk:              2561 objects, 202 archives, 5 dylibs, 444912 atoms, 168390 symbols
hyprlnk:              8 waves: parsing 12.46 ms, merging 3.49 ms
hyprlnk:              LINKEDIT: fixups 2.88 ms, exports 10.19 + trie 6.97 ms, symtab plan 11.25 ms, function starts 10.19 ms
hyprlnk:     10.4 ms  open inputs
hyprlnk:     16.3 ms  resolve symbols
hyprlnk:      6.1 ms  dead strip
hyprlnk:      1.0 ms  synthetic sections
hyprlnk:      5.3 ms  layout
hyprlnk:     21.3 ms  write sections and LINKEDIT
hyprlnk:      6.3 ms  UUID, code signature and file
```

| Phase | What happens | What makes it fast |
| --- | --- | --- |
| Open inputs | map files, read archive symbol tables, parse text stubs | one `open` per file (deduplicated by inode: `-lSystem -lc -lm` parse one stub), parallel |
| Resolve symbols | load needed objects and archive members, split them into atoms | waves of parallel parsing; names hashed and looked up on the parsing threads |
| Dead strip | mark live atoms; classify every relocation | work-stealing marking with atomic flags; one walk decides stubs, GOT slots, rebases and binds |
| Layout | sections, addresses, `__unwind_info` | per-chunk placement in parallel; unwind encodings counted by sorting |
| Write | copy and relocate sections ∥ fixups, export trie, symbol table and debug map | two buffers built side by side; export trie built in one pass over common prefixes, its offsets and bytes in parallel |
| Sign and write the file | UUID, code signature, `pwrite` | helper threads write the file while the signature is hashed (two pages at a time on the SHA unit); only the first page and the signature wait |

The output is written with `pwrite`, not through a shared mapping: macOS
treats file pages that were written through a mapping as possibly tampered
once the file runs, and kills processes that map them.

## Windows

Linking Rune's own `rune.exe` (dev profile): 2,337 objects from 221 archives
(250 crates plus the standard library), 715 MB of input, a 32 MB executable,
a 189 MB PDB. Intel Core i5-10400F (6 cores, 12 threads), Windows 11, inputs
in the file cache, best of 7 runs, wall-clock time including process
startup (about 70 ms per process here).

| | hyprlnk | lld-link 22.1 | |
| --- | ---: | ---: | ---: |
| Executable only (`/DEBUG:NONE`) | **440 ms** | 845 ms | 1.9× |
| Executable + PDB | **1.09 s** | 1.93 s | 1.8× |
| Executable + PDB, hyprlnk on 1 thread | 1.95 s | | |

`rust-lld` (the lld that ships with Rust) performs like `lld-link`. On a quiet
machine the gap is larger: the executable-only link has measured 339 ms
against 781 ms.

The outputs are equivalent: the executables are within 3 KB of each other
(lld's has a debug directory), the PDBs hold the same number of type records
(508,878) and are within 0.2 % in size.

With `/OPT:ICF`, hyprlnk's release binaries are as small as lld's or smaller
(a test program: 303,104 bytes against lld's 303,616), because unwind data
shared between functions is folded too.

## Measuring your own links

On Linux, capture with `HYPRLNK_REPRODUCE` and replay with each linker (the
saved command line is GNU ld's, which all of them take):

```sh
HYPRLNK_REPRODUCE=/tmp/links cargo build      # with hyprlnk as the linker (or under Rune)
cd /tmp/links/myapp-1234
hyprlnk -flavor gnu @link.rsp -o h --time
mold @link.rsp -o m
wild @link.rsp -o w
ld.lld @link.rsp -o l
```

On macOS, capture with `HYPRLNK_REPRODUCE` and replay with each linker:

```sh
HYPRLNK_REPRODUCE=/tmp/links cargo build      # with hyprlnk as the linker
cd /tmp/links/myapp-1234
hyprlnk -flavor darwin @link.rsp -o h --time
ld @link.rsp -o a -print_statistics
ld64.lld @link.rsp -o l
```

On Windows, capture a real link with `/REPRODUCE` (or `HYPRLNK_REPRODUCE`, which reaches
links that `rustc` runs, under Cargo or Rune), then replay it with each
linker:

```powershell
$env:HYPRLNK_REPRODUCE = "C:\links"
cargo build        # with hyprlnk as the linker
cd C:\links\myapp-1234
hyprlnk @link.rsp /OUT:h.exe /TIME
lld-link @link.rsp /OUT:l.exe
```

`/TIME` prints each phase and its details, for example:

```text
hyprlnk:              2337 objects, 221 archives, 309 imports, 606277 sections, 181386 symbols
hyprlnk:              12 waves: parsing 39.22 ms, merging 23.89 ms, libraries 3.69 ms
hyprlnk:              PDB: 103.20 ms hash types
hyprlnk:              PDB: 111.70 ms merge types
hyprlnk:              PDB: 123.20 ms module streams
hyprlnk:     46.88 ms  open inputs
hyprlnk:     68.69 ms  resolve symbols
hyprlnk:     39.10 ms  garbage collection
…
```

## Where the time goes on Windows, and why it's short

| Phase | What happens | What makes it fast |
| --- | --- | --- |
| Open inputs | map files, read archive symbol tables | memory mapping (small files are read), parallel, symbol names hashed once |
| Resolve symbols | load the objects and archive members that are needed | waves of parallel parsing; names looked up on the parsing threads; only new names touch the shared table |
| Garbage collection | find what is referenced | parallel breadth-first marking with atomic flags |
| Identical code folding | hash candidates until the partition is stable | parallel rounds, as in mold |
| Layout | group sections, assign addresses | a per-object cache of section groups |
| Copy and relocate, build PDB | write the image; build the PDB at the same time | batches of sections per thread, into a memory-mapped output |
| Write | commit the files | output already in place; temporary file renamed |
| Exit | | nothing freed or unmapped one by one |

Scaling is limited by memory bandwidth more than by cores: on a 6-core
machine the heavy phases speed up 3–4× from 1 to 12 threads.
