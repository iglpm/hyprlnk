# Performance

## Benchmarks

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

Capture a real link with `/REPRODUCE` (or `HYPRLNK_REPRODUCE`, which reaches
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

## Where the time goes, and why it's short

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
