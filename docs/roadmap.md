# Roadmap

## Done

- **Windows**: PE/COFF for x64, ARM64 and x86, with PDBs.
- **macOS**: Mach-O for arm64, arm64e and x86_64 — executables, dylibs and
  bundles, chained fixups, code signatures, the debug map, Objective-C,
  about twice as fast as Apple's ld-prime and four times lld.
- **Linux**: ELF for x86-64, x86, AArch64, ARM, RISC-V, POWER (ppc64le),
  s390x and LoongArch — executables (PIE, static, static-pie) and shared
  objects against glibc and musl, symbol versions, all TLS models with
  relaxation, IFUNC, `--gc-sections`, build IDs; Rune's default linker.

## Linux: finishing touches

- Range-extension thunks for AArch64 and ARM branches beyond their reach
- Linker relaxation on RISC-V and LoongArch
- `-z pack-relative-relocs` (`DT_RELR`), `--compress-debug-sections`,
  `--icf`
- ppc64 ELFv1, big-endian AArch64 and ARM, x32, Android
- Linker scripts with `SECTIONS` (kernels, firmware)

## macOS: finishing touches

- Branch islands (range-extension thunks) for arm64 `__text` over 128 MiB
- `-order_file`, `-why_live`
- Identical code folding (`-deduplicate`), as on Windows
- `__init_offsets` with chained fixups, Objective-C category merging
- iOS, tvOS, watchOS and visionOS tested end to end (they get the right load
  commands today)
- LTO through LLVM bitcode inputs

## Windows: finishing touches

- `/DELAYLOAD` (delay-loaded imports with the `__delayLoadHelper2` thunks)
- `/ORDER` (function ordering)
- x86 frame-pointer-omission data (`DEBUG_S_FRAMEDATA`) in PDBs
- `/GUARD:CF` (Control Flow Guard tables) and `/CETCOMPAT`'s debug entry
- Range-extension thunks for ARM64 branches farther than 128 MB
- ARM64EC and ARM64X

## Faster still

- Parallel symbol resolution (resolving in place in a concurrent table)
- Incremental relinking inside Rune: keep the previous link's state between
  builds and only redo what changed
- Starting LINKEDIT (symbol table, export trie) before layout finishes
- Smaller working set for very large links (lazier symbol decoding)

Ideas and benchmarks are welcome — open an issue.
