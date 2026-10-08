# Roadmap

## Windows: finishing touches

- `/DELAYLOAD` (delay-loaded imports with the `__delayLoadHelper2` thunks)
- `/ORDER` (function ordering)
- x86 frame-pointer-omission data (`DEBUG_S_FRAMEDATA`) in PDBs
- `/GUARD:CF` (Control Flow Guard tables) and `/CETCOMPAT`'s debug entry
- Range-extension thunks for ARM64 branches farther than 128 MB
- ARM64EC and ARM64X

## New platforms

1. **ELF** (Linux): executables and shared objects for x86-64 and AArch64,
   used through `cc -fuse-ld=hyprlnk` and by Rune directly — so Rune's main
   platforms get the same speed.
2. **Mach-O** (macOS).

## Faster still

- Parallel symbol resolution (resolving in place in a concurrent table)
- Incremental relinking inside Rune: keep the previous link's state between
  builds and only redo what changed
- Writing streams straight into the output, skipping the last copy
- Smaller working set for very large links (lazier symbol decoding)

Ideas and benchmarks are welcome — open an issue.
