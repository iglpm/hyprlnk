# macOS

hyprlnk links Mach-O executables, dylibs and bundles for **arm64**, **arm64e**
and **x86_64** (and x86_64h). It takes the command lines of Apple's `ld`
(ld64 and ld-prime) and of `ld64.lld`, and the `cc`-style command lines rustc
writes for a linker it doesn't recognize, so it slots in wherever those run.

## Using it

### With Igel

```toml
[build]
linker = "hyprlnk"
```

Igel links binaries, tests, build scripts, proc-macros and dynamic libraries
for `aarch64-apple-darwin`, `x86_64-apple-darwin` and `arm64e-apple-darwin`
with the hyprlnk built into `igl`. It tells rustc to pass ld64's command
line (`-C linker-flavor=ld64.lld`), so link arguments written for `cc` in
`.cargo/config.toml` (`-C link-arg=-fuse-ld=lld`, `-Wl,…`) keep working:
hyprlnk ignores the driver-only ones and unwraps `-Wl,` itself.

### With Cargo or rustc

Either name hyprlnk as the linker — rustc then passes a `cc`-style command
line, which hyprlnk understands —

```toml
# .cargo/config.toml
[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"
```

or keep `cc` as the driver and swap only the linker:

```toml
[target.aarch64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/ld64.hyprlnk"]
```

(`ld64.hyprlnk` is a link or copy of `hyprlnk`; a program name starting with
`ld64` selects the ld64 command line, as does `-flavor darwin`.) The fastest
route skips `cc` entirely:

```toml
[target.aarch64-apple-darwin]
linker = "/usr/local/bin/hyprlnk"
rustflags = ["-C", "linker-flavor=ld64.lld"]
```

### C, C++ and Objective-C

```sh
clang -fuse-ld=/usr/local/bin/ld64.hyprlnk main.c util.c -o app
clang++ -fuse-ld=/usr/local/bin/ld64.hyprlnk -std=c++20 *.cpp -o app
cmake -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk \
      -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=/usr/local/bin/ld64.hyprlnk ..
```

### Finding the SDK

Libraries (`-lSystem`, `-framework Foundation`) come from the SDK's `.tbd`
text stubs. hyprlnk searches `-L`/`-F` directories (re-rooted under
`-syslibroot` like ld64), then `/usr/lib` and `/System/Library/Frameworks`
inside the SDK. Without `-syslibroot` it uses `SDKROOT`, then the Command
Line Tools' or Xcode's macOS SDK.

## What it writes

| | |
| --- | --- |
| Segments | `__PAGEZERO`, `__TEXT`, `__DATA_CONST` (macOS 10.15+), `__DATA`, `__LINKEDIT`, in ld64's order; 16 KiB pages on arm64, 4 KiB on x86_64 |
| Fixups | rebase/bind opcodes (`LC_DYLD_INFO_ONLY`) below macOS 13, chained fixups (`LC_DYLD_CHAINED_FIXUPS` + `LC_DYLD_EXPORTS_TRIE`) from 13 and always on arm64e; `-fixup_chains`/`-no_fixup_chains` choose |
| Imports | stubs through `__got` slots bound at load (no lazy binding); on arm64e `__auth_stubs` through signed `__auth_got` slots |
| Exports | the export trie; executables export every visible global, as ld64 does |
| Unwinding | `__unwind_info` from compact unwind entries (folded, common encodings, compressed pages) with DWARF-mode entries pointing into a pruned `__eh_frame`; personality routines through GOT slots |
| Thread locals | `__thread_vars`/`__thread_data`/`__thread_bss`, TLV accesses relaxed to direct ones in the image |
| Debug info | the stabs debug map (`N_SO`, `N_OSO`, `N_FUN`, `N_STSYM`, `N_GSYM`), for `dsymutil`, lldb and Rust's backtraces |
| Signature | an ad-hoc, linker-signed code signature (SHA-256, 4 KiB pages) on arm64 and arm64e, as ld64 writes; `-adhoc_codesign` adds one on x86_64 |
| Identity | an `LC_UUID` hashed from the contents, `LC_BUILD_VERSION` (or `LC_VERSION_MIN_MACOSX` before 10.14), `LC_SOURCE_VERSION` |
| Also | `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, `LC_RPATH`, `LC_MAIN`, `LC_ID_DYLIB`, weak/re-exported/upward dylibs |

It relaxes GOT loads of symbols defined in the image to address computations
(`ldr` → `add` on arm64, `movq` → `leaq` on x86_64), deduplicates C strings
and fixed-size literals across inputs, and places `__thread_data` and
`__thread_bss` together so dyld copies one template per thread.

## Linking, the parts that matter

- **Atoms.** Objects built with `MH_SUBSECTIONS_VIA_SYMBOLS` (every compiler
  does) split at each symbol; C strings and literals split by content;
  `__eh_frame` splits into CIEs and FDEs. Dead stripping, deduplication and
  placement work on atoms.
- **Dylibs and text stubs.** `.tbd` files (YAML v1–v4 and JSON v5) and real
  dylibs (export trie or symbol table) provide symbols. Re-exported libraries
  — found inline in the same stub, or in the SDK — count as the parent's, and
  imports bind to the parent's ordinal, as dyld expects. `$ld$hide$`,
  `$ld$add$`, `$ld$install_name$` and `$ld$previous$` apply for the
  deployment target; arm64 links against `arm64e` stubs.
- **Precedence.** As in ld64.lld: objects beat dylibs; between an archive and
  a dylib the one earlier on the command line wins; strong definitions beat
  weak ones; `.weak_def_can_be_hidden` definitions are hidden. Weak
  definitions the image exports, and pointers to weak definitions in dylibs,
  get weak bindings (or weak-lookup binds with chained fixups) so dyld can
  coalesce them.
- **Objective-C.** Classes, categories and selector references link as
  sections; `_objc_msgSend$selector` calls (clang's default on arm64) get the
  stubs, selector names and selector references the linker must make.
  `-ObjC` loads archive members that define classes.
- **arm64e.** Signed pointers (`ARM64_RELOC_AUTHENTICATED_POINTER`) become
  authenticated rebases and binds in `DYLD_CHAINED_PTR_ARM64E_USERLAND24`
  chains; stubs, personality routines and TLV thunks use signed slots with
  ld64's schemas; the image carries the pointer-authentication ABI version.
  (ld64.lld cannot link arm64e.)

## Debugging what it wrote

```sh
hyprlnk … --time                 # where the time went
otool -lv app                    # load commands
dyld_info -fixups -exports app   # what dyld will do
codesign -v app                  # the signature
dsymutil app && lldb app         # the debug map, turned into a dSYM
```

## Not supported (yet)

- Branch islands for arm64 `__text` larger than 128 MiB (hyprlnk reports the
  out-of-range branch).
- `-r` (relocatable output), `-static`, `-preload`; LTO with LLVM bitcode
  inputs (`-C linker-plugin-lto`; ordinary `-C lto` works).
- `-order_file`, `-sectorder`, identical code folding, Objective-C category
  merging, `__init_offsets` (initializers stay pointers, which dyld runs), and
  the iOS/watchOS/tvOS/visionOS platforms beyond writing their load commands.
- 32-bit (i386, armv7) Mach-O.
