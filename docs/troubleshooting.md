# Troubleshooting

## Common errors on Linux

**`undefined symbol: foo` / `>>> referenced by …`**
A missing library (`-l`, a crate's `#[link]`, a `-sys` crate's build script),
or one for another architecture. hyprlnk names the first file referencing
the symbol, demangled.

**`unable to find library -lfoo`**
hyprlnk has no library directories of its own (like lld): `-l` looks in the
`-L` directories. Compiler drivers pass the system's; when calling hyprlnk
directly, pass them yourself (`-L/usr/lib`, or your distribution's
`/usr/lib/<triple>`).

**`cannot run the C compiler `cc``**
rustc handed hyprlnk a `cc` command line, and hyprlnk needs a C compiler to
find the C runtime. Install one, set `HYPRLNK_CC` to it, or have rustc pass
`ld` arguments (`-C linker-flavor=ld`, enough for musl targets, which bring
their own C runtime). Under Rune, `target.<triple>.linker` in
`.cargo/config.toml` names the C compiler for that target.

**`crt1.o is for x86-64, but main.o is for AArch64`** (or another pair)
An object or library of another architecture, typically the host's C runtime
in a cross build: name the cross compiler as the target's linker
(`linker = "aarch64-linux-gnu-gcc"`).

**`branch target out of range (more than 128 MiB away)`**
The AArch64 code is larger than a branch reaches; hyprlnk doesn't make
range-extension thunks yet. Split the binary (move code into a shared
object), or build with less code.

**`linker scripts with SECTIONS are not supported`**
hyprlnk lays out the output itself; kernels and firmware need GNU ld or lld.

**Debug info missing for some C objects**
hyprlnk decompresses zlib and zstd debug sections; other formats are left
out with a warning.

**Which linker wrote a file?** `readelf -p .comment file` shows `Linker:
hyprlnk <version>`.

## Common errors on macOS

**`undefined symbol: _foo` / `>>> referenced by …`**
As on Windows: a missing library (`-l`, `-framework`, a crate's `#[link]`),
or a library for another architecture or platform. Text stubs list symbols
per architecture and platform; `$ld$hide$` entries hide some for old
deployment targets.

**`library not found for -lfoo` / `framework not found for -framework Foo`**
The searched directories are printed. Pass `-L`/`-F`, or point
`-syslibroot` (or `SDKROOT`) at the SDK: `xcrun --show-sdk-path`.

**`… is built for x86_64, but the link is for arm64`**
An object or archive member of the wrong architecture. Universal files are
fine; hyprlnk picks the right slice.

**`branch target … is out of range … (±128 MiB)`**
The arm64 `__text` is larger than a branch reaches; hyprlnk doesn't make
branch islands yet. Split the binary (move code into a dylib), or build with
less code (`-C opt-level=s`).

**`absolute pointer in __TEXT,… needs a rebase at runtime, but the section is read-only`**
Position-independent images can't patch read-only code. Compile with
`-fPIC` (Rust always does), or move the data to a writable section.

**`signed pointers … need -arch arm64e`**
An arm64e object in an arm64 link; build everything for the same
architecture.

**The program is killed at launch (`Killed: 9`, "Code Signature Invalid")**
Something changed the file after linking. Relink, or re-sign with
`codesign -s - -f <file>`. hyprlnk never writes into an existing file; a tool
that patches binaries in place (or copying over a running program) can cause
this.

**No source lines in backtraces or lldb**
The debug map points at the object files; they must still exist where the
link found them (or build with `-C split-debuginfo=packed` for a `.dSYM`).
`-S` drops the debug map.

## Common errors on Windows

**`undefined symbol: …` / `>>> referenced by …`**
Something refers to a symbol nothing defines. Usually a missing library
(add it to the command line, or the crate's `#[link]`), a library for the
wrong machine, or a mismatched C runtime. Rust names are shown demangled,
with the mangled name in parentheses. `/FORCE:UNRESOLVED` writes the image
anyway (calls to the symbol will crash).

**`duplicate symbol: …` / `>>> defined at … >>> defined at …`**
Two inputs define the same non-COMDAT symbol. Often two copies of a library,
or the static and DLL C runtimes (`libcmt` and `msvcrt`) mixed.

**`cannot open library 'X.lib' (searched …)`**
The search path is printed. Set `%LIB%` (run from a developer prompt), pass
`/LIBPATH:`, or install the Windows SDK / MSVC build tools for the machine
you are linking.

**`machine type arm64 conflicts with x64`**
An input was built for another machine. Pass the right `/MACHINE` or fix the
input.

**`… LLVM bitcode (linker-plugin LTO) is not supported yet`**
Build without `-C linker-plugin-lto` (ordinary `-C lto` works: the compiler
does it).

**`cannot write 'app.exe': … (is the program still running?)`**
Windows doesn't let a running executable be replaced. Close it.

**A program builds with lld but not hyprlnk (or behaves differently)**
That's a bug — please report it (below).

## Looking inside

On Linux:

- `-t` lists each file as it is loaded; `--time` shows where the time went
  (`HYPRLNK_PROF=1` adds CPU time and busy cores per phase).
- `-Map=app.map` (or `-M`) shows where every section and symbol went.
- `readelf -lSdW app`, `readelf -VW app` (symbol versions) and
  `llvm-dwarfdump --verify app` show what was written.

On macOS:

- `-t` lists each file as it is loaded; `--time` shows where the time went.
- `otool -lv app`, `dyld_info -fixups -exports app`, `codesign -dvvv app`,
  `nm -m app` and `dsymutil -s app` (the debug map) show what was written.

On Windows:

- `/VERBOSE` lists each file read, each archive member loaded, and each
  section folded by ICF.
- `/TIME` shows where the time went.
- `llvm-readobj --file-headers --sections --coff-imports app.exe` and
  `llvm-pdbutil dump --all app.pdb` (from LLVM) show what was written.

## Reporting a bug

The most useful bug report is a link that can be replayed:

```powershell
$env:HYPRLNK_REPRODUCE = "C:\repro"   # or add /REPRODUCE:C:\repro
<build the way that fails>
```

```sh
HYPRLNK_REPRODUCE=/tmp/repro <build the way that fails>   # or --reproduce=/tmp/repro
```

`<dir>/<output>-<pid>/` then holds every input and a `link.rsp`;
`hyprlnk @link.rsp` (on macOS `hyprlnk -flavor darwin @link.rsp`, on Linux
`hyprlnk -flavor gnu @link.rsp`) repeats the link. Zip that directory (check it contains
nothing private) and attach it to an issue, with the error or the
difference you see. Under Rune or Cargo the variable reaches every link
`rustc` runs.
