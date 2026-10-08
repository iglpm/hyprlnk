# Troubleshooting

## Common errors

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

`C:\repro\<output>-<pid>\` then holds every input and a `link.rsp`;
`hyprlnk @link.rsp` repeats the link. Zip that directory (check it contains
nothing private) and attach it to an issue, with the error or the
difference you see. Under Rune or Cargo the variable reaches every link
`rustc` runs.
