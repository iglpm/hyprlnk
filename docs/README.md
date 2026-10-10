# hyprlnk documentation

| | |
| --- | --- |
| [Getting started](getting-started.md) | installing hyprlnk; using it from Rune, Cargo, `rustc`, gcc, clang, CMake, clang-cl and MSBuild |
| [Linux](linux.md) | the ELF linker: architectures, what it writes, `cc` and Rune integration, what's not supported yet |
| [macOS](macos.md) | the Mach-O linker: what it writes, unwinding, debug map, signatures, arm64e, Objective-C |
| [Command line](command-line.md) | every option, `link.exe`, ld64 and GNU ld style, with the defaults |
| [Debug info (PDB)](pdb.md) | what a hyprlnk PDB holds, how it is built so fast, natvis, determinism |
| [Performance](performance.md) | benchmarks against lld, mold, wild and Apple's ld, how to measure your own links, where the time goes |
| [Compatibility](compatibility.md) | supported inputs, architectures and features; differences from the platform linkers |
| [Architecture](architecture.md) | the phases of a link and where each lives in the source |
| [Troubleshooting](troubleshooting.md) | common errors, `/VERBOSE`, `/REPRODUCE`, reporting a bug |
| [Roadmap](roadmap.md) | what comes next |

New to linkers? A linker takes the object files a compiler produces and the
libraries they use, decides which pieces are needed, gives everything an
address, patches every reference to point at that address, and writes the
result as an executable or library — plus, on Windows, a PDB file the
debugger uses to map addresses back to functions, variables and source
lines, and on macOS a debug map that leads the debugger to the DWARF in the
object files, and a code signature the kernel checks before running it. On
Linux the DWARF goes into the output itself, and a shared library or
dynamically linked program carries the tables the dynamic loader uses to
connect it to the libraries it needs.
