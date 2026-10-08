# hyprlnk documentation

| | |
| --- | --- |
| [Getting started](getting-started.md) | installing hyprlnk; using it from Rune, Cargo, `rustc`, CMake, clang-cl and MSBuild |
| [Command line](command-line.md) | every option, with the defaults |
| [Debug info (PDB)](pdb.md) | what a hyprlnk PDB holds, how it is built so fast, natvis, determinism |
| [Performance](performance.md) | benchmarks against lld, how to measure your own links, where the time goes |
| [Compatibility](compatibility.md) | supported inputs, machines and features; differences from `link.exe` and `lld-link` |
| [Architecture](architecture.md) | the phases of a link and where each lives in the source |
| [Troubleshooting](troubleshooting.md) | common errors, `/VERBOSE`, `/REPRODUCE`, reporting a bug |
| [Roadmap](roadmap.md) | what comes next |

New to linkers? A linker takes the object files a compiler produces and the
libraries they use, decides which pieces are needed, gives everything an
address, patches every reference to point at that address, and writes the
result as an executable or DLL — plus, on Windows, a PDB file the debugger
uses to map addresses back to functions, variables and source lines.
