# hyprlnk Documentation

Welcome to the hyprlnk documentation. hyprlnk is a high-performance, drop-in linker for Windows, macOS, and Linux that delivers industry-leading linking speeds across Rust, C, and C++ codebases.

If you are new to hyprlnk, start with the [Getting Started Guide](getting-started.md).

## Documentation Index

| Guide | Description |
| :--- | :--- |
| [Getting Started](getting-started.md) | Installation options and integration guides for Rune, Cargo, rustc, GCC, Clang, CMake, and MSBuild |
| [Linux ELF Linker](linux.md) | Architecture coverage, runtime integration, glibc/musl support, and current capabilities |
| [macOS Mach-O Linker](macos.md) | Mach-O outputs, compact unwind info, debug maps, ad-hoc code signing, and Apple Silicon tuning |
| [Command Line Options](command-line.md) | Comprehensive command line flag reference across MSVC, ld64, and GNU ld syntaxes |
| [Debug Info & PDBs](pdb.md) | High-speed PDB generation, Natvis type visualizers, line tables, and deterministic debug GUIDs |
| [Performance Analysis](performance.md) | Benchmarks against platform linkers, phase-by-phase profiling, and measuring your own projects |
| [Compatibility Reference](compatibility.md) | Supported object formats, libraries, relocations, and compatibility details |
| [Internal Architecture](architecture.md) | Multi-threaded pipeline design, memory mapping, data layout, and codebase tour |
| [Troubleshooting](troubleshooting.md) | Resolving linker errors, diagnosing performance with `/TIME`, and generating `/REPRODUCE` bundles |
| [Project Roadmap](roadmap.md) | Upcoming platform features, optimization targets, and ecosystem milestones |

## What Does a Linker Do?

When a compiler runs, it turns individual source files into object files. The linker is the essential tool that combines those object files and external libraries into a working executable or shared library:
- **Symbol Resolution**: Matches function calls and global variables with their definitions across all object files and libraries.
- **Dead Code Stripping**: Discards unused functions and data sections (`/OPT:REF`, `-dead_strip`, `--gc-sections`) to shrink binaries.
- **Relocation & Layout**: Assigns final memory addresses and patches machine code instructions to reference those exact addresses.
- **Debug Info Emission**: Generates debug structures — such as PDB files on Windows, debug maps on macOS, or embedded DWARF on Linux — allowing debuggers and stack backtraces to map binary addresses back to exact source code lines.
- **System Compliance**: Emits OS-required security flags, exception unwind tables, dynamic loader tables, and cryptographic code signatures.
