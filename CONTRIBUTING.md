# Contributing to hyprlnk

Thank you for helping make linking faster for everyone. We welcome bug reports, real-world benchmark data, documentation improvements, and pull requests.

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating in the community.

## Reporting an Issue

If a link fails or emits an image that behaves differently than `link.exe`, `lld-link`, Apple's `ld`, or GNU `ld`, that is a bug.

The fastest way to help us fix the issue is with a reproducible archive:

```powershell
# Windows
$env:HYPRLNK_REPRODUCE = "C:\repro"
<run your failing build>
```

```sh
# Linux & macOS
HYPRLNK_REPRODUCE=/tmp/repro <run your failing build>
```

This generates a directory `<dir>/<output>-<pid>/` containing the input object files, libraries, and exact `link.rsp` response file. Ensure the bundle contains no proprietary code or secrets, zip it, and attach it to a [new GitHub issue](https://github.com/runepm/hyprlnk/issues/new/choose).

For security vulnerabilities, please refer directly to [SECURITY.md](SECURITY.md).

## Local Development Workflow

hyprlnk is written in standard Rust with zero external build-time dependencies. It can be developed standalone or directly within the [Rune](https://github.com/runepm/rune) monorepo (as a submodule at `hyprlnk/`):

```sh
# Build debug binary
cargo build         # or: rune build

# Run unit tests and integration suites
cargo test          # or: rune test

# Build optimized release binary for benchmarking
cargo build --release
```

### Testing Against End-to-End Workloads

hyprlnk features extensive platform test suites:
- **Windows (`tests/link.rs`)**: Tests end-to-end linking with MSVC build tools, verifying unwinding, TLS, resources, and PDB readability via `dbghelp`.
- **macOS (`tests/macho.rs`)**: Verifies Mach-O linking with clang and rustc, testing chained fixups, Objective-C stubs, code-signing, and debug maps with `dsymutil`.
- **Linux (`tests/elf.rs`)**: Tests ELF linking across glibc and musl, verifying DWARF info, shared libraries, and multiple CPU targets under QEMU.

Before opening a pull request, verify code health:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Benchmarking Changes

Performance is our primary goal. If you are submitting an optimization:
1. Benchmark a reproducible large link using `/TIME` or `--time`.
2. Compare before and after results over multiple runs on an unloaded machine.
3. Include your hardware specs and benchmark numbers in your pull request.
4. Ensure outputs remain strictly deterministic (identical inputs must produce identical binary outputs).

## Code Guidelines

- **Architecture**: Review [Linker Architecture](docs/architecture.md) for an overview of linking phases and codebase layout.
- **Clarity**: Write comments explaining *why* a particular optimization or layout decision was made.
- **Tests**: Accompany new features or bug fixes with a unit test or end-to-end integration test.
- **Git Commits**: Use descriptive commit messages with a concise summary line followed by technical context.

## License

By contributing to hyprlnk, you agree that your contributions are dual-licensed under both the [MIT License](LICENSE-MIT.md) and the [Apache License, Version 2.0](LICENSE-APACHE.md).
