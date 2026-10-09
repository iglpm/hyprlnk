# Contributing to hyprlnk

Thanks for helping make linking faster. Bug reports, benchmarks on real
projects and pull requests are all welcome. Please follow the
[code of conduct](CODE_OF_CONDUCT.md).

## Reporting a problem

A link that fails, or an image that behaves differently than with
`link.exe`/`lld-link` (Windows) or Apple's `ld`/`ld64.lld` (macOS), is a bug.
The best report comes with a replayable link:

```powershell
$env:HYPRLNK_REPRODUCE = "C:\repro"     # or pass /REPRODUCE:C:\repro
<run the build that fails>
```

```sh
HYPRLNK_REPRODUCE=/tmp/repro <run the build that fails>
```

Zip `<dir>/<output>-<pid>/` (it holds every input and a `link.rsp`) and
attach it to a [bug report](https://github.com/runepm/hyprlnk/issues/new/choose),
after checking it contains nothing private. See
[troubleshooting](docs/troubleshooting.md).

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening
an issue.

## Development

hyprlnk is a Rust crate with no build-time dependencies beyond Rust itself.
It is developed both on its own and inside the
[Rune](https://github.com/runepm/rune) repository, which includes it as a
submodule at `hyprlnk/` and builds it into the `rune` executable.

```sh
rune build            # or: cargo build
rune test             # unit tests, plus end-to-end links on Windows or macOS
rune build --release  # for benchmarking
```

The end-to-end tests link real programs and run them. `tests/link.rs` (on
Windows) uses `rustc -C linker=hyprlnk` and needs the MSVC build tools;
parts also use the `i686-pc-windows-msvc` and `aarch64-pc-windows-msvc`
targets and `lld-link`. `tests/macho.rs` (on macOS) uses rustc and clang
(the Command Line Tools); parts use the `x86_64-apple-darwin` target
(running it needs Rosetta) and arm64e. Each part skips itself when what it
needs is missing.

Before sending a pull request:

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

### Testing against real links

For changes to how images or debug info are written, check a large real
link against lld. On Windows:

```powershell
$env:HYPRLNK_REPRODUCE = "C:\links"; rune build -p <some big binary>
cd C:\links\<name>-<pid>
hyprlnk @link.rsp /OUT:h.exe /TIME
lld-link @link.rsp /OUT:l.exe
llvm-pdbutil dump --all h.pdb > NUL     # must succeed
```

On macOS:

```sh
HYPRLNK_REPRODUCE=/tmp/links rune build -p <some big binary>
cd /tmp/links/<name>-<pid>
hyprlnk -flavor darwin @link.rsp -o h --time
ld64.lld @link.rsp -o l
codesign -v h && dyld_info -fixups h > /dev/null && dsymutil -s h > /dev/null
```

Inside the Rune repository, `RUNE_BUILD_LINKER=hyprlnk rune test --workspace`
links Rune's whole test suite with your build.

### Performance work

Measure before and after with `/TIME` on a reproduced large link, best of
several runs on a quiet machine, and put the numbers in the pull request.
Keep the output deterministic: the same inputs must give the same bytes.

## Code

- [Architecture](docs/architecture.md) explains the phases and the source
  layout.
- Comments say *why*; keep them up to date with the code.
- Machine-specific details belong in `src/coff/arch.rs`.
- New behavior comes with a test: a unit test next to the code, or an
  end-to-end one in `tests/link.rs`.
- Commit messages: a short summary line, then what changed and why.

## License

By contributing, you agree that your contributions are dual-licensed under
the [MIT](LICENSE-MIT.md) and [Apache 2.0](LICENSE-APACHE.md) licenses, as
the project is.
