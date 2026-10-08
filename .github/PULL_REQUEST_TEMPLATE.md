## What and why

<!-- What this changes, and the problem it solves. Link the issue if there is one. -->

## Testing

- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
- [ ] New behavior has a test (unit test, or end-to-end in `tests/link.rs`)
- [ ] For changes to what is written: a large real link checked against
      `lld-link` (and `llvm-pdbutil dump --all` for PDB changes)
- [ ] Output is still deterministic (the same inputs give the same bytes)

## Performance

<!-- For changes that may affect speed: `/TIME` before and after on a large
reproduced link, best of several runs. Delete this section otherwise. -->
