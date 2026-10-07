//! The standalone `hyprlnk` executable. Rune runs the same linker from its own
//! executable (see `hyprlnk::EMBEDDED_ENV`).

/// The link is mostly small allocations on many threads at once.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    std::process::exit(hyprlnk::main_with_args(std::env::args_os()));
}
