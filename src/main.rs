//! The standalone `hyprlnk` executable.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    std::process::exit(hyprlnk::main_with_args(std::env::args_os()));
}
