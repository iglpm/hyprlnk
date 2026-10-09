//! Runs one link many times in a process, for profilers: `repeat <n> <linker args...>`.

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(10);
    let args: Vec<String> = args.collect();
    for _ in 0..n {
        let code = hyprlnk::main_with_args(
            std::iter::once("hyprlnk".to_string()).chain(args.iter().cloned()),
        );
        if code != 0 {
            std::process::exit(code);
        }
    }
}
