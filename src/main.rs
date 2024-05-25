use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};



fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-executable>", args[0]);
        std::process::exit(1);
    }
    Ok(())
}