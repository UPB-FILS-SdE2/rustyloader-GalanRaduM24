use nix::libc::siginfo_t;
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, Signal};
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::Read;
se std::path::Path;

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments
    println!("I like turtules");
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let elf_header: &runner::Elf32_Ehdr = unsafe { &*(buffer.as_ptr() as *const runner::Elf32_Ehdr) };
    let base_address = elf_header.e_entry as usize; // Simplified example
    let entry_point = elf_header.e_entry as usize;

    // print segments
    eprintln!(
        "Base address: 0x{:x}\nEntry point: 0x{:x}",
        base_address, entry_point
    );
    
    // determine base address

    // determine entry point

    // register SIGSEGV handler
    // Set up SIGSEGV handler
    let handler = SigHandler::SigAction(sigsegv_handler);
    let action = SigAction::new(handler, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe { sigaction(Signal::SIGSEGV, &action) }?;


    // run ELF using runner::exec_run
    runner::exec_run(base_address, entry_point);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-executable>", args[0]);
        std::process::exit(1);
    }

    exec(&args[1])?;

    Ok(())
}
