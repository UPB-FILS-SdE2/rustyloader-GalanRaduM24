use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;

mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages

    // !TODO: Handle the page fault, map the page if it's a valid access
    // and belongs to an unmapped page in a segment. Otherwise, handle
    // invalid memory access.
    std::process::exit(0);
}

fn read_segments(filename: &str) -> Result<Vec<object::Segment>, Box<dyn Error>> {
    // !TODO: Read the ELF file specified by filename and extract segment information.
    Ok(Vec::new()) // Placeholder
}

fn print_segments(segments: &[object::Segment]) {
    // !TODO: Print the segment information to stderr.
}

fn determine_base_address(segments: &[object::Segment]) -> u64 {
    // !TODO: Determine the base address for loading segments.
    0 // Placeholder
}

fn determine_entry_point(filename: &str) -> Result<u64, Box<dyn Error>> {
    // !TODO: Extract the entry point address from the ELF header.
    Ok(0) // Placeholder
}

fn register_sigsegv_handler() -> Result<(), Box<dyn Error>> {
    // !TODO: Set up the signal handler to handle SIGSEGV signals.
    Ok(())
}



fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // read ELF segments
    println!("Reading ELF segments...");
    let segments = read_segments(filename)?;

    // print segments
    println!("Segments:");
    print_segments(&segments);

    // determine base address
    println!("Determining base address...");
    let base_address = determine_base_address(&segments);

    // determine entry point
    println!("Determining entry point...");
    let entry_point = determine_entry_point(filename)?;

    // register SIGSEGV handler
    println!("Registering SIGSEGV handler...");
    register_sigsegv_handler();

    // run ELF using runner::exec_run
    println!("Running ELF...");
    runner::exec_run(base_address as usize, entry_point as usize);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // load ELF provided within the first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-executable>", args[0]);
        std::process::exit(1);
    }

    Ok(())
}