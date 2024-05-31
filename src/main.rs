use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use object::{Object, ObjectSegment};

use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, SaFlags};



mod runner;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    // map pages

    // !TODO: Handle the page fault, map the page if it's a valid access
    // and belongs to an unmapped page in a segment. Otherwise, handle
    // invalid memory access.
    eprint!("Segmentation fault at address {:#x}\n", address);
    std::process::exit(-200);
}

fn read_segments(filename: &str) -> Result<Vec<object::Segment>, Box<dyn Error>> {
    // !TODO: Read the ELF file specified by filename and extract segment information.
    Ok(Vec::new()) // Placeholder
}

fn print_segments(segments: &[object::Segment]) {
    // !TODO: Print the segment information to stderr.
    eprintln!("Segments");
    for (i, segment) in segments.iter().enumerate() {
        eprintln!(
            "{}\t{:#x}\t{}\t{:#x}\t{}\t{:?}",
            i,
            segment.address(),
            segment.size(),
            segment.file_range().0,
            segment.file_range().1,
            segment.flags()
        );
    }
}

fn determine_base_address(segments: &[object::Segment]) -> u64 {
    // !TODO: Determine the base address for loading segments.
    segments.iter().map(|s| s.address()).min().unwrap_or(0)
}

fn determine_entry_point(filename: &str) -> Result<u64, Box<dyn Error>> {
    // !TODO: Extract the entry point address from the ELF header.
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let obj_file = object::File::parse(&*buffer)?;
    Ok(obj_file.entry())
}

fn register_sigsegv_handler() -> Result<(), Box<dyn Error>> {
    // !TODO: Set up the signal handler to handle SIGSEGV signals.
    let sig_action = SigAction::new(
        SigHandler::SigAction(sigsegv_handler),
        SaFlags::SA_SIGINFO,
        SigSet::empty(),
    );
    unsafe {
        sigaction(nix::sys::signal::Signal::SIGSEGV, &sig_action)?;
    }
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

    exec(&args[1])?;

    Ok(())
}