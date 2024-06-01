use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use object::{Object, ObjectSegment};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, SaFlags};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::ptr;

mod runner;

// Signal handler for page faults
extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    eprintln!("Segmentation fault at address {:#x}", address);

    // TODO: Handle the page fault
    // Map the page if it's a valid access and belongs to an unmapped page in a segment.
    // Otherwise, handle invalid memory access.
    
    std::process::exit(0);
}

// Read segments from the ELF file
fn read_segments(filename: &str) -> Result<Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)>, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let obj_file = object::File::parse(&*buffer)?;

    let segments: Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)> = obj_file
        .segments()
        .map(|segment| (
            segment.address(),
            segment.size(),
            segment.file_range().0,
            segment.file_range().1,
            segment.file_range().1 - segment.file_range().0,
            segment.flags(),
        ))
        .collect();
    
    // Debug print to verify segment parsing
    for (i, segment) in segments.iter().enumerate() {
        eprintln!("Segment {}: Address = {:#x}, Size = {}, Offset = {:#x}, Length = {}, Flags = {:?}", i, segment.0, segment.1, segment.2, segment.4, segment.5);
    }

    Ok(segments)
}

fn print_segments(segments: &[(u64, u64, u64, u64, u64, object::SegmentFlags)]) {
    eprintln!("Segments");
    for (i, segment) in segments.iter().enumerate() {
        eprintln!(
            "{}\t{:#x}\t{}\t{:#x}\t{}\t{:?}",
            i,
            segment.0,
            segment.1,
            segment.2,
            segment.4,
            parse_flags(&segment.5)
        );
    }
}

fn parse_flags(flags: &object::SegmentFlags) -> String {
    match flags {
        object::SegmentFlags::Elf { p_flags } => {
            let read = if p_flags & 0x4 != 0 { "r" } else { "-" };
            let write = if p_flags & 0x2 != 0 { "w" } else { "-" };
            let execute = if p_flags & 0x1 != 0 { "x" } else { "-" };
            format!("{}{}{}", read, write, execute)
        }
        _ => "???".to_string(),
    }
}

fn print_entry_point(entry_point: u64) {
    eprintln!("Entry point {:#x}", entry_point);
}

fn print_base_address(base_address: u64) {
    eprintln!("Base address {:#x}", base_address);
}

// Determine the base address for loading segments
fn determine_entry_point(filename: &str) -> Result<u64, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let obj_file = object::File::parse(&*buffer)?;
    Ok(obj_file.entry())
}

fn determine_base_address(segments: &[(u64, u64, u64, u64, u64, object::SegmentFlags)]) -> u64 {
    segments.iter().map(|s| s.0).min().unwrap_or(0)
}

// Register the SIGSEGV handler
fn register_sigsegv_handler() -> Result<(), Box<dyn Error>> {
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

// Main function to load and run the ELF file
fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // Step 1: Read ELF segments
    println!("Reading ELF segments...");
    let segments = read_segments(filename)?;

    // Step 2: Print Segments
    println!("Segments:");
    print_segments(&segments);

    // Step 4: Determine Entry Point
    println!("Determining entry point...");
    let entry_point = determine_entry_point(filename)?;
    print_entry_point(entry_point);

    // Step 3: Determine Base Address
    println!("Determining base address...");
    let base_address = determine_base_address(&segments);
    print_base_address(base_address);

    // Step 5: Register SIGSEGV Handler
    println!("Registering SIGSEGV handler...");
    register_sigsegv_handler()?;

    // Step 6: Run ELF using runner::exec_run
    println!("Running ELF...");
    runner::exec_run(base_address as usize, entry_point as usize);

    Ok(())
}

// Entry point of the program
fn main() -> Result<(), Box<dyn Error>> {
    // Load ELF provided within the first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-executable>", args[0]);
        std::process::exit(1);
    }

    exec(&args[1])?;

    Ok(())
}