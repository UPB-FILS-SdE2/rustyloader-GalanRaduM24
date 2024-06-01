use nix::libc::{siginfo_t, EXIT_SUCCESS};
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::{self, Read};
use std::ptr::addr_of;
use object::{Object, ObjectSegment};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, SaFlags};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use nix::unistd::sysconf;
use nix::unistd::SysconfVar;

mod runner;

// Global variable to store segments
static mut SEGMENTS: Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)> = Vec::new();

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    // Get address
    let address = unsafe { (*siginfo).si_addr() } as usize;
    //eprintln!("Segmentation fault at address: {:#x}", address);

    unsafe {
        // Get page size
        if let Some(page_size) = sysconf(SysconfVar::PAGE_SIZE).ok().flatten() {
            // Map page
            let page_size = page_size as usize;
            for segment in addr_of!(SEGMENTS).read().iter() {
                //eprintln!(
                //    "Checking segment: start {:#x}, size {:#x}",
                //    segment.0, segment.1
                //);
                if address >= segment.0 as usize && address < (segment.0 + segment.1) as usize {
                    // Page start address
                    let page_start = address & !(page_size - 1);
                    let segment_offset = page_start as u64 - segment.0;
                    let length = segment.1 - segment_offset;
                    let prot = segment_flags_to_prot_flags(segment.5);

                    //eprintln!(
                    //    "Mapping page at address {:#x} with length {:#x} and protection {:?}",
                    //    page_start, length, prot
                    //);

                    mmap(
                        page_start as *mut c_void,
                        length as usize,
                        prot,
                        MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                        -1,
                        0,
                    ).expect("mmap failed");
                    return;
                }
            }
        }
    }

    std::process::exit(0);
}

fn segment_flags_to_prot_flags(flags: object::SegmentFlags) -> ProtFlags {
    match flags {
        // Parse flags
        object::SegmentFlags::Elf { p_flags } => {
            // PROT_EXEC = 0x1, PROT_WRITE = 0x2, PROT_READ = 0x4
            let mut prot_flags = ProtFlags::empty();
            if p_flags & 0x1 != 0 { prot_flags |= ProtFlags::PROT_EXEC; }
            if p_flags & 0x2 != 0 { prot_flags |= ProtFlags::PROT_WRITE; }
            if p_flags & 0x4 != 0 { prot_flags |= ProtFlags::PROT_READ; }
            prot_flags
        }
        _ => ProtFlags::empty(),
    }
}

fn read_segments(filename: &str) -> Result<Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)>, Box<dyn Error>> {
    // Read object file
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse object file
    let obj_file = object::File::parse(&*buffer)?;

    // Collect segments
    let segments: Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)> = obj_file
        .segments()
        .map(|segment| (
            // Address, size, file offset, file size, flags
            segment.address(),
            segment.size(),
            segment.file_range().0,
            segment.file_range().1,
            segment.file_range().1 - segment.file_range().0,
            segment.flags(),
        ))
        .collect();

    // Return segments
    Ok(segments)
}

fn print_segments(segments: &[(u64, u64, u64, u64, u64, object::SegmentFlags)]) {
    // Print segments
    eprintln!("Segments");
    for (i, segment) in segments.iter().enumerate() {
        eprintln!(
            // Address, size, file offset, file size, flags
            "{}\t{:#x}\t{}\t{:#x}\t{}\t{}",
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
    // Parse flags
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
    // Print entry point
    eprintln!("Entry point {:x}", entry_point);
}

fn print_base_address(base_address: u64) {
    // Print base address
    eprintln!("Base address {:x}", base_address);
}

fn determine_entry_point(filename: &str) -> Result<u64, Box<dyn Error>> {
    // Read object file
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    // Read file to buffer
    file.read_to_end(&mut buffer)?;
    // Parse object file
    let obj_file = object::File::parse(&*buffer)?;
    // Return entry point
    Ok(obj_file.entry())
}

fn determine_base_address(segments: &[(u64, u64, u64, u64, u64, object::SegmentFlags)]) -> u64 {
    // Find the lowest segment address
    segments.iter().map(|s| s.0).min().unwrap_or(0)
}

fn register_sigsegv_handler() -> Result<(), Box<dyn Error>> {
    // Create signal action
    let sig_action = SigAction::new(
        SigHandler::SigAction(sigsegv_handler),
        SaFlags::SA_SIGINFO,
        SigSet::empty(),
    );
    unsafe {
        // Register signal handler
        sigaction(nix::sys::signal::Signal::SIGSEGV, &sig_action)?;
    }
    Ok(())
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    // Read segments
    let segments = read_segments(filename)?;
    print_segments(&segments);

    // Save segments for later use
    unsafe {
        SEGMENTS = segments.clone();
    }

    // Determine entry point
    let entry_point = determine_entry_point(filename)?;
    print_entry_point(entry_point);

    // Determine base address
    let base_address = determine_base_address(&segments);
    print_base_address(base_address);

    // Register signal handler
    register_sigsegv_handler()?;

    // Execute
    runner::exec_run(base_address as usize, entry_point as usize);

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