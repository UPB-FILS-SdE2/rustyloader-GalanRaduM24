use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::{self, Read};
use object::{Object, ObjectSegment};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, SaFlags};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};

mod runner;

static mut SEGMENTS: Vec<(u64, u64, u64, u64, u64, object::SegmentFlags)> = Vec::new();

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;


    eprintln!("Segmentation fault at address {:#x}", address);

    unsafe {
        for segment in &SEGMENTS {
            if address >= segment.0 as usize && address < (segment.0 + segment.1) as usize {
                let page_start = address & !(4096 - 1);
                let prot = segment_flags_to_prot_flags(segment.5);

                mmap(
                    page_start as *mut c_void,
                    4096,
                    prot,
                    MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    -1,
                    0,
                ).expect("mmap failed");
                return;
            }
        }
    }

    //eprintln!("Invalid memory access at address {:#x}", address);
    std::process::exit(-0);
}

fn segment_flags_to_prot_flags(flags: object::SegmentFlags) -> ProtFlags {
    match flags {
        object::SegmentFlags::Elf { p_flags } => {
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
/*
    for (i, segment) in segments.iter().enumerate() {
        eprintln!("Segment {}: Address = {:#x}, Size = {}, Offset = {:#x}, Length = {}, Flags = {:?}", i, segment.0, segment.1, segment.2, segment.4, segment.5);
    }
    */

    Ok(segments)
}

fn print_segments(segments: &[(u64, u64, u64, u64, u64, object::SegmentFlags)]) {
    eprintln!("Segments");
    for (i, segment) in segments.iter().enumerate() {
        eprintln!(
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
    eprintln!("Entry point {:x}", entry_point);
}

fn print_base_address(base_address: u64) {
    eprintln!("Base address {:x}", base_address);
}

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

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    //println!("Reading ELF segments...");
    let segments = read_segments(filename)?;

    //println!("Segments:");
    print_segments(&segments);

    //println!("Determining entry point...");
    let entry_point = determine_entry_point(filename)?;
    print_entry_point(entry_point);

    //println!("Determining base address...");
    let base_address = determine_base_address(&segments);
    print_base_address(base_address);

    //println!("Registering SIGSEGV handler...");
    register_sigsegv_handler()?;

    //println!("Running ELF...");
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