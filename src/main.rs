use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use object::{Object, ObjectSegment, SegmentFlags};
use nix::sys::signal::{sigaction, SigAction, SigHandler, SigSet, SaFlags};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::ptr;

mod runner;

// ELF segment flag constants
const PF_X: u32 = 1 << 0; // Execute
const PF_W: u32 = 1 << 1; // Write
const PF_R: u32 = 1 << 2; // Read

static mut SEGMENTS: Option<Vec<(u64, u64, u64, u64, u64, SegmentFlags)>> = None;
static PAGE_SIZE: usize = 4096;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    print!("Segmentation fault occurred. ");
    let address = unsafe { (*siginfo).si_addr() } as usize;
    eprintln!("Segmentation fault at address {:#x}", address);

    let segments = unsafe { SEGMENTS.as_ref().expect("Segments not loaded") };
    let mut valid_access = false;

    for segment in segments {
        print!("Checking segment {:#x} - {:#x}... ", segment.0, segment.0 + segment.1);
        let seg_start = segment.0 as usize;
        let seg_end = seg_start + segment.1 as usize;

        if address >= seg_start && address < seg_end {
            print!("Valid access. ");
            valid_access = true;

            let page_start = address & !(PAGE_SIZE - 1);
            let offset = segment.2 as usize + (page_start - seg_start);
            let length = std::cmp::min(PAGE_SIZE, segment.1 as usize - (page_start - seg_start));

            let mut file = File::open("path/to/executable").unwrap();
            let mut buffer = vec![0u8; length];
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.read_exact(&mut buffer).unwrap();

            println!("Segment flags: {:?}", segment.5);
            let prot_flags = if let SegmentFlags::Elf { p_flags } = segment.5 {
                ProtFlags::from_bits_truncate(
                    (if p_flags & PF_R != 0 { ProtFlags::PROT_READ.bits() } else { 0 }) |
                    (if p_flags & PF_W != 0 { ProtFlags::PROT_WRITE.bits() } else { 0 }) |
                    (if p_flags & PF_X != 0 { ProtFlags::PROT_EXEC.bits() } else { 0 })
                )
            } else {
                ProtFlags::empty()
            };

            unsafe {
                println!("Mapping page...");
                mmap(
                    page_start as *mut c_void,
                    PAGE_SIZE,
                    prot_flags,
                    MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                    -1,
                    0,
                ).unwrap();
                
                ptr::copy_nonoverlapping(buffer.as_ptr(), page_start as *mut u8, length);
            }

            break;
        }
    }

    if !valid_access {
        eprintln!("Invalid memory access at {:#x}", address);
        std::process::exit(0);
    }
}

fn read_segments(filename: &str) -> Result<Vec<(u64, u64, u64, u64, u64, SegmentFlags)>, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let obj_file = object::File::parse(&*buffer)?;

    let segments = obj_file
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

    Ok(segments)
}

fn print_segments(segments: &[(u64, u64, u64, u64, u64, SegmentFlags)]) {
    eprintln!("Segments");
    for (i, segment) in segments.iter().enumerate() {
        println!("Segment {}:", i);
        eprintln!(
            "{}\t{:#x}\t{}\t{:#x}\t{}\t{:?}",
            i,
            segment.0,
            segment.1,
            segment.2,
            segment.3,
            segment.5
        );
    }
}

fn determine_base_address(segments: &[(u64, u64, u64, u64, u64, SegmentFlags)]) -> u64 {
    segments.iter().map(|s| s.0).min().unwrap_or(0)
}

fn determine_entry_point(filename: &str) -> Result<u64, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let obj_file = object::File::parse(&*buffer)?;
    Ok(obj_file.entry())
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
    // Step 1: Read ELF segments
    println!("Reading ELF segments...");
    let segments = read_segments(filename)?;

    // Step 2: Print Segments
    println!("Segments:");
    print_segments(&segments);

    // Step 3: Determine Base Address
    println!("Determining base address...");
    let base_address = determine_base_address(&segments);

    // Step 4: Determine Entry Point
    println!("Determining entry point...");
    let entry_point = determine_entry_point(filename)?;

    // Step 5: Register SIGSEGV Handler
    println!("Registering SIGSEGV handler...");
    register_sigsegv_handler()?;

    // Store segments for the signal handler to use
    unsafe {
        SEGMENTS = Some(segments);
    }

    // Step 6: Run ELF using runner::exec_run
    println!("Running ELF...");
    runner::exec_run(base_address as usize, entry_point as usize);

    Ok(())
}

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
