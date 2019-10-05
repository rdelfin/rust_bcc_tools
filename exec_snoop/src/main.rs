extern crate byteorder;
extern crate chrono;
extern crate clap;
extern crate failure;
extern crate libc;
extern crate systemstat;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use chrono::Duration;
use clap::{App, Arg, ArgMatches};
use failure::Error;
use systemstat::{Platform, System};

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;

#[repr(C)]
struct event_t {
    ts: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    ret: i32,
    executable: [u8; 255],
}

fn do_main(runnable: Arc<AtomicBool>, matches: ArgMatches) -> Result<(), Error> {
    let code = include_str!("execsnoop.c");

    let code = match matches.value_of("ppid") {
        Some(ppid) => code
            .replace("SHOULD_PPID_FILTER", "true")
            .replace("PPID_FILTER_VALUE", &ppid.to_string()),
        None => code
            .replace("SHOULD_PPID_FILTER", "false")
            .replace("PPID_FILTER_VALUE", "-1"),
    };

    let mut module = BPF::new(&code)?;

    let enter_tp = module.load_tracepoint("trace_entry")?;
    let return_tp = module.load_tracepoint("trace_return")?;
    module.attach_tracepoint("syscalls", "sys_enter_execve", enter_tp)?;
    module.attach_tracepoint("syscalls", "sys_exit_execve", return_tp)?;

    // Where we pick up exec events from
    let table = module.table("events");
    // Add callback for the perf pipeline
    let mut perf_map = init_perf_map(table, event_callback)?;

    // Print header
    println!(
        "{:-33} {:-7} {:-7} {:-12} {}",
        "TS", "PPID", "PID", "RET", "EXECUTABLE"
    );

    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }

    Ok(())
}

fn event_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    let boot_time = System::new()
        .boot_time()
        .expect("Could not fetch system boot time");

    Box::new(move |x| {
        let data = parse_struct(x);
        let ts_from_boot = Duration::nanoseconds(data.ts as i64);
        let date_time = boot_time + ts_from_boot;
        println!(
            "{:-33} {:-7} {:-7} {:-12} {}",
            date_time,
            data.ppid,
            data.pid,
            data.ret,
            get_string(&data.executable)
        );
    })
}

fn parse_struct(x: &[u8]) -> event_t {
    unsafe { ptr::read(x.as_ptr() as *const event_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    // CLI setup
    let matches = App::new("Exec Snoop")
        .version("1.0")
        .author("Ricardo Delfin <me@rdelfin.com>")
        .arg(
            Arg::with_name("ppid")
                .short("p")
                .value_name("PPID")
                .help("The PPID to filter for")
                .takes_value(true),
        )
        .get_matches();

    // Runnable creation
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable, matches) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
