#![no_std]
#![no_main]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use hyperlight_guest_bin::{error::Result, guest_function, host_function};

#[host_function("ReadInput")]
fn read_input(path: String) -> Result<Vec<u8>>;

/// A small deterministic checker workload shared with the Python example.
#[guest_function("Check")]
fn check(_argv: String) -> Result<String> {
    let bytes = read_input(String::from("request.json"))?;
    Ok(alloc::format!("{{\"input_bytes\":{}}}\n", bytes.len()))
}

#[guest_function("Spin")]
fn spin(_argv: String) -> String {
    loop {
        core::hint::spin_loop();
    }
}

#[guest_function("State")]
fn state(_argv: String) -> String {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    alloc::format!("{}\n", CALLS.fetch_add(1, Ordering::Relaxed) + 1)
}
