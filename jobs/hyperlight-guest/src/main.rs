#![no_std]
#![no_main]
extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use hyperlight_guest_bin::{
    error::{ErrorCode, HyperlightGuestError, Result},
    guest_function, host_function,
};
use serde_json::Value;

#[host_function("ReadInput")]
fn read_input(path: String) -> Result<Vec<u8>>;

#[host_function("SYCall")]
fn sy_call(request: String) -> Result<String>;

#[guest_function("ServiceCheck")]
fn service_check(_argv: String) -> Result<String> {
    let bytes = read_input(String::from("request.json"))?;
    let result = safeyolo_checker::service_check(&bytes, |request| {
        let reply = sy_call(request.to_string()).map_err(|e| e.message)?;
        let reply: Value = serde_json::from_str(&reply).map_err(|e| alloc::format!("{e}"))?;
        if reply["ok"] != true {
            return Err(reply["error"]
                .as_str()
                .unwrap_or("service call failed")
                .into());
        }
        Ok(reply["value"].clone())
    })
    .map_err(|message| HyperlightGuestError::new(ErrorCode::GuestError, message))?;
    Ok(alloc::format!("{result}\n"))
}

/// Operator-selected diagnostic entry; it is not an adopted predicate.
#[guest_function("ServiceProbe")]
fn service_probe(_argv: String) -> Result<String> {
    let request: Value = serde_json::from_slice(&read_input(String::from("request.json"))?)?;
    let count = request["repeat"].as_u64().unwrap_or(1);
    let mut replies = Vec::new();
    for _ in 0..count {
        replies.push(serde_json::from_str::<Value>(&sy_call(
            request["call"].to_string(),
        )?)?);
    }
    Ok(alloc::format!("{}\n", serde_json::json!(replies)))
}

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
