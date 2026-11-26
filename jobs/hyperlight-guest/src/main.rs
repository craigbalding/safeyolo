#![no_std]
#![no_main]
extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use base64::{Engine, engine::general_purpose::STANDARD};
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

fn proxy_call(request: Value) -> core::result::Result<Value, String> {
    let reply = sy_call(request.to_string()).map_err(|e| e.message)?;
    let reply: Value = serde_json::from_str(&reply).map_err(|e| alloc::format!("{e}"))?;
    if reply["ok"] != true {
        return Err(reply["error"]
            .as_str()
            .unwrap_or("proxy call failed")
            .into());
    }
    Ok(reply["value"].clone())
}

fn random_bytes(bytes: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    let reply = proxy_call(serde_json::json!({"kind":"random","length":bytes.len()}))
        .map_err(|_| getrandom::Error::UNSUPPORTED)?;
    let data = reply["data_base64"]
        .as_str()
        .ok_or(getrandom::Error::UNSUPPORTED)?;
    let count = STANDARD
        .decode_slice(data, bytes)
        .map_err(|_| getrandom::Error::UNSUPPORTED)?;
    if count != bytes.len() {
        return Err(getrandom::Error::UNSUPPORTED);
    }
    Ok(())
}
getrandom::register_custom_getrandom!(random_bytes);

#[guest_function("NetworkCheck")]
fn network_check(_argv: String) -> Result<String> {
    let bytes = read_input(String::from("request.json"))?;
    let result = safeyolo_checker::network::check(&bytes, proxy_call, || {
        proxy_call(serde_json::json!({"kind":"time"})).ok()?["unix_seconds"].as_u64()
    })
    .map_err(|message| HyperlightGuestError::new(ErrorCode::GuestError, message))?;
    Ok(alloc::format!("{result}\n"))
}

#[host_function("InvocationContext")]
fn invocation_context() -> Result<String>;

#[host_function("InitializationWitness")]
fn initialization_witness() -> Result<u64>;

#[host_function("HostPrint")]
fn host_print(text: String) -> Result<i32>;

static INITIALIZED_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn hyperlight_main() {
    // This callback runs only in the loader's initialization entry. The
    // public witness has no invocation input, credential or capability.
    INITIALIZED_AT.store(
        initialization_witness().expect("initialization witness"),
        Ordering::Relaxed,
    );
}

/// Operator-selected restore witness; this is not an adopted predicate.
#[guest_function("TemplateProbe")]
fn template_probe(_argv: String) -> Result<String> {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let calls = CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    let input = read_input(String::from("request.json"))?;
    let request: Value = serde_json::from_slice(&input)?;
    if request["mode"] == "fail" {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "requested predecessor failure".into(),
        ));
    }
    if request["mode"] == "spin" {
        host_print(String::from("template-spin-entered\n"))?;
        loop {
            core::hint::spin_loop();
        }
    }
    let context: Value = serde_json::from_str(&invocation_context()?)?;
    if request["mode"] == "hold" {
        let until = context["unix_ms"].as_u64().expect("host clock") + 1000;
        loop {
            let current: Value = serde_json::from_str(&invocation_context()?)?;
            if current["unix_ms"].as_u64().expect("host clock") >= until {
                break;
            }
        }
    }
    let completed: Value = serde_json::from_str(&invocation_context()?)?;
    Ok(alloc::format!(
        "{}\n",
        serde_json::json!({
            "initialized_at":INITIALIZED_AT.load(Ordering::Relaxed),
            "calls":calls,
            "context":context,"input":input,"completed_unix_ms":completed["unix_ms"],
        })
    ))
}

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

#[guest_function("ArtifactCheck")]
fn artifact_check(_argv: String) -> Result<String> {
    let bytes = read_input(String::from("request.json"))?;
    let result = safeyolo_checker::artifact_check(&bytes)
        .map_err(|message| HyperlightGuestError::new(ErrorCode::GuestError, message))?;
    Ok(alloc::format!("{result}\n"))
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
