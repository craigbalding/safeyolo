//! Exercise the exact production capture owner without linking every library test.
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "../src/host_platform/command_output.rs"]
mod command_output;
