//! Explicit native Windows component fixture and its prebuilt workload probe.
//! Run --prepare ROOT CREDENTIAL, then --native ROOT [--service]. The test host
//! supplies an ordinary workload account, private control/state ACLs, a readable
//! programs directory and writable work directory. No compiler/Python is used.
//! --recover ROOT ATTEMPT and --storage ROOT ATTEMPT run focused checks using the
//! retained prepared account, catalogue and ledger; they do not repeat starters.
//! --bounds ROOT ATTEMPT [--service] uses that same native catalogue for identity,
//! memory/process/output/deadline/cancellation checks, with canonical output and
//! independent Job limits/process handles. It does not run service mutations.
//! --registry ROOT ATTEMPT [--service] queries both allowed machine registry views
//! from the prepared starter catalogue; the controller owns its expected data.
#[cfg(windows)]
mod common;
#[cfg(windows)]
mod windows_component;
fn main() {
    #[cfg(windows)]
    windows_component::main();
    #[cfg(not(windows))]
    println!("Windows native fixture requires Windows and explicitly prepared inputs; skipped");
}
