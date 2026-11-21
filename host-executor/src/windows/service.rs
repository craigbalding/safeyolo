//! SCM runs the same selected executor. Account installation and privilege
//! assignment remain explicit operator choices; the binary does not elevate or
//! silently change service accounts, ACLs or local security policy.
use super::security::*;
use crate::*;
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};
use windows_sys::Win32::{Foundation::*, System::Services::*};

static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static ARGS: OnceLock<Vec<String>> = OnceLock::new();

pub(crate) fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}
pub(crate) fn stop() {
    STOP.store(true, Ordering::SeqCst);
}
fn status(state: u32, error: u32) -> Result<(), Refusal> {
    let handle = STATUS.load(Ordering::SeqCst);
    if handle.is_null() {
        return Ok(());
    }
    let value = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            1
        } else {
            0
        },
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            30_000
        } else {
            0
        },
    };
    check(
        unsafe { SetServiceStatus(handle, &value) },
        "report service status",
    )
}
pub(crate) fn ready() -> Result<(), Refusal> {
    status(SERVICE_RUNNING, 0)
}
unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            stop();
            let _ = status(SERVICE_STOP_PENDING, 0);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
unsafe extern "system" fn main(_: u32, _: *mut *mut u16) {
    let Some(args) = ARGS.get() else {
        return;
    };
    let name = match wide(&args[1]) {
        Ok(name) => name,
        Err(_) => return,
    };
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::SeqCst);
    let result = (|| {
        status(SERVICE_START_PENDING, 0)?;
        server::command(vec![
            "serve".into(),
            "--config".into(),
            args[3].clone(),
            "--state".into(),
            args[5].clone(),
        ])
    })();
    if let Err(error) = &result {
        eprintln!("{error}");
    }
    let _ = status(
        SERVICE_STOPPED,
        if result.is_ok() {
            0
        } else {
            ERROR_SERVICE_NOT_ACTIVE
        },
    );
    STATUS.store(null_mut(), Ordering::SeqCst);
}
pub(super) fn dispatch(args: Vec<String>) -> Result<(), Refusal> {
    require(
        args.len() == 6 && args[0] == "--name" && args[2] == "--config" && args[4] == "--state",
        RefusalCode::Arguments,
        "service --name SCM_NAME --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY",
    )?;
    let mut name = wide(&args[1])?;
    ARGS.set(args)
        .map_err(|_| native::unavailable("service dispatcher already selected"))?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    check(
        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) },
        "connect Windows Service dispatcher",
    )
}
