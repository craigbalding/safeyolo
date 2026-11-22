//! SCM runs the same selected executor. Account installation and privilege
//! assignment remain explicit operator choices; the binary does not elevate or
//! silently change service accounts, ACLs or local security policy.
use super::security::*;
use crate::*;
use std::io::Read;
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::{Foundation::*, System::Services::*};
use zeroize::Zeroizing;

struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: each non-null SCM/service handle has one ScHandle owner.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn scm(access: u32) -> Result<ScHandle, Refusal> {
    // SAFETY: null selects the local manager/database; access is an OS mask.
    let handle = unsafe { OpenSCManagerW(null(), null(), access) };
    if handle.is_null() {
        return Err(native::unavailable(std::io::Error::last_os_error()));
    }
    Ok(ScHandle(handle))
}

pub(super) fn install(args: &[String]) -> Result<(), Refusal> {
    require(
        args.len() == 8
            && args[0] == "--name"
            && args[2] == "--config"
            && args[4] == "--state"
            && args[6] == "--account",
        RefusalCode::Arguments,
        "service-install --name NAME --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY --account DOMAIN\\user < service-password-on-stdin",
    )?;
    let executable = std::env::current_exe().map_err(native::unavailable)?;
    absolute_local(&executable)?;
    // current_exe is a path observation, not an adoption decision. Refuse a
    // path or ancestor writable by the workload before persisting it as a service.
    protected(&executable, false)?;
    protected(std::path::Path::new(&args[3]), false)?;
    protected(std::path::Path::new(&args[5]), true)?;
    let words = [
        executable.to_string_lossy().into_owned(),
        "service".into(),
        "--name".into(),
        args[1].clone(),
        "--config".into(),
        args[3].clone(),
        "--state".into(),
        args[5].clone(),
    ];
    let command = wide(
        &words
            .iter()
            .map(|w| super::process::quote(w))
            .collect::<Vec<_>>()
            .join(" "),
    )?;
    let name = wide(&args[1])?;
    let account = wide(&args[7])?;
    let mut password = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut password)
        .map_err(native::unavailable)?;
    let password = Zeroizing::new(wide(password.trim_end_matches(['\r', '\n']))?);
    let manager = scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    // SAFETY: all strings are live NUL-terminated buffers. The password remains
    // in zeroizing memory; optional group/dependency pointers are null.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_QUERY_STATUS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            null(),
            null_mut(),
            null(),
            account.as_ptr(),
            password.as_ptr(),
        )
    };
    if service.is_null() {
        return Err(native::unavailable(std::io::Error::last_os_error()));
    }
    let _service = ScHandle(service);
    println!(
        "{}",
        serde_json::json!({"service":args[1],"account":args[7],"installed":true,"started":false,
        "next_action":"Ensure this service account owns the workload credential and has Log on as a service and the documented native-launch privileges; then use sc.exe start NAME."})
    );
    Ok(())
}

pub(super) fn remove(args: &[String]) -> Result<(), Refusal> {
    require(
        args.len() == 2 && args[0] == "--name",
        RefusalCode::Arguments,
        "service-remove --name NAME",
    )?;
    let manager = scm(SC_MANAGER_CONNECT)?;
    let name = wide(&args[1])?;
    // SAFETY: the manager and name remain valid through this call.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), DELETE) };
    if service.is_null() {
        return Err(native::unavailable(std::io::Error::last_os_error()));
    }
    let service = ScHandle(service);
    // SAFETY: this handle was opened with DELETE and remains owned until Drop.
    check(
        unsafe { DeleteService(service.0) },
        "mark selected Windows Service for deletion",
    )?;
    println!(
        "{}",
        serde_json::json!({"service":args[1],"marked_for_deletion":true,
        "retained":"Running jobs, target configuration, ledger, TLS keys, packages, workload account and Credential Manager entries remain. Stop and observe the service before removing its files."})
    );
    Ok(())
}

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
