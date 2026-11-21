//! OS handles own their native allocations. Every FFI buffer remains live and
//! correctly aligned through the call; variable-length token data is sized by
//! Windows before it is interpreted. Password buffers are zeroed on release.
use crate::*;
use std::{
    collections::BTreeSet,
    ffi::c_void,
    fs::File,
    io::Read,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Credentials::*, *},
    Storage::FileSystem::*,
    System::{SystemServices::*, Threading::*},
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn error(stage: &str) -> Refusal {
    native::unavailable(format!(
        "Windows {stage}: {}",
        std::io::Error::last_os_error()
    ))
}
pub(crate) fn check(ok: i32, stage: &str) -> Result<(), Refusal> {
    if ok == 0 { Err(error(stage)) } else { Ok(()) }
}
pub(crate) fn wide(value: &str) -> Result<Vec<u16>, Refusal> {
    require(
        !value.contains('\0'),
        RefusalCode::Arguments,
        "NUL is not a Windows argument",
    )?;
    Ok(value.encode_utf16().chain([0]).collect())
}
pub(crate) fn path_wide(path: &Path) -> Result<Vec<u16>, Refusal> {
    let bytes: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
    require(
        !bytes[..bytes.len() - 1].contains(&0),
        RefusalCode::Arguments,
        "NUL in Windows path",
    )?;
    Ok(bytes)
}
pub(crate) struct Handle(pub HANDLE);
// Kernel handles are process-wide references; each wrapper has one closer.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Handle {
    pub(crate) fn new(handle: HANDLE, stage: &str) -> Result<Self, Refusal> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(error(stage))
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub(crate) struct Local(pub *mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(crate) fn token() -> Result<Handle, Refusal> {
    let mut token = null_mut();
    check(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        },
        "executor token",
    )?;
    Handle::new(token, "executor token")
}
fn token_data(token: &Handle, kind: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>, Refusal> {
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token.0, kind, null_mut(), 0, &mut bytes);
    }
    require(
        bytes > 0,
        RefusalCode::Unavailable,
        "Windows token size unavailable",
    )?;
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    check(
        unsafe {
            GetTokenInformation(token.0, kind, buffer.as_mut_ptr().cast(), bytes, &mut bytes)
        },
        "token information",
    )?;
    Ok(buffer)
}
fn sid(sid: PSID) -> Result<String, Refusal> {
    let mut result = null_mut();
    check(
        unsafe { ConvertSidToStringSidW(sid, &mut result) },
        "SID text",
    )?;
    let _allocation = Local(result.cast());
    // ConvertSidToStringSidW returns an allocated NUL-terminated string.
    let mut length = 0;
    unsafe {
        while *result.add(length) != 0 {
            length += 1;
        }
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(result, length)
    }))
}
pub(crate) fn identity(token: &Handle) -> Result<ExecutionIdentity, Refusal> {
    let user = token_data(token, TokenUser)?;
    let principal = sid(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
    let groups = token_data(token, TokenGroups)?;
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let mut result = BTreeSet::new();
    for item in
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) }
    {
        // The logon SID changes on each LogonUser call. All other token groups,
        // including deny-only groups, remain part of the adopted identity.
        if item.Attributes & 0xc0000000 != 0xc0000000 {
            result.insert(sid(item.Sid)?);
        }
    }
    Ok(ExecutionIdentity {
        principal,
        groups: result.into_iter().collect(),
    })
}

pub(crate) fn workload(name: &str) -> Result<Handle, Refusal> {
    let name = wide(name)?;
    let mut credential = null_mut();
    check(
        unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) },
        "read selected workload credential",
    )?;
    struct Credential(*mut CREDENTIALW);
    impl Drop for Credential {
        fn drop(&mut self) {
            unsafe {
                let credential = &mut *self.0;
                if !credential.CredentialBlob.is_null() {
                    std::slice::from_raw_parts_mut(
                        credential.CredentialBlob,
                        credential.CredentialBlobSize as usize,
                    )
                    .zeroize();
                }
                CredFree(self.0.cast());
            }
        }
    }
    let credential = Credential(credential);
    let credential = unsafe { &*credential.0 };
    require(
        !credential.UserName.is_null()
            && credential.CredentialBlobSize % 2 == 0
            && credential.CredentialBlobSize > 0,
        RefusalCode::Unavailable,
        "workload credential requires username and UTF-16 password",
    )?;
    let mut length = 0;
    unsafe {
        while *credential.UserName.add(length) != 0 {
            length += 1;
        }
    }
    let account = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(credential.UserName, length)
    });
    let mut password = Zeroizing::new(Vec::new());
    for bytes in unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
    }
    .chunks_exact(2)
    {
        password.push(u16::from_le_bytes([bytes[0], bytes[1]]));
    }
    require(
        !password.contains(&0),
        RefusalCode::Unavailable,
        "credential password contains NUL",
    )?;
    password.push(0);
    let (domain, username) = match account.split_once('\\') {
        Some((domain, user)) => (Some(wide(domain)?), wide(user)?),
        None => (None, wide(&account)?),
    };
    let mut result = null_mut();
    check(
        unsafe {
            LogonUserW(
                username.as_ptr(),
                domain.as_ref().map_or(null(), |s| s.as_ptr()),
                password.as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut result,
            )
        },
        "log on separate workload account",
    )?;
    let result = Handle::new(result, "workload token")?;
    let id = identity(&result)?;
    require(
        id.principal != identity(&token()?)?.principal
            && !id.groups.iter().any(|s| s == "S-1-5-32-544"),
        RefusalCode::Unavailable,
        "broader Windows execution needs a different, non-administrative workload account",
    )?;
    // These privileges can bypass ACLs or impersonate the protected executor.
    // Reject their presence even when disabled: the account can enable them.
    let data = token_data(&result, TokenPrivileges)?;
    let privileges = unsafe { &*data.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let items = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    for name in [
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeRelabelPrivilege",
    ] {
        let mut luid = unsafe { zeroed::<LUID>() };
        check(
            unsafe { LookupPrivilegeValueW(null(), wide(name)?.as_ptr(), &mut luid) },
            "privilege identity",
        )?;
        require(
            !items
                .iter()
                .any(|p| p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart),
            RefusalCode::Unavailable,
            &format!("workload privilege {name} could bypass executor protection"),
        )?;
    }
    Ok(result)
}

pub(crate) fn store_credential(args: &[String]) -> Result<(), Refusal> {
    require(
        args.len() == 4 && args[0] == "--name" && args[2] == "--account",
        RefusalCode::Arguments,
        "credential-store --name NAME --account DOMAIN\\user < password-on-stdin",
    )?;
    let mut password = Zeroizing::new(String::new());
    std::io::stdin()
        .take(5121)
        .read_to_string(&mut password)
        .map_err(native::unavailable)?;
    let password = password.trim_end_matches(['\r', '\n']);
    let bytes = Zeroizing::new(
        password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    require(
        !password.is_empty() && !password.contains('\0') && bytes.len() <= 5120,
        RefusalCode::Arguments,
        "credential requires a nonempty UTF-16 password within Credential Manager's 5120-byte limit",
    )?;
    let (mut name, mut account) = (wide(&args[1])?, wide(&args[3])?);
    let mut credential = unsafe { zeroed::<CREDENTIALW>() };
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = name.as_mut_ptr();
    credential.UserName = account.as_mut_ptr();
    credential.CredentialBlob = bytes.as_ptr().cast_mut();
    credential.CredentialBlobSize = bytes.len() as u32;
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    check(
        unsafe { CredWriteW(&credential, 0) },
        "store selected workload credential",
    )?;
    println!("credential stored for this executor account");
    Ok(())
}

pub(crate) fn absolute_local(path: &Path) -> Result<(), Refusal> {
    require(path.is_absolute() && path.components().all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
        && path.components().all(|c| match c { Component::Normal(s) => !s.to_string_lossy().contains(':') && !s.to_string_lossy().ends_with([' ', '.']), _ => true })
        && path.components().next().is_some_and(|c| matches!(c, Component::Prefix(p) if matches!(p.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))),
        RefusalCode::Unavailable, "Windows paths require absolute local drive paths without relative components, alternate streams, trailing-dot/space aliases or UNC/device aliases")
}

fn open_path(path: &Path, access: u32, share: u32, disposition: u32) -> Result<File, Refusal> {
    absolute_local(path)?;
    let handle = unsafe {
        CreateFileW(
            path_wide(path)?.as_ptr(),
            access,
            share,
            null(),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    let handle = Handle::new(handle, "open protected path")?;
    let mut info = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    check(
        unsafe { GetFileInformationByHandle(handle.0, &mut info) },
        "path identity",
    )?;
    require(
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        RefusalCode::Unavailable,
        "reparse points are not adopted executable or control paths",
    )?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    std::mem::forget(handle);
    Ok(file)
}
pub(crate) fn read_file(path: &Path) -> Result<File, Refusal> {
    open_path(
        path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
    )
}
fn descriptor(handle: HANDLE) -> Result<Local, Refusal> {
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(native::unavailable(format!(
            "Windows path ACL: {}",
            std::io::Error::from_raw_os_error(status as i32)
        )));
    }
    Ok(Local(descriptor))
}
fn trusted_owner(descriptor: &Local) -> Result<(), Refusal> {
    let mut owner = null_mut();
    let mut defaulted = 0;
    check(
        unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) },
        "path owner",
    )?;
    let owner = sid(owner)?;
    require(
        trusted_sid(&owner)?,
        RefusalCode::Unavailable,
        "Windows protected path owner is not the executor, SYSTEM, Administrators or TrustedInstaller",
    )
}
fn trusted_sid(value: &str) -> Result<bool, Refusal> {
    Ok(value == identity(&token()?)?.principal
        || matches!(
            value,
            "S-1-5-18"
                | "S-1-5-32-544"
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        ))
}
fn mapping() -> GENERIC_MAPPING {
    GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    }
}
const CHANGE: u32 = DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD;
const REPLACE_CHILD: u32 = DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD;

fn replacement_access(path: &Path) -> u32 {
    // Windows cannot rename a volume root. Its ordinary DELETE grant therefore
    // cannot replace an ancestor; changing its DACL or deleting its children can.
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
    if path.parent().is_none() {
        REPLACE_CHILD & !DELETE
    } else {
        REPLACE_CHILD
    }
}

fn private_acl(file: &File, path: &Path, leaf: bool) -> Result<(), Refusal> {
    let descriptor = descriptor(file.as_raw_handle())?;
    trusted_owner(&descriptor)?;
    let (mut present, mut defaulted, mut acl) = (0, 0, null_mut());
    check(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) },
        "protected DACL",
    )?;
    require(
        present != 0 && !acl.is_null(),
        RefusalCode::Unavailable,
        "protected paths require a non-null DACL",
    )?;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = null_mut();
        check(
            unsafe { GetAce(acl, index as u32, &mut ace) },
            "protected ACE",
        )?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        require(
            header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8,
            RefusalCode::Unavailable,
            "protected DACL has an unsupported effective ACE type",
        )?;
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let mut mask = ace.Mask;
        unsafe {
            MapGenericMask(&mut mask, &mapping());
        }
        require(
            mask & if leaf {
                FILE_ALL_ACCESS
            } else {
                replacement_access(path)
            } == 0
                || trusted_sid(&sid((&ace.SidStart as *const u32).cast_mut().cast())?)?,
            RefusalCode::Unavailable,
            format!(
                "another account can read/change protected state or replace its path: {}",
                path.display()
            ),
        )?;
    }
    Ok(())
}
pub(crate) fn protected(path: &Path, directory: bool) -> Result<PathBuf, Refusal> {
    absolute_local(path)?;
    for (index, parent) in path.ancestors().enumerate() {
        let file = open_path(
            parent,
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
        )?;
        private_acl(&file, parent, index == 0)?;
        if index == 0 {
            require(
                file.metadata().map_err(native::unavailable)?.is_dir() == directory,
                RefusalCode::Unavailable,
                "Windows state/configuration path has the wrong type",
            )?;
        }
    }
    Ok(path.to_owned())
}
pub(crate) fn private_file(path: &Path) -> Result<File, Refusal> {
    let file = open_path(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_ALWAYS,
    )?;
    let metadata = file.metadata().map_err(native::unavailable)?;
    let mut info = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    check(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
        "ledger link count",
    )?;
    require(
        metadata.is_file() && info.nNumberOfLinks == 1,
        RefusalCode::Unavailable,
        "ledger requires a private regular file with one link",
    )?;
    private_acl(&file, path, true)?;
    Ok(file)
}
fn granted(file: &File, token: &Handle) -> Result<u32, Refusal> {
    let descriptor = descriptor(file.as_raw_handle())?;
    let mut impersonation = null_mut();
    check(
        unsafe { DuplicateToken(token.0, SecurityImpersonation, &mut impersonation) },
        "ACL check token",
    )?;
    let impersonation = Handle::new(impersonation, "ACL check token")?;
    let (mut bytes, mut result, mut allowed) = (0, 0, 0);
    unsafe {
        AccessCheck(
            descriptor.0,
            impersonation.0,
            MAXIMUM_ALLOWED,
            &mapping(),
            null_mut(),
            &mut bytes,
            &mut result,
            &mut allowed,
        );
    }
    let mut privileges = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>()).max(1)];
    check(
        unsafe {
            AccessCheck(
                descriptor.0,
                impersonation.0,
                MAXIMUM_ALLOWED,
                &mapping(),
                privileges.as_mut_ptr().cast(),
                &mut bytes,
                &mut result,
                &mut allowed,
            )
        },
        "workload path access",
    )?;
    Ok(if allowed != 0 { result } else { 0 })
}
pub(crate) fn deny_workload_write(path: &Path, token: &Handle) -> Result<(), Refusal> {
    for (index, parent) in path.ancestors().enumerate() {
        let file = open_path(
            parent,
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
        )?;
        require(
            granted(&file, token)?
                & if index == 0 {
                    CHANGE
                } else {
                    replacement_access(parent)
                }
                == 0,
            RefusalCode::Unavailable,
            format!(
                "workload account can modify protected executor inputs, executable or an ancestor: {}",
                parent.display()
            ),
        )?;
    }
    Ok(())
}

/// Keep the executable and every ancestor open without FILE_SHARE_DELETE.
/// The original application directory remains intact for native DLL/tool lookup.
pub(crate) fn executable(
    path: &str,
    expected: &str,
    max: u64,
    token: &Handle,
) -> Result<Vec<File>, Refusal> {
    let path = Path::new(path);
    deny_workload_write(path, token)?;
    let mut held = Vec::new();
    for parent in path.ancestors().skip(1) {
        held.push(open_path(
            parent,
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
        )?);
    }
    let mut file = read_file(path)?;
    let metadata = file.metadata().map_err(native::unavailable)?;
    require(
        metadata.is_file() && metadata.len() <= max,
        RefusalCode::Budget,
        "executable exceeds selected snapshot ceiling or is not a regular file",
    )?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(native::unavailable)?;
    let hash: String = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    require(
        bytes.len() as u64 <= max && hash == expected,
        RefusalCode::Stale,
        "Windows executable differs from adoption",
    )?;
    held.push(file);
    Ok(held)
}

pub(crate) fn private_descriptor() -> Result<Local, Refusal> {
    let owner = identity(&token()?)?.principal;
    let text = wide(&format!(
        "O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner})"
    ))?;
    let mut result = null_mut();
    check(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut result,
                null_mut(),
            )
        },
        "private kernel-object DACL",
    )?;
    Ok(Local(result))
}

pub(crate) fn own_job(handle: HANDLE) -> Result<(), Refusal> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(native::unavailable(format!(
            "Windows recovered job owner: {}",
            std::io::Error::from_raw_os_error(status as i32)
        )));
    }
    let _descriptor = Local(descriptor);
    require(
        sid(owner)? == identity(&token()?)?.principal,
        RefusalCode::Unavailable,
        "retained job name has another owner; leave it untouched and retain unknown cleanup",
    )
}
