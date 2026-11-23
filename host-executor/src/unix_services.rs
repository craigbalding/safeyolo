//! The OS service client is a trusted executor dependency. Arbitrary adopted
//! programs never receive its service-manager channel.
use crate::{native::unavailable, *};
use std::{os::unix::fs::MetadataExt, path::Path};

pub(crate) fn validate(operation: &Operation) -> Result<bool, Refusal> {
    let e = &operation.execution;
    if e.delegated_services.is_empty() {
        return Ok(false);
    }
    require(
        e.delegated_services.len() == 1,
        RefusalCode::Unavailable,
        "native service control requires one explicitly selected service owner",
    )?;
    let service = &e.delegated_services[0];
    require(
        service.resources.len() == 1,
        RefusalCode::Unavailable,
        "native service control requires one fixed service resource",
    )?;
    let resource = &service.resources[0];
    fn literal(word: &Word) -> Option<&str> {
        match word {
            Word::Literal { value } => Some(value.as_str()),
            Word::Argument { .. } => None,
        }
    }
    let argv: Option<Vec<_>> = e.argv.iter().map(literal).collect();
    #[cfg(target_os = "linux")]
    let (executable, expected, environment, ipc, broader) = {
        require(
            service.service == "systemd-user"
                && resource.ends_with(".service")
                && !resource
                    .chars()
                    .any(|c| matches!(c, '/' | '\0' | '*' | '?' | '[' | ']')),
            RefusalCode::Unavailable,
            "Linux native service control selects a literal systemd user .service unit",
        )?;
        require(
            matches!(
                service.capability.as_str(),
                "start" | "stop" | "restart" | "status"
            ),
            RefusalCode::Unavailable,
            "systemd user service control supports start, stop, restart and status",
        )?;
        let environment = std::collections::BTreeMap::from([
            (
                "XDG_RUNTIME_DIR",
                format!("/run/user/{}", e.identity.principal),
            ),
            ("SYSTEMD_OFFLINE", "0".into()),
        ]);
        let mut argv = vec!["--user", "--no-pager", "--no-ask-password"];
        if service.capability == "status" {
            argv.extend(["show", "--property=ActiveState", "--property=MainPID"]);
        } else {
            argv.push(service.capability.as_str());
        }
        argv.extend(["--", resource.as_str()]);
        (
            "/usr/bin/systemctl",
            argv,
            environment,
            Some(format!(
                "/run/user/{}/systemd/private",
                e.identity.principal
            )),
            [
                BroaderBound::DelegatedServices,
                BroaderBound::ProcessVisibility,
            ]
            .into(),
        )
    };
    #[cfg(target_os = "macos")]
    let (executable, expected, environment, ipc, broader) = {
        let gui = format!("gui/{}/", e.identity.principal);
        let user = format!("user/{}/", e.identity.principal);
        let label = resource
            .strip_prefix(&gui)
            .or_else(|| resource.strip_prefix(&user));
        require(
            service.service == "launchd-user"
                && label.is_some_and(|name| !name.is_empty() && !name.contains(['/', '\0'])),
            RefusalCode::Unavailable,
            "macOS native service control selects a literal launchd label in this account's user or GUI domain",
        )?;
        let argv = match service.capability.as_str() {
            "status" => vec!["print", resource.as_str()],
            "start" => vec!["kickstart", resource.as_str()],
            "stop" => vec!["kill", "SIGTERM", resource.as_str()],
            "restart" => vec!["kickstart", "-k", resource.as_str()],
            _ => {
                return Err(unavailable(
                    "the confined launchd client supports start, stop, restart and status",
                ));
            }
        };
        (
            "/bin/launchctl",
            argv,
            std::collections::BTreeMap::<&str, String>::new(),
            None::<String>,
            [
                BroaderBound::Memory,
                BroaderBound::ExecutorRestart,
                BroaderBound::NetworkIpc,
                BroaderBound::DelegatedServices,
            ]
            .into(),
        )
    };
    require(
        e.executable == executable
            && argv.as_deref() == Some(expected.as_slice())
            && e.working_directory == "/"
            && e.broader == broader,
        RefusalCode::Unavailable,
        "service control needs the native OS client, fixed action/resource and its explicit broader profile",
    )?;
    let actual_environment: Option<std::collections::BTreeMap<_, _>> = e
        .environment
        .iter()
        .map(|(name, word)| literal(word).map(|value| (name.as_str(), value.to_owned())))
        .collect();
    require(
        actual_environment.as_ref() == Some(&environment),
        RefusalCode::Unavailable,
        "trusted service clients require their exact native environment; loader/interpreter injection is not permitted",
    )?;
    let matching_ipc = match ipc {
        Some(path) => {
            matches!(e.network.ipc.as_slice(), [IpcEndpoint::UnixSocket { path: selected }] if *selected == path)
        }
        None => e.network.ipc.is_empty(),
    };
    require(
        e.filesystem.write.is_empty() && e.network.destinations.is_empty() && matching_ipc,
        RefusalCode::Unavailable,
        "service helper permits no writes or direct network; its manager channel is fixed",
    )?;
    // A digest of a workload-owned executable cannot make it a trusted broker.
    // Check the OS client's complete canonical path as well as its pinned bytes
    // in the platform backend. Root/operator replacement remains trusted.
    let canonical = Path::new(executable).canonicalize().map_err(unavailable)?;
    for path in canonical.ancestors() {
        let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
        require(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            RefusalCode::Unavailable,
            "the native service client and its parents must be root-owned and protected from workload replacement",
        )?;
    }
    Ok(true)
}

pub(crate) fn disclosure() -> String {
    "EXPLICIT BROADER DELEGATED SERVICES: the pinned OS service client is part of the trusted executor. The adopted unit definition, executable, dependencies and service-manager permissions remain external trust dependencies. Service processes and persistent effects are outside helper-process resource/cleanup controls; processes_stopped describes only the helper. No unit/configuration replacement or arbitrary program receives the manager channel".into()
}
