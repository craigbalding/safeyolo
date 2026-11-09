//! Host-vault guidance composes existing import, service and setup operations.

use crate::{Error, coding_client, host_agents, host_platform};
use hyper::Method;
use serde_json::{Value, json};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) const HELP: &str = "safeyolo [--root ROOT] agent auth NAME [--json]\nsafeyolo [--root ROOT] agent auth NAME --authentication client|host-vault [--credential NAME] [--auth-file HOST_FILE] [--authorize] [--remove-guest-auth] [--storage local|passphrase] [--passphrase-file FILE] [--json]\nWith no options, guide authentication in a host terminal. --json alone reads current state. Changes require a stopped agent and its shipped Codex/Claude setup. --auth-file uses credentials import-client once; import grants no access. --authorize explicitly selects this agent's inference service and credential until revoked/replaced. Existing network, credential and risky-route policy still applies. No host-wide network approval is added. --remove-guest-auth explicitly removes the displayed client authentication inputs; omit it to retain them and refuse a conflicting custody change. Unrelated settings and denies are retained. Later launches fetch a fresh scoped token; after invalidation stop/relaunch the client. Check prior task effects before retrying. No automatic unlock or model-request replay.";

pub(crate) fn client(agent: &host_agents::Agent) -> Result<&'static str, Error> {
    let configured = Path::new(
        agent
            .host_script
            .as_deref()
            .ok_or("agent has no harness setup")?,
    )
    .canonicalize()?;
    for name in ["codex", "claude"] {
        if let Ok((script, _)) =
            crate::host_launch::harness_setup(&host_platform::config_dir(), name)
            && script == configured
        {
            return Ok(name);
        }
    }
    Err("agent auth supports the shipped Codex and Claude setup scripts; inspect this agent's configured harness".into())
}

fn home(agent: &host_agents::Agent) -> PathBuf {
    host_platform::config_dir()
        .join("agents")
        .join(&agent.name)
        .join("home")
}

async fn admin(path: &str, method: Method, body: Value) -> Result<Value, Error> {
    crate::native_client::admin(
        &host_platform::config_path(),
        path,
        method,
        body,
        Duration::from_secs(5),
    )
    .await
}

async fn binding(agent: &host_agents::Agent, client: &str) -> Result<Value, Error> {
    let mut response = admin(
        &format!(
            "/admin/agents/{}/services",
            crate::coord_tools::segment(&agent.name)
        ),
        Method::GET,
        Value::Null,
    )
    .await?;
    let row = &response["services"][client];
    let result = if row.is_null() {
        Value::Null
    } else {
        json!({"service":client,"capability":row["capability"],"credential":row["credential"],"account":row["account"],"host":row["host"]})
    };
    crate::credentials::wipe_json(&mut response);
    Ok(result)
}

pub(crate) async fn report(agent: &host_agents::Agent) -> Result<Value, Error> {
    let current = host_agents::refresh(agent)?;
    let agent = &current;
    let client = client(agent)?;
    let selected = coding_client::selected(&home(agent), client)?;
    let authorization = binding(agent, client).await;
    let mut vault = admin("/admin/credentials/status", Method::GET, Value::Null)
        .await
        .unwrap_or_else(|_| json!({"availability":"unavailable"}));
    let credential = authorization
        .as_ref()
        .ok()
        .and_then(|row| row["credential"].as_str());
    let account = vault["credentials"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["name"].as_str() == credential))
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(vault) = vault.as_object_mut() {
        vault.remove("credentials");
    }
    Ok(json!({
        "agent":agent.name,"agent_id":agent.id,"root":host_platform::config_dir(),"client":client,
        "configuration":if selected {"host-vault"} else {"client"},
        "retained_guest_auth":coding_client::conflicts(&home(agent),client)?,
        "authorization":match authorization {Ok(row)=>json!({"state":if row.is_null(){"absent"}else{"configured"},"binding":row}),Err(_)=>json!({"state":"unavailable"})},
        "vault":vault,"selected_account":account,
        "provider_validity":"unknown","client_use":"not_observed",
        "next_action":format!("Use agent launch --name {}. Inspect approvals for this agent separately. After gateway changes or proxy restart, stop/relaunch the client to fetch a new scoped token; inspect prior task effects before retrying.",agent.name)
    }))
}

fn explain(agent: &host_agents::Agent, client: &str) {
    println!(
        "Host authentication — {} ({}) at {}. Provider: {client} subscription; service: {client}/inference. Select the credential account by its vault entry or host login file. Provider validity remains unknown until a real request succeeds.",
        agent.name,
        agent.id,
        crate::network_guard::sanitize_with_limit(
            &host_platform::config_dir().display().to_string(),
            usize::MAX
        )
    );
    println!(
        "Client-held authentication stays in the guest and can be read by the guest. Host-vault authentication keeps the selected provider login in the host's encrypted store; the guest receives only this agent's scoped service token. Storage selection happens on first import. Passphrase storage requires explicit unlock after proxy restart or lock. Host login/import leaves the original file unchanged; rotating refresh tokens can make another client using that original login require sign-in again. Import grants no service, network, credential or risky-route approval."
    );
}

#[derive(Default)]
struct Options {
    mode: Option<String>,
    credential: Option<String>,
    auth_file: Option<PathBuf>,
    storage: Option<String>,
    passphrase: Option<PathBuf>,
    authorize: bool,
    remove: bool,
}

fn parse(arguments: &[String]) -> Result<Options, Error> {
    let mut options = Options::default();
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => {}
            "--authorize" => options.authorize = true,
            "--remove-guest-auth" => options.remove = true,
            "--authentication" | "--credential" | "--auth-file" | "--storage"
            | "--passphrase-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} needs a value"))?
                    .clone();
                let duplicate = match arg.as_str() {
                    "--authentication" => options.mode.replace(value).is_some(),
                    "--credential" => options.credential.replace(value).is_some(),
                    "--auth-file" => options.auth_file.replace(value.into()).is_some(),
                    "--storage" => options.storage.replace(value).is_some(),
                    _ => options.passphrase.replace(value.into()).is_some(),
                };
                if duplicate {
                    return Err(format!("{arg} supplied twice").into());
                }
            }
            _ => return Err(format!("unknown authentication option: {arg}").into()),
        }
    }
    if options
        .mode
        .as_deref()
        .is_some_and(|mode| !matches!(mode, "client" | "host-vault"))
    {
        return Err("authentication must be client or host-vault".into());
    }
    if options.mode.as_deref() != Some("host-vault")
        && (options.auth_file.is_some()
            || options.credential.is_some()
            || options.authorize
            || options.remove
            || options.storage.is_some()
            || options.passphrase.is_some())
    {
        return Err(
            "import, authorization and removal options require --authentication host-vault".into(),
        );
    }
    if (options.storage.is_some() || options.passphrase.is_some()) && options.auth_file.is_none() {
        return Err(
            "storage options require --auth-file; use credentials unlock separately".into(),
        );
    }
    if options.auth_file.is_some() && options.credential.is_none() {
        return Err("--auth-file requires --credential NAME to select its stored account".into());
    }
    if options.authorize && options.credential.is_none() {
        return Err("--authorize requires --credential NAME".into());
    }
    Ok(options)
}

fn host_input(agent: &host_agents::Agent, path: &Path) -> Result<PathBuf, Error> {
    host_agents::refresh(agent)?;
    let path = path.canonicalize().map_err(|_|"host login file is unavailable; complete the native client's host login, then select its file")?;
    let mut shares = vec![host_platform::config_dir().join("agents").canonicalize()?];
    for shared in host_agents::list()? {
        if let Some(folder) = &shared.folder {
            match Path::new(folder).canonicalize() {
                Ok(folder) => shares.push(folder),
                // An absent saved share cannot contain this existing input.
                Err(error) if error.kind()==std::io::ErrorKind::NotFound => {},
                Err(_) => return Err("could not inspect a configured guest share; host-only login custody is unknown".into()),
            }
        }
        for mount in &shared.mounts {
            shares.push(crate::host_boot::mount(mount)?.0);
        }
    }
    if shares.iter().any(|share| path.starts_with(share)) {
        return Err("selected provider login is guest-visible; choose a host login outside the agent home and workspace/mounts".into());
    }
    if !path.is_file() {
        return Err("select a regular host login file".into());
    }
    Ok(path)
}

async fn apply(agent: &host_agents::Agent, options: Options) -> Result<(), Error> {
    let directory = host_platform::config_dir().join("agents").join(&agent.name);
    let _lock = tokio::task::spawn_blocking(move || {
        crate::host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    let current = host_agents::refresh(agent)?;
    if current.host_script != agent.host_script
        || current.folder != agent.folder
        || current.mounts != agent.mounts
    {
        return Err(
            "agent configuration changed; inspect agent auth NAME --json before applying again"
                .into(),
        );
    }
    if crate::host_lifecycle::runtime(&current).await?["runtime_state"] != "stopped" {
        return Err("stop this agent before changing its authentication; current configuration and client are unchanged".into());
    }
    let client = client(&current)?;
    let mode = options
        .mode
        .as_deref()
        .ok_or("select --authentication client or host-vault")?;
    let source = options
        .auth_file
        .as_deref()
        .map(|path| host_input(&current, path))
        .transpose()?;
    // Saved client configuration is the return point. A later failure never
    // replays an import, authorization or client request on the operator's behalf.
    coding_client::configure(&home(&current), client, mode, options.remove)?;
    crate::host_boot::setup(&current, None, Some(false)).await?;
    if let Some(source) = source {
        let mut command =
            tokio::process::Command::new(host_platform::config_dir().join("bin/safeyolo"));
        command
            .arg("--config")
            .arg(host_platform::config_path())
            .args([
                "credentials",
                "import-client",
                options.credential.as_deref().unwrap(),
                "--client",
                client,
                "--auth-file",
            ])
            .arg(source);
        if let Some(storage) = options.storage {
            command.args(["--storage", &storage]);
        }
        if let Some(passphrase) = options.passphrase {
            command.arg("--passphrase-file").arg(passphrase);
        }
        // Inherit the terminal for the existing hidden passphrase/storage prompt.
        // The import owner reports metadata only, never credential values.
        if !command
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await?
            .success()
        {
            return Err("client configuration saved; import did not report success. Inspect credentials list before choosing another explicit import. No service authorization was attempted".into());
        }
    }
    if options.authorize {
        let credential = options
            .credential
            .ok_or("--authorize requires --credential NAME")?;
        let observed = binding(&current, client).await?;
        if observed["capability"] != "inference" || observed["credential"] != credential {
            let mut result = admin(&format!("/admin/agents/{}/services",crate::coord_tools::segment(&current.name)),Method::POST,json!({"service":client,"capability":"inference","credential":credential,"allow_host_network":false})).await
                .map_err(|_|"configuration/import may be saved; service authorization did not report success. Inspect agent auth NAME --json before another authorization; do not infer a grant from import")?;
            crate::credentials::wipe_json(&mut result);
        }
    }
    Ok(())
}

pub(crate) async fn guide(agent: &host_agents::Agent, mode: &str) -> Result<(), Error> {
    let client = client(agent)?;
    explain(agent, client);
    if mode == "client" {
        return apply(
            agent,
            Options {
                mode: Some(mode.into()),
                ..Options::default()
            },
        )
        .await;
    }
    let conflicts = coding_client::conflicts(&home(agent), client)?;
    let remove = if conflicts.is_empty() {
        false
    } else {
        println!(
            "Retained guest authentication: {}. Removing these inputs does not revoke copies already read by the guest.",
            conflicts.join(", ")
        );
        let answer = crate::host_launch::input(
            "Type remove to remove these inputs, or Enter to keep client-held authentication: ",
        )?
        .ok_or("authentication selection cancelled; saved state retained")?;
        if answer.is_empty() {
            if coding_client::selected(&home(agent), client)? {
                return apply(
                    agent,
                    Options {
                        mode: Some("client".into()),
                        ..Options::default()
                    },
                )
                .await;
            }
            return Ok(());
        }
        if answer != "remove" {
            return Err("select remove or Enter; authentication is unchanged".into());
        }
        true
    };
    if coding_client::selected(&home(agent), client)? && !remove {
        if let Ok(row) = binding(agent, client).await
            && !row.is_null()
        {
            println!(
                "Reusing saved host-vault configuration and the current service binding. No login was reimported and no authorization was repeated."
            );
            return Ok(());
        }
    }
    println!(
        "Select an existing vault credential account by name. To import a file-backed host login, enter a new credential name, then select the host file. For a missing login, run the native client's supported login on the host (Codex: codex login; Claude: claude auth login), then return here. The importer does not read a keychain."
    );
    let credential =
        crate::host_launch::input("Vault credential name (Enter: save configuration only): ")?
            .unwrap_or_default();
    let mut options = Options {
        mode: Some(mode.into()),
        remove,
        ..Options::default()
    };
    if !credential.is_empty() {
        options.credential = Some(credential);
        let source = crate::host_launch::input(
            "Host login file (Enter: use the stored credential without reimporting): ",
        )?
        .unwrap_or_default();
        let selection = if !source.is_empty() {
            let source = host_input(agent, Path::new(&source))?;
            let record = crate::subscription_login::import_login(
                if client == "codex" {
                    crate::subscription_login::Client::Codex
                } else {
                    crate::subscription_login::Client::Claude
                },
                options.credential.as_deref().unwrap(),
                std::fs::File::open(&source)?,
            )?;
            options.auth_file = Some(source);
            json!(record.metadata())
        } else {
            let status = admin("/admin/credentials/status", Method::GET, Value::Null).await?;
            status["credentials"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|row| row["name"] == options.credential.as_deref().unwrap())
                })
                .cloned()
                .unwrap_or(Value::Null)
        };
        println!(
            "Selected provider/account metadata: {}. Missing account identity and provider validity remain unknown.",
            serde_json::to_string(&selection)?
        );
        println!(
            "Authorize only {} ({}) for {client}/inference using vault account {} until revoked or replaced. This replaces that service's previous binding. Existing explicit denies and separate approvals still apply.",
            agent.name,
            agent.id,
            crate::network_guard::sanitize_with_limit(
                options.credential.as_deref().unwrap(),
                usize::MAX
            )
        );
        options.authorize = matches!(
            crate::host_launch::input("Authorize this selected service binding? [y/N] ")?
                .as_deref(),
            Some("y" | "yes")
        );
    }
    apply(agent, options).await
}

pub(crate) async fn ready(agent: &host_agents::Agent) -> Result<(), Error> {
    let observed = report(agent).await?;
    if observed["configuration"] != "host-vault" {
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&observed)?);
    if observed["vault"]["availability"] == "locked" {
        if crate::host_launch::input("Passphrase vault is locked. Type unlock for the existing hidden passphrase prompt, or Enter to return: ")?.as_deref() == Some("unlock") {
            let status = tokio::process::Command::new(host_platform::config_dir().join("bin/safeyolo"))
                .arg("--config").arg(host_platform::config_path()).args(["credentials","unlock"]).kill_on_drop(true).status().await?;
            if !status.success() { return Err("vault remains locked; configuration is saved. Run credentials unlock, then repeat launch for the same agent".into()); }
        } else { return Err("vault remains locked; configuration is saved. Run credentials unlock, then repeat launch for the same agent".into()); }
    } else if observed["vault"]["availability"] != "available" {
        return Err("credential storage is absent or unavailable; inspect agent auth NAME --json and complete the selected host import before relaunch".into());
    }
    if observed["authorization"]["state"] != "configured" {
        return Err("client configuration is saved; service authorization is absent or unavailable. Run agent auth NAME, then relaunch; import alone grants no access".into());
    }
    Ok(())
}

pub(crate) async fn run(arguments: &[String]) -> Result<i32, Error> {
    if arguments.is_empty() || arguments == ["--help"] {
        println!("{HELP}");
        return Ok(0);
    }
    let name = &arguments[0];
    let agent = host_agents::list()?
        .into_iter()
        .find(|agent| &agent.name == name)
        .ok_or("agent not found")?;
    let options = parse(&arguments[1..])?;
    let result = if options.mode.is_some() {
        apply(&agent, options).await
    } else if arguments.len() == 1 {
        if !std::io::stdin().is_terminal() {
            return Err("use --json to inspect authentication, or select --authentication for noninteractive setup".into());
        }
        let client = client(&agent)?;
        explain(&agent, client);
        let saved = if coding_client::selected(&home(&agent), client)? {
            "host-vault"
        } else {
            "client"
        };
        let mode = crate::host_launch::input(&format!(
            "Authentication [client/host-vault, Enter: keep {saved}]: "
        ))?
        .unwrap_or_default();
        if mode.is_empty() {
            Ok(())
        } else if matches!(mode.as_str(), "client" | "host-vault") {
            guide(&agent, &mode).await
        } else {
            Err("select client or host-vault".into())
        }
    } else {
        Ok(())
    };
    let mut ok = result.is_ok();
    let mut report = match report(&agent).await {
        Ok(report) => report,
        Err(_) => {
            ok = false;
            json!({"agent":agent.name,"agent_id":agent.id,"configuration":"unavailable","authorization":{"state":"unavailable"},"vault":{"availability":"unavailable"},"provider_validity":"unknown","client_use":"not_observed","error":"authentication state could not be read; inspect this agent's diagnostics before retrying"})
        }
    };
    report["ok"] = json!(ok);
    if let Err(error) = result {
        report["error"] = json!(crate::network_guard::sanitize_with_limit(
            &error.to_string(),
            usize::MAX
        ));
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if ok { 0 } else { 1 })
}
