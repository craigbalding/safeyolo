//! One native operator session over existing instance, evidence and approval owners.

use std::{
    collections::VecDeque,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::Method;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

use crate::{Error, host_platform, native_client, native_config, network_guard};

pub const HELP: &str = "safeyolo [--root ROOT] inspect [--factory NAME] [--agent NAME]
safeyolo [--root ROOT] traffic list [--agent NAME] [--filter EXPRESSION] [--json]
safeyolo [--root ROOT] traffic show ID|body ID request|response|websocket ID|message ID NUMBER [--offset BYTES] [--agent NAME] [--json]
safeyolo [--root ROOT] traffic export ID FORMAT FILE [--agent NAME]
safeyolo [--root ROOT] approvals list|show ID|approve ID|reject ID [--agent NAME] [--json]
safeyolo [--root ROOT] approvals share ID --helper NAME [--agent NAME]
safeyolo [--root ROOT] logs [--agent NAME] [--lines NUMBER] [--json]
safeyolo [--root ROOT] diagnose [--agent NAME] [--json]
safeyolo helper show ID|diagnostic ID|prepare ID --reason TEXT [--socket PATH] [--token-file FILE]

inspect keeps selection only in this session; it never changes a script's target.
Factory roles come from the existing selected snapshot; live state supplies readiness.
Exports: raw, raw_request, raw_response, curl, httpie, har, zhar.
Generated commands are saved or displayed as evidence, never executed.
Sharing permits selected diagnostic/approval reads only. Helper prepares; the human decides.
Approval allows reusable Worker access to the selected host/port until explicitly removed.
Helper uses its Agent API token (default /app/agent_token) and the existing guest proxy route.
If evidence or the model is unavailable, direct policy controls and local logs/diagnose remain usable.";

pub fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "inspect" | "traffic" | "approvals" | "helper" | "logs" | "diagnose"
        )
    })
}

fn encoded(value: &str) -> String {
    const URI_COMPONENT: &percent_encoding::AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("unavailable")
}
fn safe(value: &str) -> String {
    network_guard::sanitize_with_limit(value, usize::MAX)
}
fn print_json(value: &Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn body_text(body: &mut Value) -> Result<(), Error> {
    if let Some(encoded) = body["data_base64"].as_str() {
        let bytes = STANDARD.decode(encoded)?;
        // JSON quotes text and escapes terminal controls. Binary bytes remain
        // available in the original base64 field without a lossy conversion.
        body["text"] = String::from_utf8(bytes)
            .ok()
            .map_or(Value::Null, Value::String);
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    agent: Option<String>,
    factory: Option<String>,
    helper: Option<String>,
    filter: String,
    json: bool,
    lines: usize,
    offset: u64,
    socket: Option<PathBuf>,
    token: Option<PathBuf>,
    reason: Option<String>,
    scope: serde_json::Map<String, Value>,
    positional: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, Error> {
        let mut options = Self {
            lines: 100,
            ..Self::default()
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" => options.json = true,
                "--unattributed" => {
                    options.scope.insert("unattributed".into(), json!(true));
                }
                "--agent" | "--factory" | "--helper" | "--filter" | "--lines" | "--offset"
                | "--socket" | "--token-file" | "--reason" | "--test" | "--intent" | "--role"
                | "--expect" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    match arg.as_str() {
                        "--agent" => options.agent = Some(value.clone()),
                        "--factory" => options.factory = Some(value.clone()),
                        "--helper" => options.helper = Some(value.clone()),
                        "--filter" => options.filter = value.clone(),
                        "--lines" => options.lines = value.parse()?,
                        "--offset" => options.offset = value.parse()?,
                        "--socket" => options.socket = Some(value.into()),
                        "--token-file" => options.token = Some(value.into()),
                        "--reason" => options.reason = Some(value.clone()),
                        key => {
                            options.scope.insert(
                                if key == "--test" {
                                    "test_id"
                                } else {
                                    &key[2..]
                                }
                                .into(),
                                json!(value),
                            );
                        }
                    }
                }
                value if value.starts_with('-') => {
                    return Err(format!("unknown option: {value}").into());
                }
                _ => options.positional.push(arg.clone()),
            }
        }
        if let Some(name) = &options.factory {
            validate_name(name)?;
        }
        if options.agent.is_some() && options.scope.get("unattributed") == Some(&json!(true)) {
            return Err("--agent and --unattributed are mutually exclusive".into());
        }
        Ok(options)
    }
}

fn validate_name(name: &str) -> Result<(), Error> {
    if !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !matches!(name, "." | "..")
    {
        Ok(())
    } else {
        Err("invalid agent or Factory name".into())
    }
}

fn configured_agents() -> Result<Vec<Value>, Error> {
    Ok(crate::host_agents::list()?
        .into_iter()
        .map(|agent| json!({"name":agent.name,"agent_id":agent.id}))
        .collect())
}

fn factory_agents(root: &Path, name: &str) -> Result<Vec<String>, Error> {
    Ok(crate::factory::approved(root, name)?.0.agents())
}

fn selected_agent(_root: &Path, name: &str) -> Result<Value, Error> {
    configured_agents()?
        .into_iter()
        .find(|agent| agent["name"] == name)
        .ok_or_else(|| format!("agent unavailable: {name}").into())
}

async fn admin(_root: &Path, path: &str, method: Method, body: Value) -> Result<Value, Error> {
    native_client::admin(
        &host_platform::config_path(),
        path,
        method,
        body,
        Duration::from_secs(5),
    )
    .await
}

pub(crate) async fn approval(root: &Path, id: &str, agent: Option<&str>) -> Result<Value, Error> {
    if !crate::agent_api::valid_request_id(id) {
        return Err("invalid request ID".into());
    }
    let view = admin(
        root,
        &format!("/admin/approvals/{}", encoded(id)),
        Method::GET,
        Value::Null,
    )
    .await?;
    if let Some(name) = agent {
        let current = selected_agent(root, name)?;
        if view["action"]["agent"] != name || view["action"]["agent_id"] != current["agent_id"] {
            return Err("approval does not belong to the selected current agent".into());
        }
    }
    Ok(view)
}

fn show_approval(view: &Value) -> Result<(), Error> {
    println!(
        "Request: {}\nStatus: {}\nSafeYolo effect: {}",
        safe(text(&view["request_id"])),
        safe(text(&view["status"])),
        safe(text(&view["effect"]))
    );
    if let Some(reason) = view["untrusted_reason_text"].as_str() {
        // A quoted JSON string stays visibly separate, including forged
        // Markdown/HTML headings and all terminal controls.
        println!(
            "Helper reason (untrusted text): {}",
            serde_json::to_string(reason)?
        );
    }
    Ok(())
}

pub(crate) async fn resolve(
    root: &Path,
    id: &str,
    decision: &str,
    agent: Option<&str>,
) -> Result<Value, Error> {
    let preview = approval(root, id, agent).await?;
    if preview["status"] != "pending" {
        return Ok(preview);
    }
    let path = format!("/admin/approvals/{}", encoded(id));
    match admin(root, &path, Method::POST, json!({"decision":decision})).await {
        Ok(value) => Ok(value),
        Err(error) => {
            // One canonical read, never a replay of an uncertain mutation.
            match approval(root, id, agent).await {
                Ok(value) if matches!(value["status"].as_str(), Some("approved" | "rejected")) => Ok(value),
                _ => Err(format!("decision not confirmed: {error}; read approvals show before deciding again. Direct policy controls remain available").into()),
            }
        }
    }
}

async fn share(root: &Path, id: &str, helper: &str, agent: Option<&str>) -> Result<Value, Error> {
    let _ = approval(root, id, agent).await?;
    let selected = selected_agent(root, helper)?;
    let helper_id = selected["agent_id"]
        .as_str()
        .ok_or("Helper identity unavailable")?;
    let mut shared = admin(
        root,
        &format!("/admin/approvals/{}/readers", encoded(id)),
        Method::POST,
        json!({"helper":helper,"helper_id":helper_id}),
    )
    .await?;
    shared["helper_session"] = match state(root, helper).await {
        Ok(current) => json!({
            "available":current["agent_state"] == "running", "state":current,
            "guidance":"If Helper's model or command is unavailable, inspect its logs or decide through approvals approve/reject. Sharing reads never grants network permission."
        }),
        Err(error) => json!({
            "available":false,"state":"unverified","error":safe(&error.to_string()),
            "guidance":"Helper session unavailable. Check its model/launcher or use direct approval controls."
        }),
    };
    Ok(shared)
}

pub(crate) async fn pending(root: &Path, agent: Option<&str>) -> Result<Value, Error> {
    let mut value = admin(root, "/admin/approvals", Method::GET, Value::Null).await?;
    let approvals = value["approvals"]
        .as_array_mut()
        .ok_or("pending approvals unavailable")?;
    if let Some(name) = agent {
        approvals.retain(|view| view["agent"] == name);
    }
    // Routine projections contain only the canonical summary and identity.
    for view in approvals {
        *view = json!({"request_id":view["request_id"],"agent":view["agent"],"summary":view["summary"],"target":view["approval"]["target"]});
    }
    Ok(value)
}

async fn flows(root: &Path, options: &Options) -> Result<Value, Error> {
    let mut pairs = options
        .scope
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}",
                encoded(value.as_str().unwrap_or(if value == &json!(true) {
                    "true"
                } else {
                    "false"
                }))
            )
        })
        .collect::<Vec<_>>();
    if let Some(agent) = &options.agent {
        pairs.push(format!("agent={}", encoded(agent)));
    }
    pairs.push(format!("filter={}", encoded(&options.filter)));
    admin(
        root,
        &format!("/admin/traffic/flows?{}", pairs.join("&")),
        Method::GET,
        Value::Null,
    )
    .await
}

pub(crate) async fn flow(root: &Path, id: &str, agent: Option<&str>) -> Result<Value, Error> {
    let value = admin(
        root,
        &format!("/admin/traffic/flows/{}", encoded(id)),
        Method::GET,
        Value::Null,
    )
    .await?;
    if agent.is_some_and(|agent| value["agent"] != agent) {
        return Err("flow is unavailable for the selected agent".into());
    }
    Ok(value)
}

async fn traffic(root: &Path, options: &Options) -> Result<Value, Error> {
    match options
        .positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["list"] => flows(root, options).await,
        ["show", id] => flow(root, id, options.agent.as_deref()).await,
        ["export", id, format, destination] => {
            if crate::traffic_view::ExportFormat::parse(format).is_none() {
                return Err(
                    "format must be raw, raw_request, raw_response, curl, httpie, har or zhar"
                        .into(),
                );
            }
            flow(root, id, options.agent.as_deref()).await?;
            let bytes = native_client::export(
                &host_platform::config_path(),
                &format!(
                    "/admin/traffic/flows/{}/export?format={format}&{}",
                    encoded(id),
                    options.agent.as_deref().map_or_else(
                        || "selection=all".to_owned(),
                        |agent| format!("agent={}", encoded(agent)),
                    )
                ),
                Path::new(destination),
            )
            .await?;
            Ok(
                json!({"flow_id":id,"format":format,"file":destination,"bytes":bytes,"generated_commands_executed":false}),
            )
        }
        ["body", id, side] if matches!(*side, "request" | "response") => {
            flow(root, id, options.agent.as_deref()).await?;
            let mut body = admin(
                root,
                &format!("/admin/traffic/flows/{}/body?side={side}", encoded(id)),
                Method::GET,
                Value::Null,
            )
            .await?;
            body_text(&mut body)?;
            Ok(body)
        }
        ["websocket", id] => {
            flow(root, id, options.agent.as_deref()).await?;
            admin(
                root,
                &format!("/admin/traffic/flows/{}/websocket/messages", encoded(id)),
                Method::GET,
                Value::Null,
            )
            .await
        }
        ["message", id, number] => {
            let number: u64 = number.parse()?;
            flow(root, id, options.agent.as_deref()).await?;
            let mut body = admin(
                root,
                &format!(
                    "/admin/traffic/flows/{}/websocket/messages/{number}/body?offset={}",
                    encoded(id),
                    options.offset
                ),
                Method::GET,
                Value::Null,
            )
            .await?;
            body_text(&mut body)?;
            Ok(body)
        }
        _ => Err("usage: safeyolo traffic --help".into()),
    }
}

fn logs(_root: &Path, options: &Options) -> Result<Value, Error> {
    let config = native_config::read(&host_platform::config_path())?;
    let path = config
        .audit_log_path
        .ok_or("audit log path is unavailable")?;
    let input = std::io::BufReader::new(std::fs::File::open(&path)?);
    let mut rows = VecDeque::new();
    for line in input.lines() {
        let line = line?;
        let row: Value = serde_json::from_str(&line)
            .map_err(|_| "local audit record is invalid; raw log remains inspectable")?;
        if options
            .agent
            .as_ref()
            .is_some_and(|agent| row["agent"] != *agent)
        {
            continue;
        }
        rows.push_back(json!({"ts":row["ts"],"event":row["event"],"agent":row["agent"],"request_id":row["request_id"],"decision":row["decision"],"summary":row["summary"]}));
        if rows.len() > options.lines {
            rows.pop_front();
        }
    }
    Ok(json!({"file":path,"events":rows}))
}

async fn state(root: &Path, agent: &str) -> Result<Value, Error> {
    let selected = selected_agent(root, agent)?;
    let inventory = admin(root, "/admin/agents", Method::GET, Value::Null).await?;
    inventory["agents"]
        .as_array()
        .ok_or("agent inventory unavailable")?
        .iter()
        .find(|current| current["name"] == agent && current["agent_id"] == selected["agent_id"])
        .cloned()
        .ok_or_else(|| "selected agent identity is no longer in the live inventory".into())
}

async fn diagnose(root: &Path, options: &Options) -> Result<Value, Error> {
    let config = native_config::read(&host_platform::config_path())?;
    let local = config
        .policy_file
        .as_ref()
        .ok_or("policy path is unavailable")?;
    let policy = match crate::policy::Policy::from_native_path(local) {
        Ok(_) => "valid".to_owned(),
        Err(error) => format!("invalid: {error}"),
    };
    let active = match admin(root, "/admin/policy/baseline", Method::GET, Value::Null).await {
        Ok(value) => {
            json!({"available":true,"status":value["status"],"saved_matches_active":value["saved_matches_active"]})
        }
        Err(error) => {
            json!({"available":false,"error":safe(&error.to_string()),"guidance":"Local logs remain available. Restore the Admin API, then read policy show; active state is unverified."})
        }
    };
    let mut value =
        json!({"root":root,"local_policy":policy,"admin":active,"audit_log":config.audit_log_path});
    if let Some(name) = &options.agent {
        validate_name(name)?;
        let last = root.join("agents").join(name).join("current-launch.json");
        match std::fs::read(last) {
            Ok(bytes) => {
                let record: Value = serde_json::from_slice(&bytes)?;
                value["last_recorded_launch"] = json!({"agent":name,"agent_id":record["agent_id"],"state":record["state"],"exit_code":record["exit_code"],"live_state_verified":false});
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                value["last_recorded_launch"] = json!({"available":false})
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(value)
}

async fn helper(options: &Options) -> Result<Value, Error> {
    let parts = options
        .positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let [operation, id] = parts.as_slice() else {
        return Err("usage: safeyolo helper --help".into());
    };
    if !crate::agent_api::valid_request_id(id) {
        return Err("invalid request ID".into());
    }
    let token = options
        .token
        .as_deref()
        .unwrap_or(Path::new("/app/agent_token"));
    let approval = format!("/approvals/{}", encoded(id));
    let path = if *operation == "diagnostic" {
        format!("/explain?request_id={}", encoded(id))
    } else {
        approval.clone()
    };
    if !matches!(*operation, "show" | "diagnostic" | "prepare") {
        return Err("Helper supports show, diagnostic and typed preparation only".into());
    }
    let read = native_client::helper(
        options.socket.as_deref(),
        token,
        &path,
        Method::GET,
        Value::Null,
    )
    .await?;
    if *operation != "prepare" {
        return Ok(read);
    }
    let reason = options
        .reason
        .as_ref()
        .ok_or("prepare requires --reason; the reason is untrusted text")?;
    if read["status"] != "pending" {
        return Err("request is no longer pending; read canonical state".into());
    }
    native_client::helper(
        options.socket.as_deref(),
        token,
        &format!("{approval}/prepare"),
        Method::POST,
        json!({"action":read["action"],"reason":reason}),
    )
    .await
}

async fn attach(root: &Path, agent: &str) -> Result<(), Error> {
    let current = state(root, agent).await?;
    if current["attachable"] != true {
        return Err(
            "the selected agent has no existing attachable terminal; use state or logs".into(),
        );
    }
    // #817 owns this fixed native transport. Do not derive argv from evidence,
    // implement another terminal owner, or fall back to the Python CLI.
    let status = tokio::process::Command::new(std::env::current_exe()?)
        .arg("--config")
        .arg(host_platform::config_path())
        .args(["agent", "attach", agent])
        .status()
        .await?;
    if !status.success() {
        return Err("native terminal attachment failed or is unavailable; the selected target is retained. #817 owns the host attach operation".into());
    }
    Ok(())
}

async fn inspect(root: &Path, options: &Options) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "inspect requires a terminal; use direct commands with explicit --agent and --json"
                .into(),
        );
    }
    let mut agents = configured_agents()?;
    if let Some(factory) = &options.factory {
        let names = factory_agents(root, factory)?;
        agents.retain(|agent| names.iter().any(|name| agent["name"] == *name));
    }
    if agents.is_empty() {
        return Err("no configured agents in this workflow".into());
    }
    let instance = std::fs::read_to_string(
        native_config::read(&host_platform::config_path())?
            .data_dir()
            .join("instance_id"),
    )?;
    let mut selected = options.agent.clone();
    if selected
        .as_ref()
        .is_some_and(|name| !agents.iter().any(|agent| agent["name"] == *name))
    {
        return Err("selected agent is not in this workflow".into());
    }
    let workflow = options.factory.as_deref().unwrap_or("instance agents");
    loop {
        println!(
            "\nInstance: {} | Workflow: {} | Agent: {}",
            safe(instance.trim()),
            safe(workflow),
            selected
                .as_deref()
                .map(safe)
                .unwrap_or_else(|| "select once".into())
        );
        if selected.is_none() {
            for agent in &agents {
                println!(
                    "{} ({})",
                    safe(text(&agent["name"])),
                    safe(text(&agent["agent_id"]))
                );
            }
        }
        println!(
            "select NAME | state | traffic [FILTER] | show ID | body ID SIDE | websocket ID | message ID NUMBER [--offset BYTES] | export ID FORMAT FILE | pending | approval ID | share ID HELPER | approve ID | reject ID | logs | diagnose | attach | back | quit"
        );
        print!("inspect> ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input)? == 0 {
            break;
        }
        let (command, rest) = input
            .trim()
            .split_once(' ')
            .map_or((input.trim(), ""), |(command, rest)| (command, rest.trim()));
        if matches!(command, "quit" | "q") {
            break;
        }
        if command == "back" {
            println!("Returned to workflow {workflow}; selected agent retained.");
            continue;
        }
        if command == "select" {
            if agents.iter().any(|agent| agent["name"] == rest) {
                selected = Some(rest.into());
            } else {
                eprintln!("Agent is unavailable in this workflow.");
            }
            continue;
        }
        let Some(name) = selected.as_deref() else {
            eprintln!("Select an agent once.");
            continue;
        };
        let result: Result<(), Error> = async {
            let local = Options {
                agent: Some(name.into()),
                lines: options.lines,
                ..Options::default()
            };
            match command {
                "state" => print_json(&state(root, name).await?),
                "traffic" => print_json(
                    &flows(
                        root,
                        &Options {
                            filter: rest.into(),
                            ..local
                        },
                    )
                    .await?,
                ),
                "show" | "body" | "websocket" | "message" | "export" => {
                    let mut parts = vec![command.to_owned()];
                    if command == "export" {
                        parts.extend(rest.splitn(3, ' ').map(str::to_owned));
                    } else {
                        parts.extend(rest.split_whitespace().map(str::to_owned));
                    }
                    let mut evidence = Options::parse(&parts)?;
                    evidence.agent = Some(name.into());
                    print_json(&traffic(root, &evidence).await?)
                }
                "pending" => print_json(&pending(root, Some(name)).await?),
                "approval" => show_approval(&approval(root, rest, Some(name)).await?),
                "approve" | "reject" => {
                    show_approval(&approval(root, rest, Some(name)).await?)?;
                    show_approval(&resolve(root, rest, command, Some(name)).await?)
                }
                "share" => {
                    let (id, helper) = rest.split_once(' ').ok_or("share requires ID HELPER")?;
                    print_json(&share(root, id, helper.trim(), Some(name)).await?)
                }
                "logs" => print_json(&logs(root, &local)?),
                "diagnose" => print_json(&diagnose(root, &local).await?),
                "attach" => attach(root, name).await,
                _ => Err("unknown inspect action".into()),
            }
        }
        .await;
        if let Err(error) = result {
            eprintln!("Unavailable: {}", safe(&error.to_string()));
        }
    }
    println!(
        "Returned to workflow {}; Agent: {}",
        safe(workflow),
        selected
            .as_deref()
            .map(safe)
            .unwrap_or_else(|| "none".into())
    );
    Ok(())
}

pub async fn run(config: &Path, args: &[String]) -> Result<(), Error> {
    let root = config
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    host_platform::in_config(config.to_owned(), run_inner(root, args)).await
}

async fn run_inner(root: &Path, args: &[String]) -> Result<(), Error> {
    if args.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let options = Options::parse(&args[1..])?;
    let value = match args[0].as_str() {
        "inspect" => return inspect(root, &options).await,
        "traffic" => traffic(root, &options).await?,
        "logs" => logs(root, &options)?,
        "diagnose" => diagnose(root, &options).await?,
        "helper" => helper(&options).await?,
        "approvals" => {
            match options
                .positional
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                [] | ["list"] => pending(root, options.agent.as_deref()).await?,
                ["show", id] => approval(root, id, options.agent.as_deref()).await?,
                [decision @ ("approve" | "reject"), id] => {
                    resolve(root, id, decision, options.agent.as_deref()).await?
                }
                ["share", id] => {
                    share(
                        root,
                        id,
                        options
                            .helper
                            .as_deref()
                            .ok_or("share requires --helper NAME")?,
                        options.agent.as_deref(),
                    )
                    .await?
                }
                _ => return Err("usage: safeyolo approvals --help".into()),
            }
        }
        _ => return Err("usage: safeyolo inspect --help".into()),
    };
    if args[0] == "approvals" && !options.json && value.get("action").is_some() {
        show_approval(&value)
    } else {
        print_json(&value)
    }
}
