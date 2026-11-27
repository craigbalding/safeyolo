//! Read-only navigation, before any instance or agent lookup.

use safeyolo_proxy as sy;
use std::ffi::OsString;

const VERSION_USAGE: &str = "safeyolo --version";
const CONFIG: &str = "safeyolo config check FILE\nValidate a TOML configuration without activating it.\nExample: safeyolo config check ./config.toml";

const CORE_USAGE: &str =
    "safeyolo [--instance-dir PATH | --config FILE] [--json] start|stop|status|doctor";
const POLICY_REFERENCE: &str = "safeyolo policy show [--json]
safeyolo policy check FILE
safeyolo policy evaluate FILE REQUEST_JSON [--json]
safeyolo policy apply FILE [--json]
safeyolo policy capabilities [--json]
safeyolo policy assess SNAPSHOT_REQUEST_ID FILE [--json]
safeyolo policy restore APPROVAL_ID --operation-id req-ID [--json]
check and evaluate are read-only. apply activates a validated policy. show distinguishes saved and active policy. assess and restore use retained snapshot authority; restore prepares a separate operator decision.";

const OVERVIEW: &str = "SafeYolo — run coding agents with controlled access

Start here
  agent launch [WORKSPACE]  Create or resume an agent (current folder by default)
  agent list                List saved agents and their observed state
  status                    Inspect this instance and find the next action
  watch                     Review pending approvals and decide in place

Manage and recover
  agent --help              Start, stop, attach, configure and diagnose agents
  doctor                    Check host prerequisites and the request pipeline
  logs                      Read recent audit events
  inspect                   Explore an agent's access and evidence
  upgrade                   Review and apply a packaged component upgrade

Configure access
  configure --help          Connections, support and approval delegation
  credentials --help        Store or import selected authentication
  services --help           Inspect and authorize scoped service access
  policy --help             Check, assess and activate policy
  mount --help              Protect host directories from writable extra mounts
  tls --help                Inspect the CA, trust upstream CAs, TLS passthrough

Advanced and automation
  coord --help              Rooms, native work, signals and collaboration
  factory --help            Set up and run supervised agent roles
  guest --help              Acquire or select the next guest image
  job --help                Validate and run bounded jobs
  lab --help / demo --help  Run owned demonstrations and acceptance fixtures
  instance --help           Ephemeral instances and cleanup
  helpers --help            Packaging, clients, transport and authoring tools

Use COMMAND --help for options and examples. Human output is the default,
including when redirected; select --json for complete structured records.

Instance selection (optional, before the command)
  --instance-dir PATH       Select an instance directory
  --config FILE             Select its TOML configuration instead
Explicit selection overrides SAFEYOLO_NATIVE_CONFIG_PATH, SAFEYOLO_CONFIG_DIR,
SAFEYOLO_HOME, then ~/.safeyolo. Status and help never start services.

Examples
  safeyolo agent launch
  safeyolo agent launch ./project --name builder --harness codex
  safeyolo agent list
  safeyolo status --json";

const AGENT: &str = "Agents — saved identities, persistent homes and separate runtimes

  list                      List agents; no runtime is started
  launch [WORKSPACE]         Create or resume a coding agent
  status NAME               Inspect current observations
  start NAME                Start the saved agent
  stop NAME                 Stop its runtime; retain home and workspace
  attach NAME               Return to a running coding-agent terminal
  shell NAME                Open a guest shell independently of the coding agent
  auth NAME                 Inspect and select authentication custody
  watch NAME                Follow the selected agent's activity
  diagnostics NAME          Probe the selected runtime and explain recovery
  publish NAME              Share a guest HTTP port locally or over the tailnet
  publications NAME         Inspect this agent's web publications
  unpublish NAME            Stop only a selected web publication
  recover NAME              Recover guest control after inspecting diagnostics
  create / configure        Save workspace, memory, launcher and mount settings
  mount / unmount           Change shares in the current run
  mounts                    Change shares for the next start
  retire NAME               Preview stopping and removing the saved definition
  lifecycle                 Scheduled saved-worker lifecycle controls

Use agent ACTION --help for syntax and material effects.
Examples: safeyolo agent list; safeyolo agent launch . --name builder";

const POLICY: &str = "Policy — inspect, validate and activate access rules

  show                      Inspect saved versus effective policy
  check FILE                Validate without activating or spending quotas
  evaluate FILE REQUEST     Evaluate a request description offline
  apply FILE                Validate and activate a policy
  capabilities              Discover supported policy controls
  assess REQUEST_ID FILE    Assess a candidate against a retained snapshot
  restore APPROVAL_ID       Prepare a snapshot restore for review
  feeds --help              Configure and refresh destination feeds

Examples: safeyolo policy show; safeyolo policy check ./policy.toml
Select --json for complete records. apply changes effective policy; check does not.";

const COORD: &str = "Coord — collaboration and canonical work

  start / stop              Control this instance's managed NATS
  status [ROOM]             Inspect NATS or a selected room's observations
  room create NAME / list   Manage rooms
  grant / revoke            Set agent room permissions
  send / chat / history     Read and send messages
  work --help               Native assignments, checks and acceptance
  signal --help             Attention signals and timed events
  brief --help              Read or change standing context
  state ROOM               Read room inventory
  inventory --help          Advertise capabilities and resources
  catch-up --help           Summarize retained room activity
  federation --help         Configure inter-instance collaboration
  completion-notes --help   Inspect retained completion candidates
  proposals --help          Review verified factory proposals
  mattermost --help         External conversation adapter
  dispatch-trigger --help   Prepare an approved publication trigger

Use coord ACTION --help for options. Select --json for structured results.
Custom NATS ports are selected on coord start; repeat them after stopping NATS.";

/// Return true only for an intentional, state-free help journey. Guided bare
/// commands (launch, upgrade, inspect, lab and demo) retain their behavior.
pub fn show(arguments: &[OsString]) -> bool {
    let mut words: Vec<_> = arguments
        .iter()
        .take_while(|v| *v != "--")
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    let explicit = words.iter().any(|v| v == "--help" || v == "-h")
        || words.first().is_some_and(|v| v == "help");
    words.retain(|v| !matches!(v.as_str(), "--help" | "-h" | "help"));
    if words.is_empty() {
        println!("{OVERVIEW}\nVersion and source identity: {VERSION_USAGE}");
        return true;
    }
    let group = words[0].as_str();
    let bare_group = words.len() == 1
        && matches!(
            group,
            "agent"
                | "mount"
                | "policy"
                | "config"
                | "coord"
                | "job"
                | "guest"
                | "credentials"
                | "services"
                | "approvals"
                | "traffic"
                | "support"
                | "helpers"
                | "tls"
                | "signals"
                | "codex"
                | "instance"
                | "factory"
        );
    if !explicit && !bare_group {
        return false;
    }
    let path = words.join(" ");
    let reference = match group {
        "agent" if words.len() == 1 => {
            println!("{AGENT}");
            return true;
        }
        "agent" if words.get(1).is_some_and(|v| v == "list") => {
            println!(
                "safeyolo agent list [--json]\nList saved agents and current observations. No agent is started.\nExample: safeyolo agent list"
            );
            return true;
        }
        "agent"
            if words.get(1).is_some_and(|word| {
                matches!(word.as_str(), "publish" | "unpublish" | "publications")
            }) =>
        {
            sy::host_commands::WEB_HELP
        }
        "agent" if words.get(1).is_some_and(|word| word == "launch") => {
            sy::host_commands::AGENT_LAUNCH_HELP
        }
        "agent" if words.get(1).is_some_and(|word| word == "auth") => {
            sy::host_commands::AGENT_AUTH_HELP
        }
        "agent" if words.get(1).is_some_and(|word| word == "lifecycle") => {
            println!(
                "{}\nExample: safeyolo agent lifecycle builder status",
                sy::host_commands::AGENT_LIFECYCLE_HELP
            );
            return true;
        }
        "agent" => sy::host_commands::AGENT_HELP,
        "policy" if words.len() == 1 => {
            println!("{POLICY}");
            return true;
        }
        "policy" if words.get(1).is_some_and(|v| v == "feeds") => sy::policy_feeds::HELP,
        "policy" => POLICY_REFERENCE,
        "init" => {
            "safeyolo init\nCreate configuration, a fresh instance identity and local TLS CA. Existing configuration is preserved and refused; the installer supplies packaged runtime inputs.\nExample: safeyolo init"
        }
        "config" => CONFIG,
        "coord" if words.len() == 1 => {
            println!("{COORD}");
            return true;
        }
        "coord"
            if words.get(1).is_some_and(|word| {
                matches!(
                    word.as_str(),
                    "start" | "stop" | "status" | "state" | "room" | "grant" | "revoke"
                )
            }) =>
        {
            sy::coord_rooms::LIFECYCLE_HELP
        }
        // Remaining nested Coord references are owned by their native parsers.
        "coord" => return false,
        "credentials" => super::credential_commands::CREDENTIAL_HELP,
        "services" => super::credential_commands::SERVICE_HELP,
        "factory" => sy::factory::HELP,
        "guest" => sy::guest_acquisition::HELP,
        "upgrade" => sy::guest_acquisition::COMPONENT_UPGRADE_HELP,
        "job" => sy::jobs::HELP,
        "lab" => sy::lab::HELP,
        "demo" => sy::demo::HELP,
        "instance" => {
            println!(
                "{}\nExample: safeyolo instance run --ephemeral -- safeyolo status",
                sy::instance::HELP
            );
            return true;
        }
        "signals" => sy::signals::HELP,
        "configure" => return false,
        "approvals" | "traffic" | "support" | "logs" if words.len() == 1 => {
            println!(
                "{}",
                match group {
                    "logs" =>
                        "Logs — read retained audit events and recorded links\n\n  logs [--agent NAME]        Read recent events\n  list                      Discover retained namespaces and pivots\n  connection ID             Follow a recorded connection\n  request ID                Follow a recorded request\n\nOrdinary views summarize retained evidence. Select --file PATH for offline input, --lines NUMBER for retention, or --json for complete original records and metadata.\nUse logs ACTION --help for required instance/runtime selection and evidence limits. Reads enable no capture.",
                    "approvals" =>
                        "Approvals — review and decide requested access\n\n  list                      List pending requests\n  show ID                   Read the permission and offered options\n  explain ID                Explain the selected option without deciding\n  approve / reject ID       Decide through the existing resolver\n  ask / context ID          Request or read agent context\n  review --agent NAME       Review a selected agent's requests\n  delegations               Inspect saved reviewers\n  delegation --help         Check, apply or revoke a named delegation\n  share ID --helper NAME    Share selected diagnostic/approval reads\n  narrow-diagnostics --help Narrow a diagnostic disclosure proposal\n\nUse approvals ACTION --help for syntax and effects. Decide directly: safeyolo watch",
                    "traffic" =>
                        "Traffic — inspect retained requests and responses\n\n  list                      List matching flows\n  show ID                   Read one flow\n  body ID request|response  Read a retained body\n  websocket ID              Read WebSocket metadata\n  message ID NUMBER         Read a retained message\n  export ID FORMAT FILE     Save selected evidence\n\nUse traffic ACTION --help for syntax and evidence limits. No capture is enabled by reading.",
                    _ =>
                        "Support — inspect scoped grants and retained operations\n\n  grants                    Inspect saved support access\n  verify GRANT TARGET       Verify current access as the selected supporter\n  notices                   Read support notices\n  result OPERATION_ID       Read a retained support result\n  receipts                  List operation receipts\n  receipt / recover ID      Read a receipt or compare current state\n  preview / apply NAME      Review or apply an authored proposal\n  revoke / report NAME      Revoke or inspect named access\n\nUse support ACTION --help for required agent/owner selection and authority limits.",
                }
            );
            return true;
        }
        "approvals" | "traffic" | "logs" | "diagnose" | "observations" | "support" | "inspect"
        | "helper" => sy::operator_commands::help(group),
        "mount" => {
            "safeyolo mount list [--json]\nsafeyolo mount protect PATH\nsafeyolo mount unprotect PATH\nProtect a path and descendants against writable extra mounts. Existing shares and workspaces stay unchanged. Explicit :ro permits a protected source.\nExample: safeyolo mount protect ~/private"
        }
        "start" | "stop" | "status" | "doctor" => {
            println!(
                "{}\n{}\nExample: safeyolo {group}",
                CORE_USAGE
                    .replace(" [--instance-dir PATH | --config FILE]", "")
                    .replace("start|stop|status|doctor", group),
                match group {
                    "start" =>
                        "Start the host proxy and its optional Coord service. Agent runtimes start separately.",
                    "stop" =>
                        "Stop the host proxy and managed Coord. Agent runtimes remain intact.",
                    "doctor" =>
                        "Run ordered prerequisite and request-pipeline checks. Exit 0: pass/warnings; exit 1: failed or unknown required checks. Skipped checks never count as passes. No service is started or repaired.",
                    _ =>
                        "Read this instance's proxy and agent observations. A running proxy does not establish coding-agent readiness.",
                }
            );
            return true;
        }
        "tls" => sy::tls_commands::HELP,
        "helpers" => {
            "Automation and authoring helpers\n\n  host --help           Linux host preparation and installer operations\n  host-package --help   Verify and unpack host archives\n  codex --help          Prefetch or import native Codex packages\n  guest-command stage   Stage a guest command from explicit input files\n  ssh-proxy --help       Proxy a supported SSH transport\n  test-context --help    Format or declare test attribution\n  helper --help          Agent API machine interface\n  dispatch --help        Generate/check publication artifacts\n\nTransport and artifact commands deliberately emit their requested payload."
        }
        "host" => sy::linux_host::HELP,
        "host-package" => sy::host_package::HELP,
        "codex" => sy::codex_package::HELP,
        "ssh-proxy" => sy::ssh_proxy::HELP,
        "dispatch" => sy::dispatch::HELP,
        _ => return false,
    };
    // Remove repeated global selectors from references; selection is explained
    // once in the overview. Keep the authoritative options and effects.
    let reference = reference
        .replace(" [--instance-dir PATH | --config FILE]", "")
        .replace(" [--instance-dir PATH]", "");
    let mut printed = false;
    for line in reference.lines() {
        if !line.starts_with("safeyolo ") || words.len() == 1 || command_matches(line, &path) {
            print_wrapped(line);
            printed = true;
        }
    }
    if !printed {
        println!("Use safeyolo {group} --help to choose a supported action.");
    }
    println!(
        "\nExample: safeyolo {}{}",
        path,
        match path.as_str() {
            "agent launch" => " ./project --name builder",
            "agent create" | "agent configure" => " builder --workspace ./project",
            "agent status" | "agent stop" | "agent start" | "agent diagnostics" | "agent auth"
            | "agent attach" | "agent shell" | "agent retire" => " builder",
            "coord room" => " list",
            "coord start" | "coord stop" | "coord status" => "",
            "coord state" => " team",
            _ => return true,
        }
    );
    true
}

pub fn usage_error(arguments: &[String]) -> String {
    match arguments.first().map(String::as_str) {
        Some("config") => format!("unknown or incomplete configuration command\n{CONFIG}"),
        Some("policy") => format!("unknown or incomplete policy command\n{POLICY}"),
        _ => "unknown or incomplete command; use safeyolo --help".to_owned(),
    }
}

fn print_wrapped(line: &str) {
    let continuation = if line.starts_with("safeyolo ") {
        "  "
    } else {
        ""
    };
    let mut width = 0;
    for word in line.split_whitespace() {
        let length = word.chars().count();
        if width > 0 && width + 1 + length > 88 {
            print!("\n{continuation}");
            width = continuation.len();
        } else if width > 0 {
            print!(" ");
            width += 1;
        }
        print!("{word}");
        width += length;
    }
    println!();
}

fn command_matches(line: &str, path: &str) -> bool {
    let words: Vec<_> = line.split_whitespace().skip(1).collect();
    words.len() >= path.split_whitespace().count()
        && path
            .split_whitespace()
            .zip(words)
            .all(|(wanted, offered)| offered.split('|').any(|word| word == wanted))
}
