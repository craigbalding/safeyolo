//! Native agent Coord tools and model-turn supervisor; no operator credentials.
use safeyolo_proxy::{Error, coord_tools::Client};
use serde_json::Value;
use std::{ffi::OsString, io::Read, path::PathBuf};

fn input() -> Result<Value, Error> {
    let mut source = String::new();
    std::io::stdin()
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut source)?;
    if source.len() > 2 * 1024 * 1024 {
        return Err("input exceeds the checkpoint/request bound".into());
    }
    Ok(serde_json::from_str(&source)?)
}

async fn run() -> Result<(), Error> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [kind, help] if kind == "ssh-proxy" && help == "--help" => {
            println!(
                "{}",
                safeyolo_proxy::ssh_proxy::HELP.replace("safeyolo ", "safeyolo-coord ")
            );
        }
        [kind, host, port] if kind == "ssh-proxy" => {
            safeyolo_proxy::ssh_proxy::run(
                host.to_str().ok_or("SSH host must be UTF-8")?,
                port.to_str().ok_or("SSH port must be UTF-8")?.parse()?,
            )
            .await?;
        }
        [kind, ..] if kind == "completion-notes" || kind == "proposals" => {
            safeyolo_proxy::factory_proposals::run_agent(&arguments).await?;
        }
        [kind, rest @ ..] if kind == "repo-map" => {
            safeyolo_proxy::repo_map::run(rest)?;
        }
        [kind] if kind == "--version" => println!(
            "safeyolo-coord {} commit={} profile={}",
            env!("CARGO_PKG_VERSION"),
            env!("SAFEYOLO_BUILD_REVISION"),
            env!("SAFEYOLO_BUILD_PROFILE")
        ),
        [kind] if kind == "mcp" => {
            return safeyolo_proxy::coord_tools::stdio(Client::default()).await;
        }
        [kind, name] if kind == "call" => {
            let args = input()?;
            println!(
                "{}",
                Client::default()
                    .call(name.to_str().ok_or("tool name must be UTF-8 text")?, &args)
                    .await?
            );
        }
        [kind, path] if kind == "inspect-state" => println!(
            "{}",
            safeyolo_proxy::coord_supervisor::inspect(&PathBuf::from(path))?
        ),
        [kind, separator, args @ ..] if kind == "preflight" && separator == "--" => {
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is missing")?);
            safeyolo_proxy::coord_supervisor::preflight(
                &home.join(".safeyolo/coord-supervisor.json"),
                args,
            )
            .await?;
            println!("Guest harness and Coord prerequisites are ready");
        }
        [kind, path] if kind == "read-state" => println!(
            "{}",
            serde_json::to_string(&safeyolo_proxy::coord_supervisor::State::load(
                &PathBuf::from(path)
            )?)?
        ),
        [kind, path] if kind == "write-state" => {
            let state: safeyolo_proxy::coord_supervisor::State = serde_json::from_value(input()?)?;
            state.save(&PathBuf::from(path))?;
        }
        [kind, room, targets @ ..] if kind == "release-preview" => println!(
            "{}",
            serde_json::to_string(&safeyolo_proxy::coord_supervisor::release_preview(
                input()?,
                room.to_str().ok_or("room name must be UTF-8 text")?,
                &targets
                    .iter()
                    .map(|target| target
                        .to_str()
                        .map(str::to_owned)
                        .ok_or("target must be UTF-8 text"))
                    .collect::<Result<Vec<_>, _>>()?
            )?)?
        ),
        [kind, rest @ ..] if kind == "supervise" => {
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is missing")?);
            let mut config = home.join(".safeyolo/coord-supervisor.json");
            let mut state = home.join(".safeyolo/coord-supervisor-state.json");
            let mut once = false;
            let mut position = 0;
            while position < rest.len() {
                match rest[position]
                    .to_str()
                    .ok_or("supervisor option must be UTF-8 text")?
                {
                    "--" => {
                        position += 1;
                        break;
                    }
                    "--once" => once = true,
                    "--config" | "--state" => {
                        let field = &rest[position];
                        position += 1;
                        let value = rest.get(position).ok_or("supervisor path is missing")?;
                        if field == "--config" {
                            config = value.into();
                        } else {
                            state = value.into();
                        }
                    }
                    _ => return Err("unknown supervisor option".into()),
                }
                position += 1;
            }
            return safeyolo_proxy::coord_supervisor::run(
                &config,
                &state,
                rest[position..].to_vec(),
                once,
            )
            .await;
        }
        [kind] if kind == "--help" || kind == "help" => println!(
            "safeyolo-coord mcp\nsafeyolo-coord call TOOL < ARGUMENTS_JSON\nsafeyolo-coord supervise [--config FILE] [--state FILE] [--once] [-- HARNESS_ARGS...]\nsafeyolo-coord inspect-state FILE\nsafeyolo-coord stage-runtime HOME LINUX_EXECUTABLE\nsafeyolo-coord claude-state HOME OPERATOR_HOME\nsafeyolo-coord stage-mcp HOME codex|claude [--require-agent-local]\nsafeyolo-coord codex-state [--home HOME] [--mcp-launcher COMMAND] [--require-agent-local] [adopt|reset]\nsafeyolo-coord factory-stage CONFIG INSTRUCTIONS AGENT SNAPSHOT ROLE codex|pi\nsafeyolo-coord ordinary-stage CONFIG AGENT ROOMS COORDINATORS\nRuns tools and supervision inside the guest through its proxy and Agent API token. Staging runs on the operator host. Fresh native checkpoints only; uncertain work requires retained-history and working-tree inspection before repeated writes."
        ),
        _ => return safeyolo_proxy::coord_setup::run(&arguments),
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("safeyolo-coord: {error}");
        std::process::exit(1);
    }
}
