//! Published choices and foreground composition of the existing upgrade owners.

use std::io::{IsTerminal, Write};

use super::*;

pub(super) fn handles(arguments: &[OsString]) -> bool {
    arguments.is_empty()
        || arguments == ["releases"]
        || arguments
            .iter()
            .any(|arg| arg == "--preview" || arg == "--activate")
}

fn host_asset() -> Result<String, Error> {
    let platform = consumer_platform()?;
    let (os, architecture) = platform.os_architecture();
    let libc = if os == "linux"
        && !Command::new("getconf")
            .arg("GNU_LIBC_VERSION")
            .output()
            .is_ok_and(|output| output.status.success())
    {
        "-musl"
    } else {
        ""
    };
    Ok(format!(
        "safeyolo-{os}-{architecture}{libc}-production.tar.gz"
    ))
}

fn release_choices(records: &Value, asset: &str) -> Result<Vec<Value>, Error> {
    let records = records
        .as_array()
        .ok_or("host release discovery returned no release list")?;
    Ok(records
        .iter()
        .filter(|record| {
            let tag = record["tag_name"].as_str().unwrap_or_default();
            let valid_tag = tag.strip_prefix("host-").is_some_and(|sha| {
                sha.len() == 40
                    && sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
            let has_asset = |name: &str| {
                record["assets"].as_array().is_some_and(|assets| {
                    assets.iter().any(|item| {
                        item["name"] == name && item["size"].as_u64().is_some_and(|size| size > 0)
                    })
                })
            };
            valid_tag
                && record["draft"] == false
                && record["prerelease"] == false
                && has_asset(asset)
                && has_asset("SHA256SUMS")
        })
        .map(|record| {
            json!({
                "release":record["tag_name"], "published_at":record["published_at"],
                "asset":asset,
            })
        })
        .collect())
}

async fn releases() -> Result<Vec<Value>, Error> {
    // The same HTTPS trust and proxy route as install.sh. This catalogue is
    // advisory; the bootstrap and package/OCI owners verify selected bytes.
    let output = tokio::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-time",
            "30",
            "--max-filesize",
            "4194304",
            "--header",
            "Accept: application/vnd.github+json",
            "--user-agent",
            "safeyolo-upgrade",
            "https://api.github.com/repos/craigbalding/safeyolo/releases?per_page=100",
        ])
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!("host release discovery unavailable: {}. Use upgrade --release host-COMMIT or --bundle DIRECTORY with an explicit target", String::from_utf8_lossy(&output.stderr)).into());
    }
    let mut choices = release_choices(&serde_json::from_slice(&output.stdout)?, &host_asset()?)?;
    choices.sort_by(|left, right| {
        right["published_at"]
            .as_str()
            .cmp(&left["published_at"].as_str())
    });
    if choices.is_empty() {
        return Err("no supported host package found in the latest 100 release records; use upgrade --release host-COMMIT or --bundle DIRECTORY with an explicit target".into());
    }
    Ok(choices)
}

pub(super) async fn discover_guest(
    package: &PackageGuest,
    current: Option<&GuestSelection>,
) -> Result<String, Error> {
    let store = component_guest_store(current)?;
    fs::create_dir_all(&store)?;
    let _lock = crate::host_platform::lock_host_state(&store.join("acquire.lock"))?;
    let (index, _) = resolve_guest(&registry_client()?, package, &store, None).await
        .map_err(|error| format!("compatible guest discovery unavailable: {error}. Retained selection is unchanged; select a verified --guest-index sha256:DIGEST explicitly"))?;
    Ok(index.identity.digest)
}

fn input(prompt: &str) -> Result<String, Error> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().to_owned())
}

fn proxy_observation(root: &Path) -> Result<Value, Error> {
    let Some(record) = crate::guest_commands::read_state(&root.join("data/proxy-process.json"))?
    else {
        return Ok(json!({"state":"unknown", "reason":"no owned proxy process record"}));
    };
    let Some((pid, token)) = record["pid"].as_i64().zip(record["token"].as_str()) else {
        return Ok(json!({"state":"unknown", "reason":"invalid proxy process record"}));
    };
    if crate::host_lifecycle::process_token(pid).as_deref() != Some(token) {
        return Ok(
            json!({"state":"unavailable", "reason":"recorded proxy process is no longer verified live"}),
        );
    }
    for binary in retained_host_binaries(root, "safeyolo-proxy")? {
        if crate::host_platform::process_has_path_argument(
            pid,
            &binary,
            b"--config",
            &root.join("config.toml"),
        ) {
            let binary = binary.canonicalize()?;
            let host = binary
                .parent()
                .and_then(Path::parent)
                .ok_or("proxy binary has no package directory")?;
            let selected = status(root)?;
            let checksum = hash_file(&host.join("SHA256SUMS"))?;
            return Ok(json!({"state":"running", "pid":pid, "host_package":host,
                "host":describe_host(host)?["host"],
                "host_checksums_sha256":checksum,
                "matches_selected_host":selected["current"]["host_checksums_sha256"] == checksum,
            }));
        }
    }
    Ok(
        json!({"state":"unknown", "pid":pid, "reason":"running executable could not be matched to an owned retained host"}),
    )
}

async fn observations(root: &Path) -> Value {
    let proxy = proxy_observation(root)
        .unwrap_or_else(|error| json!({"state":"unknown", "error":error.to_string()}));
    let agents = match crate::host_agents::list() {
        Err(error) => json!({"state":"unknown", "error":error.to_string()}),
        Ok(agents) => {
            let mut results = Vec::new();
            for agent in agents {
                let runtime = crate::host_runs::observe(&agent.name).await;
                let context = crate::guest_commands::read_state(
                    &root
                        .join("agents")
                        .join(&agent.name)
                        .join("config-share/host-launch-context.json"),
                );
                let inputs = match context {
                    Ok(Some(context))
                        if runtime["runtime_state"] == "running"
                            && runtime["run_id"].is_string()
                            && context["generation"] == runtime["run_id"]
                            && context["agent_id"] == agent.id =>
                    {
                        let selected = selected_boot_inputs(root).ok();
                        let matches = context["host_package"].as_str().and_then(|path| {
                            // An initial boot recorded ROOT, whose aliases
                            // can now select another pair. That path alone
                            // cannot identify the bytes used at boot.
                            let host = Path::new(path);
                            if host == root {
                                return None;
                            }
                            let guest = Path::new(context["guest_inputs"].as_str()?);
                            let (selected_host, selected_guest) = selected.as_ref()?;
                            Some(
                                host.canonicalize().ok()? == selected_host.canonicalize().ok()?
                                    && guest.canonicalize().ok()?
                                        == selected_guest.canonicalize().ok()?,
                            )
                        });
                        json!({"host_package":context["host_package"], "guest_inputs":context["guest_inputs"],
                                "matches_selected_inputs":matches, "source":"paths recorded at boot for the observed current run; mutable aliases do not prove component identity"})
                    }
                    Ok(_) => {
                        json!({"state":"unknown", "reason":"no launch context matched to a verified running incarnation"})
                    }
                    Err(error) => json!({"state":"unknown", "error":error.to_string()}),
                };
                results
                    .push(json!({"name":agent.name, "runtime":runtime, "running_inputs":inputs}));
            }
            json!(results)
        }
    };
    json!({"observed_at":time::OffsetDateTime::now_utc().unix_timestamp(), "proxy":proxy, "agents":agents})
}

fn display_preview(view: &Value) {
    let host = |pair: &Value| {
        format!(
            "{} ({})",
            pair["host"]["source_commit"].as_str().unwrap_or("unknown"),
            pair["host"]["profile"].as_str().unwrap_or("unknown")
        )
    };
    let guest = |pair: &Value| {
        pair["guest"]["version"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned()
    };
    eprintln!(
        "Installation: {}\nSelected host: {}\nProposed host: {}\nSelected guest: {}\nProposed guest: {}\nObserved proxy: {} from {} (matches selected host: {})",
        view["root"].as_str().unwrap_or("unknown"),
        host(&view["selected"]["current"]),
        host(&view["proposed"]),
        guest(&view["selected"]["current"]),
        guest(&view["proposed"]),
        view["observed"]["proxy"]["state"]
            .as_str()
            .unwrap_or("unknown"),
        view["observed"]["proxy"]["host"]["source_commit"]
            .as_str()
            .unwrap_or("unknown"),
        view["observed"]["proxy"]["matches_selected_host"]
    );
    if let Some(agents) = view["observed"]["agents"].as_array() {
        for agent in agents {
            eprintln!(
                "Agent {}: {}; recorded host: {}; guest inputs: {}; matches selected inputs: {}",
                agent["name"].as_str().unwrap_or("unknown"),
                agent["runtime"]["runtime_state"]
                    .as_str()
                    .unwrap_or("unknown"),
                agent["running_inputs"]["host_package"]
                    .as_str()
                    .unwrap_or("unknown"),
                agent["running_inputs"]["guest_inputs"]
                    .as_str()
                    .unwrap_or("unknown"),
                agent["running_inputs"]["matches_selected_inputs"]
            );
        }
    } else {
        eprintln!(
            "Agent observations unavailable: {}",
            view["observed"]["agents"]
        );
    }
    eprintln!(
        "Activation reuses a proxy already running the proposed host; otherwise it stops and starts this instance's proxy and managed Coord, interrupting traffic and Coord. Agents keep running with their existing inputs unless you choose to restart them.\nPolicy, credentials, homes and audit data are retained. Component rollback does not reverse later user-state changes."
    );
}

fn proposed(prepared: &Prepared) -> Result<Value, Error> {
    let mut pair = describe_host(&prepared.host)?;
    pair["guest"] = serde_json::to_value(&prepared.guest)?;
    Ok(pair)
}

fn report(root: &Path, selected: Result<Value, Error>, observed: Value) -> Value {
    json!({"root":root, "selected":selected.unwrap_or_else(|error| json!({"state":"unknown", "error":error.to_string()})), "observed":observed})
}

async fn restart_agent(root: &Path, name: &str) -> Result<(), Error> {
    // Invoke the selected CLI so setup locks, ownership and launcher behavior
    // remain with the ordinary agent operations.
    for operation in ["stop", "start"] {
        let output = tokio::process::Command::new(root.join("bin/safeyolo"))
            .arg("--root")
            .arg(root)
            .args(["agent", operation, name])
            .output()
            .await?;
        if !output.status.success() {
            return Err(format!(
                "agent {operation} {name} failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }
    Ok(())
}

pub(super) async fn run(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    let root = root.canonicalize()?;
    if !root.join("config.toml").is_file() {
        return Err("upgrade requires an installed native instance".into());
    }
    crate::host_platform::in_config(root.join("config.toml"), run_inner(&root, arguments)).await
}

async fn run_inner(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    if arguments == ["releases"] {
        let choices = match releases().await {
            Ok(choices) => choices,
            Err(error) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"root":root, "state":"unavailable", "error":error.to_string(), "explicit_selection":"upgrade --release host-COMMIT or --bundle DIRECTORY"})
                    )?
                );
                return Err(error);
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"root":root, "releases":choices, "scope":"latest 100 release records; published production packages for this host"})
            )?
        );
        return Ok(());
    }
    let interactive = arguments.is_empty();
    if interactive && !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return Err("guided upgrade needs a terminal; use upgrade releases, then upgrade --release RELEASE --preview or --activate".into());
    }
    let mut bundle = None;
    let mut release = None;
    let mut index = None;
    let mut discovered_index = None;
    let mut preview = false;
    let mut activate = false;
    let mut restarts = Vec::new();
    let mut options = arguments.iter();
    while let Some(option) = options.next() {
        if option == "--preview" && !preview && !activate {
            preview = true;
        } else if option == "--activate" && !activate && !preview {
            activate = true;
        } else {
            let value = options.next().ok_or("upgrade option requires a value")?;
            if option == "--bundle" && bundle.is_none() && release.is_none() {
                bundle = Some(PathBuf::from(value));
            } else if option == "--release" && release.is_none() && bundle.is_none() {
                release = Some(value.to_str().ok_or("release must be UTF-8")?.to_owned());
            } else if option == "--guest-index" && index.is_none() {
                let value = value.to_str().ok_or("guest index must be UTF-8")?;
                guest_oci::sha256_hex(value)?;
                index = Some(value.to_owned());
            } else if option == "--restart-agent" {
                restarts.push(value.to_str().ok_or("agent name must be UTF-8")?.to_owned());
            } else {
                return Err(format!("unknown or duplicate guided upgrade option\n{HELP}").into());
            }
        }
    }
    if !activate && !restarts.is_empty() {
        return Err("--restart-agent requires --activate".into());
    }
    let result = async {
        if bundle.is_none() && release.is_none() {
            let choices = releases().await?;
            let choice = if interactive {
                eprintln!(
                    "Installation: {}\nPublished production host packages:",
                    root.display()
                );
                for (number, choice) in choices.iter().enumerate() {
                    eprintln!(
                        "{}: {} ({})",
                        number + 1,
                        choice["release"].as_str().unwrap(),
                        choice["published_at"].as_str().unwrap_or("date unknown")
                    );
                }
                let answer = input("Release number [1], or q to leave unchanged: ")?;
                if answer == "q" {
                    return Ok(());
                }
                if answer.is_empty() {
                    0
                } else {
                    answer
                        .parse::<usize>()?
                        .checked_sub(1)
                        .ok_or("release number starts at 1")?
                }
            } else {
                0
            };
            release = Some(
                choices
                    .get(choice)
                    .ok_or("release number is outside the displayed list")?["release"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let prepared = {
            let _lock = crate::host_platform::lock_host_state(&root.join("guest-install.lock"))?;
            prepare(root, bundle.as_deref(), release.as_deref(), index.as_deref(), Some(&mut discovered_index)).await?
        };
        let mut view = report(root, Ok(prepared.before.clone()), observations(root).await);
        view["proposed"] = proposed(&prepared)?;
        view["release"] = json!(release);
        view["effect"] = json!({"proxy":"reuse a proxy already running the proposed host; otherwise stop and start this instance's proxy and managed Coord, interrupting traffic and Coord", "agents":"running agents keep their inputs; restart only the agents you choose", "retention":"policy, credentials, homes, audit and unrelated installations are retained", "rollback":"the existing previous-pair command restores components; it does not reverse later user-state changes"});
        if interactive {
            display_preview(&view);
            let answer = input("Activate now? [y/N]: ")?;
            if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
                println!("Selection is unchanged. Verified inputs are retained; run upgrade again when ready to activate.");
                return Ok(());
            }
            activate = true;
            let names = input("Agents to stop and start (space-separated names; empty keeps all running agents): ")?;
            restarts = names.split_whitespace().map(str::to_owned).collect();
        } else if preview {
            view["outcome"] = json!("preview_only");
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        } else { display_preview(&view); }
        // Validate names before interrupting any component.
        if !restarts.is_empty() {
            let agents = crate::host_agents::list()?;
            for name in &restarts {
                if !agents.iter().any(|agent| agent.name == *name) { return Err(format!("agent not found: {name}").into()); }
            }
            restarts.sort(); restarts.dedup();
        }
        let _lock = crate::host_platform::lock_host_state(&root.join("guest-install.lock"))?;
        check_prepared(root, &prepared)?;
        let proxy = proxy_observation(root).unwrap_or_else(|error| json!({"state":"unknown", "error":error.to_string()}));
        let already_running = proxy["state"] == "running"
            && proxy["host_checksums_sha256"] == proposed(&prepared)?["host_checksums_sha256"];
        if !already_running { crate::host_commands::stop_proxy().await?; }
        select(root, &prepared)?;
        crate::host_commands::start_proxy().await?;
        let proxy = proxy_observation(root)?;
        if proxy["state"] != "running" || proxy["matches_selected_host"] != true {
            return Err("selected host could not be verified as the running proxy".into());
        }
        for name in &restarts { restart_agent(root, name).await?; }
        let mut result = report(root, status(root), observations(root).await);
        result["outcome"] = json!("proxy_activated");
        result["agent_restart_commands_completed"] = json!(restarts);
        result["agent_activation"] = json!("inspect observed current-run inputs; other agents retain their inputs until restarted");
        if interactive {
            println!("The proxy at {} is running the selected host. Completed agent stop/start commands: {}. Other agents keep their existing inputs.", root.display(), if restarts.is_empty() { "none".to_owned() } else { restarts.join(", ") });
        } else { println!("{}", serde_json::to_string_pretty(&result)?); }
        Ok::<_, Error>(())
    }.await;
    if let Err(error) = &result {
        let mut failure = report(root, status(root), observations(root).await);
        failure["outcome"] = json!("incomplete");
        failure["error"] = json!(error.to_string());
        let mut retry = vec![
            json!("safeyolo"),
            json!("--root"),
            json!(root),
            json!("upgrade"),
        ];
        if let Some(bundle) = &bundle {
            retry.extend([json!("--bundle"), json!(bundle)]);
        }
        if let Some(release) = &release {
            retry.extend([json!("--release"), json!(release)]);
        }
        if let Some(index) = index.as_ref().or(discovered_index.as_ref()) {
            retry.extend([json!("--guest-index"), json!(index)]);
        }
        retry.push(json!(if activate { "--activate" } else { "--preview" }));
        for name in &restarts {
            retry.extend([json!("--restart-agent"), json!(name)]);
        }
        failure["next_action"] = json!({"inspect":["safeyolo", "--root", root, "upgrade", "status"], "retry_after_inspection":retry});
        if !failure["selected"]["previous"].is_null() && root.join("safeyolo-upgrade").is_file() {
            failure["next_action"]["rollback"] =
                json!([root.join("safeyolo-upgrade"), "--root", root, "rollback"]);
            failure["next_action"]["after_rollback"] = json!(["safeyolo", "--root", root, "start"]);
            failure["next_action"]["limit"] = json!(
                "rollback restores the retained previous components only; stop the proxy first if running. It does not reverse later user-state changes"
            );
        }
        println!("{}", serde_json::to_string_pretty(&failure)?);
    }
    result
}
