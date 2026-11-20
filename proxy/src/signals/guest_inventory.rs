//! Read effective Debian package state through the existing owned guest transport.
use super::*;
use crate::{RuntimeState, host_runs::AgentRun, policy::Policy};

const RECORD_LIMIT: u64 = 4 * 1024 * 1024;
// No network, package mutation, sourced guest files or guest-side scheduler.
const COMMAND: &str = r#"set -eu
export LC_ALL=C
/usr/bin/cat /etc/os-release
printf '\nSAFEYOLO_PACKAGES\n'
/usr/bin/dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\n'
printf 'SAFEYOLO_INVENTORY_END\n'
"#;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectionPolicy {
    pub interval_seconds: Option<u64>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}
impl CollectionPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.interval_seconds == Some(0)
            || self.timeout_seconds == 0
            || std::time::Instant::now()
                .checked_add(Duration::from_secs(self.timeout_seconds))
                .is_none()
            || self.max_output_bytes == 0
            || self.max_output_bytes > 1024 * 1024
        {
            return Err("guest_inventory needs a positive optional interval, a supported positive timeout and max_output_bytes in 1..1048576".into());
        }
        Ok(())
    }
}

/// The same host-owned complete inventory format accepted from adopted checks.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    pub agent_id: String,
    pub run_id: String,
    pub observed_at: u64,
    pub distribution: String,
    pub packages: BTreeMap<String, String>,
    pub services: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct Collection {
    basis: String,
    request_id: Value,
    attempted_at: u64,
    run: Option<AgentRun>,
    state: String,
    diagnostic: Option<String>,
    inventory: Option<Inventory>,
}
fn path(root: &Path, rule: &str, agent: &str) -> PathBuf {
    directory(root)
        .join("guest-inventory")
        .join(rule)
        .join(format!("{agent}.json"))
}
pub(super) fn request_path(root: &Path, rule: &str) -> PathBuf {
    directory(root)
        .join("assessment-requests")
        .join(format!("{rule}.json"))
}
fn read(root: &Path, rule: &str, agent: &str) -> Result<Option<Collection>, Error> {
    crate::guest_commands::read_state_bounded(&path(root, rule, agent), RECORD_LIMIT)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}
pub(super) fn inventory(root: &Path, rule: &str, agent: &str) -> Result<Option<Inventory>, Error> {
    Ok(read(root, rule, agent)?.and_then(|record| record.inventory))
}

fn authorize(
    root: &Path,
    runtime: &RuntimeState,
    config: &Configuration,
    run: &AgentRun,
) -> Result<(), Error> {
    let current = runtime
        .read()
        .map_err(|_| "guest assessment runtime unavailable")?;
    if digest(&configuration(root)?) != digest(config)
        || current
            .policy
            .as_ref()
            .is_none_or(|policy| !run.current(policy))
    {
        return Err("guest assessment adoption, identity or running guest changed".into());
    }
    Ok(())
}

pub(super) async fn collect_due(root: &Path, runtime: &RuntimeState) -> Result<u64, Error> {
    let config = configuration(root)?;
    let mut due = u64::MAX;
    for (rule_name, rule) in &config.rules {
        let Some(collection) = &rule.guest_inventory else {
            continue;
        };
        let request = crate::guest_commands::read_state(&request_path(root, rule_name))?
            .unwrap_or(Value::Null);
        for agent in &rule.agents {
            let policy = runtime
                .read()
                .map_err(|_| "guest assessment runtime unavailable")?
                .policy
                .clone()
                .ok_or("guest assessment policy unavailable")?;
            let run = policy.agent_run(agent);
            let basis = digest(rule);
            let previous = read(root, rule_name, agent)?;
            let requested = !request["request_id"].is_null()
                && previous
                    .as_ref()
                    .is_none_or(|old| old.request_id != request["request_id"]);
            let next = previous.as_ref().and_then(|old| {
                collection
                    .interval_seconds
                    .map(|interval| old.attempted_at.saturating_add(interval))
            });
            let scheduled = collection.interval_seconds.is_some()
                && (previous
                    .as_ref()
                    .is_none_or(|old| old.run != run || old.basis != basis)
                    || next.is_none_or(|next| now() >= next));
            if requested || scheduled {
                let mut record = Collection {
                    basis,
                    request_id: request["request_id"].clone(),
                    attempted_at: now(),
                    run: run.clone(),
                    state: "unavailable".into(),
                    diagnostic: None,
                    inventory: None,
                };
                // Invalidate old evidence before attempting another collection.
                save(&path(root, rule_name, agent), &record)?;
                let result = async {
                    let run = run
                        .as_ref()
                        .ok_or("no current owned running guest; stopped agents stay stopped")?;
                    authorize(root, runtime, &config, run)?;
                    let observed = crate::host_runs::observe(agent).await;
                    if observed["run_id"] != run.run_id || observed["exec"] != true {
                        return Err::<Inventory, Error>(
                            "current guest execution is unavailable; inspect agent diagnostics"
                                .into(),
                        );
                    }
                    let output = crate::host_platform::guest_command_output_bounded(
                        agent,
                        COMMAND,
                        Duration::from_secs(collection.timeout_seconds),
                        collection.max_output_bytes,
                        &mut || authorize(root, runtime, &config, run),
                    )
                    .await?;
                    let inventory = parse_output(&output, run, record.attempted_at)?;
                    let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
                    authorize(root, runtime, &config, run)?;
                    Ok(inventory)
                }
                .await;
                match result {
                    Ok(inventory) => {
                        record.state = "complete".into();
                        record.inventory = Some(inventory);
                    }
                    Err(error) => record.diagnostic = Some(error.to_string()),
                }
                // Recheck at publication, including a stop/replacement after capture.
                let _lock = crate::approvals::lock_policy(&root.join("policy.toml"))?;
                if let Some(run) = &run
                    && let Err(error) = authorize(root, runtime, &config, run)
                {
                    record.state = "unavailable".into();
                    record.inventory = None;
                    record.diagnostic = Some(error.to_string());
                }
                save(&path(root, rule_name, agent), &record)?;
                if let Some(interval) = collection.interval_seconds {
                    due = due.min(record.attempted_at.saturating_add(interval));
                }
            } else if let Some(next) = next {
                due = due.min(next);
            }
        }
    }
    Ok(due)
}

fn parse_output(output: &Value, run: &AgentRun, at: u64) -> Result<Inventory, Error> {
    if output["state"] != "completed"
        || output["exit_code"] != 0
        || output["stdout_truncated"] != false
        || output["stderr_truncated"] != false
        || output["stderr"].as_str() != Some("")
    {
        return Err("guest package collection failed, timed out or returned incomplete output; no complete inventory was published".into());
    }
    let output = output["stdout"]
        .as_str()
        .ok_or("guest inventory output unavailable")?;
    let (release, packages) = output
        .split_once("\nSAFEYOLO_PACKAGES\n")
        .ok_or("guest distribution evidence is incomplete")?;
    let field = |name: &str| {
        release
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(|value| value.trim_matches(['\'', '"']))
    };
    if field("ID") != Some("debian") {
        return Err(
            "guest distribution is unsupported; only Debian package assessment is implemented"
                .into(),
        );
    }
    let codename = field("VERSION_CODENAME")
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .ok_or("guest Debian distribution codename unavailable")?;
    let packages = packages
        .strip_suffix("SAFEYOLO_INVENTORY_END\n")
        .ok_or("guest package inventory is incomplete")?;
    let mut inventory = Inventory {
        agent_id: run.agent_id.clone(),
        run_id: run.run_id.clone(),
        observed_at: at,
        distribution: format!("debian:{codename}"),
        packages: BTreeMap::new(),
        services: vec![],
    };
    for row in packages.lines() {
        let fields = row.split('\t').collect::<Vec<_>>();
        let [status, package, version] = fields.as_slice() else {
            return Err("malformed guest package row".into());
        };
        match *status {
            "installed" => {}
            "not-installed" | "config-files" => continue,
            _ => {
                return Err(format!(
                    "guest package {package} has transitional or unknown dpkg state {status}; complete package assessment is unavailable"
                )
                .into());
            }
        }
        if package.is_empty()
            || !package.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'+' | b'-' | b'.' | b':')
            })
            || !responses::valid_debian_version(version)
            || inventory
                .packages
                .insert((*package).into(), (*version).into())
                .is_some()
        {
            return Err("malformed or duplicate installed package evidence".into());
        }
    }
    if inventory.packages.is_empty() {
        return Err("Debian package inventory is empty; collection is unverified".into());
    }
    Ok(inventory)
}

pub(super) fn fresh(
    inventory: &Inventory,
    rule: &responses::Rule,
    agent: &str,
    policy: &Policy,
) -> bool {
    policy
        .agent_run(agent)
        .is_some_and(|run| run.agent_id == inventory.agent_id && run.run_id == inventory.run_id)
        && inventory.observed_at <= now()
        && rule
            .inventory_max_age_seconds
            .is_some_and(|age| now() - inventory.observed_at < age)
}
pub(super) fn status(
    root: &Path,
    name: &str,
    rule: &responses::Rule,
    agent: &str,
    policy: Option<&Policy>,
) -> Result<Value, Error> {
    let Some(record) = read(root, name, agent)? else {
        return Ok(json!({"state":"not_assessed","fresh":false}));
    };
    let fresh = policy.map(|policy| {
        record
            .inventory
            .as_ref()
            .is_some_and(|inventory| fresh(inventory, rule, agent, policy))
    });
    Ok(
        json!({"state":record.state,"fresh":fresh,"attempted_at":record.attempted_at,
        "run":record.run,"request_id":record.request_id,"diagnostic":record.diagnostic,
        "distribution":record.inventory.as_ref().map(|inventory| &inventory.distribution),
        "package_count":record.inventory.as_ref().map(|inventory| inventory.packages.len()),
        "next_action":match fresh {Some(true)=>"Read the advisory response; inventory alone does not establish repair or running-code adoption.",Some(false)=>"Inspect agent diagnostics and collection status, then request signals assess for this rule after resolving the unmet evidence need.",None=>"Read the selection observation time and current runtime separately; this status read does not collect guest state."}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> AgentRun {
        AgentRun {
            agent: "alice".into(),
            agent_id: "ag-11111111111111111111111111111111".into(),
            run_id: "11111111111111111111111111111111".into(),
        }
    }
    fn output() -> Value {
        json!({"state":"completed","exit_code":0,"stdout_truncated":false,"stderr_truncated":false,"stderr":"",
            "stdout":"ID=debian\nVERSION_CODENAME=\"trixie\"\n\nSAFEYOLO_PACKAGES\ninstalled\tcurl\t8.0-1\nconfig-files\tremoved\t1.0\ninstalled\tlibc6:arm64\t2.41-1\nSAFEYOLO_INVENTORY_END\n"})
    }
    #[test]
    fn complete_inventory_keeps_effective_versions_and_excludes_removed_packages() {
        let inventory = parse_output(&output(), &run(), 123).unwrap();
        assert_eq!(inventory.distribution, "debian:trixie");
        assert_eq!(inventory.packages.len(), 2);
        assert_eq!(inventory.packages["curl"], "8.0-1");
        assert_eq!(inventory.packages["libc6:arm64"], "2.41-1");
        assert_eq!(inventory.run_id, run().run_id);
        assert_eq!(inventory.observed_at, 123);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mixed_dpkg_states_preserve_uncertainty_through_advisory_assessment() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let run = run();
        let _backend =
            super::super::test_runs::agent_run(root, &run.agent, &run.agent_id, &run.run_id);
        fs::write(
            root.join("policy.toml"),
            format!(
                "[agents.alice]\nagent_id='{}'\n[hosts.'*']\negress='deny'\n",
                run.agent_id
            ),
        )
        .unwrap();
        let proxy_config: crate::Config = serde_json::from_value(json!({
            "native_product":true,"policy_file":root.join("policy.toml"),"data_dir":root.join("data"),
            "listeners":[],"admin_port":0,"readiness_file":root.join("ready"),
            "audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"circuit_breaker_enabled":false
        })).unwrap();
        let proxy = crate::Proxy::start(proxy_config).await.unwrap();
        let mut source = super::super::tests::source();
        source.list = None;
        source.follow = false;
        let config: Configuration = serde_json::from_value(json!({"sources":{"test":source},"rules":{"packages":{
            "source":"test","agents":["alice"],"min_severity":7,"authority":"approval","on_stale":"retain","on_inactive":"retain",
            "inventory_max_age_seconds":60,"guest_inventory":{"timeout_seconds":1,"max_output_bytes":1024},
            "response":{"kind":"notify","room":"maintenance","recipients":[run.agent_id]}
        }}})).unwrap();
        fs::write(root.join("signals.toml"), toml::to_string(&config).unwrap()).unwrap();
        let finding = Update {
            source_id: source.source_id.clone(),
            id: "advisories.curl".into(),
            revision: 1,
            observed_at: now() - 1,
            expires_at: now() + 3600,
            withdrawn: false,
            evidence_refs: vec![],
            evidence: Evidence::Advisory {
                distribution: Some("debian:trixie".into()),
                severity: 9.,
                subject: Subject::Package {
                    name: "curl".into(),
                    distribution: "debian:trixie".into(),
                    fixed_version: Some("8.0-2".into()),
                },
            },
        };
        save(
            &accepted_path(root, "test", &finding.id),
            &Accepted {
                source_digest: digest(&source),
                update: finding,
            },
        )
        .unwrap();
        for status in [
            "unpacked",
            "half-configured",
            "half-installed",
            "triggers-awaited",
            "triggers-pending",
            "unknown",
            "not-installed",
            "config-files",
            "installed",
        ] {
            let mut capture = output();
            capture["stdout"] = json!(
                capture["stdout"]
                    .as_str()
                    .unwrap()
                    .replace("installed\tcurl", &format!("{status}\tcurl"))
            );
            let result = parse_output(&capture, &run, now());
            let record = Collection {
                basis: digest(&config.rules["packages"]),
                request_id: Value::Null,
                attempted_at: now(),
                run: Some(run.clone()),
                state: if result.is_ok() {
                    "complete"
                } else {
                    "unavailable"
                }
                .into(),
                diagnostic: result.as_ref().err().map(ToString::to_string),
                inventory: result.ok(),
            };
            save(&path(root, "packages", "alice"), &record).unwrap();
            responses::reconcile(root.into(), proxy.runtime.clone(), Value::Null)
                .await
                .unwrap();
            let selection = &responses::status(root).unwrap()[0]["selection"];
            let expected = match status {
                "installed" => "affected",
                "not-installed" | "config-files" => "unaffected",
                _ => "unknown_or_stale",
            };
            assert_eq!(
                selection["applicability"], expected,
                "{status}: {selection}"
            );
            if expected == "unknown_or_stale" {
                assert_eq!(selection["inventory"]["state"], "unavailable");
                assert!(
                    selection["inventory"]["diagnostic"]
                        .as_str()
                        .unwrap()
                        .contains(status)
                );
            }
        }
        proxy.shutdown().await;
    }
    #[test]
    fn failed_truncated_unsupported_and_partial_inventory_never_becomes_complete() {
        for (field, value) in [
            ("state", json!("timed_out")),
            ("exit_code", json!(7)),
            ("stdout_truncated", json!(true)),
            ("stderr_truncated", json!(true)),
            ("stderr", json!("read error")),
        ] {
            let mut value_ = output();
            value_[field] = value;
            assert!(parse_output(&value_, &run(), 123).is_err(), "{field}");
        }
        for text in [
            output()["stdout"]
                .as_str()
                .unwrap()
                .replace("SAFEYOLO_INVENTORY_END\n", ""),
            output()["stdout"]
                .as_str()
                .unwrap()
                .replace("ID=debian", "ID=alpine"),
            output()["stdout"]
                .as_str()
                .unwrap()
                .replace("8.0-1", "not-a-version"),
            "ID=debian\nVERSION_CODENAME=trixie\n\nSAFEYOLO_PACKAGES\nSAFEYOLO_INVENTORY_END\n"
                .into(),
        ] {
            let mut value = output();
            value["stdout"] = json!(text);
            assert!(parse_output(&value, &run(), 123).is_err());
        }
    }
    #[tokio::test]
    async fn manual_requests_and_intervals_use_the_control_pass_without_starting_stopped_agents() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("policy.toml"),"[agents.alice]\nagent_id='ag-11111111111111111111111111111111'\n[hosts.'*']\negress='deny'\n").unwrap();
        let proxy_config:crate::Config=serde_json::from_value(json!({"native_product":true,"policy_file":root.join("policy.toml"),"data_dir":root.join("data"),"listeners":[],"admin_port":0,"readiness_file":root.join("ready"),"audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"circuit_breaker_enabled":false})).unwrap();
        let proxy = crate::Proxy::start(proxy_config).await.unwrap();
        let mut source = super::super::tests::source();
        source.list = None;
        source.follow = false;
        let mut config:Configuration=serde_json::from_value(json!({"sources":{"test":source},"rules":{"packages":{
            "source":"test","agents":["alice"],"min_severity":7,"authority":"standing","on_stale":"retain","on_inactive":"release","inventory_max_age_seconds":60,
            "guest_inventory":{"timeout_seconds":1,"max_output_bytes":1024},"response":{"kind":"notify","room":"maintenance","recipients":[run().agent_id]}}}})).unwrap();
        fs::write(root.join("signals.toml"), toml::to_string(&config).unwrap()).unwrap();
        let mut follow = Follow::default();
        follow
            .poll(root.into(), proxy.runtime.clone(), Value::Null)
            .await
            .unwrap();
        follow.response.take().unwrap().await.unwrap().unwrap();
        assert!(
            read(root, "packages", "alice").unwrap().is_none(),
            "manual-only adoption collects only on explicit request"
        );
        command(root, &["assess".into(), "packages".into()])
            .await
            .unwrap();
        assert_eq!(
            super::super::status(root).unwrap()["responses"][0]["assessment_pending"],
            true
        );
        follow
            .poll(root.into(), proxy.runtime.clone(), Value::Null)
            .await
            .unwrap();
        follow.response.take().unwrap().await.unwrap().unwrap();
        let first = read(root, "packages", "alice").unwrap().unwrap();
        assert_eq!(
            super::super::status(root).unwrap()["responses"][0]["assessment_pending"],
            false
        );
        assert_eq!(first.state, "unavailable");
        assert!(first.inventory.is_none());
        assert!(
            first
                .diagnostic
                .unwrap()
                .contains("stopped agents stay stopped")
        );
        assert!(!root.join("agents/alice/runtime.json").exists());
        assert_eq!(collect_due(root, &proxy.runtime).await.unwrap(), u64::MAX);
        assert_eq!(
            read(root, "packages", "alice")
                .unwrap()
                .unwrap()
                .attempted_at,
            first.attempted_at
        );
        config
            .rules
            .get_mut("packages")
            .unwrap()
            .guest_inventory
            .as_mut()
            .unwrap()
            .interval_seconds = Some(5);
        fs::write(root.join("signals.toml"), toml::to_string(&config).unwrap()).unwrap();
        let next = collect_due(root, &proxy.runtime).await.unwrap();
        assert!(next >= now() && next <= now() + 5);
        let mut prior = read(root, "packages", "alice").unwrap().unwrap();
        prior.attempted_at = now() - 10;
        save(&path(root, "packages", "alice"), &prior).unwrap();
        collect_due(root, &proxy.runtime).await.unwrap();
        assert!(
            read(root, "packages", "alice")
                .unwrap()
                .unwrap()
                .attempted_at
                > prior.attempted_at
        );
        assert!(!root.join("agents/alice/runtime.json").exists());
        config.rules.clear();
        fs::write(root.join("signals.toml"), toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(collect_due(root, &proxy.runtime).await.unwrap(), u64::MAX);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn command_and_bounded_capture_read_real_debian_package_state() {
        // Exercises the collector inside this Debian test environment. The
        // installed acceptance separately exercises target-guest transport.
        let child = tokio::process::Command::new("/bin/sh")
            .args(["-c", COMMAND])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = crate::host_platform::wait_guest_command_output_bounded(
            child,
            Duration::from_secs(30),
            1024 * 1024,
        )
        .await
        .unwrap();
        let inventory = parse_output(&output, &run(), now()).unwrap();
        assert!(inventory.packages.contains_key("dpkg"));
        assert!(inventory.packages.contains_key("base-files"));
        let actual = std::process::Command::new("/usr/bin/dpkg-query")
            .args(["-W", "-f=${Version}", "dpkg"])
            .output()
            .unwrap();
        assert!(actual.status.success());
        assert_eq!(
            inventory.packages["dpkg"],
            String::from_utf8(actual.stdout).unwrap()
        );
    }
}
