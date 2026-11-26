//! Execute adopted guest maintenance through the existing bounded guest transport.
use super::*;
use crate::{RuntimeState, host_runs::AgentRun};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Procedure {
    checkpoint_command: String,
    patch_command: String,
    restart_command: Option<String>,
    health_command: String,
    recover_command: String,
    timeout_seconds: u64,
    max_output_bytes: usize,
    /// Empty means any hour; otherwise effects wait for these UTC hours.
    #[serde(default)]
    utc_hours: Vec<u8>,
}

impl Procedure {
    pub(super) fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        for command in [
            &self.checkpoint_command,
            &self.patch_command,
            &self.health_command,
            &self.recover_command,
        ]
        .into_iter()
        .chain(self.restart_command.iter())
        {
            if command.trim().is_empty() || command.len() > 16384 || command.contains('\0') {
                return Err("maintenance needs explicit guest checkpoint, patch, health and recovery commands of 1..16384 bytes".into());
            }
        }
        if self.timeout_seconds == 0
            || std::time::Instant::now()
                .checked_add(Duration::from_secs(self.timeout_seconds))
                .is_none()
            || self.max_output_bytes == 0
            || self.max_output_bytes > 1024 * 1024
            || self.utc_hours.iter().any(|hour| *hour > 23)
        {
            return Err("maintenance needs a supported positive timeout, output bound 1..1048576 and UTC hours 0..23".into());
        }
        Ok(())
    }
    pub(super) fn due(&self) -> bool {
        self.utc_hours.is_empty()
            || self
                .utc_hours
                .contains(&time::OffsetDateTime::now_utc().hour())
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn request(
    procedure: &Procedure,
    selected: &[Update],
    operation: &str,
) -> Result<Value, Error> {
    let mut requirements = Vec::new();
    for update in selected {
        let Evidence::Advisory {
            subject:
                Subject::Package {
                    name,
                    distribution,
                    fixed_version: Some(version),
                },
            ..
        } = &update.evidence
        else {
            return Err("maintenance needs an applicable Debian package advisory with an available fixed version; no effect was requested".into());
        };
        if !distribution.starts_with("debian:") {
            return Err("automatic maintenance supports Debian package requirements; select the distribution's explicit update path".into());
        }
        requirements.push(
            json!({"package":name,"version":version,"distribution":distribution,
            "advisory":format!("{}/{}",update.source_id,update.id)}),
        );
    }
    Ok(json!({"operation_id":operation,"requirements":requirements,
        "checkpoint_command":procedure.checkpoint_command,"patch_command":procedure.patch_command,
        "restart_command":procedure.restart_command,"health_command":procedure.health_command,
        "recover_command":procedure.recover_command}))
}

pub(super) async fn execute(
    root: &Path,
    runtime: &RuntimeState,
    config: &Configuration,
    agent: &str,
    procedure: &Procedure,
    request: &Value,
    prepared: &mut Value,
) -> Result<(&'static str, Value), Error> {
    let run = runtime
        .read()
        .map_err(|_| "maintenance runtime unavailable")?
        .policy
        .as_ref()
        .and_then(|policy| policy.agent_run(agent))
        .ok_or("maintenance needs a current owned running guest; stopped agents stay stopped")?;
    let authorize = || authorize(root, runtime, config, &run);
    authorize()?;
    let observed = crate::host_runs::observe(agent).await;
    if observed["run_id"] != run.run_id || observed["exec"] != true {
        return Err(
            "maintenance guest execution is unavailable; inspect this agent's diagnostics".into(),
        );
    }
    // Save exact inputs before the first external effect. A repeated helper
    // request reads this operation's result; it never executes the recipe twice.
    *prepared = json!({"request":request,"run":run});
    let command = format!(
        "printf '%s' {} | sudo -n /safeyolo/safeyolo-guest retained-state maintain",
        quote(&serde_json::to_string(request)?)
    );
    let output = crate::host_platform::guest_command_output_bounded(
        agent,
        &command,
        Duration::from_secs(procedure.timeout_seconds),
        procedure.max_output_bytes,
        &mut || authorize(),
    )
    .await?;
    authorize()?;
    if output["state"] != "completed"
        || output["exit_code"] != 0
        || output["stdout_truncated"] != false
        || output["stderr_truncated"] != false
    {
        return Err("maintenance reply is incomplete; inspect the original guest maintenance-status operation before any retry".into());
    }
    let receipt: Value = serde_json::from_str(
        output["stdout"]
            .as_str()
            .ok_or("maintenance receipt missing")?,
    )?;
    if receipt["operation_id"] != request["operation_id"] {
        return Err("maintenance receipt does not match the selected operation".into());
    }
    let status = match (receipt["phase"].as_str(), receipt["outcome"].as_str()) {
        (Some("complete"), Some("verified")) => "verified",
        (Some("complete"), Some("pending_restart")) => "pending_restart",
        (Some("complete"), Some("recovered")) => "recovered",
        (Some("complete"), Some("failed" | "recovery_failed")) => "failed",
        _ => "uncertain",
    };
    Ok((
        status,
        json!({"effect":"guest_maintenance","agent":agent,"run":run,"receipt":receipt,
        "next_action":match status {
            "verified"=>"The observed guest satisfies its adopted package requirements and health check. Read coverage before claiming wider maintenance.",
            "pending_restart"=>"Old package files remain mapped by continuing processes. Restart the identified services or explicitly recreate this guest under the adopted interruption policy; a new base selection alone is insufficient.",
            "recovered"=>"The previous package and covered-file state was restored and its health check passed. Remediation remains required; inspect the failed update before selecting another attempt.",
            _=>"Inspect the retained guest maintenance receipt, private logs and reached effective state before selecting recovery or another attempt. Transport completion alone does not establish repair."
        }}),
    ))
}

fn authorize(
    root: &Path,
    runtime: &RuntimeState,
    config: &Configuration,
    run: &AgentRun,
) -> Result<(), Error> {
    if digest(&configuration(root)?) != digest(config)
        || runtime
            .read()
            .map_err(|_| "maintenance runtime unavailable")?
            .policy
            .as_ref()
            .is_none_or(|policy| !run.current(policy))
    {
        return Err("maintenance policy, target identity or running guest changed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn procedure() -> Procedure {
        serde_json::from_value(json!({"checkpoint_command":"checkpoint-guest",
            "patch_command":"safeyolo-guest-state restore --apply","restart_command":null,
            "health_command":"check-running-service","recover_command":"restore-checkpoint",
            "timeout_seconds":60,"max_output_bytes":65536}))
        .unwrap()
    }
    #[test]
    fn adopted_procedure_carries_exact_effects_and_separate_advisory_requirement() {
        let mut update = Update {
            source_id: "debian".into(),
            id: "advisory".into(),
            revision: 1,
            observed_at: now(),
            expires_at: now() + 100,
            withdrawn: false,
            evidence_refs: vec![],
            evidence: Evidence::Advisory {
                distribution: Some("debian:trixie".into()),
                severity: 7.,
                subject: Subject::Package {
                    name: "curl".into(),
                    distribution: "debian:trixie".into(),
                    fixed_version: Some("8.0-2".into()),
                },
            },
        };
        let procedure = procedure();
        procedure.validate().unwrap();
        let request = request(&procedure, &[update.clone()], "req-example").unwrap();
        assert_eq!(
            request["requirements"][0],
            json!({"package":"curl","version":"8.0-2",
            "distribution":"debian:trixie","advisory":"debian/advisory"})
        );
        assert_eq!(
            request["patch_command"],
            "safeyolo-guest-state restore --apply"
        );
        if let Evidence::Advisory {
            subject: Subject::Package { fixed_version, .. },
            ..
        } = &mut update.evidence
        {
            *fixed_version = None;
        }
        assert!(super::request(&procedure, &[update], "req-no-fix").is_err());
    }
    #[test]
    fn timing_and_transport_limits_are_explicit() {
        let mut procedure = procedure();
        assert!(procedure.due());
        procedure.utc_hours = vec![(time::OffsetDateTime::now_utc().hour() + 1) % 24];
        assert!(!procedure.due());
        procedure.utc_hours = vec![24];
        assert!(procedure.validate().is_err());
        procedure.utc_hours.clear();
        procedure.timeout_seconds = 0;
        assert!(procedure.validate().is_err());
        assert_eq!(quote("one'$(two)"), "'one'\\''$(two)'");
    }
}
