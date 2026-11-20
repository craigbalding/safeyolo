//! Operator-owned support authority for explicit durable peers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Policy, Result, delegation::Agent, invalid};

pub(crate) mod diagnostics;

#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Lifecycle {
    StartSandbox,
    StartHarness,
    RestartHarness,
    StopSandbox,
    RestartSandbox,
}

#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Notification {
    LaunchFailed,
    SandboxAvailability,
    ControlAvailability,
    SandboxRecovered,
    CommandExit,
    CommandRestart,
    CommandFailed,
    SupervisorExit,
    SupervisorRestart,
    NeedsOperator,
    ObservationHealth,
}

#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryDirection {
    pub factory: String,
    pub snapshot_id: String,
    pub types: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(extend("x-scope" = "Explicit durable support and target identities in the owning instance", "x-lifetime" = "Optional expiry; acknowledgment and current identities/trust required", "x-effects" = "Permit inspection and selected guest administration, logs, lifecycle, notices and factory directions. Guest administration reaches target-accessible credentials, mounts and delegations.", "x-dependencies" = "Operator-owned support preview/apply; live target and control for guest execution; current peer trust for remote support", "x-gaps" = "Static validation does not verify identities, trust, runtime or grant acknowledgment."))]
pub(crate) struct Grant {
    pub instance_id: String,
    pub support: Agent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_peer_epoch: Option<i64>,
    pub targets: Vec<Agent>,
    pub guest_admin: bool,
    /// Exact guest paths selected by the operator. Execution uses the guest
    /// transport; it never follows guest-controlled links on the host.
    pub guest_logs: Vec<String>,
    pub lifecycle: Vec<Lifecycle>,
    #[serde(default)]
    pub notifications: Vec<Notification>,
    #[serde(default)]
    pub signal_rooms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factory_directions: Vec<FactoryDirection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<diagnostics::Scope>,
    pub expires_at: Option<String>,
    pub acknowledgment: Option<String>,
}

impl Grant {
    pub(crate) fn revision(&self) -> String {
        let mut value = json!(self);
        value
            .as_object_mut()
            .expect("grant")
            .shift_remove("acknowledgment");
        crate::approvals::pending::digest(&value)
    }

    pub(crate) fn active(&self) -> bool {
        !super::delegation::expired(self.expires_at.as_deref())
            && self.acknowledgment.as_deref() == Some(self.revision().as_str())
    }

    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut warnings = vec!["Revocation, narrowing and expiry prevent newly unauthorized operations. Admitted commands may continue; disclosed data and file or external changes cannot be undone.".into()];
        if self.guest_admin {
            warnings.push("Guest administration of both producer and reviewer is common administrative control. Configured actor checks still apply, but the reviewer is not independent of this manager. Keep a required independent decider outside the manager's administration.".into());
            warnings.push("Guest administration permits arbitrary guest commands, including existing passwordless guest sudo, all target-accessible files, writable mounts, credentials, network and services, Agent API permissions and existing delegations. Authority can reach other peers and approval decisions through the target. Standing grants follow capabilities later given to the target. Direct target checks do not confine this indirect reach.".into());
            warnings.push("The authority report shows typed upstream and downstream reach within the selected owner inventory and authorized disclosure. Inspect its supporting paths and unknown frontier. Partial evidence cannot establish reviewer independence.".into());
        }
        if !self.guest_logs.is_empty() {
            warnings.push("Selected log paths are read inside the guest. Guest links may lead to any target-accessible data, including shared mounts and credentials. This permission is broader than host-observed inspection.".into());
        }
        warnings
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.instance_id.is_empty() || (self.targets.is_empty() && self.diagnostics.is_none()) {
            return Err(invalid(
                "support grant needs an owning instance and explicit targets",
            ));
        }
        if let Some(scope) = &self.diagnostics {
            scope.validate()?;
            if self.support_instance_id.is_some()
                || self.guest_admin
                || !self.guest_logs.is_empty()
                || !self.lifecycle.is_empty()
                || !self.notifications.is_empty()
                || !self.signal_rooms.is_empty()
                || !self.factory_directions.is_empty()
            {
                return Err(invalid(
                    "diagnostic disclosure selects local read-only sources separately from support actions",
                ));
            }
            if scope
                .runs
                .keys()
                .any(|id| !self.targets.iter().any(|target| &target.agent_id == id))
            {
                return Err(invalid(
                    "diagnostic run selection needs an explicit durable subject",
                ));
            }
        }
        let mut targets = BTreeSet::new();
        for agent in std::iter::once(&self.support).chain(&self.targets) {
            if !crate::host_platform::valid_agent_name(&agent.name)
                || !crate::desktop_present::valid_agent_id(&agent.agent_id)
            {
                return Err(invalid(
                    "support grant needs valid durable agent identities",
                ));
            }
        }
        for agent in &self.targets {
            if !targets.insert(&agent.agent_id) {
                return Err(invalid("support targets must be distinct"));
            }
        }
        if self.lifecycle.iter().collect::<BTreeSet<_>>().len() != self.lifecycle.len() {
            return Err(invalid("support lifecycle actions must be distinct"));
        }
        for selected in &self.factory_directions {
            if !crate::coord_supervisor::simple_name(&selected.factory)
                || selected.snapshot_id.len() != 64
                || !selected.snapshot_id.bytes().all(|b| b.is_ascii_hexdigit())
                || selected.types.is_empty()
                || selected
                    .types
                    .iter()
                    .any(|kind| !crate::coord_supervisor::type_name(kind))
            {
                return Err(invalid(
                    "factory direction requires a factory, exact approved snapshot and explicit direction types",
                ));
            }
        }
        if self.notifications.contains(&Notification::NeedsOperator) && self.signal_rooms.is_empty()
        {
            return Err(invalid(
                "needs_operator notices require explicit signal_rooms disclosure",
            ));
        }
        if self
            .guest_logs
            .iter()
            .any(|path| !path.starts_with('/') || path.contains('\0') || path.len() >= 4096)
        {
            return Err(invalid(
                "guest log paths must be absolute and fit the Linux guest's 4096-byte path limit including NUL",
            ));
        }
        if self
            .expires_at
            .as_deref()
            .is_some_and(|expiry| super::parse_expiry(expiry).is_none())
        {
            return Err(invalid(
                "support expiry must be an RFC 3339 timestamp or null for standing authority",
            ));
        }
        Ok(())
    }
}

pub(crate) fn parse(document: &Value) -> Result<BTreeMap<String, Grant>> {
    let mut grants = BTreeMap::new();
    if let Some(values) = document.get("support_grants") {
        for (name, value) in super::object(values, "support_grants")? {
            if !crate::host_platform::valid_agent_name(name) {
                return Err(invalid("invalid support grant name"));
            }
            let grant: Grant = serde_json::from_str(value.as_str().ok_or_else(|| {
                invalid("support grants must contain the acknowledged JSON preview")
            })?)
            .map_err(|error| invalid(format!("support_grants.{name}: {error}")))?;
            grant.validate()?;
            if grant.acknowledgment.as_deref() != Some(grant.revision().as_str()) {
                return Err(invalid(
                    "acknowledge the exact support preview before apply",
                ));
            }
            // Identity replacement invalidates existing grants at use time. It
            // must not make the rest of the operator's policy unloadable.
            grants.insert(name.clone(), grant);
        }
    }
    Ok(grants)
}

impl Policy {
    pub(crate) fn support_grants(&self) -> BTreeMap<String, Grant> {
        self.native
            .as_ref()
            .and_then(|native| parse(&native.authored).ok())
            .unwrap_or_default()
    }
}
