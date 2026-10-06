//! Selected peer reads belong to the existing operator-owned agent policy.

use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Policy, Result, invalid};

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Read {
    Diagnostic,
    Approval,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRead {
    reader_id: String,
    agent: String,
    agent_id: String,
    request_id: String,
    reads: Vec<Read>,
}

pub(crate) fn validate_reads(value: Option<&Value>) -> Result<()> {
    if let Some(value) = value {
        let reads: Vec<EvidenceRead> = serde_json::from_value(value.clone())
            .map_err(|_| invalid("evidence_reads must contain selected reader/agent identities, request_id and reads"))?;
        for read in reads {
            if read.reader_id.is_empty()
                || read.agent.is_empty()
                || read.agent_id.is_empty()
                || !crate::agent_api::valid_request_id(&read.request_id)
                || read.reads.is_empty()
            {
                return Err(invalid(
                    "evidence_reads requires identities, a request ID and at least one read",
                ));
            }
        }
    }
    Ok(())
}

impl Policy {
    pub(crate) fn evidence_agent_id(&self, name: &str) -> Option<&str> {
        self.native
            .as_ref()?
            .authored
            .get("agents")?
            .get(name)?
            .get("agent_id")?
            .as_str()
            .filter(|id| !id.is_empty())
    }

    pub(crate) fn evidence_reader(
        &self,
        caller: &str,
        request_id: &str,
        read: Read,
    ) -> Option<String> {
        let caller_id = self.evidence_agent_id(caller)?;
        let configured = self
            .native
            .as_ref()?
            .authored
            .get("agents")?
            .get(caller)?
            .get("evidence_reads")?;
        let grants: Vec<EvidenceRead> = serde_json::from_value(configured.clone()).ok()?;
        grants
            .into_iter()
            .find(|grant| {
                grant.reader_id == caller_id
                    && grant.request_id == request_id
                    && grant.reads.contains(&read)
                    && self.evidence_agent_id(&grant.agent) == Some(grant.agent_id.as_str())
            })
            .map(|grant| grant.agent)
    }

    /// Hash the full compiled network permissions, including named-list inputs
    /// and the active task. The historical display hash loses host names and
    /// therefore cannot establish that a prepared action is still current.
    pub(crate) fn network_action_revision(&self, agent: &str) -> Option<String> {
        let native = self.native.as_ref()?;
        let network = |baseline: &super::Baseline| {
            let permissions: Vec<&Value> = baseline.value["permissions"]
                .as_array()?
                .iter()
                .filter(|permission| {
                    permission["action"]
                        .as_str()
                        .is_some_and(|action| super::glob("network:request", action))
                        && permission
                            .pointer("/condition/agent")
                            .and_then(Value::as_str)
                            .is_none_or(|pattern| super::glob(agent, pattern))
                })
                .collect();
            Some(
                json!({"permissions":permissions,"budgets":baseline.value["budgets"],
                "domains":baseline.value["domains"],"clients":baseline.value["clients"]}),
            )
        };
        let mut value = json!({"baseline":network(self.baseline.as_ref()?)?,
            "global_budget":self.global_budget,
            "task":self.task.as_ref().and_then(|task| network(&task.baseline)),
            "controls":native.controls.network});
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&value).ok()?);
        crate::credentials::wipe_json(&mut value);
        Some(
            digest(&SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }
}
