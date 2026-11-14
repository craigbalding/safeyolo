//! Operator-approved native work policy. Roles resolve to configured durable IDs.
use super::*;
use crate::coord_rooms::work::subjects::Principal;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub name: String,
    pub snapshot_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
    pub reviewer: String,
    pub criterion: String,
    #[serde(default)]
    pub independent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    #[serde(default)]
    pub creators: Vec<String>,
    #[serde(default)]
    pub authorities: Vec<String>,
    pub deciders: Vec<String>,
    #[serde(default)]
    pub independent: bool,
    #[serde(default)]
    pub checks: Vec<Check>,
}

impl Policy {
    pub(super) fn validate(&self, snapshot: &Snapshot) -> Result<(), Error> {
        for roles in [&self.creators, &self.authorities, &self.deciders] {
            let mut seen = BTreeSet::new();
            if roles
                .iter()
                .any(|r| !snapshot.roles.contains_key(r) || !seen.insert(r))
            {
                return Err("Factory work participants must name distinct declared roles".into());
            }
        }
        if self.deciders.is_empty() {
            return Err("Factory work policy must name an acceptance decider".into());
        }
        for check in &self.checks {
            if !snapshot.roles.contains_key(&check.reviewer)
                || check.criterion.trim().is_empty()
                || check.criterion.len() > 1024
            {
                return Err("Factory work check requires a declared reviewer role and a criterion of 1..1024 UTF-8 bytes".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SelectedCheck {
    pub reviewer: Principal,
    pub criterion: String,
    pub independent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Selection {
    pub reference: Reference,
    pub checks: Vec<SelectedCheck>,
    pub current_checks: Vec<String>,
}

pub(crate) struct Resolved {
    pub room: String,
    pub creators: Vec<Principal>,
    pub authorities: Vec<Principal>,
    pub deciders: Vec<Principal>,
    pub independent: bool,
    pub selection: Selection,
}

pub(crate) fn resolve(
    root: &Path,
    policy_file: &Path,
    reference: &Reference,
) -> Result<Resolved, Error> {
    let (snapshot, _) = approved(root, &reference.name)?;
    if snapshot.id()? != reference.snapshot_id {
        return Err("Factory work requires the currently approved snapshot".into());
    }
    let selected = snapshot
        .work
        .as_ref()
        .ok_or("Factory has no native work policy")?;
    let policy = crate::policy::Policy::from_native_path(policy_file)?;
    let principal = |role: &str| -> Result<Principal, Error> {
        let agent = &snapshot
            .roles
            .get(role)
            .ok_or("Factory role is missing")?
            .agent;
        let id = policy
            .evidence_agent_id(agent)
            .ok_or("Factory role lacks a unique configured durable agent ID")?;
        Ok(Principal {
            kind: "agent".into(),
            id: id.into(),
        })
    };
    let participants = |roles: &[String]| {
        roles
            .iter()
            .map(|r| principal(r))
            .collect::<Result<Vec<_>, Error>>()
    };
    let checks = selected
        .checks
        .iter()
        .map(|c| {
            Ok(SelectedCheck {
                reviewer: principal(&c.reviewer)?,
                criterion: c.criterion.clone(),
                independent: c.independent,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Resolved {
        room: snapshot.room.clone(),
        creators: participants(&selected.creators)?,
        authorities: participants(&selected.authorities)?,
        deciders: participants(&selected.deciders)?,
        independent: selected.independent,
        selection: Selection {
            reference: reference.clone(),
            checks,
            current_checks: vec![],
        },
    })
}

/// Capture the approved selection before an automatic admission starts.
pub(crate) fn current_reference(root: &Path, name: &str) -> Result<Reference, Error> {
    let (snapshot, _) = approved(root, name)?;
    Ok(Reference {
        name: name.into(),
        snapshot_id: snapshot.id()?,
    })
}
