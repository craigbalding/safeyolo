//! Reconcile adopted responses through the existing list, approval and Work owners.
use super::*;
use crate::{
    RuntimeState,
    approvals::{self, pending},
    policy::Policy,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rule {
    source: String,
    pub(super) agents: Vec<String>,
    min_severity: f64,
    distribution: Option<String>,
    authority: Authority,
    on_stale: Inactive,
    on_inactive: Inactive,
    response: Response,
    /// Optional effective-state record written by an adopted inventory check.
    pub(super) inventory: Option<PathBuf>,
    pub(super) inventory_max_age_seconds: Option<u64>,
    /// Explicit adoption of collection from the current running Debian guest.
    pub(super) guest_inventory: Option<guest_inventory::CollectionPolicy>,
    #[serde(default)]
    startup_before_work: bool,
}
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Authority {
    Standing,
    Approval,
}
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Inactive {
    Retain,
    Release,
    Respond,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    /// Explicitly adopted guest recipe; the host still owns authority and run selection.
    Maintenance(super::maintenance::Procedure),
    /// The operator's existing network rules select the effect of each list.
    List {
        feeds: BTreeMap<String, String>,
        body: String,
    },
    /// A retained notification uses the ordinary targeted Coord delivery owner.
    Notify {
        room: String,
        recipients: Vec<String>,
    },
    /// Assessment, check/job execution, maintenance and lifecycle requests remain
    /// ordinary assigned Work. Its executor still owns its effect authority.
    Work {
        room: String,
        assignee: String,
        title: String,
        requirement: String,
    },
}

pub(super) fn validate(config: &Configuration) -> Result<(), Error> {
    let mut feeds = std::collections::BTreeSet::new();
    for (rule_name, rule) in &config.rules {
        name(rule_name)?;
        if !config.sources.contains_key(&rule.source)
            || rule.agents.is_empty()
            || !rule.min_severity.is_finite()
            || !(0.0..=10.0).contains(&rule.min_severity)
        {
            return Err(
                "response rule needs an adopted source, selected agents and severity 0..10".into(),
            );
        }
        for agent in &rule.agents {
            name(agent)?;
        }
        if rule
            .inventory
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
            || ((rule.inventory.is_some() || rule.guest_inventory.is_some())
                && rule.inventory_max_age_seconds.is_none_or(|age| age == 0))
        {
            return Err(
                "inventory needs an absolute host-owned path and positive freshness limit".into(),
            );
        }
        if let Some(collection) = &rule.guest_inventory {
            collection.validate()?;
            if rule.inventory.is_some() {
                return Err(
                    "select guest_inventory collection or an external inventory file for a rule"
                        .into(),
                );
            }
        }
        if rule.startup_before_work && rule.guest_inventory.is_none() {
            return Err("startup_before_work needs adopted guest_inventory collection".into());
        }
        if rule.on_inactive == Inactive::Respond
            || (rule.on_stale == Inactive::Respond
                && matches!(rule.response, Response::List { .. }))
        {
            return Err("on_stale = 'respond' selects notification or Work for unknown evidence; on_inactive supports retain or release".into());
        }
        match &rule.response {
            Response::Maintenance(procedure) => {
                procedure.validate()?;
                if rule.guest_inventory.is_none() {
                    return Err("maintenance needs current guest_inventory collection, not a base or external inventory".into());
                }
            }
            Response::List {
                feeds: targets,
                body,
            } => {
                if body.is_empty()
                    || targets.len() != rule.agents.len()
                    || rule.agents.iter().any(|a| !targets.contains_key(a))
                {
                    return Err("a list response needs one separate feed per selected agent and explicit membership".into());
                }
                for feed in targets.values() {
                    name(feed)?;
                    if !feeds.insert(feed)
                        || config
                            .sources
                            .values()
                            .any(|s| s.list.as_ref() == Some(feed))
                    {
                        return Err("each response list needs one owner; it cannot also follow a distributed source".into());
                    }
                }
            }
            Response::Notify { room, recipients } => {
                name(room)?;
                if recipients.is_empty() {
                    return Err("notification needs explicit recipients".into());
                }
                for recipient in recipients {
                    if !crate::agent_api::coord::valid_agent_id(recipient) {
                        return Err("notification recipients need durable agent IDs".into());
                    }
                }
            }
            Response::Work {
                room,
                assignee,
                title,
                requirement,
            } => {
                name(room)?;
                if !crate::agent_api::coord::valid_agent_id(assignee)
                    || title.is_empty()
                    || title.len() > 400
                    || requirement.is_empty()
                    || requirement.len() > 1024
                {
                    return Err(
                        "response Work needs a durable assignee, title and requirement reference"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_targets(root: &Path, config: &Configuration) -> Result<(), Error> {
    for feed in config
        .sources
        .values()
        .filter_map(|source| source.list.as_deref())
    {
        crate::policy_feeds::signal_target(root, feed)?;
    }
    for rule in config.rules.values() {
        if let Response::List { feeds, .. } = &rule.response {
            for feed in feeds.values() {
                crate::policy_feeds::signal_target(root, feed)?;
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Reaction {
    identity: String,
    active: bool,
    status: String,
    approval_id: Option<String>,
    result: Value,
    #[serde(default)]
    episode: u64,
}
fn path(root: &Path, rule: &str, agent: &str) -> PathBuf {
    directory(root)
        .join("responses")
        .join(rule)
        .join(format!("{agent}.json"))
}
fn read(root: &Path, rule: &str, agent: &str) -> Result<Reaction, Error> {
    Ok(crate::guest_commands::read_state(&path(root, rule, agent))?
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default())
}

fn effect_scope(root: &Path, rule: &Rule, policy: &Policy) -> Result<Value, Error> {
    let Response::List { feeds, .. } = &rule.response else {
        return Ok(Value::Null);
    };
    let targets = feeds
        .values()
        .map(|feed| crate::policy_feeds::signal_target(root, feed))
        .collect::<Result<Vec<_>, _>>()?;
    let feeds = feeds.values().cloned().collect::<Vec<_>>();
    Ok(
        json!({"targets":targets,"policy":policy.signal_list_scope(&feeds).ok_or("signal list policy unavailable")?}),
    )
}

/// Revision and delivery order alone do not change a finding's meaning.
fn finding_basis(updates: &[Update]) -> String {
    digest(
        &updates
            .iter()
            .map(|update| {
                (
                    format!("{}/{}", update.source_id, update.id),
                    &update.evidence,
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
}

fn findings_current(original: &[Update], current: &[Accepted], source: &Source) -> bool {
    !original.is_empty()
        && original.iter().all(|finding| {
            current.iter().any(|accepted| {
                accepted.update.id == finding.id
                    && accepted.update.source_id == finding.source_id
                    && accepted.update.evidence == finding.evidence
                    && !accepted.update.withdrawn
                    && accepted.update.fresh(source, now())
            })
        })
}

fn inventory_basis(root: &Path, name: &str, rule: &Rule, agent: &str, policy: &Policy) -> Value {
    let inventory = if rule.guest_inventory.is_some() {
        guest_inventory::inventory(root, name, agent)
    } else if let Some(file) = &rule.inventory {
        crate::guest_commands::read_state_bounded(file, 1024 * 1024).and_then(|value| {
            value
                .map(serde_json::from_value::<guest_inventory::Inventory>)
                .transpose()
                .map_err(Into::into)
        })
    } else {
        return Value::Null;
    };
    match inventory {
        Ok(Some(inventory)) if guest_inventory::fresh(&inventory, rule, agent, policy) => {
            json!(digest(&json!([
                inventory.agent_id,
                inventory.run_id,
                inventory.distribution,
                inventory.packages,
                inventory.services
            ])))
        }
        _ => json!("unknown_or_stale"),
    }
}

#[allow(clippy::too_many_arguments)]
fn approval_findings_current(
    root: &Path,
    name: &str,
    rule: &Rule,
    agent: &str,
    policy: &Policy,
    action: &Value,
    original: &[Update],
    current: &[Accepted],
    source: &Source,
) -> bool {
    if action["inventory_basis"] != inventory_basis(root, name, rule, agent, policy) {
        return false;
    }
    if original.is_empty() {
        let (selected, unknown, _) = select_findings(
            root,
            name,
            rule,
            agent,
            current,
            source,
            policy,
            &Value::Null,
        );
        if matches!(rule.response, Response::Maintenance(_)) {
            return selected.is_empty() && !unknown && action["respond_unknown"] == false;
        }
        return action["respond_unknown"] == true && rule.on_stale == Inactive::Respond && unknown;
    }
    findings_current(original, current, source)
        && original.iter().all(|finding| {
            if rule.inventory.is_some()
                || (rule.guest_inventory.is_some()
                    && matches!(
                        finding.evidence,
                        Evidence::Advisory {
                            subject: Subject::Package { .. },
                            ..
                        }
                    ))
            {
                matches!(
                    applicability(root, name, rule, agent, finding, policy, &Value::Null),
                    Ok(Some(true))
                )
            } else {
                true
            }
        })
}

/// Inventory checks attest effective state, not saved desired packages. This
/// record is host-selected, freshness-bounded and bound to the current agent run.
fn applicability(
    root: &Path,
    rule_name: &str,
    rule: &Rule,
    agent: &str,
    update: &Update,
    policy: &Policy,
    services: &Value,
) -> Result<Option<bool>, Error> {
    let Some(agent_id) = policy.evidence_agent_id(agent) else {
        return Ok(None);
    };
    let Evidence::Advisory { subject, .. } = &update.evidence else {
        return Ok(Some(false));
    };
    let collected_package =
        rule.guest_inventory.is_some() && matches!(subject, Subject::Package { .. });
    if rule.inventory.is_some() || collected_package {
        let inventory = if let Some(file) = &rule.inventory {
            crate::guest_commands::read_state_bounded(file, 1024 * 1024)?
                .map(serde_json::from_value::<guest_inventory::Inventory>)
                .transpose()?
        } else {
            guest_inventory::inventory(root, rule_name, agent)?
        };
        let Some(inventory) = inventory else {
            return Ok(None);
        };
        if inventory.agent_id != agent_id
            || !guest_inventory::fresh(&inventory, rule, agent, policy)
        {
            return Ok(None);
        }
        return match subject {
            Subject::Service { name } => Ok(Some(inventory.services.contains(name))),
            Subject::Package {
                name,
                distribution,
                fixed_version,
            } => {
                if &inventory.distribution != distribution {
                    return Ok(Some(false));
                }
                if !distribution.starts_with("debian:") {
                    return Ok(None);
                }
                let versions = inventory
                    .packages
                    .iter()
                    .filter(|(package, _)| package.split(':').next() == Some(name.as_str()))
                    .map(|(_, version)| version)
                    .collect::<Vec<_>>();
                if versions
                    .iter()
                    .any(|version| !valid_debian_version(version))
                {
                    return Ok(None);
                }
                if versions.is_empty() {
                    return Ok(Some(false));
                }
                let Some(fixed) = fixed_version else {
                    return Ok(None);
                };
                Ok(Some(
                    versions
                        .iter()
                        .any(|version| debian_compare(version, fixed).is_lt()),
                ))
            }
            Subject::Destination { .. } => destination(policy, agent, subject),
        };
    }
    match subject {
        Subject::Service { name } => {
            let Some(services) = services.as_array() else {
                return Ok(None);
            };
            Ok(Some(services.iter().any(|service| {
                service["agent"] == agent
                    && service["name"] == *name
                    && service["state"] == "listening"
            })))
        }
        Subject::Destination { .. } => destination(policy, agent, subject),
        Subject::Package { .. } => Ok(None),
    }
}
fn destination(policy: &Policy, agent: &str, subject: &Subject) -> Result<Option<bool>, Error> {
    let Subject::Destination { hostname } = subject else {
        return Ok(None);
    };
    let crate::policy::checks::Subject::Hostname { hostname } =
        (crate::policy::checks::Subject::Hostname {
            hostname: hostname.clone(),
        })
        .normalized()?
    else {
        return Ok(None);
    };
    if policy.native_controls().is_some_and(|controls| {
        !controls.network.enabled
            || matches!(controls.network.action, crate::policy::native::Action::Warn)
    }) {
        return Ok(Some(true));
    }
    let decision = policy.evaluate(
        crate::policy::NetworkRequest {
            agent: Some(agent),
            host: &hostname,
            port: Some(443),
            method: "GET",
            path: "/",
        },
        now() as f64 * 1000.,
        false,
    )?;
    Ok(Some(decision.effect != crate::policy::Effect::Deny))
}

// Debian's epoch/upstream/revision ordering. Package transaction and process
// restart verification belong to the maintenance consumer, not this comparator.
pub(super) fn valid_debian_version(value: &str) -> bool {
    let rest = if let Some((epoch, rest)) = value.split_once(':') {
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rest
    } else {
        value
    };
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
    upstream.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && upstream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'~' | b':'))
        && !revision.is_empty()
        && revision
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'))
}
fn debian_compare(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> (&str, &str, &str) {
        let (epoch, rest) = s.split_once(':').unwrap_or(("0", s));
        let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, "0"));
        (epoch, upstream, revision)
    }
    fn number(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        let a = a
            .iter()
            .skip_while(|&&c| c == b'0')
            .copied()
            .collect::<Vec<_>>();
        let b = b
            .iter()
            .skip_while(|&&c| c == b'0')
            .copied()
            .collect::<Vec<_>>();
        a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
    }
    fn order(c: Option<u8>) -> u16 {
        match c {
            Some(b'~') => 0,
            None => 1,
            Some(c) if c.is_ascii_alphabetic() => c as u16 + 2,
            Some(c) => c as u16 + 258,
        }
    }
    fn compare(a: &str, b: &str) -> std::cmp::Ordering {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let (mut i, mut j) = (0, 0);
        while i < a.len() || j < b.len() {
            while a.get(i).is_some_and(|c| !c.is_ascii_digit())
                || b.get(j).is_some_and(|c| !c.is_ascii_digit())
            {
                // A digit has the same ordering as the end of a non-digit run.
                let x = a.get(i).copied().filter(|c| !c.is_ascii_digit());
                let y = b.get(j).copied().filter(|c| !c.is_ascii_digit());
                let result = order(x).cmp(&order(y));
                if !result.is_eq() {
                    return result;
                }
                i += usize::from(x.is_some());
                j += usize::from(y.is_some());
            }
            let (ai, bj) = (i, j);
            while a.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            let result = number(&a[ai..i], &b[bj..j]);
            if !result.is_eq() {
                return result;
            }
        }
        std::cmp::Ordering::Equal
    }
    let (ae, au, ar) = parts(a);
    let (be, bu, br) = parts(b);
    number(ae.as_bytes(), be.as_bytes())
        .then_with(|| compare(au, bu))
        .then_with(|| compare(ar, br))
}

fn list_expiry(selected: &[Update], source: &Source) -> Option<u64> {
    selected
        .iter()
        .map(|update| {
            update
                .expires_at
                .min(update.observed_at.saturating_add(source.max_age_seconds))
        })
        .min()
}

#[allow(clippy::too_many_arguments)]
fn select_findings(
    root: &Path,
    rule_name: &str,
    rule: &Rule,
    agent: &str,
    accepted: &[Accepted],
    source: &Source,
    policy: &Policy,
    services: &Value,
) -> (Vec<Update>, bool, bool) {
    let mut selected = Vec::new();
    let mut unknown = accepted.is_empty()
        || (rule.guest_inventory.is_some()
            && inventory_basis(root, rule_name, rule, agent, policy) == "unknown_or_stale");
    let mut inactive = false;
    for record in accepted {
        let update = &record.update;
        let Evidence::Advisory {
            distribution,
            severity,
            ..
        } = &update.evidence
        else {
            unknown = true;
            continue;
        };
        if rule
            .distribution
            .as_ref()
            .is_some_and(|wanted| distribution.as_ref() != Some(wanted))
        {
            continue;
        }
        if update.withdrawn || *severity < rule.min_severity {
            inactive = true;
            continue;
        }
        if !update.fresh(source, now()) {
            unknown = true;
            continue;
        }
        match applicability(root, rule_name, rule, agent, update, policy, services) {
            Ok(Some(true)) => selected.push(update.clone()),
            Ok(Some(false)) => {
                inactive = true;
            }
            Ok(None) | Err(_) => {
                unknown = true;
            }
        }
    }
    (selected, unknown, inactive)
}

pub(super) async fn reconcile(
    root: PathBuf,
    runtime: RuntimeState,
    services: Value,
) -> Result<u64, Error> {
    let config = configuration(&root)?;
    let (policy, writer) = {
        let current = runtime.read().map_err(|_| "signal runtime unavailable")?;
        (
            current.policy.clone().ok_or("signal policy unavailable")?,
            current.audit.clone(),
        )
    };
    let mut next_due = u64::MAX;
    for (rule_name, rule) in &config.rules {
        let source = &config.sources[&rule.source];
        let accepted = read_accepted(&root, &rule.source, source)?;
        for record in &accepted {
            let deadline = record.update.expires_at.min(
                record
                    .update
                    .observed_at
                    .saturating_add(source.max_age_seconds),
            );
            if deadline > now() {
                next_due = next_due.min(deadline);
            }
        }
        if let Some(file) = &rule.inventory
            && let Ok(Some(value)) = crate::guest_commands::read_state_bounded(file, 1024 * 1024)
            && let Some(deadline) = value["observed_at"].as_u64().and_then(|at| {
                rule.inventory_max_age_seconds
                    .map(|age| at.saturating_add(age))
            })
            && deadline > now()
        {
            next_due = next_due.min(deadline);
        }
        for agent in &rule.agents {
            if rule.guest_inventory.is_some()
                && let Ok(Some(inventory)) = guest_inventory::inventory(&root, rule_name, agent)
                && let Some(age) = rule.inventory_max_age_seconds
                && inventory.observed_at.saturating_add(age) > now()
            {
                next_due = next_due.min(inventory.observed_at.saturating_add(age));
            }
            let (selected, unknown, inactive) = select_findings(
                &root, rule_name, rule, agent, &accepted, source, &policy, &services,
            );
            let mut reaction = read(&root, rule_name, agent)?;
            let respond_unknown = unknown && rule.on_stale == Inactive::Respond;
            let active = !selected.is_empty() || respond_unknown;
            let retain = !active
                && if unknown {
                    rule.on_stale == Inactive::Retain
                } else {
                    rule.on_inactive == Inactive::Retain
                };
            let scope = effect_scope(&root, rule, &policy)?;
            let dispatch_findings =
                (!matches!(rule.response, Response::List { .. })).then(|| finding_basis(&selected));
            let identity = digest(&json!([
                rule,
                source.source_id,
                (rule.authority == Authority::Approval).then(|| digest(source)),
                scope,
                dispatch_findings,
                respond_unknown,
                (rule.authority == Authority::Approval)
                    .then(|| inventory_basis(&root, rule_name, rule, agent, &policy)),
                policy.evidence_agent_id(agent),
                policy.agent_run(agent),
                matches!(rule.response, Response::Maintenance(_))
                    .then(
                        || crate::guest_commands::read_state(&guest_inventory::request_path(
                            &root, rule_name
                        ))
                        .map(|request| request.unwrap_or(Value::Null)["request_id"].clone())
                    )
                    .transpose()?,
                active
            ]));
            let inventory_status = if rule.guest_inventory.is_some() {
                guest_inventory::status(&root, rule_name, rule, agent, Some(&policy))?
            } else {
                json!({"external_path":rule.inventory,"max_age_seconds":rule.inventory_max_age_seconds})
            };
            let current = json!({"rule":rule_name,"agent":agent,"agent_id":policy.evidence_agent_id(agent),"run":policy.agent_run(agent),"source":rule.source,"affected":!selected.is_empty(),"response_identity":identity,
                "applicability":if unknown {"unknown_or_stale"} else if active {"affected"} else {"unaffected"},
                "inventory":inventory_status,"source_evidence":accepted.iter().map(|record|json!({"id":record.update.id,"observed_at":record.update.observed_at,"expires_at":record.update.expires_at,"fresh":record.update.fresh(source,now()),"fix_available":match &record.update.evidence {Evidence::Advisory{subject:Subject::Package{fixed_version,..},..}=>Some(fixed_version.is_some()),_=>None}})).collect::<Vec<_>>(),
                "responding_to_uncertainty":respond_unknown,
                "next_action":if unknown {"Inspect inventory and source freshness; resolve unavailable evidence. A response does not establish repair."}else if active {"Read the response receipt and the maintenance owner's result; repair and running-code adoption remain unverified."}else{"No finding meets this rule in the current evidence; other maintenance coverage remains outside this assessment."},
                "findings":selected,"authority":rule.authority,"inactive_evidence":inactive,
                "effect":rule.response,"effect_scope":scope,"observed_at":now()});
            save(
                &path(&root, rule_name, agent).with_extension("status.json"),
                &current,
            )?;
            if let Response::Maintenance(procedure) = &rule.response {
                if !procedure.due() {
                    reaction.status = "deferred_window".into();
                    reaction.result = json!({"effect":"no_maintenance","next_action":"Maintenance waits for the adopted UTC hours; the affected startup work remains gated."});
                    save(&path(&root, rule_name, agent), &reaction)?;
                    next_due = next_due.min(now() + 60);
                    continue;
                }
                // Uncertainty is visible and never an instruction to patch.
                if unknown && selected.is_empty() {
                    reaction.status = "unavailable".into();
                    if reaction.result.is_null() {
                        reaction.result = json!({"effect":"no_maintenance","next_action":"Resolve stale, unsupported, partial or no-fix evidence; retained remediation requirements remain in force."});
                    }
                    save(&path(&root, rule_name, agent), &reaction)?;
                    continue;
                }
            }
            if retain {
                continue;
            }
            let reconcile_list = reaction.identity == identity
                && matches!(reaction.status.as_str(), "applied" | "verified")
                && matches!(rule.response, Response::List { .. });
            if reconcile_list
                && reaction.result["expires_at"] == json!(list_expiry(&selected, source))
            {
                if let Response::List { feeds, .. } = &rule.response {
                    let captured = policy.native_list_file_status().values().any(|status| {
                        status["active_snapshot"]["source"] == feeds[agent]
                            && status["active_snapshot"]["version"]
                                == reaction.result["snapshot_version"]
                            && status["saved_matches_active"] == true
                            && (!active || status["active_snapshot"]["stale"] == false)
                    });
                    let status = if captured { "verified" } else { "applied" };
                    if reaction.status != status {
                        reaction.status = status.into();
                        reaction.result["network_activation"] = if captured {
                            json!(
                                "running policy captured the complete local snapshot; new admissions use it"
                            )
                        } else {
                            json!(
                                "waiting for the running policy to capture the current local snapshot"
                            )
                        };
                        save(&path(&root, rule_name, agent), &reaction)?;
                    }
                    if !captured {
                        next_due = next_due.min(now() + 1);
                    }
                }
                continue;
            }
            if !reconcile_list
                && reaction.identity == identity
                && matches!(
                    reaction.status.as_str(),
                    "verified"
                        | "dispatched"
                        | "notified"
                        | "failed"
                        | "uncertain"
                        | "pending_restart"
                        | "recovered"
                )
            {
                continue;
            }
            if reaction.identity != identity {
                reaction = Reaction {
                    identity: identity.clone(),
                    active,
                    status: "selected".into(),
                    episode: reaction.episode + 1,
                    ..Reaction::default()
                };
            }
            let operation = format!(
                "req-{}",
                &digest(&json!([rule_name, agent, identity, reaction.episode]))[..32]
            );
            // Refreshing validity preserves the already-authorised list effect.
            // Its identity still binds the rule, target, source and policy scope.
            if !reconcile_list
                && (active || matches!(rule.response, Response::Maintenance(_)))
                && rule.authority == Authority::Approval
            {
                let action = json!({"kind":"signal_response","rule":rule_name,"agent":agent,
                    "agent_id":policy.evidence_agent_id(agent),"basis":digest(rule),"identity":identity,
                    "source_basis":digest(source),
                    "inventory_basis":inventory_basis(&root,rule_name,rule,agent,&policy),"respond_unknown":respond_unknown,
                    "effect_scope":scope,
                    "findings":selected});
                let record = match writer.approvals().get(&operation)? {
                    Some(record) => record,
                    None => {
                        let expiry = selected
                            .iter()
                            .map(|u| {
                                u.expires_at
                                    .min(u.observed_at.saturating_add(source.max_age_seconds))
                            })
                            .min()
                            .unwrap_or_else(|| now().saturating_add(source.max_age_seconds));
                        let expiry = time::OffsetDateTime::from_unix_timestamp(expiry as i64)?
                            .format(&time::format_description::well_known::Rfc3339)?;
                        let record=writer.approvals().submit(pending::Authority{revision:approval_revision(&policy,&action).ok_or("signal approval authority unavailable")?,
                            resource_digest:digest(&action),action:action.clone(),method:"POST".into(),scheme:"http".into(),port:None,
                            options:vec![pending::OptionScope{id:"once".into(),effect:format!("Apply this adopted signal response once for {agent}: {}. Recheck current evidence and local applicability before dispatch.",serde_json::to_string(&rule.response)?),session_id:None,parameters:json!({"effect_scope":scope})}],
                            expires_at:Some(expiry),credential_bindings:Default::default()},&operation,&policy)?;
                        let mut event = crate::audit::Event::new(
                            "ops.signal_response_requested",
                            crate::audit::Kind::Ops,
                            crate::audit::Severity::Low,
                            "Adopted signal response needs an operator decision",
                        );
                        event.agent = Some(agent.clone());
                        event.request_id = Some(operation.clone());
                        event.approval = Some(crate::audit::Approval {
                            required: true,
                            approval_type: crate::audit::ApprovalType::SignalResponse,
                            key: record.approval_id.clone(),
                            target: agent.clone(),
                            scope_hint:
                                json!({"rule":rule_name,"agent_id":policy.evidence_agent_id(agent)})
                                    .into(),
                        });
                        event.details=json!({"approval_id":record.approval_id,"authority":record.authority,"selection":current}).into();
                        writer.emit_confirmed(event).await?;
                        record
                    }
                };
                let original = serde_json::from_value::<Vec<Update>>(
                    record.authority.action["findings"].clone(),
                )?;
                let status = record.current_status(&policy)?;
                let expired = time::OffsetDateTime::parse(
                    record
                        .authority
                        .expires_at
                        .as_deref()
                        .ok_or("signal approval expiry unavailable")?,
                    &time::format_description::well_known::Rfc3339,
                )?
                .unix_timestamp()
                    <= now() as i64;
                if finding_basis(&original) != finding_basis(&selected) || expired {
                    // A delayed decision is bound to its original findings.
                    // Select another approval only after real evidence changes.
                    writer.approvals().decide(&record.approval_id, |old| {
                        if old.status == "pending" {
                            old.status = "superseded".into();
                        }
                        Ok(())
                    })?;
                    reaction.episode += 1;
                    reaction.status = "selected".into();
                    save(&path(&root, rule_name, agent), &reaction)?;
                    next_due = next_due.min(now() + 1);
                    continue;
                }
                reaction.approval_id = Some(record.approval_id.clone());
                reaction.status = match status.as_str() {
                    "approved" => "approved",
                    "pending" => "pending_approval",
                    "rejected" => "rejected",
                    _ => "superseded",
                }
                .into();
                save(&path(&root, rule_name, agent), &reaction)?;
                if reaction.status == "pending_approval" {
                    next_due = next_due.min(now() + 1);
                }
                if reaction.status != "approved" {
                    continue;
                }
            }
            // Saving the attempt precedes effects. Each owner below has an
            // idempotent current-state write or a retained exact operation ID.
            reaction.status = "attempted".into();
            save(&path(&root, rule_name, agent), &reaction)?;
            let result = apply(
                &root,
                &runtime,
                &policy,
                &config,
                rule_name,
                rule,
                agent,
                &selected,
                &services,
                respond_unknown,
                &operation,
                &mut reaction,
            )
            .await;
            match result {
                Ok((status, result)) => {
                    reaction.status = status.into();
                    reaction.result = result;
                    if status == "applied" {
                        next_due = next_due.min(now() + 1);
                    }
                }
                Err(error) => {
                    reaction.status = if reaction.result["prepared"].is_object() {
                        "uncertain"
                    } else {
                        "failed"
                    }
                    .into();
                    let retained = std::mem::take(&mut reaction.result);
                    reaction.result = json!({"diagnostic":error.to_string(),"operation_id":operation,"retained":retained,"next_action":"inspect this response and the existing effect owner before selecting a changed rule or retry"});
                }
            }
            save(&path(&root, rule_name, agent), &reaction)?;
            let mut event = crate::audit::Event::new(
                "ops.signal_response",
                crate::audit::Kind::Ops,
                crate::audit::Severity::Low,
                "Adopted signal response reached a result",
            );
            event.agent = Some(agent.clone());
            event.request_id = Some(operation);
            event.details = json!({"selection":current,"response":reaction}).into();
            writer.emit_confirmed(event).await?;
        }
    }
    Ok(next_due)
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    root: &Path,
    runtime: &RuntimeState,
    selected_policy: &Policy,
    config: &Configuration,
    rule_name: &str,
    rule: &Rule,
    agent: &str,
    selected: &[Update],
    services: &Value,
    respond_unknown: bool,
    operation: &str,
    reaction: &mut Reaction,
) -> Result<(&'static str, Value), Error> {
    let live = runtime
        .read()
        .map_err(|_| "signal runtime unavailable")?
        .clone();
    let policy = live.policy.as_ref().ok_or("signal policy unavailable")?;
    if policy.evidence_agent_id(agent) != selected_policy.evidence_agent_id(agent)
        || policy.agent_run(agent) != selected_policy.agent_run(agent)
        || effect_scope(root, rule, policy)? != effect_scope(root, rule, selected_policy)?
    {
        return Err("signal target identity or run changed before response".into());
    }
    let config_path = live
        .config
        .native_config_path
        .as_deref()
        .ok_or("signal host configuration unavailable")?;
    let instance_root = live
        .config
        .native_config_dir
        .as_deref()
        .ok_or("signal instance root unavailable")?;
    // Recheck saved source/rule adoption immediately before the effect.
    if digest(&configuration(root)?) != digest(config) {
        return Err("signal policy changed before response".into());
    }
    let current = read_accepted(root, &rule.source, &config.sources[&rule.source])?;
    if selected.iter().any(|update| {
        !current.iter().any(|a| {
            a.update == *update
                && update.fresh(&config.sources[&rule.source], now())
                && !update.withdrawn
        }) || !matches!(
            applicability(root, rule_name, rule, agent, update, policy, services),
            Ok(Some(true))
        )
    }) {
        return Err("signal evidence changed before response; no effect was requested".into());
    }
    let (_, current_unknown, _) = select_findings(
        root,
        rule_name,
        rule,
        agent,
        &current,
        &config.sources[&rule.source],
        policy,
        services,
    );
    if respond_unknown != (current_unknown && rule.on_stale == Inactive::Respond) {
        return Err("signal assessment changed before response; reassess current evidence".into());
    }
    match &rule.response {
        Response::Maintenance(procedure) => {
            let request = super::maintenance::request(procedure, selected, operation)?;
            reaction.result["prepared"] = json!({"request":request});
            save(&path(root, rule_name, agent), reaction)?;
            let mut prepared = reaction.result["prepared"].clone();
            let (status, mut result) = super::maintenance::execute(
                root,
                runtime,
                config,
                agent,
                procedure,
                &request,
                &mut prepared,
            )
            .await?;
            result["assessment_partial"] = json!(current_unknown);
            if current_unknown && status == "verified" {
                result["next_action"] = json!(
                    "Selected package requirements were verified, but other source/applicability evidence is unknown. Resolve that evidence before claiming complete maintenance."
                );
                Ok(("partial", result))
            } else {
                Ok((status, result))
            }
        }
        Response::List { feeds, body } => {
            let _lock = approvals::lock_policy(&root.join("policy.toml"))?;
            let previous = crate::policy_feeds::load_list(root, &feeds[agent])?.snapshot;
            let prefix = format!("local-response:{rule_name}:");
            let revision = previous
                .as_ref()
                .and_then(|snapshot| snapshot.provider_version.as_deref())
                .and_then(|version| version.strip_prefix(&prefix))
                .map(str::parse::<u64>)
                .transpose()?
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("response list revision exhausted")?;
            let expires_at = list_expiry(selected, &config.sources[&rule.source]);
            let update = Update {
                source_id: "local-response".into(),
                id: rule_name.into(),
                revision,
                // This is the time of the local desired-state decision. The
                // originating evidence keeps its own age in the selection.
                observed_at: now(),
                expires_at: expires_at.unwrap_or(now() + 1),
                withdrawn: selected.is_empty(),
                evidence_refs: vec![],
                evidence: Evidence::List { body: body.clone() },
            };
            crate::policy_feeds::adopt_signal(root, &feeds[agent], &update, body)?;
            Ok((
                "applied",
                json!({"effect":"complete_local_list_snapshot","feed":feeds[agent],"membership_active":!selected.is_empty(),
                    "expires_at":expires_at,"snapshot_version":digest(&update),
                    "network_activation":"policy watcher; applies to new admissions only"}),
            ))
        }
        _ if selected.is_empty() && !respond_unknown => Ok((
            "verified",
            json!({"effect":"no_new_dispatch","prior_dispatch":"a withdrawal does not undo a completed external operation"}),
        )),
        Response::Work {
            room,
            assignee,
            title,
            requirement,
        } => {
            let evidence = notify(
                root,
                config_path,
                rule_name,
                agent,
                selected,
                room,
                std::slice::from_ref(assignee),
                Some(requirement),
                reaction,
            )
            .await?;
            let sequence = evidence["sequence"]
                .as_u64()
                .ok_or("signal input publication has no canonical sequence")?;
            use crate::coord_rooms::work::{self, Actor, Mutation, subjects::Principal};
            let mut conn = crate::coord_rooms::open(instance_root)?;
            let result = work::mutate(
                None,
                &mut conn,
                room,
                Actor::Operator,
                Mutation::Create {
                    title: format!("{title} ({agent}; signal rule {rule_name})"),
                    external_ref: Some(format!("coord://{room}/{sequence}")),
                    assignee: Some(Principal {
                        kind: "agent".into(),
                        id: assignee.clone(),
                    }),
                    factory: None,
                },
                Some(operation),
            )?;
            Ok((
                "dispatched",
                json!({"effect":"assigned_work","receipt":result,"input":evidence,"verification":"executor has not yet reported the requested check/job/lifecycle effect"}),
            ))
        }
        Response::Notify { room, recipients } => {
            let receipt = notify(
                root,
                config_path,
                rule_name,
                agent,
                selected,
                room,
                recipients,
                None,
                reaction,
            )
            .await?;
            Ok((
                "notified",
                json!({"effect":"retained_targeted_notification","receipt":receipt,"model_receipt":"unverified"}),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn notify(
    root: &Path,
    config_path: &Path,
    rule_name: &str,
    agent: &str,
    selected: &[Update],
    room: &str,
    recipients: &[String],
    requirement: Option<&String>,
    reaction: &mut Reaction,
) -> Result<Value, Error> {
    let coord = crate::agent_api::coord::OperatorCoord::open(config_path)?;
    let prepared = if reaction.result["prepared"].is_object() {
        serde_json::from_value(reaction.result["prepared"].clone())?
    } else {
        let assessment = crate::guest_commands::read_state(
            &path(root, rule_name, agent).with_extension("status.json"),
        )?;
        let body = serde_json::to_string(
            &json!({"source":"adopted_signal_rule","rule":rule_name,"affected_agent":agent,"findings":selected,
            "assessment":assessment,
            "requirement":requirement,"authority":"Evidence and notification grant no execution authority. Execute only within the adopted owner policy."}),
        )?;
        let prepared = coord
            .prepare_for_agent_ids(room, &body, "text/plain", recipients)
            .await?;
        reaction.result = json!({"prepared":prepared});
        save(&path(root, rule_name, agent), reaction)?;
        prepared
    };
    coord.authorize_prepared(room, &prepared).await?;
    if let Some(sequence) = coord.find_prepared(room, &prepared).await? {
        return Ok(json!({"sequence":sequence,"envelope":prepared.envelope,
            "attention_intent":{"mode":"targeted"},
            "attention_recipients":prepared.attention_manifest["recipients"],
            "attention_status":"not_verified","publication":"reconciled_from_history"}));
    }
    if reaction.result["publish_attempted"] == true {
        return Err(
            "signal notification publication remains unknown; no automatic resend was made".into(),
        );
    }
    // A crash after this save must reconcile retained history, even after the
    // broker's finite duplicate window. Missing history never permits replay.
    reaction.result["publish_attempted"] = json!(true);
    save(&path(root, rule_name, agent), reaction)?;
    Ok(coord.publish_prepared(room, &prepared).await?)
}

pub(crate) fn approval_revision(policy: &Policy, action: &Value) -> Option<String> {
    let root = policy.source_path()?.parent()?;
    let config = configuration(root).ok()?;
    let rule_name = action["rule"].as_str()?;
    let rule = config.rules.get(rule_name)?;
    let agent = action["agent"].as_str()?;
    let scope = effect_scope(root, rule, policy).ok()?;
    let source = config.sources.get(&rule.source)?;
    let original = serde_json::from_value::<Vec<Update>>(action["findings"].clone()).ok()?;
    let current = read_accepted(root, &rule.source, source).ok()?;
    (digest(rule) == action["basis"]
        && digest(config.sources.get(&rule.source)?) == action["source_basis"]
        && approval_findings_current(
            root, rule_name, rule, agent, policy, action, &original, &current, source,
        )
        && scope == action["effect_scope"]
        && rule.agents.iter().any(|a| a == agent)
        && rule.authority == Authority::Approval
        && policy.evidence_agent_id(agent) == action["agent_id"].as_str())
    .then(|| {
        digest(&json!([
            rule,
            scope,
            policy.evidence_agent_id(agent),
            policy.agent_run(agent),
            inventory_basis(root, rule_name, rule, agent, policy)
        ]))
    })
}
pub(crate) fn resolve(
    state: &RuntimeState,
    writer: &crate::audit::Writer,
    id: &str,
    decision: approvals::network_action::Decision,
    reviewer: bool,
) -> approvals::Result<(u16, Value)> {
    if reviewer {
        return Err(approvals::invalid(
            "signal response requires its operator's decision",
        ));
    }
    let policy = state
        .read()
        .map_err(|_| approvals::invalid("runtime unavailable"))?
        .policy
        .clone()
        .ok_or_else(|| approvals::invalid("policy unavailable"))?;
    let record=writer.approvals().decide(id,|record|{
        if record.status!="pending"{return Ok(());}
        record.status=record.current_status(&policy)?;
        if record.status!="pending"{return Ok(());}
        let action=&record.authority.action;
        let root=policy.source_path().and_then(Path::parent).ok_or_else(||approvals::invalid("response root missing"))?;
        let config=configuration(root).map_err(|_|approvals::invalid("signal policy unavailable"))?;
        let rule=config.rules.get(action["rule"].as_str().unwrap_or("")).ok_or_else(||approvals::invalid("response rule removed"))?;
        let source=&config.sources[&rule.source];
        let current=read_accepted(root,&rule.source,source).map_err(|_|approvals::invalid("signal evidence unavailable"))?;
        let original:Vec<Update>=serde_json::from_value(action["findings"].clone()).map_err(|_|approvals::invalid("signal approval findings unavailable"))?;
        let valid=approval_findings_current(root,action["rule"].as_str().unwrap_or(""),rule,action["agent"].as_str().unwrap_or(""),&policy,action,&original,&current,source);
        record.status=if !valid{"superseded"}else if matches!(decision,approvals::network_action::Decision::Reject){"rejected"}else{"approved"}.into();
        record.option=(record.status=="approved").then(||"once".into());
        record.result=json!({"status":"decision_recorded","effect_applied":false,"next_action":"the running proxy rechecks scope and applicability before dispatch"});
        Ok(())
    })?.ok_or_else(||approvals::invalid("signal approval missing"))?;
    Ok((
        200,
        json!({"approval_id":record.approval_id,"status":record.status,"result":record.result}),
    ))
}

pub(super) fn status(root: &Path) -> Result<Value, Error> {
    let config = configuration(root)?;
    let mut responses = Vec::new();
    for (name, rule) in &config.rules {
        for agent in &rule.agents {
            let request =
                crate::guest_commands::read_state(&guest_inventory::request_path(root, name))?
                    .unwrap_or(Value::Null);
            let collection = if rule.guest_inventory.is_some() {
                guest_inventory::status(root, name, rule, agent, None)?
            } else {
                Value::Null
            };
            responses.push(json!({"rule":name,"agent":agent,"response":read(root,name,agent)?,
            "assessment_request":request,"assessment_pending":!request["request_id"].is_null() && collection["request_id"]!=request["request_id"],
            "recorded_collection":collection,"selection":crate::guest_commands::read_state(&path(root,name,agent).with_extension("status.json"))?}));
        }
    }
    Ok(json!(responses))
}

pub(super) fn startup_rules(root: &Path, agent: &str) -> Result<Vec<String>, Error> {
    Ok(configuration(root)?
        .rules
        .into_iter()
        .filter_map(|(name, rule)| {
            (rule.startup_before_work && rule.agents.iter().any(|selected| selected == agent))
                .then_some(name)
        })
        .collect())
}

/// The booted guest remains available for authorized maintenance/recovery while
/// coding launches wait for the already adopted signal response owner.
pub(super) async fn before_work(root: &Path, agent: &str) -> Result<(), Error> {
    let config = configuration(root)?;
    let rules = startup_rules(root, agent)?;
    if rules.is_empty() {
        return Ok(());
    }
    let policy = Policy::from_native_path(&root.join("policy.toml"))?;
    let run = policy
        .agent_run(agent)
        .ok_or("startup maintenance needs a current owned guest")?;
    for name in rules {
        let rule = &config.rules[&name];
        let collection = rule
            .guest_inventory
            .as_ref()
            .ok_or("startup collection missing")?;
        let request_path = guest_inventory::request_path(root, &name);
        let old = crate::guest_commands::read_state(&request_path)?.unwrap_or(Value::Null);
        let inventory = guest_inventory::status(root, &name, rule, agent, Some(&policy))?;
        let request = if old["startup_run"] == run.run_id
            && old["rule_basis"] == digest(rule)
            && (inventory["request_id"] != old["request_id"] || inventory["fresh"] == true)
        {
            old
        } else {
            let request = json!({"request_id":uuid::Uuid::new_v4().to_string(),"requested_at":now(),
                "startup_run":run.run_id,"rule_basis":digest(rule)});
            save(&request_path, &request)?;
            request
        };
        let timeout = collection.timeout_seconds.saturating_add(2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
        loop {
            if digest(&configuration(root)?) != digest(&config)
                || !run.current(&Policy::from_native_path(&root.join("policy.toml"))?)
            {
                return Err("startup maintenance policy or guest changed; inspect the same agent before starting work".into());
            }
            let collection = guest_inventory::status(root, &name, rule, agent, Some(&policy))?;
            let selection = crate::guest_commands::read_state(
                &path(root, &name, agent).with_extension("status.json"),
            )?
            .unwrap_or(Value::Null);
            let reaction = read(root, &name, agent)?;
            let selected_current = collection["request_id"] == request["request_id"]
                && collection["fresh"] == true
                && selection["run"]["run_id"] == run.run_id
                && selection["inventory"]["request_id"] == request["request_id"]
                && selection["response_identity"] == reaction.identity;
            if selected_current {
                let complete = match &rule.response {
                    Response::Maintenance(_) => reaction.status == "verified",
                    _ => {
                        matches!(
                            reaction.status.as_str(),
                            "verified" | "dispatched" | "notified"
                        ) || (selection["affected"] == false
                            && selection["applicability"] == "unaffected")
                    }
                };
                if complete {
                    break;
                }
                if matches!(
                    reaction.status.as_str(),
                    "pending_approval"
                        | "rejected"
                        | "superseded"
                        | "failed"
                        | "uncertain"
                        | "unavailable"
                        | "pending_restart"
                        | "recovered"
                        | "deferred_window"
                ) {
                    return Err(format!("Startup work for {agent} is waiting on signal rule {name}: {}. Read signals status and the retained approval/maintenance result; the guest remains available for authorized recovery.", reaction.status).into());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("Startup work for {agent} is waiting on signal rule {name}. Read signals status; the running proxy must collect current evidence and finish the adopted response. No coding command was launched.").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn startup_is_explicit_and_unknown_evidence_does_not_open_the_work_gate() {
        let root = tempfile::tempdir().unwrap();
        assert!(startup_rules(root.path(), "alice").unwrap().is_empty());
        before_work(root.path(), "alice").await.unwrap();
        let config:Configuration=serde_json::from_value(json!({"sources":{"test":super::super::tests::source()},"rules":{"packages":{
            "source":"test","agents":["alice"],"min_severity":7,"authority":"standing","on_stale":"retain","on_inactive":"release",
            "startup_before_work":true,"guest_inventory":{"timeout_seconds":1,"max_output_bytes":65536},"inventory_max_age_seconds":60,
            "response":{"kind":"notify","room":"maintenance","recipients":["ag-11111111111111111111111111111111"]}}}})).unwrap();
        validate(&config).unwrap();
        fs::write(
            root.path().join("signals.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        assert_eq!(
            startup_rules(root.path(), "alice").unwrap(),
            vec!["packages"]
        );
        assert!(startup_rules(root.path(), "bob").unwrap().is_empty());
        fs::write(root.path().join("policy.toml"),"[agents.alice]\nagent_id='ag-11111111111111111111111111111111'\n[hosts.'*']\negress='deny'\n").unwrap();
        assert!(
            before_work(root.path(), "alice")
                .await
                .unwrap_err()
                .to_string()
                .contains("current owned guest")
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn effective_package_changes_freshness_and_run_replacement_revalidate_delayed_approvals() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let id = "ag-11111111111111111111111111111111";
        let generation = "11111111111111111111111111111111";
        fs::write(
            root.join("policy.toml"),
            format!("[agents.alice]\nagent_id='{id}'\n[hosts.'*']\negress='deny'\n"),
        )
        .unwrap();
        let backend = super::super::test_runs::agent_run(root, "alice", id, generation);
        let policy = Policy::from_native_path(&root.join("policy.toml")).unwrap();
        let inventory = root.join("effective.json");
        let write_inventory = |version: &str, at: u64, run: &str| {
            save(&inventory,&json!({"agent_id":id,"run_id":run,"observed_at":at,"distribution":"debian:trixie","packages":{"curl:arm64":version},"services":[]})).unwrap()
        };
        write_inventory("8.0-1", now(), generation);
        let mut source = super::super::tests::source();
        source.list = None;
        let config:Configuration=serde_json::from_value(json!({"sources":{"test":source},"rules":{"packages":{
            "source":"test","agents":["alice"],"min_severity":7,"authority":"approval","on_stale":"respond","on_inactive":"release",
            "inventory":inventory,"inventory_max_age_seconds":60,"response":{"kind":"notify","room":"maintenance","recipients":[id]}}}})).unwrap();
        fs::write(root.join("signals.toml"), toml::to_string(&config).unwrap()).unwrap();
        let rule = &config.rules["packages"];
        let source = &config.sources["test"];
        let mut finding = Update {
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
                source_digest: digest(source),
                update: finding.clone(),
            },
        )
        .unwrap();
        let unsupported = Accepted {
            source_digest: digest(source),
            update: Update {
                evidence: Evidence::List {
                    body: "wrong evidence kind".into(),
                },
                ..finding.clone()
            },
        };
        assert!(
            select_findings(
                root,
                "packages",
                rule,
                "alice",
                &[unsupported],
                source,
                &policy,
                &Value::Null
            )
            .1,
            "unsupported evidence cannot report an unaffected assessment"
        );
        let mut collected_rule = rule.clone();
        collected_rule.inventory = None;
        collected_rule.guest_inventory = Some(guest_inventory::CollectionPolicy {
            interval_seconds: Some(5),
            timeout_seconds: 1,
            max_output_bytes: 1024,
        });
        let mut below_threshold = finding.clone();
        if let Evidence::Advisory { severity, .. } = &mut below_threshold.evidence {
            *severity = 1.;
        }
        assert!(
            select_findings(
                root,
                "packages",
                &collected_rule,
                "alice",
                &[Accepted {
                    source_digest: digest(source),
                    update: below_threshold
                }],
                source,
                &policy,
                &Value::Null
            )
            .1,
            "unavailable adopted guest collection stays unknown even below the severity threshold"
        );
        assert_eq!(
            applicability(
                root,
                "packages",
                rule,
                "alice",
                &finding,
                &policy,
                &Value::Null
            )
            .unwrap(),
            Some(true)
        );
        let action = json!({"rule":"packages","agent":"alice","agent_id":id,"basis":digest(rule),"source_basis":digest(source),"effect_scope":Value::Null,
            "inventory_basis":inventory_basis(root,"packages",rule,"alice",&policy),"findings":[finding.clone()],"respond_unknown":false});
        let revision = approval_revision(&policy, &action).expect("fresh vulnerable current run");
        write_inventory("8.0-1", now() + 60, generation);
        assert!(
            approval_revision(&policy, &action).is_none(),
            "future evidence is unknown"
        );
        write_inventory("8.0-1", now(), generation);
        assert_eq!(
            approval_revision(&policy, &action),
            Some(revision),
            "unchanged capture needs no new decision"
        );
        write_inventory("8.0-2", now(), generation);
        assert_eq!(
            applicability(
                root,
                "packages",
                rule,
                "alice",
                &finding,
                &policy,
                &Value::Null
            )
            .unwrap(),
            Some(false),
            "unchanged advisory follows local package repair"
        );
        assert!(
            approval_revision(&policy, &action).is_none(),
            "old decision cannot dispatch after repair"
        );
        if let Evidence::Advisory {
            subject: Subject::Package { fixed_version, .. },
            ..
        } = &mut finding.evidence
        {
            *fixed_version = None;
        }
        finding
            .validate(source, &finding.id, now())
            .expect("no-fix evidence remains a valid explicit finding");
        assert_eq!(
            applicability(
                root,
                "packages",
                rule,
                "alice",
                &finding,
                &policy,
                &Value::Null
            )
            .unwrap(),
            None,
            "no-fix evidence keeps version applicability unknown"
        );
        write_inventory("8.0-1", now() - 60, generation);
        assert!(approval_revision(&policy, &action).is_none());
        let mut unknown_action = action.clone();
        unknown_action["findings"] = json!([]);
        unknown_action["respond_unknown"] = json!(true);
        unknown_action["inventory_basis"] =
            inventory_basis(root, "packages", rule, "alice", &policy);
        assert!(
            approval_revision(&policy, &unknown_action).is_some(),
            "adopted approval can respond to stale inventory"
        );
        write_inventory("8.0-2", now(), generation);
        assert!(
            approval_revision(&policy, &unknown_action).is_none(),
            "fresh unaffected evidence supersedes the uncertainty decision"
        );
        write_inventory("8.0-1", now() - 60, generation);
        assert_eq!(
            applicability(
                root,
                "packages",
                rule,
                "alice",
                &finding,
                &policy,
                &Value::Null
            )
            .unwrap(),
            None
        );
        write_inventory("8.0-1", now(), "replaced-run");
        assert_eq!(
            applicability(
                root,
                "packages",
                rule,
                "alice",
                &finding,
                &policy,
                &Value::Null
            )
            .unwrap(),
            None
        );
        write_inventory("8.0-1", now(), generation);
        drop(backend);
        assert!(
            approval_revision(&policy, &action).is_none(),
            "exited backend cannot retain run authority"
        );
    }
    #[test]
    fn finding_identity_ignores_revision_age_and_order_but_keeps_meaning() {
        let a = Update {
            source_id: "fixture".into(),
            id: "advisories.one".into(),
            revision: 1,
            observed_at: now() - 10,
            expires_at: now() + 60,
            withdrawn: false,
            evidence_refs: vec![],
            evidence: Evidence::Advisory {
                distribution: Some("debian:trixie".into()),
                severity: 8.5,
                subject: Subject::Service { name: "web".into() },
            },
        };
        let mut b = a.clone();
        b.id = "advisories.two".into();
        let basis = finding_basis(&[a.clone(), b.clone()]);
        let mut renewed = a.clone();
        renewed.revision += 1;
        renewed.observed_at += 1;
        renewed.expires_at += 1;
        assert_eq!(basis, finding_basis(&[b.clone(), renewed.clone()]));
        renewed.evidence = Evidence::Advisory {
            distribution: Some("debian:trixie".into()),
            severity: 8.5,
            subject: Subject::Service {
                name: "another-service".into(),
            },
        };
        assert_ne!(basis, finding_basis(&[b, renewed]));
    }
    #[test]
    fn destination_uses_canonical_dns_and_the_effective_network_control() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.toml");
        let source = "[hosts.'*']\negress='allow'\n[hosts.'blocked.test']\negress='deny'\n";
        fs::write(&path, source).unwrap();
        let subject = Subject::Destination {
            hostname: "BLOCKED.TEST.".into(),
        };
        let policy = Policy::from_native_path(&path).unwrap();
        assert_eq!(
            destination(&policy, "alice", &subject).unwrap(),
            Some(false)
        );
        for control in ["enabled=false", "action='warn'"] {
            fs::write(&path, format!("{source}\n[controls.network]\n{control}\n")).unwrap();
            let policy = Policy::from_native_path(&path).unwrap();
            assert_eq!(destination(&policy, "alice", &subject).unwrap(), Some(true));
        }
    }
    #[test]
    fn debian_ordering_keeps_epoch_revision_backports_and_tilde() {
        for (old, new) in [
            ("1.0~rc1-1", "1.0-1"),
            ("1.0-1", "1.0-1+deb13u1"),
            ("2:1.0-1", "3:0.1-1"),
            ("1.0-1~bpo13+1", "1.0-1"),
            ("1.9", "1.10"),
        ] {
            assert!(debian_compare(old, new).is_lt(), "{old} < {new}");
        }
        assert!(debian_compare("01:1.0-01", "1:1.0-1").is_eq());
    }
}
