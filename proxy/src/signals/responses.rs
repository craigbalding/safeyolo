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
    inventory_max_age_seconds: Option<u64>,
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
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
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
            || (rule.inventory.is_some()
                && rule.inventory_max_age_seconds.is_none_or(|age| age == 0))
        {
            return Err(
                "inventory needs an absolute host-owned path and positive freshness limit".into(),
            );
        }
        match &rule.response {
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

/// Inventory checks attest effective state, not saved desired packages. This
/// record is host-selected, freshness-bounded and bound to the current agent run.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    agent_id: String,
    run_id: String,
    observed_at: u64,
    distribution: String,
    packages: BTreeMap<String, String>,
    services: Vec<String>,
}

fn applicability(
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
    if let Some(file) = &rule.inventory {
        let Some(value) = crate::guest_commands::read_state_bounded(file, 1024 * 1024)? else {
            return Ok(None);
        };
        let inventory: Inventory = serde_json::from_value(value)?;
        let Some(run) = policy.agent_run(agent) else {
            return Ok(None);
        };
        if inventory.agent_id != agent_id
            || inventory.run_id != run.run_id
            || inventory.observed_at > now()
            || now() - inventory.observed_at
                >= rule
                    .inventory_max_age_seconds
                    .expect("validated inventory age")
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
                Ok(match inventory.packages.get(name) {
                    None => Some(false), // The adopted record is a complete effective inventory.
                    Some(version) => valid_debian_version(version)
                        .then(|| debian_compare(version, fixed_version).is_lt()),
                })
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
        if let Some(file) = &rule.inventory {
            if let Ok(Some(value)) = crate::guest_commands::read_state_bounded(file, 1024 * 1024) {
                if let Some(deadline) = value["observed_at"].as_u64().and_then(|at| {
                    rule.inventory_max_age_seconds
                        .map(|age| at.saturating_add(age))
                }) {
                    if deadline > now() {
                        next_due = next_due.min(deadline);
                    }
                }
            }
        }
        for agent in &rule.agents {
            let mut selected = Vec::new();
            let mut unknown = accepted.is_empty();
            let mut inactive = false;
            for record in &accepted {
                let update = &record.update;
                let Evidence::Advisory {
                    distribution,
                    severity,
                    ..
                } = &update.evidence
                else {
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
                match applicability(rule, agent, update, &policy, &services) {
                    Ok(Some(true)) => selected.push(update.clone()),
                    Ok(Some(false)) => {
                        inactive = true;
                    }
                    Ok(None) | Err(_) => {
                        unknown = true;
                    }
                }
            }
            let mut reaction = read(&root, rule_name, agent)?;
            let active = !selected.is_empty();
            let retain = !active
                && if unknown {
                    rule.on_stale == Inactive::Retain
                } else {
                    rule.on_inactive == Inactive::Retain
                };
            let scope = effect_scope(&root, rule, &policy)?;
            let dispatch_findings = (!matches!(rule.response, Response::List { .. })).then(|| {
                selected
                    .iter()
                    .map(|u| (&u.id, u.revision))
                    .collect::<Vec<_>>()
            });
            let identity = digest(&json!([
                rule,
                source.source_id,
                (rule.authority == Authority::Approval).then(|| digest(source)),
                scope,
                dispatch_findings,
                policy.evidence_agent_id(agent),
                policy.agent_run(agent),
                active
            ]));
            let current = json!({"rule":rule_name,"agent":agent,"source":rule.source,"affected":active,
                "applicability":if unknown {"unknown_or_stale"} else if active {"affected"} else {"unaffected"},
                "findings":selected,"authority":rule.authority,"inactive_evidence":inactive,
                "effect":rule.response,"effect_scope":scope,"observed_at":now()});
            save(
                &path(&root, rule_name, agent).with_extension("status.json"),
                &current,
            )?;
            if retain {
                continue;
            }
            if reaction.identity == identity && reaction.status == "applied" {
                next_due = next_due.min(now() + 1);
                if let Response::List { feeds, .. } = &rule.response {
                    let active = policy.native_list_file_status().values().any(|status| {
                        status["active_snapshot"]["source"] == feeds[agent]
                            && status["saved_matches_active"] == true
                    });
                    if active {
                        reaction.status = "verified".into();
                        reaction.result["network_activation"] = json!(
                            "running policy captured the complete local snapshot; new admissions use it"
                        );
                        save(&path(&root, rule_name, agent), &reaction)?;
                    }
                }
                continue;
            }
            if reaction.identity == identity
                && matches!(
                    reaction.status.as_str(),
                    "verified" | "dispatched" | "notified" | "rejected" | "failed" | "uncertain"
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
            if active && rule.authority == Authority::Approval {
                next_due = next_due.min(now() + 1);
                let action = json!({"kind":"signal_response","rule":rule_name,"agent":agent,
                    "agent_id":policy.evidence_agent_id(agent),"basis":digest(rule),"identity":identity,
                    "source_basis":digest(source),
                    "effect_scope":scope,
                    "findings":selected.iter().map(|u|(&u.id,u.revision)).collect::<Vec<_>>()});
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
                            .expect("active findings");
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
                if record.authority.action["findings"] != action["findings"] {
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
                    continue;
                }
                reaction.approval_id = Some(record.approval_id.clone());
                reaction.status = match record.current_status(&policy)?.as_str() {
                    "approved" => "approved",
                    "pending" => "pending_approval",
                    "rejected" => "rejected",
                    _ => "superseded",
                }
                .into();
                save(&path(&root, rule_name, agent), &reaction)?;
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
        })
    }) {
        return Err("signal evidence changed before response; no effect was requested".into());
    }
    match &rule.response {
        Response::List { feeds, body } => {
            let _lock = approvals::lock_policy(&root.join("policy.toml"))?;
            let update = Update {
                source_id: "local-response".into(),
                id: rule_name.into(),
                revision: reaction.episode,
                // This is the time of the local desired-state decision. The
                // originating evidence keeps its own age in the selection.
                observed_at: now(),
                expires_at: selected
                    .iter()
                    .map(|u| u.expires_at)
                    .min()
                    .unwrap_or(now() + 1),
                withdrawn: selected.is_empty(),
                evidence_refs: vec![],
                evidence: Evidence::List { body: body.clone() },
            };
            crate::policy_feeds::adopt_signal(root, &feeds[agent], &update, body)?;
            Ok((
                "applied",
                json!({"effect":"complete_local_list_snapshot","feed":feeds[agent],"membership_active":!selected.is_empty(),"network_activation":"policy watcher; applies to new admissions only"}),
            ))
        }
        _ if selected.is_empty() => Ok((
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
                &[assignee.clone()],
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
        let body = serde_json::to_string(
            &json!({"source":"adopted_signal_rule","rule":rule_name,"affected_agent":agent,"findings":selected,
            "requirement":requirement,"authority":"Evidence and notification grant no execution authority. Execute only within the adopted owner policy."}),
        )?;
        let prepared = coord
            .prepare_for_agent_ids(room, &body, "text/plain", recipients)
            .await?;
        reaction.result = json!({"prepared":prepared});
        save(&path(root, rule_name, agent), reaction)?;
        prepared
    };
    Ok(coord.publish_prepared(room, &prepared).await?)
}

pub(crate) fn approval_revision(policy: &Policy, action: &Value) -> Option<String> {
    let root = policy.source_path()?.parent()?;
    let config = configuration(root).ok()?;
    let rule = config.rules.get(action["rule"].as_str()?)?;
    let agent = action["agent"].as_str()?;
    let scope = effect_scope(root, rule, policy).ok()?;
    (digest(rule) == action["basis"]
        && digest(config.sources.get(&rule.source)?) == action["source_basis"]
        && scope == action["effect_scope"]
        && rule.agents.iter().any(|a| a == agent)
        && rule.authority == Authority::Approval
        && policy.evidence_agent_id(agent) == action["agent_id"].as_str())
    .then(|| {
        digest(&json!([
            rule,
            scope,
            policy.evidence_agent_id(agent),
            policy.agent_run(agent)
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
        let valid=action["findings"].as_array().is_some_and(|findings|findings.iter().all(|finding|current.iter().any(|a|
            a.update.id==finding[0] && json!(a.update.revision)==finding[1] && !a.update.withdrawn && a.update.fresh(source,now())
        )));
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
    for (name, rule) in config.rules {
        for agent in rule.agents {
            responses.push(json!({"rule":name,"agent":agent,"response":read(root,&name,&agent)?,
            "selection":crate::guest_commands::read_state(&path(root,&name,&agent).with_extension("status.json"))?}));
        }
    }
    Ok(json!(responses))
}

#[cfg(test)]
mod tests {
    use super::*;
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
