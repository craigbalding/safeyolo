//! Checked early stop is bound to current canonical Work, not an idle model.
use super::*;
use crate::{
    coord_rooms::work,
    policy::checks::{Subject, Truth},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation_id: String,
    shutdown_work_id: String,
}

// Work's immutable external reference identifies this finite lifecycle action.
// It cannot turn an existing ordinary assignment into an excluded shutdown item.
const SELF_STOP_REF: &str = "safeyolo:lifecycle/self-stop";

fn receipt(conn: &Connection, agent: &str, id: &str) -> Result<Option<(String, Value)>, Error> {
    conn.query_row("SELECT a.request_hash,COALESCE(r.outcome_json,a.outcome_json) FROM coord_operations a LEFT JOIN coord_operations r ON r.principal_kind=a.principal_kind AND r.principal_id=a.principal_id AND r.operation_id=a.operation_id AND r.operation_type='lifecycle_self_stop_result' WHERE a.principal_kind='agent' AND a.principal_id=?1 AND a.operation_type='lifecycle_self_stop' AND a.operation_id=?2",
        params![agent,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))
        .optional()?.map(|(hash,text)|Ok((hash,serde_json::from_str(&text)?))).transpose()
}

pub(super) async fn request(
    state: &RuntimeState,
    run: &crate::host_runs::AgentRun,
    input: Value,
) -> Result<Value, Error> {
    let request: Request = serde_json::from_value(input).map_err(|_| {
        crate::peer_support::refuse(400, "supply operation_id and shutdown_work_id only")
    })?;
    if !crate::peer_support::operations::valid_operation_id(&request.operation_id) {
        return Err(crate::peer_support::refuse(
            400,
            "supply a valid original operation_id",
        ));
    }
    let policy = crate::peer_support::current_policy(state)?;
    if !run.current(&policy) {
        return Err(crate::peer_support::refuse(
            403,
            "trusted current-run self-stop requester required",
        ));
    }
    let root = host_platform::config_dir();
    let mut conn = coord_rooms::open(&root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let hash = crate::policy::checks::content_digest(&serde_json::to_vec(&request)?);
    if let Some((original, value)) = receipt(&tx, &run.agent_id, &request.operation_id)? {
        if original != hash {
            return Err(crate::peer_support::refuse(
                409,
                "operation_id already identifies a different self-stop request",
            ));
        }
        return Ok(value);
    }
    let mut current = load(&tx, &run.agent_id)?
        .ok_or_else(|| crate::peer_support::refuse(409, "no active configured lifecycle"))?;
    if current["run_id"] != run.run_id
        || current["phase"] != "active"
        || current["stop_request"]
            .get("status")
            .is_some_and(|s| s == "accepted" || s == "checking")
    {
        return Err(crate::peer_support::refuse(
            409,
            "worker activation changed, closed or already has a pending stop request",
        ));
    }
    let config: Configuration = serde_json::from_value(current["configuration"].clone())?;
    let room = config.completion_room.ok_or_else(|| {
        crate::peer_support::refuse(
            403,
            "checked completion stop was not selected for this activation",
        )
    })?;
    let room_id = work::authorize(&tx, &room, work::Actor::Agent(&run.agent_id), true)?;
    let shutdown: Value = serde_json::from_str(&tx.query_row(
        "SELECT document_json FROM coord_work WHERE room_id=?1 AND work_id=?2",
        params![room_id, request.shutdown_work_id],
        |r| r.get::<_, String>(0),
    )?)?;
    if shutdown["claim_agent_id"] != run.agent_id
        || shutdown["state"] != "claimed"
        || shutdown["assignee"]["id"] != run.agent_id
        || shutdown["check"].is_object()
        || shutdown["challenge"].is_object()
        || shutdown["created_by"] != json!({"kind":"agent","id":run.agent_id})
        || shutdown["external_ref"] != SELF_STOP_REF
    {
        return Err(crate::peer_support::refuse(
            409,
            "shutdown Work must be self-created, self-assigned and claimed with external_ref=safeyolo:lifecycle/self-stop in the configured completion room",
        ));
    }
    if current["completion_room_id"] != room_id {
        return Err(crate::peer_support::refuse(
            409,
            "completion room identity changed",
        ));
    }
    let result = json!({"operation_id":request.operation_id,"status":"accepted","agent_id":run.agent_id,
        "run_id":run.run_id,"activation_id":current["activation_id"],
        "shutdown_work_id":request.shutdown_work_id,"requested_at":now(),
        "meaning":"Request retained. This does not prove checked completion or sandbox shutdown."});
    tx.execute("INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('agent',?1,'lifecycle_self_stop',?2,?3,'accepted',?4,?5)",
        params![run.agent_id,request.operation_id,hash,result.to_string(),now()])?;
    current["stop_request"] = result.clone();
    save(&tx, &run.agent_id, &current)?;
    tx.commit()?;
    Ok(result)
}

pub(super) fn read(root: &Path, agent: &str, id: &str) -> Result<Value, Error> {
    receipt(&coord_rooms::open(root)?, agent, id)?
        .map(|(_, v)| v)
        .ok_or_else(|| {
            crate::peer_support::refuse(404, "self-stop request not found for this worker")
        })
}

fn scope_work(
    conn: &Connection,
    agent: &Agent,
    room: &str,
    cursor: i64,
    policy: &crate::policy::Policy,
) -> Result<Vec<(Value, bool)>, Error> {
    let mut query=conn.prepare("SELECT w.document_json,EXISTS(SELECT 1 FROM coord_attention_edges e WHERE e.recipient_agent_id=?1 AND e.kind='work_changed' AND e.object_id=w.work_id AND e.feed_sequence>?3) FROM coord_work w WHERE w.room_id=?2 ORDER BY w.work_id")?;
    let rows = query
        .query_map(params![agent.id, room, cursor], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let participant = work::subjects::Principal {
        kind: "agent".into(),
        id: agent.id.clone(),
    };
    let mut works = Vec::new();
    for (text, changed) in rows {
        let work: work::Work = serde_json::from_str(&text)?;
        let actions: Vec<_> = work::actions::for_work(conn, &work, work::Actor::Agent(&agent.id))?
            .into_iter()
            .filter(|action| action.requires_action)
            .collect();
        // Retain assigned execution and review scope, including completed work.
        // Canonical actions also cover decision roles without an execution claim.
        if work.assignee.as_ref() != Some(&participant)
            && work.claim_agent_id.as_deref() != Some(&agent.id)
            && !work
                .check
                .as_ref()
                .is_some_and(|c| c.reviewer == participant)
            && !work
                .challenge
                .as_ref()
                .is_some_and(|c| c.responder == participant || c.deciders.contains(&participant))
            && !work
                .acceptance_requirements
                .as_ref()
                .is_some_and(|r| r.deciders.contains(&participant))
            && actions.is_empty()
        {
            continue;
        }
        let mut described = work::describe_with_policy(conn, work, Some(policy))?;
        described["required_actions"] = serde_json::to_value(actions)?;
        works.push((described, changed));
    }
    Ok(works)
}

pub(super) fn initial_scope(
    conn: &Connection,
    agent: &Agent,
    config: &Configuration,
    room_id: &str,
    policy: &crate::policy::Policy,
) -> Result<(Vec<String>, i64), Error> {
    let room = work::authorize(
        conn,
        config
            .completion_room
            .as_deref()
            .ok_or("completion room missing")?,
        work::Actor::Agent(&agent.id),
        true,
    )?;
    if room != room_id {
        return Err("completion room identity changed".into());
    }
    let cursor = conn
        .query_row(
            "SELECT last_sequence FROM coord_attention_feeds WHERE recipient_agent_id=?1",
            [&agent.id],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    let mut ids = Vec::new();
    for (work, _) in scope_work(conn, agent, room_id, cursor, policy)? {
        if !execution_and_acceptance_complete(&work) {
            ids.push(
                work["work_id"]
                    .as_str()
                    .ok_or("Work identity missing")?
                    .into(),
            );
        }
    }
    Ok((ids, cursor))
}

fn snapshot(
    conn: &Connection,
    agent: &Agent,
    current: &Value,
    policy: &crate::policy::Policy,
) -> Result<Value, Error> {
    let room = current["completion_room_id"]
        .as_str()
        .ok_or("completion room identity missing")?;
    let shutdown = current["stop_request"]["shutdown_work_id"]
        .as_str()
        .ok_or("shutdown Work missing")?;
    let initial = current["initial_work_ids"]
        .as_array()
        .ok_or("activation scope references missing")?;
    let cursor = current["work_attention_at_activation"]
        .as_i64()
        .ok_or("activation attention reference missing")?;
    let mut works = Vec::new();
    let config: Configuration = serde_json::from_value(current["configuration"].clone())?;
    for (work, changed) in scope_work(conn, agent, room, cursor, policy)? {
        let id = work["work_id"].as_str().ok_or("Work identity missing")?;
        if id == shutdown
            || config
                .completion_excluded_work_ids
                .iter()
                .any(|excluded| excluded == id)
            || (!changed && !initial.iter().any(|initial| initial == id))
        {
            continue;
        }
        works.push(work);
    }
    Ok(json!({"agent_id":agent.id,"run_id":current["run_id"],
        "activation_id":current["activation_id"],"configuration_revision":current["configuration_revision"],
        "room_id":room,"excluded_shutdown_work_id":shutdown,
        "excluded_future_work_ids":config.completion_excluded_work_ids,"work":works}))
}

fn execution_and_acceptance_complete(work: &Value) -> bool {
    work["required_actions"]
        .as_array()
        .is_some_and(Vec::is_empty)
        && (work["state"] == "cancelled"
            || (work["state"] == "done"
                && (work["acceptance_requirements"].is_null()
                    || work["acceptance_status"]["state"] == "accepted")))
}

fn complete(scope: &Value) -> bool {
    scope["work"]
        .as_array()
        .is_some_and(|works| works.iter().all(execution_and_acceptance_complete))
}

fn finish(agent: &Agent, request: &Value, status: &str, result: Value) -> Result<(), Error> {
    let mut conn = coord_rooms::open(&host_platform::config_dir())?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let id = request["operation_id"]
        .as_str()
        .ok_or("self-stop operation missing")?;
    let (request_hash, mut view) =
        receipt(&tx, &agent.id, id)?.ok_or("self-stop receipt disappeared")?;
    view["status"] = json!(status);
    view["result"] = result;
    view["observed_at"] = json!(now());
    tx.execute("INSERT OR IGNORE INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('agent',?1,'lifecycle_self_stop_result',?2,?3,?4,?5,?6)",
        params![agent.id,id,request_hash,status,view.to_string(),now()])?;
    let receipt = receipt(&tx, &agent.id, id)?
        .ok_or("self-stop result disappeared")?
        .1;
    if let Some(mut current) = load(&tx, &agent.id)?
        && current["stop_request"]["operation_id"] == id
    {
        current["stop_request"] = receipt;
        save(&tx, &agent.id, &current)?;
    }
    tx.commit()?;
    Ok(())
}

pub(super) fn interrupted(agent: &Agent, request: &Value) -> Result<(), Error> {
    finish(
        agent,
        request,
        "unverified",
        json!({"reason":"Host lifecycle execution was interrupted. Inspect this original request and the actual worker before another effect; no automatic retry was selected."}),
    )
}

pub(super) async fn execute(
    state: &RuntimeState,
    agent: &Agent,
    initial: &Value,
) -> Result<(), Error> {
    let result = checked_stop(state, agent, initial).await;
    let request = &initial["stop_request"];
    match result {
        Ok(value) => finish(
            agent,
            request,
            if value["runtime_state"] == "stopped" {
                "stopped"
            } else {
                "refused"
            },
            result_without_lifecycle(&value),
        ),
        Err(error) => finish(
            agent,
            request,
            "unverified",
            json!({"error":error.to_string(),
            "next_action":"Inspect the original lifecycle request and current worker diagnostics before submitting another stop request."}),
        ),
    }
}

async fn checked_stop(
    state: &RuntimeState,
    agent: &Agent,
    initial: &Value,
) -> Result<Value, Error> {
    let root = host_platform::config_dir();
    let policy = crate::peer_support::current_policy(state)?;
    let caller = crate::host_runs::AgentRun {
        agent: agent.name.clone(),
        agent_id: agent.id.clone(),
        run_id: initial["run_id"]
            .as_str()
            .ok_or("self-stop run missing")?
            .into(),
    };
    if !caller.current(&policy) {
        return Err("self-stop requester is no longer the current worker run".into());
    }
    let authority = policy.work_authority_digest();
    let config: Configuration = serde_json::from_value(initial["configuration"].clone())?;
    let conn = coord_rooms::open(&root)?;
    let room = config
        .completion_room
        .as_deref()
        .ok_or("completion room missing")?;
    work::authorize(&conn, room, work::Actor::Agent(&agent.id), true)?;
    let scope = snapshot(&conn, agent, initial, &policy)?;
    if !complete(&scope) {
        return Ok(
            json!({"state":"refused","reason":"current scoped Work has unfinished execution, required native actions or required acceptance","scope":scope}),
        );
    }
    let name = config
        .completion_check
        .as_ref()
        .ok_or("completion check missing")?;
    let condition = config
        .completion_require
        .as_ref()
        .ok_or("completion predicate missing")?;
    let subject = Subject::Value {
        value: scope.to_string(),
    };
    let runtime = state.read().map_err(|_| "runtime unavailable")?.clone();
    let evidence = policy
        .named_checks()
        .invoke_challenge(name, subject.clone(), &runtime, state)
        .await?;
    if policy
        .named_checks()
        .named_truth(name, condition, &subject, evidence.clone(), now() as u64)
        != Truth::True
    {
        return Ok(
            json!({"state":"refused","reason":"adopted completion check failed or is unavailable","evidence":evidence}),
        );
    }
    let lock = SetupLock::acquire_in_async(&root.join("agents").join(&agent.name)).await?;
    let current_policy = crate::peer_support::current_policy(state)?;
    if current_policy.work_authority_digest() != authority {
        return Err("adopted authority changed while the completion check was pending".into());
    }
    if current_policy.named_checks().named_truth(
        name,
        condition,
        &subject,
        evidence.clone(),
        now() as u64,
    ) != Truth::True
    {
        return Err("completion evidence expired before scope closure".into());
    }
    if !close_scope(
        &root,
        agent,
        initial,
        &current_policy,
        &scope,
        &serde_json::to_value(evidence)?,
    )? {
        return Ok(
            json!({"state":"refused","reason":"work scope, worker run or stop request changed during its check"}),
        );
    }
    let guard = || {
        if !caller.current(&crate::peer_support::current_policy(state)?) {
            return Err("self-stop requester authority changed".into());
        }
        let run = crate::host_runs::read(&agent.name)?.ok_or("current sandbox run missing")?;
        if run["agent_id"] != agent.id || run["run_id"] != initial["run_id"] {
            return Err("checked shutdown cannot stop a replacement run".into());
        }
        Ok(())
    };
    super::super::stop_authorized(agent, Some(lock), &guard).await
}

fn close_scope(
    root: &Path,
    agent: &Agent,
    initial: &Value,
    policy: &crate::policy::Policy,
    scope: &Value,
    evidence: &Value,
) -> Result<bool, Error> {
    let mut conn = coord_rooms::open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut current = load(&tx, &agent.id)?.ok_or("lifecycle receipt disappeared")?;
    let config: Configuration = serde_json::from_value(current["configuration"].clone())?;
    let room = work::authorize(
        &tx,
        config
            .completion_room
            .as_deref()
            .ok_or("completion room missing")?,
        work::Actor::Agent(&agent.id),
        true,
    )?;
    if current["completion_room_id"] != room {
        return Ok(false);
    }
    if current["phase"] != "active"
        || current["run_id"] != initial["run_id"]
        || current["activation_id"] != initial["activation_id"]
        || current["stop_request"]["operation_id"] != initial["stop_request"]["operation_id"]
        || !complete(scope)
        || snapshot(&tx, agent, &current, policy)? != *scope
    {
        return Ok(false);
    }
    current["phase"] = json!("closing");
    current["closed_at"] = json!(now());
    current["stop_reason"] = json!("checked_completion");
    current["checked_scope"] = scope.clone();
    current["completion_evidence"] = evidence.clone();
    save(&tx, &agent.id, &current)?;
    tx.commit()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{change, work_fixture};
    use super::*;

    fn worker_policy(root: &Path) -> (Agent, crate::policy::Policy) {
        let path = root.join("policy.toml");
        std::fs::write(
            &path,
            "[controls.network]\nenabled=false\n[agents.worker]\nagent_id='worker'\n",
        )
        .unwrap();
        let policy = crate::policy::Policy::from_native_path(&path).unwrap();
        let agent = Agent {
            name: "worker".into(),
            id: "worker".into(),
            folder: None,
            launcher: None,
            host_script: None,
            memory_mb: None,
            rootfs_overlay: None,
            nested_docker: false,
            user_default_args: vec![],
            mounts: vec![],
            dangerously_allow_unowned: false,
            lifecycle: None,
        };
        (agent, policy)
    }

    fn act(conn: &mut Connection, who: &str, input: Value, op: &str) -> Value {
        work::mutate(
            None,
            conn,
            "work",
            work::Actor::Agent(who),
            serde_json::from_value(input).unwrap(),
            Some(op),
        )
        .unwrap()["work"]
            .clone()
    }

    fn activation(
        conn: &Connection,
        agent: &Agent,
        policy: &crate::policy::Policy,
        shutdown: &Value,
    ) -> Value {
        let config = json!({"mode":"on_demand","completion_room":"work","completion_check":"done",
            "completion_require":{"op":"finding","check":"done"}});
        let (ids, cursor) = initial_scope(
            conn,
            agent,
            &configuration(&config).unwrap(),
            "rm-work",
            policy,
        )
        .unwrap();
        let initial = json!({"agent_id":"worker","run_id":"run-a","activation_id":"activation-a",
            "configuration_revision":"revision-a","phase":"active","configuration":config,"completion_room_id":"rm-work",
            "initial_work_ids":ids,"work_attention_at_activation":cursor,
            "stop_request":{"operation_id":"stop-op","shutdown_work_id":shutdown["work_id"]}});
        save(conn, "worker", &initial).unwrap();
        initial
    }

    fn finish_task(conn: &mut Connection, work: &Value, prefix: &str) -> Value {
        let claimed = change(
            conn,
            json!({"action":"claim","work_id":work["work_id"],
            "expected_version":work["version"],"expected_generation":work["claim_generation"]}),
            &format!("{prefix}-claim"),
        )["work"]
            .clone();
        change(
            conn,
            json!({"action":"complete","work_id":work["work_id"],"expected_version":claimed["version"],
            "expected_generation":claimed["claim_generation"],"short_result":"Completed"}),
            &format!("{prefix}-complete"),
        )
    }
    #[test]
    fn exact_scope_excludes_only_shutdown_and_selected_future_work_and_refuses_arrivals() {
        let root = work_fixture();
        let (agent, policy) = worker_policy(root.path());
        let mut conn = coord_rooms::open(root.path()).unwrap();
        let make = |conn: &mut Connection, title: &str, op: &str| {
            change(
                conn,
                json!({"action":"create","title":title,
            "assignee":{"kind":"agent","id":"worker"}}),
                op,
            )["work"]
                .clone()
        };
        let first = make(&mut conn, "Actual task", "first");
        let shutdown = make(&mut conn, "Self-stop", "stop");
        let future = make(&mut conn, "Future backlog", "future");
        let history = make(&mut conn, "Completed earlier activation", "history");
        finish_task(&mut conn, &history, "history");
        let config = json!({"mode":"on_demand","completion_room":"work","completion_check":"done",
            "completion_require":{"op":"finding","check":"done"},"completion_excluded_work_ids":[future["work_id"]]});
        let (ids, cursor) = initial_scope(
            &conn,
            &agent,
            &configuration(&config).unwrap(),
            "rm-work",
            &policy,
        )
        .unwrap();
        assert!(
            !ids.iter()
                .any(|id| id == history["work_id"].as_str().unwrap())
        );
        let initial = json!({"agent_id":"worker","run_id":"run-a","activation_id":"activation-a",
            "configuration_revision":"revision-a","phase":"active","configuration":config,"completion_room_id":"rm-work",
            "initial_work_ids":ids,"work_attention_at_activation":cursor,
            "stop_request":{"operation_id":"stop-op","shutdown_work_id":shutdown["work_id"]}});
        save(&conn, "worker", &initial).unwrap();
        let scope = snapshot(&conn, &agent, &initial, &policy).unwrap();
        assert_eq!(scope["work"].as_array().unwrap().len(), 1);
        assert_eq!(scope["work"][0]["work_id"], first["work_id"]);
        assert!(
            !complete(&scope),
            "unfinished scoped Work must refuse early stop"
        );
        finish_task(&mut conn, &first, "first");
        let scope = snapshot(&conn, &agent, &initial, &policy).unwrap();
        assert!(complete(&scope));
        let mut pending = scope.clone();
        pending["work"][0]["acceptance_requirements"] = json!({"version":1});
        pending["work"][0]["acceptance_status"] = json!({"state":"pending"});
        assert!(
            !complete(&pending),
            "execution completion cannot replace selected acceptance"
        );
        let arrival = make(&mut conn, "Arrived while the check ran", "arrival");
        assert!(
            !close_scope(
                root.path(),
                &agent,
                &initial,
                &policy,
                &scope,
                &json!({"check":"done"})
            )
            .unwrap()
        );
        assert_eq!(
            retained(root.path(), "worker").unwrap().unwrap()["phase"],
            "active"
        );
        finish_task(&mut conn, &arrival, "arrival");
        let scope = snapshot(&conn, &agent, &initial, &policy).unwrap();
        assert!(
            close_scope(
                root.path(),
                &agent,
                &initial,
                &policy,
                &scope,
                &json!({"check":"done"})
            )
            .unwrap()
        );
        assert_eq!(
            retained(root.path(), "worker").unwrap().unwrap()["phase"],
            "closing"
        );
        conn.execute(
            "UPDATE memberships SET permissions='receive' WHERE principal_id='worker'",
            [],
        )
        .unwrap();
        assert!(
            close_scope(root.path(), &agent, &initial, &policy, &scope, &Value::Null).is_err(),
            "scope closure must recheck current room authority"
        );
    }

    #[test]
    fn native_decisions_block_scope_closure_until_their_named_mutations_settle_them() {
        for kind in [
            "decide_acceptance",
            "resolve_challenge",
            "cancelled_challenge",
        ] {
            for arrives_during_check in [false, true] {
                let root = work_fixture();
                let (agent, policy) = worker_policy(root.path());
                let mut conn = coord_rooms::open(root.path()).unwrap();
                for who in ["producer", "other-decider"] {
                    conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-work','agent',?1,'send,receive',1)", [who]).unwrap();
                }
                let shutdown = act(
                    &mut conn,
                    "worker",
                    json!({"action":"create","title":"Self-stop",
                    "assignee":{"kind":"agent","id":"worker"}}),
                    "shutdown",
                );
                let mut output = act(
                    &mut conn,
                    "producer",
                    json!({"action":"create","title":"Another worker's output",
                    "assignee":{"kind":"agent","id":"producer"}}),
                    "create-output",
                );
                output = act(
                    &mut conn,
                    "producer",
                    json!({"action":"claim","work_id":output["work_id"],
                    "expected_version":output["version"],"expected_generation":0}),
                    "claim-output",
                );
                output = act(
                    &mut conn,
                    "producer",
                    json!({"action":"publish_output","work_id":output["work_id"],
                    "expected_version":output["version"],"expected_generation":1,"expected_target_generation":0,
                    "target_ref":"artifact:decision-proof","execution_outcome":"succeeded","summary":"Retained output","evidence_refs":[]}),
                    "publish-output",
                );
                output = act(
                    &mut conn,
                    "producer",
                    json!({"action":"complete","work_id":output["work_id"],
                    "expected_version":output["version"],"expected_generation":1}),
                    "complete-output",
                );

                let before = activation(&conn, &agent, &policy, &shutdown);
                let checked = snapshot(&conn, &agent, &before, &policy).unwrap();
                assert!(complete(&checked));
                let decision = if kind == "decide_acceptance" {
                    output = act(
                        &mut conn,
                        "producer",
                        json!({"action":"set_requirements","work_id":output["work_id"],
                        "expected_version":output["version"],"expected_generation":1,"expected_requirements_version":0,
                        "authorities":[{"kind":"agent","id":"producer"}],
                        "deciders":[{"kind":"agent","id":"worker"},{"kind":"agent","id":"other-decider"}],
                        "independent":true,"checks":[],"challenges":[],"reason":"Select independent decisions"}),
                        "requirements",
                    );
                    // Global acceptance can pass while this worker still owes its own decision.
                    act(
                        &mut conn,
                        "other-decider",
                        json!({"action":"decide_acceptance","work_id":output["work_id"],
                        "expected_version":output["version"],"expected_generation":1,"expected_requirements_version":1,
                        "expected_target_generation":1,"verdict":"approve","summary":"Inspected the exact output"}),
                        "other-approval",
                    )
                } else {
                    let mut challenge = act(
                        &mut conn,
                        "other-decider",
                        json!({"action":"raise_challenge",
                        "subject":{"kind":"output","work_id":output["work_id"],"target_generation":1},
                        "assertion":"Output needs disposition","grounds":"Independent result questioned","evidence_refs":[],
                        "responder":{"kind":"agent","id":"producer"},"deciders":[{"kind":"agent","id":"worker"}],
                        "independent":true}),
                        "challenge",
                    );
                    if kind == "cancelled_challenge" {
                        act(
                            &mut conn,
                            "other-decider",
                            json!({"action":"cancel","work_id":challenge["work_id"],
                            "expected_version":challenge["version"],"expected_generation":0,"reason":"Response cancelled; disposition still required"}),
                            "cancel-response",
                        )
                    } else {
                        challenge = act(
                            &mut conn,
                            "producer",
                            json!({"action":"claim","work_id":challenge["work_id"],
                            "expected_version":challenge["version"],"expected_generation":0}),
                            "claim-response",
                        );
                        act(
                            &mut conn,
                            "producer",
                            json!({"action":"respond_challenge","work_id":challenge["work_id"],
                            "expected_version":challenge["version"],"expected_generation":1,"summary":"Response retained","evidence_refs":[]}),
                            "respond",
                        )
                    }
                };
                let initial = if arrives_during_check {
                    assert!(
                        !close_scope(
                            root.path(),
                            &agent,
                            &before,
                            &policy,
                            &checked,
                            &Value::Null
                        )
                        .unwrap(),
                        "new {kind} must invalidate the earlier completed scope"
                    );
                    before
                } else {
                    let initial = activation(&conn, &agent, &policy, &shutdown);
                    assert!(
                        initial["initial_work_ids"]
                            .as_array()
                            .unwrap()
                            .contains(&decision["work_id"]),
                        "initial {kind} must be retained even when execution/acceptance is complete"
                    );
                    initial
                };
                let actions = work::actions::read(
                    &mut conn,
                    "work",
                    work::Actor::Agent("worker"),
                    decision["work_id"].as_str().unwrap(),
                    true,
                )
                .unwrap();
                let action = actions["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|a| a["requires_action"] == true)
                    .unwrap();
                assert_eq!(
                    action["kind"],
                    if kind == "decide_acceptance" {
                        kind
                    } else {
                        "resolve_challenge"
                    }
                );
                act(
                    &mut conn,
                    "worker",
                    json!({"action":"receive_action","work_id":decision["work_id"],"action_key":action["key"]}),
                    "receive-decision",
                );
                let scope = snapshot(&conn, &agent, &initial, &policy).unwrap();
                assert_eq!(scope["work"][0]["work_id"], decision["work_id"]);
                assert_eq!(
                    scope["work"][0]["required_actions"][0]["kind"],
                    action["kind"]
                );
                assert!(!complete(&scope), "receiving {kind} cannot complete it");
                assert!(
                    !close_scope(root.path(), &agent, &initial, &policy, &scope, &Value::Null)
                        .unwrap()
                );
                assert_eq!(
                    retained(root.path(), "worker").unwrap().unwrap()["phase"],
                    "active"
                );

                let settle = if kind == "decide_acceptance" {
                    json!({"action":"decide_acceptance","work_id":decision["work_id"],"expected_version":decision["version"],
                        "expected_generation":decision["claim_generation"],"expected_requirements_version":1,"expected_target_generation":1,
                        "verdict":"approve","summary":"Worker independently decided"})
                } else {
                    json!({"action":"resolve_challenge","work_id":decision["work_id"],"expected_version":decision["version"],
                        "expected_generation":decision["claim_generation"],"expected_response_version":decision["challenge"]["response"]["work_version"].as_i64().unwrap_or(0),
                        "decision":"dismissed","reason":"Independent disposition retained","evidence_refs":[]})
                };
                act(&mut conn, "worker", settle, "settle-decision");
                let scope = snapshot(&conn, &agent, &initial, &policy).unwrap();
                assert_eq!(scope["work"][0]["work_id"], decision["work_id"]);
                assert_eq!(scope["work"][0]["required_actions"], json!([]));
                assert!(complete(&scope));
                assert!(
                    close_scope(root.path(), &agent, &initial, &policy, &scope, &Value::Null)
                        .unwrap()
                );
                assert_eq!(
                    retained(root.path(), "worker").unwrap().unwrap()["phase"],
                    "closing"
                );
            }
        }
    }
}
