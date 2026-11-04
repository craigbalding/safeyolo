//! Owning-host work reads, creation and explicit claim recovery.
use super::{
    Error, Path, open,
    work::{self, Actor, Mutation},
};
use serde_json::{Value, json};

pub(super) const HELP: &str = concat!(
    "safeyolo [--root ROOT] coord work create ROOM TITLE [--external-ref REF] [--operation-id ID]\nsafeyolo [--root ROOT] coord work import-github ROOM URL [--operation-id ID]\nsafeyolo [--root ROOT] coord work list ROOM [--state open|claimed|done|cancelled] [--after WORK_ID] [--limit N]\nsafeyolo [--root ROOT] coord work show ROOM WORK_ID\nsafeyolo [--root ROOT] coord work release ROOM WORK_ID --expected-version N --expected-generation N [--operation-id ID]\nsafeyolo [--root ROOT] coord work complete ROOM WORK_ID --expected-version N --expected-generation N [--short-result TEXT] [--operation-id ID]\nsafeyolo [--root ROOT] coord work reassign ROOM WORK_ID --agent-id AGENT_ID --expected-version N --expected-generation N [--operation-id ID]\nsafeyolo [--root ROOT] coord work cancel ROOM WORK_ID --expected-version N --expected-generation N --reason TEXT [--operation-id ID]\nsafeyolo [--root ROOT] coord work attest ROOM WORK_ID --target-generation N --kind KIND --verdict approve|reject|abstain --summary TEXT [--evidence-refs JSON_ARRAY] [--operation-id ID]\nsafeyolo [--root ROOT] coord work attestations ROOM WORK_ID [--after ATTESTATION_ID] [--limit N]\nsafeyolo [--root ROOT] coord work outputs ROOM WORK_ID [--after-version N] [--limit N]\n\nUse the owning host account. Agents claim through claim_work using their authenticated durable ID. Reassign can claim open work, replace a holder or reopen done/cancelled work; release explicitly removes a claim. Time and process liveness never transfer ownership. Each claim or reassignment increments claim_generation. All changes increment version. Repeat an operation ID with its original inputs to recover an ambiguous result; changed input conflicts. Current room authority is checked on every agent read or mutation, including retries. Work changes notify current receive-authorized agents except the agent actor. Attention resolves the original immutable work version. Canonical work input is bounded to 262144 UTF-8 bytes. Lists return up to 200 items ordered by work_id; next_after is a continuation value, not a snapshot across pages. external_ref and target_ref remain opaque to local work operations. import-github validates a GitHub issue or pull request HTTPS URL and seeds local work without network access. Agents can use read_github_work for separate, read-only external metadata through their own GitHub service grant. GitHub state never changes local claims, completion or targets. target_ref is never fetched. New work has no candidate (target_generation=0). The holder uses publish_work_output to atomically select a retained immutable target_ref and attributed execution outcome. Publication requires expected version, claim generation and target generation. It advances target_generation and leaves work completion separate. A retained holder may correct done work; another producer needs operator reassignment. Earlier outputs and attestations remain readable. Integrations use the actual producer's authenticated transport; neither an arbitrary producer field nor host publication on behalf of a holder is supported. Cancellation clears ownership and advances the claim generation without reporting successful completion. Outputs lists return original publications ordered by work_version, at most 200 items and 65536 item JSON bytes, with next_after_version. Target generation is separate from claim generation. Attest uses the current target generation, without an expected work version, and derives its author from identity. It does not complete work or decide a vote. Attestation kind is nonempty and at most 128 UTF-8 bytes; summary is nonempty and at most 1024; at most 16 evidence refs of 1024 bytes each; the complete serialized record is at most 32768 bytes. target_ref is nonempty and at most 1024 UTF-8 bytes. Evidence refs are untrusted external content. Attestation lists contain at most 200 items and 65536 item JSON bytes, ordered by attestation_id with next_after; pages do not share a snapshot. --evidence-refs accepts a JSON array of strings.",
    "\n\nAssigned checks and challenges:\nsafeyolo coord work request-check ROOM --subject JSON --criterion TEXT --reviewer JSON [--independent true|false] [--external-ref REF] [--operation-id ID]\nsafeyolo coord work answer-check ROOM WORK_ID --expected-version N --expected-generation N --verdict approve|reject|abstain --summary TEXT [--evidence-refs JSON_ARRAY] [--operation-id ID]\nsafeyolo coord work raise-challenge ROOM --subject JSON --assertion TEXT --grounds TEXT --responder JSON --deciders JSON_ARRAY [--independent true|false] [--evidence-refs JSON_ARRAY] [--external-ref REF] [--operation-id ID]\nsafeyolo coord work respond-challenge ROOM WORK_ID --expected-version N --expected-generation N --summary TEXT [--correction JSON] [--evidence-refs JSON_ARRAY] [--operation-id ID]\nsafeyolo coord work resolve-challenge ROOM WORK_ID --expected-version N --expected-generation N --expected-response-version N --decision upheld|dismissed|withdrawn --reason TEXT [--evidence-refs JSON_ARRAY] [--operation-id ID]\nsafeyolo coord work recover-challenge-deciders ROOM WORK_ID --expected-version N --expected-generation N --deciders JSON_ARRAY --reason TEXT [--operation-id ID]\nsafeyolo coord work reviews ROOM WORK_ID [--after WORK_ID] [--limit N]\nsafeyolo coord work show ROOM WORK_ID [--version N]\n\nA participant is {kind:agent,id:DURABLE_ID} or {kind:operator,id:operator}, encoded as JSON. Subject JSON selects kind=work/check with work_id/version, or kind=output with work_id/target_generation. Only the named reviewer/responder may claim and answer. Independent review excludes the authenticated subject producer. Answering settles a check; responding leaves a challenge unresolved. Only named deciders or the operator can dispose a challenge. Corrections preserve history in work revisions. Optional checks/challenges do not create acceptance requirements. Review pages contain at most 200 items and 65536 item JSON bytes; use show for full records. All mutations accept operation-ID replay with original inputs; stale expectations conflict.",
    "\n\nSelected output acceptance:\nsafeyolo coord work set-requirements ROOM WORK_ID --expected-version N --expected-generation N --expected-requirements-version N --authorities JSON_ARRAY --deciders JSON_ARRAY [--independent true|false] [--checks JSON_ARRAY] [--challenges JSON_ARRAY] --reason TEXT [--operation-id ID]\nsafeyolo coord work decide-acceptance ROOM WORK_ID --expected-version N --expected-generation N --expected-requirements-version N --expected-target-generation N --verdict approve|reject|abstain --summary TEXT [--evidence-refs JSON_ARRAY] [--operation-id ID]\n\nThe creator or operator selects initial requirements (version 0). Later amendments require an existing selected authority or operator. Ownership and production alone grant no policy authority; an explicit authorized delegation can name a worker. Checks/challenges are arrays of {work_id,version} selecting current related review definitions. The operator can recover authority. Only explicitly selected deciders can decide acceptance. Approval validates required current-output checks and challenge dispositions atomically. Rejection and uncertainty remain possible with outstanding obligations. Each author has one effective decision; corrections retain immutable history. Output/context/review changes stale the affected approval. Conflicting eligible decisions require explicit correction or an authorized policy amendment. Unselected work can complete normally without implying acceptance. show includes current acceptance_status and reasons; immutable receipts describe their original revision."
);

pub(super) fn run(root: &Path, arguments: &[String]) -> Result<Value, Error> {
    let [command, room, rest @ ..] = arguments else {
        return Err(HELP.into());
    };
    let mut positional = Vec::new();
    let mut options = serde_json::Map::new();
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        if arg.starts_with("--") {
            let value = args.next().ok_or("work option requires a value")?;
            let allowed: &[&str] = match command.as_str() {
                "create" => &["--external-ref", "--operation-id"],
                "import-github" => &["--operation-id"],
                "list" => &["--state", "--after", "--limit"],
                "show" => &["--version"],
                "reviews" => &["--after", "--limit"],
                "request-check" => &[
                    "--subject",
                    "--criterion",
                    "--reviewer",
                    "--independent",
                    "--external-ref",
                    "--operation-id",
                ],
                "raise-challenge" => &[
                    "--subject",
                    "--assertion",
                    "--grounds",
                    "--evidence-refs",
                    "--responder",
                    "--deciders",
                    "--independent",
                    "--external-ref",
                    "--operation-id",
                ],
                "answer-check" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--verdict",
                    "--summary",
                    "--evidence-refs",
                    "--operation-id",
                ],
                "respond-challenge" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--summary",
                    "--evidence-refs",
                    "--correction",
                    "--operation-id",
                ],
                "resolve-challenge" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--expected-response-version",
                    "--decision",
                    "--reason",
                    "--evidence-refs",
                    "--operation-id",
                ],
                "recover-challenge-deciders" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--deciders",
                    "--reason",
                    "--operation-id",
                ],
                "set-requirements" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--expected-requirements-version",
                    "--authorities",
                    "--deciders",
                    "--independent",
                    "--checks",
                    "--challenges",
                    "--reason",
                    "--operation-id",
                ],
                "decide-acceptance" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--expected-requirements-version",
                    "--expected-target-generation",
                    "--verdict",
                    "--summary",
                    "--evidence-refs",
                    "--operation-id",
                ],
                "attestations" => &["--after", "--limit"],
                "cancel" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--reason",
                    "--operation-id",
                ],
                "outputs" => &["--after-version", "--limit"],
                "attest" => &[
                    "--target-generation",
                    "--kind",
                    "--verdict",
                    "--summary",
                    "--evidence-refs",
                    "--operation-id",
                ],
                "release" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--operation-id",
                ],
                "complete" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--short-result",
                    "--operation-id",
                ],
                "reassign" => &[
                    "--expected-version",
                    "--expected-generation",
                    "--agent-id",
                    "--operation-id",
                ],
                _ => &[],
            };
            if !allowed.contains(&arg.as_str())
                || options.contains_key(arg.trim_start_matches("--").replace('-', "_").as_str())
            {
                return Err("unknown or duplicate work option".into());
            }
            let field = arg.trim_start_matches("--").replace('-', "_");
            let value = if [
                "expected_version",
                "expected_generation",
                "expected_response_version",
                "expected_requirements_version",
                "expected_target_generation",
                "version",
                "target_generation",
                "after_version",
                "limit",
            ]
            .contains(&field.as_str())
            {
                json!(
                    value
                        .parse::<i64>()
                        .map_err(|_| "work expectation/limit must be an integer")?
                )
            } else if [
                "subject",
                "reviewer",
                "responder",
                "deciders",
                "correction",
                "evidence_refs",
                "authorities",
                "checks",
                "challenges",
            ]
            .contains(&field.as_str())
            {
                serde_json::from_str(value)?
            } else if field == "independent" {
                json!(
                    value
                        .parse::<bool>()
                        .map_err(|_| "independent must be true or false")?
                )
            } else {
                json!(value)
            };
            options.insert(field, value);
        } else {
            positional.push(arg.as_str());
        }
    }
    super::bootstrap(root)?;
    let mut conn = open(root)?;
    match (command.as_str(), positional.as_slice()) {
        ("import-github", [url]) => {
            let reference = work::github::Reference::parse(url)?;
            Ok(work::mutate(
                &mut conn,
                room,
                Actor::Operator,
                serde_json::from_value(reference.create())?,
                options.get("operation_id").and_then(Value::as_str),
            )?)
        }
        ("list", []) => Ok(work::list(
            &mut conn,
            room,
            Actor::Operator,
            options.get("after").and_then(Value::as_str).unwrap_or(""),
            options
                .get("limit")
                .map_or(Some(50), Value::as_u64)
                .ok_or("limit must be positive")? as usize,
            options.get("state").and_then(Value::as_str),
        )?),
        ("show", [id]) => match options.get("version").and_then(Value::as_i64) {
            Some(version) => Ok(work::read_at_version(
                &mut conn,
                room,
                Actor::Operator,
                id,
                version,
            )?),
            None => Ok(work::read(&mut conn, room, Actor::Operator, id)?),
        },
        ("reviews", [id]) => Ok(work::reviews::list(
            &mut conn,
            room,
            Actor::Operator,
            id,
            options.get("after").and_then(Value::as_str).unwrap_or(""),
            options
                .get("limit")
                .map_or(Some(50), Value::as_u64)
                .ok_or("limit must be positive")? as usize,
        )?),
        ("attestations", [id]) => Ok(work::attestations::list(
            &mut conn,
            room,
            Actor::Operator,
            id,
            options.get("after").and_then(Value::as_str).unwrap_or(""),
            options
                .get("limit")
                .map_or(Some(50), Value::as_u64)
                .ok_or("limit must be positive")? as usize,
        )?),
        ("outputs", [id]) => Ok(work::outputs::list(
            &mut conn,
            room,
            Actor::Operator,
            id,
            options
                .get("after_version")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            options
                .get("limit")
                .map_or(Some(50), Value::as_u64)
                .ok_or("limit must be positive")? as usize,
        )?),
        ("create", [title]) => {
            let operation = options.remove("operation_id");
            Ok(work::mutate(
                &mut conn,
                room,
                Actor::Operator,
                Mutation::Create {
                    title: (*title).into(),
                    external_ref: options
                        .get("external_ref")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                },
                operation.as_ref().and_then(Value::as_str),
            )?)
        }
        ("request-check" | "raise-challenge", []) => {
            let operation = options.remove("operation_id");
            options.insert("action".into(), json!(command.replace('-', "_")));
            Ok(work::mutate(
                &mut conn,
                room,
                Actor::Operator,
                serde_json::from_value(Value::Object(options))?,
                operation.as_ref().and_then(Value::as_str),
            )?)
        }
        (
            "release"
            | "complete"
            | "reassign"
            | "cancel"
            | "attest"
            | "answer-check"
            | "respond-challenge"
            | "resolve-challenge"
            | "recover-challenge-deciders"
            | "set-requirements"
            | "decide-acceptance",
            [id],
        ) => {
            let operation = options.remove("operation_id");
            options.insert("action".into(), json!(command.replace('-', "_")));
            options.insert("work_id".into(), json!(id));
            let mutation: Mutation = serde_json::from_value(Value::Object(options))?;
            Ok(work::mutate(
                &mut conn,
                room,
                Actor::Operator,
                mutation,
                operation.as_ref().and_then(Value::as_str),
            )?)
        }
        _ => Err(HELP.into()),
    }
}
