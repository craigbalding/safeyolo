//! Owning-host work reads, creation and explicit claim recovery.
use super::{
    Error, Path, open,
    work::{self, Actor, Mutation},
};
use serde_json::{Value, json};

pub(super) const HELP: &str = "safeyolo [--root ROOT] coord work create ROOM TITLE [--external-ref REF] [--operation-id ID]\nsafeyolo [--root ROOT] coord work import-github ROOM URL [--operation-id ID]\nsafeyolo [--root ROOT] coord work list ROOM [--state open|claimed|done] [--after WORK_ID] [--limit N]\nsafeyolo [--root ROOT] coord work show ROOM WORK_ID\nsafeyolo [--root ROOT] coord work release ROOM WORK_ID --expected-version N --expected-generation N [--operation-id ID]\nsafeyolo [--root ROOT] coord work complete ROOM WORK_ID --expected-version N --expected-generation N [--short-result TEXT] [--operation-id ID]\nsafeyolo [--root ROOT] coord work reassign ROOM WORK_ID --agent-id AGENT_ID --expected-version N --expected-generation N [--operation-id ID]\nsafeyolo [--root ROOT] coord work change-target ROOM WORK_ID --expected-version N --expected-target-generation N --target-ref REF [--operation-id ID]\nsafeyolo [--root ROOT] coord work attest ROOM WORK_ID --target-generation N --kind KIND --verdict approve|reject|abstain --summary TEXT [--evidence-refs JSON_ARRAY] [--operation-id ID]\nsafeyolo [--root ROOT] coord work attestations ROOM WORK_ID [--after ATTESTATION_ID] [--limit N]\n\nUse the owning host account. Agents claim through claim_work using their authenticated durable ID. Reassign can claim open work or replace a holder; release explicitly removes a claim. Time and process liveness never transfer ownership. Each claim or reassignment increments claim_generation. All changes increment version. Repeat an operation ID with its original inputs to recover an ambiguous result; changed input conflicts. Current room authority is checked on every agent read or mutation, including retries. Work changes notify current receive-authorized agents except the agent actor. Attention resolves the original immutable work version. Canonical work input is bounded to 262144 UTF-8 bytes. Lists return up to 200 items ordered by work_id; next_after is a continuation value, not a snapshot across pages. external_ref and target_ref remain opaque to local work operations. import-github validates a GitHub issue or pull request HTTPS URL and seeds local work without network access. Agents can use read_github_work for separate, read-only external metadata through their own GitHub service grant. GitHub state never changes local claims, completion or targets. target_ref is never fetched. New work has no candidate (target_generation=0). An explicit change-target advances target_generation even if the ref is reused after squash/rebase. Old attestations remain visible as stale. Target generation is separate from claim generation. Attest uses the current target generation, without an expected work version, and derives its author from identity. It does not complete work or decide a vote. Attestation kind is nonempty and at most 128 UTF-8 bytes; summary is nonempty and at most 1024; at most 16 evidence refs of 1024 bytes each; the complete serialized record is at most 32768 bytes. target_ref is nonempty and at most 1024 UTF-8 bytes. Evidence refs are untrusted external content. Attestation lists contain at most 200 items and 65536 item JSON bytes, ordered by attestation_id with next_after; pages do not share a snapshot. --evidence-refs accepts a JSON array of strings.";

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
                "attestations" => &["--after", "--limit"],
                "change-target" => &[
                    "--expected-version",
                    "--expected-target-generation",
                    "--target-ref",
                    "--operation-id",
                ],
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
                "expected_target_generation",
                "target_generation",
                "limit",
            ]
            .contains(&field.as_str())
            {
                json!(
                    value
                        .parse::<i64>()
                        .map_err(|_| "work expectation/limit must be an integer")?
                )
            } else if field == "evidence_refs" {
                serde_json::from_str(value)?
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
        ("show", [id]) => Ok(work::read(&mut conn, room, Actor::Operator, id)?),
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
        ("release" | "complete" | "reassign" | "change-target" | "attest", [id]) => {
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
