//! Owning-host work reads, creation and explicit claim recovery.
use super::{
    Error, Path, open,
    work::{self, Actor, Mutation},
};
use serde_json::{Value, json};

pub(super) const HELP: &str = "safeyolo [--root ROOT] coord work create ROOM TITLE [--external-ref REF] [--operation-id ID]\nsafeyolo [--root ROOT] coord work list ROOM [--state open|claimed|done] [--after WORK_ID] [--limit N]\nsafeyolo [--root ROOT] coord work show ROOM WORK_ID\nsafeyolo [--root ROOT] coord work release ROOM WORK_ID --expected-version N --expected-generation N [--operation-id ID]\nsafeyolo [--root ROOT] coord work complete ROOM WORK_ID --expected-version N --expected-generation N [--short-result TEXT] [--operation-id ID]\nsafeyolo [--root ROOT] coord work reassign ROOM WORK_ID --agent-id AGENT_ID --expected-version N --expected-generation N [--operation-id ID]\n\nUse the owning host account. Agents claim through claim_work using their authenticated durable ID. Reassign can claim open work or replace a holder; release explicitly removes a claim. Time and process liveness never transfer ownership. Each claim or reassignment increments claim_generation. All changes increment version. Repeat an operation ID with its original inputs to recover an ambiguous result; changed input conflicts. Current room authority is checked on every agent read or mutation, including retries. Work changes notify current receive-authorized agents except the agent actor. Attention resolves the original immutable work version. Canonical work input is bounded to 262144 UTF-8 bytes. Lists return up to 200 items ordered by work_id; next_after is a continuation value, not a snapshot across pages. external_ref is opaque and is never fetched.";

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
                "list" => &["--state", "--after", "--limit"],
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
            let value =
                if ["expected_version", "expected_generation", "limit"].contains(&field.as_str()) {
                    json!(
                        value
                            .parse::<i64>()
                            .map_err(|_| "work expectation/limit must be an integer")?
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
        ("release" | "complete" | "reassign", [id]) => {
            let operation = options.remove("operation_id");
            options.insert("action".into(), json!(command));
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
