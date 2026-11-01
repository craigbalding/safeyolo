//! Owning-host signal inspection and explicit resolution.
use super::{Error, Path, open, signals, work::Actor};
use serde_json::{Value, json};

pub(super) const HELP: &str = "safeyolo [--root ROOT] coord signal list ROOM [--state current|resolved|superseded|all] [--needs-operator] [--after ID] [--limit N]
safeyolo [--root ROOT] coord signal show ROOM SIGNAL_ID [--revision N]
safeyolo [--root ROOT] coord signal create ROOM blocker|decision|result|correction SUMMARY --basis observed|inferred [--work-id ID] [--ref REF ...] [--supersedes SIGNAL_ID --expected-revision N] [--operation-id ID]
safeyolo [--root ROOT] coord signal resolve ROOM SIGNAL_ID --expected-revision N [--operation-id ID]
safeyolo [--root ROOT] watch [--once] [--json] [--jsonl FILE]

Use the owning host account. Agents use create_signal, read_signal and list_signals with their authenticated room membership. observed is the author's report, never independent attestation. A correction supersedes only its author's signal and requires its current revision. The operator may resolve any author's current signal. Original immutable revisions remain readable.
Summary: 1..1024 UTF-8 bytes. Refs: at most 16 opaque strings of 1024 bytes; they are never fetched. Mutations: at most 32768 bytes. Lists: at most 100 items and 65536 bytes per page, ordered by signal_id; next_after continues without a shared snapshot. Current room_state includes bounded signals and needs_operator pages.
Default room grants include send, receive and page_operator. To revoke paging independently, replace the grant with: coord grant ROOM AGENT send receive. Creation still works; existing pending signals remain pending. Only new permitted blocker/decision claims page. Identical current blocker/decision input from the same author is deduplicated even with another operation ID. At most 5 new pages per author per room and 20 per room in 60 seconds; excess claims remain stored with page_status=rate_limited. Results and corrections do not page. Resolution or supersession clears needs_operator without removing history. Completing work never creates a signal.
Choose an operation ID before writing. Repeat its original inputs to recover an ambiguous result; changed input conflicts. watch lists pending canonical metadata and fetches exact immutable revisions through Admin API. --jsonl reads existing audit JSONL (or - for stdin), deduplicates signal revisions, and fetches the revision in each event. Signal prose is absent from audit JSONL. Terminal controls are escaped and markup is printed as text. Detaching watch removes no pending state.";

pub(super) fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let [command, room, rest @ ..] = args else {
        return Err(HELP.into());
    };
    let mut positional = Vec::new();
    let mut options = serde_json::Map::new();
    let mut refs = Vec::new();
    let mut needs = false;
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        if arg == "--needs-operator" && command == "list" && !needs {
            needs = true;
            continue;
        }
        if arg.starts_with("--") {
            let allowed: &[&str] = match command.as_str() {
                "create" => &[
                    "--basis",
                    "--work-id",
                    "--ref",
                    "--supersedes",
                    "--expected-revision",
                    "--operation-id",
                ],
                "resolve" => &["--expected-revision", "--operation-id"],
                "show" => &["--revision"],
                "list" => &["--state", "--after", "--limit"],
                _ => &[],
            };
            if !allowed.contains(&arg.as_str()) {
                return Err("unknown signal option".into());
            }
            let value = args.next().ok_or("signal option requires a value")?;
            if arg == "--ref" {
                refs.push(value.clone());
                continue;
            }
            let field = arg.trim_start_matches("--").replace('-', "_");
            if options.contains_key(&field) {
                return Err("duplicate signal option".into());
            }
            let value = if ["revision", "expected_revision", "limit"].contains(&field.as_str()) {
                json!(
                    value
                        .parse::<i64>()
                        .map_err(|_| "signal revision/limit must be an integer")?
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
        ("list", []) => Ok(signals::list(
            &mut conn,
            room,
            Actor::Operator,
            options.get("after").and_then(Value::as_str).unwrap_or(""),
            options
                .get("limit")
                .map_or(Some(50), Value::as_u64)
                .ok_or("limit must be positive")? as usize,
            options.get("state").and_then(Value::as_str),
            needs,
        )?),
        ("show", [id]) => Ok(signals::read(
            &mut conn,
            room,
            Actor::Operator,
            id,
            options.get("revision").and_then(Value::as_i64),
        )?),
        ("create", [kind, summary]) => {
            let operation = options.remove("operation_id");
            if let Some(id) = options.remove("supersedes") {
                let expected = options
                    .remove("expected_revision")
                    .ok_or("--supersedes requires --expected-revision")?;
                options.insert(
                    "supersedes".into(),
                    json!({"signal_id":id,"expected_revision":expected}),
                );
            }
            options.insert("action".into(), json!("create"));
            options.insert("kind".into(), json!(kind));
            options.insert("summary".into(), json!(summary));
            options.insert("refs".into(), json!(refs));
            let mutation = serde_json::from_value(Value::Object(options))?;
            Ok(signals::mutate(
                &mut conn,
                room,
                Actor::Operator,
                mutation,
                operation.as_ref().and_then(Value::as_str),
            )?)
        }
        ("resolve", [id]) => {
            let operation = options.remove("operation_id");
            options.insert("action".into(), json!("resolve"));
            options.insert("signal_id".into(), json!(id));
            let mutation = serde_json::from_value(Value::Object(options))?;
            Ok(signals::mutate(
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
