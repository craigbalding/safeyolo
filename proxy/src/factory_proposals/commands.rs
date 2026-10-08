//! CLI callers use the existing local operator or scoped Agent API reader.

use super::*;
use crate::{agent_api::coord::OperatorCoord, coord_tools::Client};

pub const HELP: &str = "safeyolo [--root ROOT] coord completion-notes ROOM SEQUENCE\nsafeyolo [--root ROOT] coord proposals observe ROOM SEQUENCE --verified FILE [--candidate INDEX] [--ledger FILE]\nsafeyolo [--root ROOT] coord proposals list|pending [--ledger FILE]\nsafeyolo [--root ROOT] coord proposals presented ROOM SEQUENCE [--ledger FILE] [--relay NAME]\nsafeyolo [--root ROOT] coord proposals outcome ROOM SEQUENCE [--ledger FILE]\nsafeyolo [--root ROOT] coord proposals reconcile ROOM [--since SEQUENCE] [--ledger FILE] [--relay NAME]\n\nThe agent CLI supports the same operations as safeyolo-coord completion-notes|proposals, using its scoped Agent API reader.\nEvery envelope is read from retained Coord data; there is no envelope-file or operator-attribution input.\n--verified is Relay's checked observation plus an explicit coverage result (null or an issue reference); candidate text is not verified evidence.\nPending returns frozen bodies for Relay to send unchanged through its existing Coord tool. No command publishes or applies a recommendation.\nReconcile retained history before pending after restart or unknown publication. Outcome requires an exact retained operator message.\nDefault ledger: the selected native data directory's coord/factory-proposals.json on the host, or $SAFEYOLO_COORD_DATA_DIR/factory-proposals.json in a guest (otherwise ~/.safeyolo/data/coord/factory-proposals.json).";

enum Reader {
    Operator(OperatorCoord),
    Agent(Client),
}
impl Reader {
    async fn page(&self, room: &str, since: u64, limit: usize) -> Result<Value, Error> {
        match self {
            Self::Operator(reader) => {
                let (_cancel, rx) = tokio::sync::watch::channel(false);
                Ok(reader.read(room, since, limit, false, rx).await?)
            }
            Self::Agent(reader) => {
                reader
                    .call(
                        "read_room",
                        &json!({"room_name":room,"since_sequence":since,"limit":limit}),
                    )
                    .await
            }
        }
    }
    async fn envelope(&self, room: &str, sequence: u64) -> Result<Value, Error> {
        let page = self
            .page(
                room,
                sequence.checked_sub(1).ok_or("sequence must be positive")?,
                1,
            )
            .await?;
        let messages = page["messages"]
            .as_array()
            .ok_or("Coord returned no message page")?;
        let message = messages
            .first()
            .filter(|m| messages.len() == 1 && m["sequence"].as_u64() == Some(sequence))
            .ok_or("requested retained Coord sequence is unavailable; no state was changed")?;
        crate::completion_notes::provenance(message)?;
        Ok(message.clone())
    }
    async fn shutdown(&self) {
        if let Self::Operator(reader) = self {
            reader.shutdown().await;
        }
    }
}

#[derive(Default)]
struct Options {
    ledger: Option<PathBuf>,
    verified: Option<PathBuf>,
    candidate: usize,
    since: u64,
    relay: Option<String>,
    positional: Vec<String>,
}
fn options(command: &str, args: &[String]) -> Result<Options, Error> {
    let mut parsed = Options::default();
    let mut seen = BTreeSet::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg.starts_with("--") {
            if !seen.insert(arg.clone()) {
                return Err("duplicate proposal option".into());
            }
            let value = args.next().ok_or("proposal option needs a value")?;
            match arg.as_str() {
                "--ledger" if command != "completion-notes" => parsed.ledger = Some(value.into()),
                "--verified" if command == "observe" => parsed.verified = Some(value.into()),
                "--candidate" if command == "observe" => {
                    parsed.candidate = value
                        .parse()
                        .map_err(|_| "candidate index must be nonnegative")?
                }
                "--since" if command == "reconcile" => {
                    parsed.since = value
                        .parse()
                        .map_err(|_| "since sequence must be nonnegative")?
                }
                "--relay" if matches!(command, "presented" | "reconcile") => {
                    parsed.relay = Some(bounded(value, "Relay name", 128)?)
                }
                _ => return Err("unknown option for this proposal command".into()),
            }
        } else {
            parsed.positional.push(arg.clone());
        }
    }
    let count = match command {
        "completion-notes" | "observe" | "presented" | "outcome" => 2,
        "reconcile" => 1,
        "pending" | "list" => 0,
        _ => return Err("unknown proposal command; use proposals --help".into()),
    };
    if parsed.positional.len() != count || command == "observe" && parsed.verified.is_none() {
        return Err("invalid proposal arguments; use proposals --help".into());
    }
    Ok(parsed)
}

async fn execute(
    reader: Option<&Reader>,
    command: &str,
    options: Options,
    default_path: PathBuf,
) -> Result<Value, Error> {
    let envelope = if matches!(
        command,
        "completion-notes" | "observe" | "presented" | "outcome"
    ) {
        let sequence = options.positional[1]
            .parse()
            .map_err(|_| "sequence must be positive")?;
        Some(
            reader
                .ok_or("Coord reader is missing")?
                .envelope(&options.positional[0], sequence)
                .await?,
        )
    } else {
        None
    };
    if command == "completion-notes" {
        return Ok(serde_json::to_value(crate::completion_notes::parse(
            envelope.as_ref().ok_or("envelope is missing")?,
        )?)?);
    }
    let candidate = if command == "observe" {
        let parsed =
            crate::completion_notes::parse(envelope.as_ref().ok_or("envelope is missing")?)?;
        if parsed.trailer_status != "valid" {
            return Ok(json!([]));
        }
        let candidate = parsed
            .candidates
            .get(options.candidate)
            .ok_or("candidate index is outside the validated trailer")?
            .clone();
        if candidate["type"] != "FACTORY_CANDIDATE" {
            return Ok(json!([]));
        }
        Some(candidate)
    } else {
        None
    };
    // Validate verified input and coverage before opening or writing a ledger.
    let verified = if command == "observe" {
        let value = read_json(
            options
                .verified
                .as_deref()
                .ok_or("verified input is missing")?,
        )?;
        shape(&value, &["observation", "coverage"])?;
        let mut observation: Observation = serde_json::from_value(value["observation"].clone())?;
        observation.normalize()?;
        let coverage: Option<String> = serde_json::from_value(value["coverage"].clone())?;
        optional(&coverage, "existing issue ref", MAX_REF_BYTES)?;
        Some((observation, coverage))
    } else {
        None
    };
    let mut ledger = Ledger::open(options.ledger.as_deref().unwrap_or(&default_path))?;
    let relay = options.relay.as_deref().unwrap_or("relay");
    match command {
        "observe" => {
            let (observation, coverage) = verified.ok_or("verified input is missing")?;
            Ok(json!([ledger.observe(candidate.as_ref().ok_or("candidate is missing")?, observation, coverage)?.wire()?]))
        }
        "pending" => Ok(json!(ledger.pending()?)),
        "list" => Ok(json!(ledger.records.values().map(Record::wire).collect::<Result<Vec<_>,_>>()?)),
        "presented" => Ok(ledger.presented(envelope.as_ref().ok_or("envelope is missing")?, relay)?
            .ok_or("presentation must be an exact canonical Relay send of a currently pending revision")?.wire()?),
        "outcome" => ledger.outcome(envelope.as_ref().ok_or("envelope is missing")?)?.wire(),
        "reconcile" => {
            let reader = reader.ok_or("Coord reader is missing")?;
            let mut since = options.since;
            let mut reconciled = Vec::new();
            loop {
                if ledger.pending()?.is_empty() {
                    break;
                }
                let page = reader.page(&options.positional[0], since, 100).await?;
                if page["history_truncated"] == true {
                    return Err("retained history is truncated; prior publication remains unknown. Inspect surviving messages before deciding whether to send again".into());
                }
                let messages = page["messages"].as_array().filter(|m| m.len() <= 100).ok_or("invalid retained Coord page")?;
                if messages.is_empty() { break }
                for message in messages {
                    let sequence = message["sequence"].as_u64().filter(|s| *s > since).ok_or("invalid retained Coord sequence order")?;
                    if let Some(record) = ledger.presented(message, relay)? { reconciled.push(record.wire()?); }
                    since = sequence;
                }
                if page["has_more"] == false {
                    break;
                }
            }
            Ok(json!(reconciled))
        }
        _ => Err("unknown proposal operation".into()),
    }
}

async fn run(config: Option<&Path>, args: &[String]) -> Result<(), Error> {
    if args.is_empty()
        || args == ["--help"]
        || args == ["proposals", "--help"]
        || args == ["completion-notes", "--help"]
    {
        println!("{HELP}");
        return Ok(());
    }
    let (command, rest) = match args {
        [kind, command, rest @ ..] if kind == "proposals" => (command.as_str(), rest),
        [kind, rest @ ..] if kind == "completion-notes" => (kind.as_str(), rest),
        _ => return Err("usage: coord proposals --help".into()),
    };
    let options = options(command, rest)?;
    let default_path = if let Some(config) = config {
        crate::native_config::read(config)?
            .data_dir
            .ok_or("native data directory is missing")?
            .join("coord")
            .join(LEDGER_NAME)
    } else {
        std::env::var_os("SAFEYOLO_COORD_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".safeyolo/data/coord")
            })
            .join(LEDGER_NAME)
    };
    let reader = if matches!(command, "list" | "pending") {
        None
    } else if let Some(config) = config {
        Some(Reader::Operator(OperatorCoord::open(config)?))
    } else {
        Some(Reader::Agent(Client::default()))
    };
    let result = execute(reader.as_ref(), command, options, default_path).await;
    if let Some(reader) = reader {
        reader.shutdown().await;
    }
    println!("{}", serde_json::to_string_pretty(&result?)?);
    Ok(())
}
pub async fn run_operator(config: &Path, args: &[String]) -> Result<(), Error> {
    run(Some(config), args).await
}
pub async fn run_agent(args: &[String]) -> Result<(), Error> {
    run(None, args).await
}
