//! Local operator communication through the existing Coord publication owner.

use std::{
    collections::{BTreeSet, VecDeque},
    io::{BufRead, IsTerminal, Read, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rustyline::{DefaultEditor, ExternalPrinter, error::ReadlineError};
use serde_json::{Value, json};

use crate::{Error, agent_api::coord::OperatorCoord, coord_timeline};

pub const HELP: &str = "safeyolo [--root ROOT] coord send ROOM [TEXT | --file FILE | --stdin] [--to AGENT ...] [--content-type text/plain|text/markdown]\nsafeyolo [--root ROOT] coord chat ROOM [--since SEQUENCE] [--to AGENT] [--observe]\nsafeyolo [--root ROOT] coord history ROOM [--since SEQUENCE]\nsafeyolo [--root ROOT] coord watch ROOM [--history COUNT] [--since SEQUENCE] [--once] [--raw|--json] [--max-text COUNT] [--redact] [--show-unknown] [--no-color]\nsafeyolo coord watch --jsonl FILE [--raw|--json] [--max-text COUNT] [--redact] [--show-unknown]\n\nSend reads exactly one UTF-8 input and preserves its payload. --to targets receive-authorized members; otherwise it notifies the room.\nChat receives while you edit. :paste/:p reads the host clipboard, :edit/:e opens $VISUAL or $EDITOR, :q exits. Composed clipboard/editor messages require confirmation. Chat requires a terminal on stdin and stdout.\nWatch renders room messages and Codex/Pi harness events. Text is complete by default. --max-text limits only display; --redact is optional. --json preserves canonical payloads as JSONL. --jsonl - reads stdin.\nUnknown publication is reported without automatic retry. Inspect history before deciding whether to send again.";

#[derive(Default)]
struct Options {
    room: Option<String>,
    text: Option<String>,
    file: Option<String>,
    stdin: bool,
    targets: Vec<String>,
    content_type: Option<String>,
    since: u64,
    since_selected: bool,
    observe: bool,
    history: Option<usize>,
    once: bool,
    jsonl: Option<String>,
    display: coord_timeline::Display,
}

fn parse(command: &str, args: &[String]) -> Result<Options, Error> {
    let mut options = Options::default();
    let mut args = args.iter();
    let mut seen = BTreeSet::new();
    let mut positional = false;
    while let Some(arg) = args.next() {
        if !positional && arg == "--" {
            positional = true;
            continue;
        }
        if !positional && arg.starts_with('-') {
            let option = match arg.as_str() {
                "-f" => "--file",
                "--plain" => "--no-color",
                v => v,
            };
            if option != "--to" && !seen.insert(option.to_owned()) {
                return Err(format!("duplicate {option} option").into());
            }
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("{option} requires a value"))
            };
            match option {
                "--file" if command == "send" => options.file = Some(value()?.clone()),
                "--stdin" if command == "send" => options.stdin = true,
                "--content-type" if command == "send" => {
                    options.content_type = Some(value()?.clone())
                }
                "--to" if matches!(command, "send" | "chat") => {
                    options.targets.push(value()?.clone())
                }
                "--since" if command != "send" => {
                    options.since = value()?
                        .parse()
                        .map_err(|_| "--since requires a nonnegative sequence")?;
                    options.since_selected = true;
                }
                "--observe" if command == "chat" => options.observe = true,
                "--history" if command == "watch" => {
                    options.history = Some(
                        value()?
                            .parse()
                            .map_err(|_| "--history requires a nonnegative count")?,
                    )
                }
                "--once" if command == "watch" => options.once = true,
                "--jsonl" if command == "watch" => options.jsonl = Some(value()?.clone()),
                "--max-text" if command == "watch" => {
                    let count = value()?
                        .parse::<usize>()
                        .ok()
                        .filter(|count| *count > 0)
                        .ok_or("--max-text requires a positive count")?;
                    options.display.max_text = Some(count);
                }
                "--raw" if command == "watch" => options.display.raw = true,
                "--json" if command == "watch" => options.display.json = true,
                "--redact" if command == "watch" => options.display.redact = true,
                "--show-unknown" if command == "watch" => options.display.show_unknown = true,
                "--no-color" if command == "watch" => options.display.no_color = true,
                _ => return Err(format!("unknown coord {command} option: {arg}").into()),
            }
        } else if options.room.is_none() {
            options.room = Some(arg.clone());
        } else if command == "send" && options.text.is_none() {
            options.text = Some(arg.clone());
        } else {
            return Err(format!("unexpected coord {command} argument").into());
        }
    }
    if options.display.raw && options.display.json {
        return Err("choose either --raw or --json".into());
    }
    if options.jsonl.is_some()
        && (options.room.is_some()
            || options.since_selected
            || options.history.is_some()
            || options.once)
    {
        return Err("--jsonl cannot be combined with room/history options".into());
    }
    if options.jsonl.is_none() && options.room.is_none() {
        return Err("a room is required".into());
    }
    if command == "chat"
        && (options.targets.len() > 1 || (options.observe && !options.targets.is_empty()))
    {
        return Err("chat accepts one --to target in interactive mode".into());
    }
    Ok(options)
}

fn body(options: &Options) -> Result<String, Error> {
    let selected = usize::from(options.text.is_some())
        + usize::from(options.file.is_some())
        + usize::from(options.stdin);
    if selected != 1 {
        return Err("provide exactly one of TEXT, --file, or --stdin".into());
    }
    let body = if let Some(path) = &options.file {
        std::fs::read_to_string(path).map_err(|_| "could not read message file as UTF-8")?
    } else if options.stdin {
        let mut body = String::new();
        std::io::stdin()
            .read_to_string(&mut body)
            .map_err(|_| "could not read message from stdin as UTF-8")?;
        body
    } else {
        options.text.clone().unwrap_or_default()
    };
    if body.trim().is_empty() {
        return Err("message body must be non-empty".into());
    }
    Ok(body)
}

fn notify(targets: &[String]) -> Value {
    if targets.is_empty() {
        json!("room")
    } else {
        json!(targets)
    }
}

fn accepted(value: &Value) -> String {
    format!(
        "message accepted; sequence={}; attention={}; delivery={}",
        value["sequence"],
        value["attention_intent"]["mode"]
            .as_str()
            .unwrap_or("unknown"),
        value["attention_status"].as_str().unwrap_or("unknown")
    )
}

// The approved host-local snapshot selects the default recipient, as in the
// existing operator chat. No guest assertion or natural-language brief does.
fn factory_target(config: &Path, room: &str) -> Result<Option<String>, Error> {
    let root = config
        .parent()
        .ok_or("configuration has no parent")?
        .join("factories");
    if !root.exists() {
        return Ok(None);
    }
    let mut targets = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let directory = entry?.path();
        let pointer = directory.join("approved");
        if !pointer.is_file() {
            continue;
        }
        let id = std::fs::read_to_string(pointer)?;
        let id = id.trim();
        if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid approved Factory snapshot identity; use --to explicitly".into());
        }
        let bytes = std::fs::read(directory.join("snapshots").join(format!("{id}.json")))?;
        if crate::coord_setup::sha256(&bytes) != id {
            return Err(
                "approved Factory snapshot identity does not match; use --to explicitly".into(),
            );
        }
        let snapshot: Value = serde_json::from_slice(&bytes)?;
        if snapshot["room"] != room {
            continue;
        }
        let role = snapshot["operator_input"]["to"]
            .as_str()
            .ok_or("approved Factory operator-input role is missing")?;
        let agent = snapshot["roles"][role]["agent"]
            .as_str()
            .ok_or("approved Factory operator-input agent is missing")?;
        targets.insert(agent.to_owned());
    }
    if targets.len() > 1 {
        return Err("room has multiple approved Factory coordinators; use --to explicitly".into());
    }
    Ok(targets.into_iter().next())
}

async fn page(
    client: &OperatorCoord,
    room: &str,
    cursor: u64,
    cancel: &tokio::sync::watch::Receiver<bool>,
) -> Result<Value, crate::agent_api::coord::OperatorCoordError> {
    client.read(room, cursor, 200, false, cancel.clone()).await
}

async fn receive(
    client: &OperatorCoord,
    room: &str,
    mut cursor: u64,
    cancel: tokio::sync::watch::Receiver<bool>,
    mut ready: tokio::sync::watch::Receiver<bool>,
    mut emit: impl FnMut(&Value) -> Result<(), Error>,
    mut connection: impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut failures = 0u32;
    while !*cancel.borrow() {
        let result = async {
            let woke = client.read(room, cursor, 1, true, cancel.clone()).await?;
            if woke["messages"].as_array().is_none_or(Vec::is_empty) {
                return Ok(());
            }
            // A wake is an edge. Read canonically from the last rendered cursor.
            loop {
                let p = page(client, room, cursor, &cancel).await?;
                while !*ready.borrow() {
                    tokio::select! {
                        result = ready.changed() => { if result.is_err() { return Ok(()); } },
                        _ = crate::coord_operator::cancelled(cancel.clone()) => return Ok(()),
                    }
                }
                for message in p["messages"].as_array().into_iter().flatten() {
                    // Output failure cannot advance the cursor past unseen text.
                    emit(message).map_err(|error| {
                        crate::agent_api::coord::OperatorCoordError::display_error(
                            error.to_string(),
                        )
                    })?;
                    cursor = message["sequence"].as_u64().unwrap_or(cursor);
                }
                if p["has_more"] != true {
                    break;
                }
            }
            Ok::<_, crate::agent_api::coord::OperatorCoordError>(())
        }
        .await;
        if *cancel.borrow() {
            break;
        }
        match result {
            Ok(()) => {
                if failures > 0 {
                    connection(&format!("recovered cursor={cursor}"))?;
                }
                failures = 0;
            }
            Err(error) if error.unavailable => {
                failures = failures.saturating_add(1);
                let delay = (1u64 << failures.min(5).saturating_sub(1)).min(30);
                connection(&format!(
                    "lost cursor={cursor}; retrying in {delay}s: {error}"
                ))?;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                    _ = cancelled(cancel.clone()) => break,
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn cancelled(mut cancel: tokio::sync::watch::Receiver<bool>) {
    while !*cancel.borrow() {
        if cancel.changed().await.is_err() {
            break;
        }
    }
}

fn compose(editor: bool) -> Result<String, Error> {
    if editor {
        let file = tempfile::Builder::new()
            .prefix("safeyolo-coord-")
            .suffix(".md")
            .tempfile()?;
        let editor = std::env::var("VISUAL")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                std::env::var("EDITOR")
                    .ok()
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_else(|| "vi".into());
        // Host-authored editor settings may contain arguments. Pass the path
        // separately so neither its contents nor its name become shell code.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("coord-editor")
            .arg(file.path())
            .status()?;
        if !status.success() {
            return Err("editor failed; nothing sent".into());
        }
        return Ok(String::from_utf8_lossy(&std::fs::read(file.path())?).into_owned());
    }
    for (program, args) in [
        ("pbpaste", vec![]),
        ("wl-paste", vec!["--no-newline"]),
        ("xclip", vec!["-selection", "clipboard", "-o"]),
        ("xsel", vec!["--clipboard", "--output"]),
    ] {
        // Preserve the existing clipboard deadline and decoding behavior.
        // Dropping the owned child on timeout prevents a hung clipboard tool
        // from holding the operator's prompt indefinitely.
        let output = tokio::runtime::Handle::current().block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::process::Command::new(program)
                    .args(args)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
        });
        match output {
            Ok(Ok(output)) if output.status.success() => {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Ok(Ok(_)) => continue,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err("clipboard command timed out; nothing sent".into()),
        }
    }
    Err("clipboard unavailable; use :edit with $EDITOR, or coord send --file".into())
}

async fn chat(
    client: Arc<OperatorCoord>,
    options: Options,
    targets: Vec<String>,
) -> Result<(), Error> {
    let room = options.room.as_deref().ok_or("room missing")?;
    let (cancel, cancellation) = tokio::sync::watch::channel(false);
    let mut cursor = options.since;
    loop {
        let p = page(&client, room, cursor, &cancellation).await?;
        for message in p["messages"].as_array().into_iter().flatten() {
            print!("{}", coord_timeline::chat_message(message));
        }
        cursor = p["next_cursor"].as_u64().ok_or("room cursor is missing")?;
        if p["has_more"] != true {
            break;
        }
    }
    println!(
        "attached to room {}{}; :paste/:p, :edit/:e, :q to quit",
        coord_timeline::visible(room),
        if targets.is_empty() {
            "; attention=room".into()
        } else {
            format!("; target={}", coord_timeline::visible(&targets.join(",")))
        }
    );
    let room = room.to_owned();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || -> Result<(), Error> {
        let mut editor = DefaultEditor::new()?;
        let mut printer = editor.create_external_printer()?;
        let mut notices = editor.create_external_printer()?;
        let (render, ready) = tokio::sync::watch::channel(true);
        let receiving = client.clone();
        let receiving_room = room.clone();
        let receiver = handle.spawn(async move {
            let result = receive(
                &receiving,
                &receiving_room,
                cursor,
                cancellation,
                ready,
                |message| {
                    printer.print(coord_timeline::chat_message(message))?;
                    Ok(())
                },
                |state| {
                    notices.print(format!("CONN {state}"))?;
                    Ok(())
                },
            )
            .await;
            if let Err(error) = &result {
                let _ = notices.print(format!(
                    "receive stopped: {}; reattach after repairing room access",
                    coord_timeline::visible(&error.to_string())
                ));
            }
            result
        });
        let result = (|| -> Result<(), Error> {
            loop {
                let line = match editor.readline("op> ") {
                    Ok(line) => line,
                    Err(ReadlineError::Eof | ReadlineError::Interrupted) => break,
                    Err(error) => return Err(error.into()),
                };
                if line.trim() == ":q" {
                    break;
                }
                let body = if matches!(line.trim(), ":paste" | ":p" | ":edit" | ":e") {
                    let edit = matches!(line.trim(), ":edit" | ":e");
                    if edit {
                        render.send_replace(false);
                    }
                    let composed = compose(edit);
                    render.send_replace(true);
                    match composed {
                        Err(error) => {
                            println!("{}", coord_timeline::visible(&error.to_string()));
                            continue;
                        }
                        Ok(body) if body.trim().is_empty() => continue,
                        Ok(body) => {
                            println!(
                                "{} lines, {} bytes: {}",
                                body.lines().count(),
                                body.len(),
                                coord_timeline::visible(body.lines().next().unwrap_or_default())
                            );
                            let answer = match editor.readline("send? [Y/n] ") {
                                Ok(answer) => answer,
                                Err(ReadlineError::Eof | ReadlineError::Interrupted) => break,
                                Err(error) => return Err(error.into()),
                            };
                            if !matches!(
                                answer.trim().to_ascii_lowercase().as_str(),
                                "" | "y" | "yes"
                            ) {
                                println!("cancelled");
                                continue;
                            }
                            body
                        }
                    }
                } else {
                    line
                };
                if body.trim().is_empty() {
                    continue;
                }
                match handle.block_on(client.send(&room, &body, "text/markdown", notify(&targets)))
                {
                    Ok(value) => println!("{}", accepted(&value)),
                    Err(error) => println!("{}", coord_timeline::visible(&error.to_string())),
                }
            }
            Ok(())
        })();
        cancel.send_replace(true);
        let received = handle.block_on(receiver)?;
        handle.block_on(client.shutdown());
        result?;
        received?;
        println!("detached");
        Ok(())
    })
    .await?
}

pub async fn run(config: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments.len() < 2 || arguments[1] == "--help" {
        println!("{HELP}");
        return Ok(());
    }
    let command = &arguments[0];
    let mut options = parse(command, &arguments[1..])?;
    if let Some(path) = &options.jsonl {
        let input: Box<dyn BufRead> = if path == "-" {
            Box::new(std::io::stdin().lock())
        } else {
            Box::new(std::io::BufReader::new(std::fs::File::open(path)?))
        };
        for line in input.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            if serde_json::from_str::<Value>(&line).is_err() {
                eprintln!("coord watch: invalid JSONL event; continuing with the next line");
                continue;
            }
            let message = json!({"sent_at":time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,"sender_kind":"agent","sender_agent_name":"reviewer","body":line});
            print!("{}", options.display.message(&message));
        }
        return Ok(());
    }
    let room = options.room.as_deref().ok_or("room missing")?.to_owned();
    if command == "chat" && !options.observe {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err("interactive coord chat requires a terminal on stdin and stdout; use coord send or chat --observe".into());
        }
        if options.targets.is_empty() {
            options.targets.extend(factory_target(config, &room)?);
        }
        let targets = options.targets.clone();
        return chat(Arc::new(OperatorCoord::open(config)?), options, targets).await;
    }
    let client = OperatorCoord::open(config)?;
    if command == "send" {
        let body = body(&options)?;
        let result = client
            .send(
                &room,
                &body,
                options.content_type.as_deref().unwrap_or("text/markdown"),
                notify(&options.targets),
            )
            .await;
        client.shutdown().await;
        println!("{}", accepted(&result?));
        return Ok(());
    }
    let (cancel, cancellation) = tokio::sync::watch::channel(false);
    let (_render, ready) = tokio::sync::watch::channel(true);
    let display = |message: &Value| {
        if command == "chat" {
            coord_timeline::chat_message(message)
        } else if command == "history" {
            format!("{message}\n")
        } else {
            options.display.message(message)
        }
    };
    let result = async {
        let mut cursor = options.since;
        let mut failures = 0u32;
        let mut history = VecDeque::new();
        loop {
            let p = match page(&client, &room, cursor, &cancellation).await {
                Ok(page) => {
                    if failures > 0 {
                        eprintln!("CONN recovered cursor={cursor}");
                    }
                    failures = 0;
                    page
                }
                Err(error) if command == "watch" && !options.once && error.unavailable => {
                    failures = failures.saturating_add(1);
                    let delay = (1u64 << failures.min(5).saturating_sub(1)).min(30);
                    eprintln!("CONN lost cursor={cursor}; retrying in {delay}s: {error}");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(delay)) => continue,
                        _ = tokio::signal::ctrl_c() => return Ok(()),
                    }
                }
                Err(error) => return Err(error.into()),
            };
            for message in p["messages"].as_array().into_iter().flatten() {
                if command == "watch" && !options.since_selected {
                    let count = options.history.unwrap_or(30);
                    if count > 0 {
                        if history.len() == count {
                            history.pop_front();
                        }
                        history.push_back(message.clone());
                    }
                } else {
                    print!("{}", display(message));
                }
            }
            cursor = p["next_cursor"].as_u64().ok_or("room cursor is missing")?;
            if p["has_more"] != true {
                break;
            }
        }
        for message in history {
            print!("{}", display(&message));
        }
        std::io::stdout().flush()?;
        if command == "history" || options.once {
            return Ok(());
        }
        tokio::select! {
            result = receive(&client, &room, cursor, cancellation.clone(), ready,
                |message| { print!("{}", display(message)); std::io::stdout().flush()?; Ok(()) },
                |state| { eprintln!("CONN {state}"); Ok(()) }) => result,
            _ = tokio::signal::ctrl_c() => { cancel.send_replace(true); Ok(()) },
        }
    }
    .await;
    cancel.send_replace(true);
    client.shutdown().await;
    result
}
