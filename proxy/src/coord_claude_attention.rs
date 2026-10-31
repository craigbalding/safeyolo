//! Opt-in queue/wake input on Claude Code's native streaming JSON connection.

use crate::{
    Error,
    coord_attention::{Mode, attributed_content, next_page, write_json},
    coord_tools::Client,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, ffi::OsString, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const HELP: &str = "safeyolo-coord claude-attention [--mode queue] [--degrade-to queue] [--since CURSOR] [--session ID] [--home NAME] [-- CLAUDE_OPTIONS]\n\nUse as a Claude Code streaming JSON stdio connection. The complete native client runs with --print --input-format stream-json --output-format stream-json --verbose --replay-user-messages. Native user messages, controls, tools and permission replies pass through. Queue waits for the native turn and queued frontend work to finish, then supplies attributed user input, waking an idle process. This integration implements no context-only, steer or interrupt mode. Unsupported modes fail unless --degrade-to queue explicitly selects queue/wake. SAFEYOLO_CLAUDE_BIN selects the complete native client (default claude), including an authorized gateway launcher. Native authentication, configuration and permissions still apply.\n\nThe bound notification identifies a new session, or --session resumes an existing native session. Pending means canonical resolution; submitted means native stdin was written; delivered means the matching native user message was replayed. Observe assistant output and result separately for model application. Keep next_cursor with the native session ID. Restart with --session and --since; inspect native history and Coord retention before replaying uncertain input. Only 128 recent attention IDs are held in memory. No separate durable inbox or attachment to an unrelated TUI is provided. Claude channels remain a separate opt-in interface with their own native consent and availability requirements.";

pub async fn run(arguments: &[OsString]) -> Result<(), Error> {
    if arguments == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let mut requested = Mode::Queue;
    let mut cursor = 0u64;
    let mut resume = None;
    let mut client = Client::default();
    let mut degrade = false;
    let mut position = 0;
    while position < arguments.len() && arguments[position] != "--" {
        let option = arguments[position]
            .to_str()
            .ok_or("attention option must be UTF-8")?;
        let value = arguments
            .get(position + 1)
            .and_then(|value| value.to_str())
            .ok_or("attention option needs a value")?;
        match option {
            "--mode" => requested = Mode::parse(value)?,
            "--since" => cursor = value.parse()?,
            "--session" => resume = Some(value.to_owned()),
            "--home" => client.home = Some(value.to_owned()),
            "--degrade-to" if value == "queue" => degrade = true,
            _ => return Err(format!("unknown attention option/value: {option}").into()),
        }
        position += 2;
    }
    if requested != Mode::Queue && !degrade {
        return Err("unsupported Claude streaming attention mode; use --degrade-to queue only if queue/wake is intended".into());
    }
    let session = resume
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut child = tokio::process::Command::new(
        std::env::var_os("SAFEYOLO_CLAUDE_BIN").unwrap_or_else(|| "claude".into()),
    )
    .args(arguments.get(position + 1..).unwrap_or_default())
    .args([
        "--print",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--replay-user-messages",
    ])
    .arg(if resume.is_some() {
        "--resume"
    } else {
        "--session-id"
    })
    .arg(&session)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()?;
    let result = async {
        let mut native_input = child.stdin.take().ok_or("missing Claude stdin")?;
        let mut native_output = BufReader::new(child.stdout.take().ok_or("missing Claude stdout")?).lines();
        let mut frontend_input = BufReader::new(tokio::io::stdin()).lines();
        let mut frontend_output = tokio::io::stdout();
        let mut active = false;
        let mut receiving = true;
        let mut pending: Option<Value> = None;
        let mut submitted: Option<String> = None;
        let mut delivered = VecDeque::new();
        let mut page = Box::pin(next_page(client.clone(), cursor));
        write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/bound","params":{"session_id":session,"capabilities":{"context":false,"queue":true,"steer":false,"interrupt":false,"wake_idle":true,"attach_unrelated_tui":false},"requested_mode":format!("{requested:?}").to_lowercase(),"effective_mode":"queue","confirmation":"native_process_started; observe native user replay and model results separately"}})).await?;
        loop {
            tokio::select! {
                line = frontend_input.next_line() => {
                    let Some(line) = line? else { native_input.shutdown().await?; return Ok(()); };
                    let value: Value = serde_json::from_str(&line)?;
                    if value["type"] == "user" { active = true; }
                    write_json(&mut native_input, &value).await?;
                }
                line = native_output.next_line() => {
                    let Some(line) = line? else { return Err("native Claude closed; inspect native history before repeating uncertain input".into()); };
                    let value: Value = serde_json::from_str(&line)?;
                    if value["session_id"].as_str() == Some(&session) && value["parent_tool_use_id"].is_null() {
                        if value["type"] == "assistant" { active = true; }
                        if value["type"] == "result" {
                            active = value["queued_turn_count"].as_u64().is_some_and(|count| count > 0);
                            if submitted.is_some() {
                                receiving = false;
                                submitted = None;
                                write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/rejected","params":{"safe_cursor":cursor,"native_result":value,"recovery":"matching native user replay was not observed; inspect native history before replay"}})).await?;
                            }
                        }
                        if value["type"] == "user" && submitted.as_deref().is_some_and(|id| value["uuid"].as_str() == Some(id)) {
                            let accepted = pending.take().ok_or("missing pending Claude attention")?;
                            let id = accepted["objects"][0]["edge"]["attention_id"].as_str().ok_or("missing attention ID")?.to_owned();
                            cursor = accepted["next_cursor"].as_u64().ok_or("missing attention cursor")?;
                            submitted = None;
                            delivered.push_back(id.clone());
                            if delivered.len() > 128 { delivered.pop_front(); }
                            write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/delivered","params":{"attention_id":id,"next_cursor":cursor,"session_id":session,"confirmation":"native_user_replayed"}})).await?;
                            page = Box::pin(next_page(client.clone(), cursor));
                        }
                    }
                    write_json(&mut frontend_output, &value).await?;
                }
                result = &mut page, if receiving && pending.is_none() => {
                    let result = match result {
                        Ok(page) => page,
                        Err(error) => {
                            receiving = false;
                            write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/stopped","params":{"error":error.to_string(),"safe_cursor":cursor,"native_connection":"continues"}})).await?;
                            continue;
                        }
                    };
                    let objects = result["objects"].as_array().ok_or("invalid canonical attention page")?;
                    let next = result["next_cursor"].as_u64().filter(|next| *next >= cursor).ok_or("invalid attention cursor")?;
                    if objects.len() > 1 { return Err("canonical attention page exceeds requested limit".into()); }
                    if let Some(event) = objects.first() {
                        let id = event["edge"]["attention_id"].as_str().filter(|id| crate::coord_tools::attention_id(id)).ok_or("invalid canonical attention ID")?;
                        if next == cursor { return Err("canonical attention did not advance its cursor".into()); }
                        if !delivered.iter().any(|seen| seen == id) {
                            write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/pending","params":{"attention_id":id,"next_cursor":next,"safe_cursor":cursor,"confirmation":"canonical_object_resolved"}})).await?;
                            pending = Some(result);
                        }
                    }
                    if pending.is_none() { cursor = next; page = Box::pin(next_page(client.clone(), cursor)); }
                }
            }
            if receiving && !active && submitted.is_none() && let Some(page) = &pending {
                let id = uuid::Uuid::new_v4().to_string();
                write_json(&mut native_input, &json!({"type":"user","uuid":id,"session_id":session,"parent_tool_use_id":null,"message":{"role":"user","content":attributed_content(&page["objects"][0])}})).await?;
                write_json(&mut frontend_output, &json!({"jsonrpc":"2.0","method":"safeyolo/attention/submitted","params":{"attention_id":page["objects"][0]["edge"]["attention_id"],"safe_cursor":cursor,"native_message_id":id,"confirmation":"native_request_sent"}})).await?;
                submitted = Some(id);
                active = true;
            }
        }
    }.await;
    // Closing the adapter must also stop the owned model consumer. Keep its
    // ordinary session history for recovery, including unfinished turns.
    if let Some(pid) = child.id() {
        // The child handle still owns this unreaped PID. Claude's SIGTERM
        // handler stops its tools and records the unfinished native turn.
        if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
            let error = std::io::Error::last_os_error();
            // A child that exited before the signal is already stopped.
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
    }
    match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
        Ok(status) => {
            status?;
        }
        Err(_) => {
            child.kill().await?;
            child.wait().await?;
        }
    }
    if result.is_err() {
        eprintln!(
            "Claude attention stopped: session={session}, safe_cursor={cursor}; inspect native history before replay"
        );
    }
    result
}
