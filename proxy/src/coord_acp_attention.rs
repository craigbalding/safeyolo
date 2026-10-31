//! Opt-in Coord attention on complete native Gemini and Hermes ACP connections.

use crate::{
    Error,
    coord_attention::{Mode, attributed_content, next_page, write_json},
    coord_tools::Client,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const HELP: &str = "safeyolo-coord acp-attention gemini|hermes [--mode context|queue|steer|interrupt] [--degrade-to queue] [--since CURSOR] [--session ID] [--home NAME] [-- NATIVE_OPTIONS]\n\nUse as a native ACP stdio connection. The frontend initializes and creates/loads its ordinary native session; all native requests, tools and permission replies pass through. Default queue waits for the current prompt to complete, then sends session/prompt, waking an idle session. interrupt sends session/cancel and waits for the active prompt to finish before delivering. Hermes steer uses its native /steer command while active. Standard Gemini ACP does not expose steer or context-only; Hermes ACP has no context-only primitive. Unsupported modes fail unless the operator explicitly selects --degrade-to queue. SAFEYOLO_GEMINI_BIN and SAFEYOLO_HERMES_BIN select complete clients (defaults gemini and hermes-acp).\n\nsafeyolo/attention notifications distinguish canonical resolution, native submission and native response. A prompt response is not proof of a successful model reply. Keep next_cursor with the native session ID; resume/load that session with --since after restart. Inspect native history and canonical retention before replaying uncertain input. Recent attention IDs are bounded to 128 in memory; Coord remains the durable content source. This connection does not attach to an unrelated TUI or change a running factory.";

#[derive(Clone, Copy, PartialEq)]
enum Harness {
    Gemini,
    Hermes,
}

fn supported(harness: Harness, mode: Mode) -> bool {
    mode != Mode::Context && (mode != Mode::Steer || harness == Harness::Hermes)
}

fn hermes_steer_acknowledged(text: &str) -> bool {
    text.starts_with("⏩ Steer queued for the active turn:")
}

pub async fn run(arguments: &[OsString]) -> Result<(), Error> {
    if arguments == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let harness = match arguments.first().and_then(|value| value.to_str()) {
        Some("gemini") => Harness::Gemini,
        Some("hermes") => Harness::Hermes,
        _ => return Err("acp-attention requires gemini or hermes".into()),
    };
    let mut mode = Mode::Queue;
    let mut cursor = 0u64;
    let mut session: Option<String> = None;
    let mut client = Client::default();
    let mut degrade = false;
    let mut position = 1;
    while position < arguments.len() && arguments[position] != "--" {
        let option = arguments[position]
            .to_str()
            .ok_or("attention option must be UTF-8")?;
        let value = arguments
            .get(position + 1)
            .and_then(|value| value.to_str())
            .ok_or("attention option needs a value")?;
        match option {
            "--mode" => mode = Mode::parse(value)?,
            "--since" => cursor = value.parse()?,
            "--session" => session = Some(value.to_owned()),
            "--home" => client.home = Some(value.to_owned()),
            "--degrade-to" if value == "queue" => degrade = true,
            _ => return Err(format!("unknown attention option/value: {option}").into()),
        }
        position += 2;
    }
    let requested = mode;
    if !supported(harness, mode) {
        if !degrade {
            return Err("unsupported native attention mode; use --degrade-to queue only if queue/wake is intended".into());
        }
        mode = Mode::Queue;
    }
    let (variable, default) = if harness == Harness::Gemini {
        ("SAFEYOLO_GEMINI_BIN", "gemini")
    } else {
        ("SAFEYOLO_HERMES_BIN", "hermes-acp")
    };
    let program = std::env::var_os(variable).unwrap_or_else(|| default.into());
    let mut command = tokio::process::Command::new(program);
    if harness == Harness::Gemini {
        // The native launcher otherwise forks a second Node runtime for heap
        // sizing. That runtime can outlive the stdio owner when a frontend
        // closes during a permission request, defeating session restart.
        command.arg("--acp").env("GEMINI_CLI_NO_RELAUNCH", "1");
    }
    let mut child = command
        .args(arguments.get(position + 1..).unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let result = async {
        let mut native_input = child.stdin.take().ok_or("missing ACP stdin")?;
        let mut native_output = BufReader::new(child.stdout.take().ok_or("missing ACP stdout")?).lines();
        let mut frontend_input = BufReader::new(tokio::io::stdin()).lines();
        let mut frontend_output = tokio::io::stdout();
        let mut opens: HashMap<String, Option<String>> = HashMap::new();
        let mut active = HashSet::new();
        let mut initialized = false;
        let mut loaded = false;
        let mut receiving = true;
        let mut pending: Option<Value> = None;
        let mut internal: Option<(Value, bool)> = None;
        let mut steer_acknowledged = false;
        let mut cancelled = false;
        let mut delivered: VecDeque<String> = VecDeque::new();
        let mut page = Box::pin(next_page(client.clone(), cursor));
        let request_prefix = format!("safeyolo-attention-{}-", uuid::Uuid::new_v4());
        let mut serial = 0u64;
        loop {
            tokio::select! {
                line = frontend_input.next_line() => {
                    let Some(line) = line? else { native_input.shutdown().await?; return Ok(()); };
                    let value: Value = serde_json::from_str(&line)?;
                    if value["method"] == "initialize" { initialized = true; }
                    if matches!(value["method"].as_str(),Some("session/new" | "session/load" | "session/resume")) && !value["id"].is_null() {
                        opens.insert(value["id"].to_string(),value["params"]["sessionId"].as_str().map(str::to_owned));
                    }
                    if value["method"] == "session/prompt" && value["params"]["sessionId"].as_str() == session.as_deref() {
                        active.insert(value["id"].to_string());
                    }
                    write_json(&mut native_input,&value).await?;
                }
                line = native_output.next_line() => {
                    let Some(line) = line? else { return Err("native ACP closed; inspect native history before repeating uncertain input".into()); };
                    let value: Value = serde_json::from_str(&line)?;
                    // Native permission requests can reuse frontend request IDs.
                    // Only responses complete an open or an active prompt.
                    let response = value.get("id").is_some() && value.get("method").is_none();
                    if internal.as_ref().is_some_and(|(_,steer)| *steer) && value["method"] == "session/update"
                        && value["params"]["sessionId"].as_str() == session.as_deref()
                        && let Some(text) = value["params"]["update"]["content"]["text"].as_str() {
                        steer_acknowledged |= hermes_steer_acknowledged(text);
                    }
                    if response && internal.as_ref().is_some_and(|(id,_)| value.get("id") == Some(id)) {
                        let (_,steer) = internal.take().unwrap();
                        if !value["error"].is_null() || (steer && !steer_acknowledged) {
                            write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/rejected","params":{"native_error":value["error"],"steer_unconfirmed":steer && !steer_acknowledged,"safe_cursor":cursor,"recovery":"inspect native history before replay; an unconfirmed steer may have become a native queued prompt"}})).await?;
                            receiving = false;
                            continue;
                        }
                        let accepted = pending.take().ok_or("missing pending ACP attention")?;
                        let id = accepted["objects"][0]["edge"]["attention_id"].as_str().ok_or("missing attention ID")?.to_owned();
                        cursor = accepted["next_cursor"].as_u64().ok_or("missing attention cursor")?;
                        delivered.push_back(id.clone());
                        if delivered.len()>128 { delivered.pop_front(); }
                        write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/delivered","params":{"attention_id":id,"next_cursor":cursor,"session_id":session,"confirmation":"native_request_completed","stop_reason":value["result"]["stopReason"]}})).await?;
                        page = Box::pin(next_page(client.clone(),cursor));
                    } else {
                        if response { active.remove(&value["id"].to_string()); }
                        if let Some(requested_session) = response.then(|| opens.remove(&value["id"].to_string())).flatten()
                            && value["error"].is_null() {
                            let id = value["result"]["sessionId"].as_str().map(str::to_owned).or(requested_session).ok_or("native open has no session ID")?;
                            if session.is_none() { session = Some(id.clone()); }
                            if session.as_deref()==Some(&id) {
                                loaded=true;
                                write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/bound","params":{"session_id":id,"capabilities":{"context":false,"queue":true,"steer":harness==Harness::Hermes,"interrupt":true,"wake_idle":true,"attach_unrelated_tui":false},"requested_mode":format!("{requested:?}").to_lowercase(),"effective_mode":format!("{mode:?}").to_lowercase(),"confirmation":"observe native session updates and model replies separately"}})).await?;
                            }
                        }
                        write_json(&mut frontend_output,&value).await?;
                    }
                }
                result = &mut page, if receiving && initialized && loaded && pending.is_none() => {
                    let result = match result {
                        Ok(page)=>page,
                        Err(error)=>{
                            receiving=false;
                            write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/stopped","params":{"error":error.to_string(),"safe_cursor":cursor,"native_connection":"continues"}})).await?;
                            continue;
                        }
                    };
                    let objects=result["objects"].as_array().ok_or("invalid canonical attention page")?;
                    let next=result["next_cursor"].as_u64().filter(|next| *next>=cursor).ok_or("invalid attention cursor")?;
                    if objects.len()>1 { return Err("canonical attention page exceeds requested limit".into()); }
                    if let Some(event)=objects.first() {
                        let id=event["edge"]["attention_id"].as_str().filter(|id| crate::coord_tools::attention_id(id)).ok_or("invalid canonical attention ID")?;
                        if next==cursor { return Err("canonical attention did not advance its cursor".into()); }
                        if !delivered.iter().any(|seen| seen==id) {
                            write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/pending","params":{"attention_id":id,"next_cursor":next,"safe_cursor":cursor,"confirmation":"canonical_object_resolved"}})).await?;
                            pending=Some(result);
                            cancelled=false;
                        }
                    }
                    if pending.is_none() { cursor=next; page=Box::pin(next_page(client.clone(),cursor)); }
                }
            }
            if receiving && internal.is_none() && let Some(pending_page) = &pending {
                let session=session.as_ref().ok_or("missing bound session")?;
                if !active.is_empty() && mode==Mode::Interrupt && !cancelled {
                    write_json(&mut native_input,&json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session}})).await?;
                    cancelled=true;
                }
                if active.is_empty() || (mode==Mode::Steer && !cancelled) {
                    let steer=mode==Mode::Steer && !active.is_empty();
                    let content=attributed_content(&pending_page["objects"][0]);
                    let content=if steer {format!("/steer {content}")} else {content};
                    serial+=1;
                    let id=json!(format!("{request_prefix}{serial}"));
                    write_json(&mut native_input,&json!({"jsonrpc":"2.0","id":id,"method":"session/prompt","params":{"sessionId":session,"prompt":[{"type":"text","text":content}]}})).await?;
                    write_json(&mut frontend_output,&json!({"jsonrpc":"2.0","method":"safeyolo/attention/submitted","params":{"attention_id":pending_page["objects"][0]["edge"]["attention_id"],"safe_cursor":cursor,"confirmation":"native_request_sent"}})).await?;
                    internal=Some((id,steer));
                    steer_acknowledged=false;
                }
            }
        }
    }.await;
    if tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .is_err()
    {
        child.kill().await?;
        child.wait().await?;
    }
    if result.is_err() {
        eprintln!(
            "ACP attention stopped: session={session:?}, safe_cursor={cursor}; inspect native history before replay"
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_modes_and_native_steer_receipts_remain_distinct() {
        assert!(!supported(Harness::Gemini, Mode::Steer));
        assert!(!supported(Harness::Gemini, Mode::Context));
        assert!(!supported(Harness::Hermes, Mode::Context));
        assert!(supported(Harness::Hermes, Mode::Steer));
        assert!(hermes_steer_acknowledged(
            "⏩ Steer queued for the active turn: External SafeYolo Coord event."
        ));
        assert!(!hermes_steer_acknowledged("unsupported control"));
        assert!(!hermes_steer_acknowledged(
            "No active turn — queued for the next turn. (1 queued)"
        ));
    }
}
