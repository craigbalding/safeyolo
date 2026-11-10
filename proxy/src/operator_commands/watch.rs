//! Live approval review uses the existing subscriber, explanation and resolver.

use super::*;
use crate::coord_operator::signals::{WatchUpdate, follow};
use rustyline::{DefaultEditor, ExternalPrinter, error::ReadlineError};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct PendingRequests {
    numbered: BTreeMap<usize, Value>,
    next_number: usize,
    deferred: BTreeSet<usize>,
    current: bool,
}

impl PendingRequests {
    fn replace(&mut self, mut current: BTreeMap<String, Value>) -> bool {
        let before = self.numbered.clone();
        let recovered = !self.current;
        self.numbered.retain(|number, previous| {
            let id = text(&previous["approval_id"]);
            if let Some(value) = current.remove(id) {
                *previous = value;
                true
            } else {
                self.deferred.remove(number);
                false
            }
        });
        for value in current.into_values() {
            self.next_number += 1;
            self.numbered.insert(self.next_number, value);
        }
        self.current = true;
        recovered || self.numbered != before
    }

    fn render(&self, color: bool) -> Result<String, Error> {
        if !self.current && self.numbered.is_empty() {
            return Ok(format!(
                "{}: unavailable (current count unknown)\n",
                cue("PENDING APPROVALS", "33", color)
            ));
        }
        let mut output = format!(
            "{}: {}{}\n",
            cue("PENDING APPROVALS", "33", color),
            self.numbered.len(),
            if self.current {
                " (current state refreshed)"
            } else {
                " (last observed; unavailable or stale)"
            }
        );
        for (number, view) in &self.numbered {
            output.push_str(&format!(
                "  #{number}{} agent={} {}\n",
                if self.deferred.contains(number) {
                    " [left pending]"
                } else {
                    ""
                },
                safe(text(&view["agent"])),
                context_json(&view["summary"])?
            ));
        }
        if self.current && self.numbered.is_empty() {
            output.push_str("No pending approval requests. Watching for arrivals.\n");
        }
        if let Some(number) = self.numbered.keys().next() {
            output.push_str(&format!(
                "Type a displayed request number (for example, {number}) at watch> to review it.\n"
            ));
        }
        Ok(output)
    }
}

fn cue(label: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{label}\x1b[0m")
    } else {
        label.into()
    }
}

fn line(editor: &mut DefaultEditor, prompt: &str) -> Result<Option<String>, Error> {
    match editor.readline(prompt) {
        Ok(answer) => Ok(Some(answer)),
        Err(ReadlineError::Eof | ReadlineError::Interrupted) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn supported(view: &Value) -> bool {
    matches!(
        view["action"]["kind"].as_str(),
        Some(
            "network_allow"
                | "credential_allow"
                | "gateway_route"
                | "service_authorize"
                | "contract_binding"
                | "coord_access"
                | "coord_collaboration"
                | "operator_action"
        )
    )
}

// Numbers are display selections only. Resolve only the immutable canonical ID
// and inspected scope; never look up a new request by its position after input.
fn review(
    config: &Path,
    number: usize,
    entry: &Value,
    editor: &mut DefaultEditor,
    handle: &tokio::runtime::Handle,
    requests: &Mutex<PendingRequests>,
    color: bool,
) -> Result<bool, Error> {
    let id = entry["approval_id"]
        .as_str()
        .ok_or("approval identity unavailable")?;
    let view = match handle.block_on(approval(config, id, None)) {
        Ok(view) => view,
        Err(error) => {
            println!(
                "Request #{number} unavailable: {}. Use list to inspect pending requests again.",
                safe(&error.to_string())
            );
            return Ok(true);
        }
    };
    if view["approval_id"] != id || view["agent"] != entry["agent"] {
        println!("Request #{number} identity changed. Use list to select the current request.");
        return Ok(true);
    }
    println!(
        "{} #{number} | Agent: {} ({}) | Action: {} | Destination: {}",
        cue("REVIEW", "36", color),
        safe(text(&view["agent"])),
        safe(text(&view["action"]["agent_id"])),
        safe(text(&view["action"]["kind"])),
        context_json(&view["approval"]["target"])?
    );
    show_approval(&view)?;
    if view["status"] != "pending" {
        println!(
            "Request #{number} is no longer pending. Use list to review the remaining requests."
        );
        return Ok(true);
    }
    if !supported(&view) {
        println!(
            "This request type has no watch decision control. It remains pending. Inspect it with safeyolo approvals show {id} --json and use its specific policy control."
        );
        return Ok(true);
    }
    // Use the host's explanation for scope, lifetime and non-grants. A failed
    // explanation does not remove the existing manual decision path.
    match handle.block_on(explain(config, id, None, None)) {
        Ok(explanation) => show_explanation(&explanation)?,
        Err(error) => println!("Explanation unavailable: {}", safe(&error.to_string())),
    }
    let mut selected_option = None::<String>;
    loop {
        let prompt = format!(
            "Request #{number}: {} / explain [OPTION] / ask / context / later > ",
            approval_decision_commands(&view)
        );
        let Some(answer) = line(editor, &prompt)? else {
            return Ok(false);
        };
        let parts: Vec<_> = answer.split_whitespace().collect();
        match parts.as_slice() {
            ["q" | "quit"] => return Ok(false),
            [] | ["later" | "back"] => {
                requests
                    .lock()
                    .map_err(|_| "pending view unavailable")?
                    .deferred
                    .insert(number);
                println!(
                    "{} No decision sent for request #{number}. Use list or {number} to inspect current pending state.",
                    cue("UNCHANGED", "33", color)
                );
                return Ok(true);
            }
            ["list" | "l"] => {
                print!(
                    "{}",
                    requests
                        .lock()
                        .map_err(|_| "pending view unavailable")?
                        .render(color)?
                );
            }
            [command @ ("ask" | "a" | "context" | "c")] => {
                match handle.block_on(approval_context(
                    config,
                    id,
                    None,
                    matches!(*command, "ask" | "a"),
                )) {
                    Ok(context) => show_context(&context)?,
                    Err(error) => println!(
                        "Agent context unavailable: {}. Approve/reject remains available.",
                        safe(&error.to_string())
                    ),
                }
            }
            ["explain" | "e"] | ["explain" | "e", _] => {
                let option = parts.get(1).copied().or(selected_option.as_deref());
                match handle.block_on(explain(config, id, None, option)) {
                    Ok(explanation) => {
                        show_explanation(&explanation)?;
                        selected_option = explanation["selected_option"]["id"]
                            .as_str()
                            .map(str::to_owned);
                    }
                    Err(error) => println!("Explanation unavailable: {}", safe(&error.to_string())),
                }
            }
            ["approve"] | ["approve", _] | ["reject"] => {
                let decision = parts[0];
                let mut option = if decision == "approve" {
                    parts
                        .get(1)
                        .map(|value| (*value).to_owned())
                        .or(selected_option.clone())
                } else {
                    None
                };
                if decision == "approve"
                    && option.is_none()
                    && view["action"]["kind"] == "service_authorize"
                    && view["options"]
                        .as_array()
                        .is_some_and(|options| options.len() > 1)
                {
                    let Some(answer) = line(editor, "Option ID (Enter leaves pending): ")? else {
                        return Ok(false);
                    };
                    if answer.trim().is_empty() {
                        continue;
                    }
                    option = Some(answer.trim().to_owned());
                }
                // resolve_preview re-reads identity, scope, options and current
                // status. It reconciles a lost response without replaying POST.
                match handle.block_on(resolve_preview(
                    config,
                    &view,
                    decision,
                    None,
                    option.as_deref(),
                )) {
                    Ok(outcome) => {
                        println!(
                            "{} Request #{number}: {}",
                            cue("CANONICAL OUTCOME", "36", color),
                            safe(text(&outcome["status"]))
                        );
                        show_approval(&outcome)?;
                    }
                    Err(error) => println!(
                        "{} Request #{number}: {}. No decision is retried automatically; select this request again to inspect current state.",
                        cue("DECISION NOT CONFIRMED", "31", color),
                        safe(&error.to_string())
                    ),
                }
                return Ok(true);
            }
            _ => println!(
                "Choose approve [OPTION], reject, explain [OPTION], ask, context, list or later. q detaches."
            ),
        }
    }
}

pub(crate) async fn run(config: &Path, no_color: bool) -> Result<(), Error> {
    let config = config.to_owned();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || host_platform::with_config(config.clone(), || -> Result<(), Error> {
        let color = !no_color && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|term| term != "dumb");
        let mut editor = DefaultEditor::new()?;
        let mut printer = editor.create_external_printer()?;
        let requests = Arc::new(Mutex::new(PendingRequests::default()));
        println!("SafeYolo live approvals | Instance configuration: {}", safe(&config.display().to_string()));
        println!("Type a displayed request number to review it; list revisits pending requests; later leaves a request pending; q or Ctrl-C detaches. Waiting for current pending state.");
        let received_requests = requests.clone();
        let receiving_config = config.clone();
        let receiver = handle.spawn(async move {
            follow(&receiving_config, false, |update| {
                let output = {
                    let mut pending = received_requests.lock().map_err(|_| "pending view unavailable")?;
                    match update {
                        WatchUpdate::Display(output) => output,
                        WatchUpdate::Approvals { current, .. } => {
                            if pending.replace(current) { pending.render(color)? } else { String::new() }
                        }
                        WatchUpdate::Stale(notice) => {
                            pending.current = false;
                            format!("{}: {notice}\n", cue("STALE / UNAVAILABLE", "31", color))
                        }
                        WatchUpdate::Notice(notice) => format!("{notice}\n"),
                    }
                };
                if !output.is_empty() { printer.print(output)?; }
                Ok(())
            }).await
        });
        let result = (|| -> Result<(), Error> {
            loop {
                let Some(answer) = line(&mut editor, "watch> ")? else { break; };
                let answer = answer.trim();
                if matches!(answer, "q" | "quit") { break; }
                if matches!(answer, "" | "list" | "l") {
                    print!("{}", requests.lock().map_err(|_| "pending view unavailable")?.render(color)?);
                    continue;
                }
                let selected = answer.trim_start_matches('#').parse::<usize>().ok().and_then(|number| {
                    requests.lock().ok()?.numbered.get(&number).cloned().map(|entry| (number, entry))
                });
                let Some((number, entry)) = selected else {
                    println!("Choose a current request number or list. Resolved numbers are never reassigned.");
                    continue;
                };
                if !review(&config, number, &entry, &mut editor, &handle, &requests, color)? { break; }
            }
            Ok(())
        })();
        receiver.abort();
        // Release readline's external printer before joining its sender.
        drop(editor);
        match handle.block_on(receiver) {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {},
            Err(error) => return Err(error.into()),
        }
        result?;
        println!("Detached. Undecided requests remain pending.");
        Ok(())
    })).await?
}
