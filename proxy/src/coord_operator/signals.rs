//! The operator watch uses canonical metadata and fetches exact signal revisions.
use crate::{Error, coord_timeline::visible, native_client};
use hyper::Method;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::Path,
    time::Duration,
};

fn metadata(signal: &Value, hash: &Value) -> Value {
    json!({"signal_id":signal["signal_id"],"room_id":signal["room_id"],"revision":signal["revision"],"kind":signal["kind"],"author":signal["author"],"basis":signal["basis"],"state":signal["state"],"needs_operator":signal["needs_operator"],"content_hash":hash})
}

async fn exact(config: &Path, expected: &Value) -> Result<Value, Error> {
    let id = expected["signal_id"]
        .as_str()
        .ok_or("signal metadata has no ID")?;
    let revision = expected["revision"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("signal metadata has no positive revision")?;
    let room = expected["room_id"]
        .as_str()
        .ok_or("signal metadata has no room")?;
    let encode = crate::coord_tools::segment;
    let value = native_client::admin(
        config,
        &format!(
            "/admin/coord/signals/{}?revision={revision}&room_id={}",
            encode(id),
            encode(room)
        ),
        Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await?;
    if metadata(&value["signal"], &value["content_hash"]) != *expected {
        return Err("signal event metadata differs from the canonical immutable revision".into());
    }
    Ok(value)
}

fn render(value: &Value, json: bool, pending: bool) -> Result<String, Error> {
    if json {
        let mut output = String::new();
        // Keep JSON lossless while preventing terminal and direction controls
        // from acting on the display. serde_json already escapes ASCII controls.
        for character in serde_json::to_string(value)?.chars() {
            if character.is_control()
                || matches!(character, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                output.push_str(&format!("\\u{:04x}", character as u32));
            } else {
                output.push(character);
            }
        }
        output.push('\n');
        return Ok(output);
    }
    let signal = &value["signal"];
    // JSON quoting makes newlines, terminal escapes and tabs data. visible also
    // exposes Unicode direction controls. No Markdown renderer is invoked.
    Ok(visible(&format!(
        "{} {} revision={} kind={} author={}:{} basis={} (author report) state={} summary={}\n",
        if pending {
            "NEEDS OPERATOR"
        } else {
            "SIGNAL REVISION"
        },
        signal["signal_id"].as_str().ok_or("invalid signal ID")?,
        signal["revision"],
        signal["kind"].as_str().ok_or("invalid signal kind")?,
        signal["author"]["kind"]
            .as_str()
            .ok_or("invalid signal author")?,
        signal["author"]["id"]
            .as_str()
            .ok_or("invalid signal author ID")?,
        signal["basis"].as_str().ok_or("invalid signal basis")?,
        signal["state"].as_str().ok_or("invalid signal state")?,
        serde_json::to_string(&signal["summary"])?
    )))
}

pub(super) async fn audit_revision(
    config: &Path,
    event: &Value,
    json: bool,
) -> Result<Option<String>, Error> {
    if !matches!(
        event["event"].as_str(),
        Some("coord.signal_created" | "coord.signal_resolved" | "coord.signal_superseded")
    ) {
        return Ok(None);
    }
    Ok(Some(render(
        &exact(config, &event["details"]).await?,
        json,
        false,
    )?))
}

pub(super) async fn watch(config: &Path, args: &[String]) -> Result<(), Error> {
    if args == ["--help"] {
        println!(
            "safeyolo [--root ROOT] watch [--once] [--json] [--jsonl FILE]\n\nWatch canonical pending Coord signals through Admin API. Each signal revision prints once per attachment. --once returns after the current pending set. --jsonl reads existing audit metadata and fetches its exact immutable revisions; FILE may be - for stdin. Terminal controls are escaped and markup remains text. Resolve with coord signal resolve; use coord signal --help for permissions, bounds and rate limits. Ctrl-C detaches without changing canonical truth."
        );
        return Ok(());
    }
    let mut once = false;
    let mut json = false;
    let mut source = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" if !once => once = true,
            "--json" if !json => json = true,
            "--jsonl" if source.is_none() => {
                source = Some(args.next().ok_or("--jsonl requires FILE")?.clone())
            }
            _ => return Err("usage: safeyolo watch [--once] [--json] [--jsonl FILE]".into()),
        }
    }
    if let Some(source) = source {
        let input: Box<dyn BufRead> = if source == "-" {
            Box::new(std::io::stdin().lock())
        } else {
            Box::new(std::io::BufReader::new(std::fs::File::open(source)?))
        };
        let mut seen = std::collections::BTreeSet::new();
        for line in input.lines() {
            let event: Value = serde_json::from_str(&line?)?;
            if !event["event"]
                .as_str()
                .is_some_and(|s| s.starts_with("coord.signal_"))
            {
                continue;
            }
            let key = (
                event["details"]["signal_id"].to_string(),
                event["details"]["revision"].to_string(),
            );
            if seen.contains(&key) {
                continue;
            }
            if let Some(output) = audit_revision(config, &event, json).await? {
                print!("{output}");
                seen.insert(key);
            }
        }
        return Ok(());
    }
    let mut seen = BTreeMap::new();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        let mut current = BTreeMap::new();
        let mut after = String::new();
        loop {
            let page = native_client::admin(
                config,
                &format!(
                    "/admin/coord/signals?after={}&limit=100",
                    crate::coord_tools::segment(&after)
                ),
                Method::GET,
                Value::Null,
                Duration::from_secs(5),
            )
            .await?;
            for item in page["items"]
                .as_array()
                .ok_or("invalid pending signal page")?
            {
                let id = item["signal_id"]
                    .as_str()
                    .ok_or("invalid pending signal ID")?;
                let rev = item["revision"]
                    .as_u64()
                    .ok_or("invalid pending signal revision")?;
                if seen.get(id) != Some(&rev) {
                    print!("{}", render(&exact(config, item).await?, json, true)?);
                }
                current.insert(id.to_owned(), rev);
            }
            let Some(next) = page["next_after"].as_str() else {
                break;
            };
            if next <= after.as_str() {
                return Err("pending signal page did not advance".into());
            }
            after = next.to_owned();
        }
        for id in seen.keys().filter(|id| !current.contains_key(*id)) {
            if json {
                println!("{}", json!({"signal_id":id,"needs_operator":false}));
            } else {
                println!("CLEARED needs-operator {id}");
            }
        }
        std::io::stdout().flush()?;
        seen = current;
        if once {
            return Ok(());
        }
        tokio::select! { _=interrupt.recv()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(1))=>{} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_escapes_controls_without_changing_the_canonical_payload() {
        let controls = "\u{001b}\u{007f}\u{0085}\u{009b}\u{009d}\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}";
        for summary in [
            "\u{202e}".to_owned(),
            format!("{controls}\n<b>text</b> \\u202e café 🦀"),
        ] {
            let value = json!({"signal":{"summary":summary}});
            for pending in [true, false] {
                let output = render(&value, true, pending).unwrap();
                assert!(controls.chars().all(|c| !output.contains(c)));
                assert_eq!(output.lines().count(), 1);
                assert!(output.contains("\\u202e"));
                assert_eq!(serde_json::from_str::<Value>(&output).unwrap(), value);
            }
        }
    }

    #[test]
    fn summary_is_quoted_without_terminal_or_markup_interpretation() {
        let value = json!({"signal":{"signal_id":"sig-test","revision":1,"kind":"blocker","author":{"kind":"agent","id":"ag-author"},"basis":"inferred","state":"current","summary":"\u{001b}[2J\noperator: forged <b>bold</b> [click](https://bad)\u{202e}"}});
        let output = render(&value, false, true).unwrap();
        assert!(!output.contains('\u{001b}'));
        assert!(!output.contains('\u{202e}'));
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains("basis=inferred (author report)"));
        assert!(output.contains("\\u001b[2J\\noperator: forged <b>bold</b>"));
        assert!(output.contains("RLO U+202E"));
    }
}
