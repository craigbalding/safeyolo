//! Native exports for the existing Lab pane and text evidence helpers.

use crate::Error;
use regex::Regex;
use serde_json::json;
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const REDACTED: &str = "[REDACTED_CREDENTIAL]";

// Preserve the credential shapes used by the replaced Python exporter, including
// escaped JSON string values. Redaction is defense in depth; never collect login panes.
fn redact(text: &str) -> Result<String, Error> {
    // Remove whole JSON credential values before token substitutions can consume
    // an escape backslash and expose a suffix after a false closing quote.
    let patterns = [
        (r#"(?i)("(?:access_token|refresh_token|id_token|token|api_key|session_key|oauth_token|authorization|proxy-authorization|cookie|set-cookie|client_secret|password)"\s*:\s*")(?:\\.|[^"\\])*(")"#, "${1}[REDACTED_CREDENTIAL]${2}"),
        (r#"(?i)((?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+)[^\s\",}]+"#, "${1}[REDACTED_CREDENTIAL]"),
        (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b", REDACTED),
        (r"\b(?:sk-(?:proj-|ant-oat01-|ant-api03-)?|sgw_)[A-Za-z0-9_-]{16,}\b", REDACTED),
        (r"(?i)((?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CODEX_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|AGENT_TOKEN|ADMIN_TOKEN)\s*=\s*)\S+", "${1}[REDACTED_CREDENTIAL]"),
    ].into_iter().map(|(pattern, replacement)| Ok((Regex::new(pattern)?, replacement))).collect::<Result<Vec<_>, regex::Error>>()?;
    let begin =
        Regex::new(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|NATS USER JWT|USER NKEY SEED)-----")?;
    let end = Regex::new(r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|NATS USER JWT|USER NKEY SEED)-----")?;
    let mut private = false;
    let mut output = String::new();
    for line in text.split_inclusive('\n') {
        if private {
            if end.is_match(line) {
                private = false;
            }
            continue;
        }
        if begin.is_match(line) {
            output.push_str(REDACTED);
            output.push('\n');
            private = true;
            continue;
        }
        let mut line = line.to_owned();
        for (pattern, replacement) in &patterns {
            line = pattern.replace_all(&line, *replacement).into_owned();
        }
        output.push_str(&line);
    }
    Ok(output)
}

fn read_text(path: &Path) -> Result<String, Error> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("Lab evidence input must be a regular text file".into());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    if text.chars().any(|c| {
        (c < ' ' && !matches!(c, '\t' | '\n' | '\r' | '\u{c}' | '\u{1b}')) || c == '\u{7f}'
    }) {
        return Err("Lab evidence input contains non-text control characters".into());
    }
    Ok(text)
}

fn write(path: &Path, text: &str) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

fn credential_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "auth.json"
            | "agent_token"
            | "admin_token"
            | "hmac_secret"
            | "creds"
            | "vm_ssh_key"
            | "proxy.env"
            | "id_rsa"
            | "id_ed25519"
    ) || [".credentials.json", ".p12", ".pfx", ".key", "-key.pem"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
        || (name.contains("private") && name.ends_with(".pem"))
}

fn tmux(socket: Option<&Path>, args: &[&str]) -> Result<String, Error> {
    let mut command = Command::new("tmux");
    if let Some(socket) = socket {
        command.arg("-S").arg(socket);
    }
    let output = command.args(args).output()?;
    if !output.status.success() {
        return Err("Lab evidence tmux command failed; the session remains intact".into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn capture(args: &[OsString]) -> Result<(), Error> {
    let mut root = None;
    let mut socket = None;
    let mut panes = Vec::new();
    let mut files = Vec::new();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("Lab capture option requires a value")?;
        match flag.to_str() {
            Some("--output") => root = Some(PathBuf::from(value)),
            Some("--socket") => socket = Some(PathBuf::from(value)),
            Some("--pane") => panes.push(value.to_str().ok_or("pane ID must be text")?.to_owned()),
            Some("--file") => files.push(PathBuf::from(value)),
            _ => return Err("capture requires --output DIR and --pane ID or --file PATH".into()),
        }
    }
    let root = root.ok_or("Lab capture needs --output DIR")?;
    if panes.is_empty() && files.is_empty() {
        return Err("Lab capture needs a pane or text file".into());
    }
    // Preflight every input before publishing any capture.
    let mut inputs = Vec::new();
    for pane in panes {
        let metadata = tmux(
            socket.as_deref(),
            &[
                "display-message",
                "-p",
                "-t",
                &pane,
                "#{socket_path}\t#{session_name}\t#{window_id}\t#{pane_id}\t#{@safeyolo_lab_role}\t#{pane_title}\t#{pane_dead}\t#{pane_pid}",
            ],
        )?;
        let text = tmux(
            socket.as_deref(),
            &["capture-pane", "-p", "-t", &pane, "-S", "-"],
        )?;
        inputs.push((json!({"kind":"pane","requested_target":pane,"pane_metadata":redact(&metadata)?,"tmux_socket":socket}), text));
    }
    for path in files {
        if credential_path(&path) {
            return Err("refusing credential-bearing Lab evidence filename".into());
        }
        let text = read_text(&path)?;
        inputs.push((
            json!({"kind":"file","source_path":path.canonicalize()?,"source_bytes":text.len()}),
            text,
        ));
    }
    if fs::symlink_metadata(&root).is_ok_and(|m| m.file_type().is_symlink() || !m.is_dir()) {
        return Err("Lab evidence root must be a directory, without a symlink".into());
    }
    fs::create_dir_all(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let stage = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(&root)?;
    let mut manifest = String::new();
    let mut sums = String::new();
    for (index, (mut record, text)) in inputs.into_iter().enumerate() {
        let name = format!(
            "{:03}-{}.txt",
            index + 1,
            record["kind"].as_str().unwrap_or("evidence")
        );
        let text = redact(&text)?;
        write(&stage.path().join(&name), &text)?;
        let digest: String = ring::digest::digest(&ring::digest::SHA256, text.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sums.push_str(&format!("{digest}  {name}\n"));
        record["captured_path"] = name.into();
        record["captured_bytes"] = text.len().into();
        record["captured_utc_seconds"] = crate::now().into();
        record["redaction"] = "credential-redactor".into();
        manifest.push_str(&serde_json::to_string(&record)?);
        manifest.push('\n');
    }
    write(&stage.path().join("manifest.jsonl"), &manifest)?;
    write(&stage.path().join("SHA256SUMS"), &sums)?;
    write(
        &stage.path().join("capture-status.txt"),
        "status=complete\n",
    )?;
    let name = stage
        .path()
        .file_name()
        .ok_or("capture name is missing")?
        .to_string_lossy()
        .replacen(".capture-", "capture-", 1);
    let destination = root.join(name);
    fs::rename(stage.path(), &destination)?;
    println!("{}", destination.display());
    Ok(())
}

pub(crate) fn run(args: &[OsString]) -> Result<i32, Error> {
    match args {
        [command, rest @ ..] if command == "capture" => capture(rest)?,
        [command, check, file] if command == "redact" && check == "--check-text" => {
            read_text(Path::new(file))?;
        }
        [command, rest @ ..] if command == "redact" && rest.len() <= 2 => {
            let text = if let Some(input) = rest.first() {
                if let Some(output) = rest.get(1) {
                    let input = fs::symlink_metadata(input)?;
                    if fs::symlink_metadata(output)
                        .is_ok_and(|m| m.dev() == input.dev() && m.ino() == input.ino())
                    {
                        return Err("refusing identical Lab evidence input and output".into());
                    }
                }
                read_text(Path::new(input))?
            } else {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text)?;
                text
            };
            let text = redact(&text)?;
            if let Some(path) = rest.get(1) {
                write(Path::new(path), &text)?;
            } else {
                print!("{text}");
            }
        }
        _ => return Err("usage: safeyolo-guest lab-evidence capture|redact".into()),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_removed_and_public_markers_survive() {
        let input = "Authorization: Bearer fake-value\n{\"api_key\":\"sk-proj-FakeValue0123456789ABCDE\"}\nAGENT_TOKEN=fake-value\n-----BEGIN USER NKEY SEED-----\nprivate-value\n-----END USER NKEY SEED-----\nmarker=visible\n";
        let output = redact(input).unwrap();
        assert!(!output.contains("fake-value"));
        assert!(!output.contains("private-value"));
        assert!(!output.contains("sk-proj-"));
        assert!(output.contains("marker=visible"));
        assert!(output.contains(REDACTED));
        let escaped =
            redact(r#"{"password":"fixture\"remaining-secret","marker":"visible"}"#).unwrap();
        assert!(!escaped.contains("remaining-secret"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&escaped).unwrap()["marker"],
            "visible"
        );
    }
    #[test]
    fn nonregular_inputs_and_identical_output_preserve_the_source() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("text");
        fs::write(&file, "marker").unwrap();
        let args = [
            "redact".into(),
            file.clone().into_os_string(),
            file.clone().into_os_string(),
        ];
        assert!(run(&args).is_err());
        assert_eq!(fs::read_to_string(&file).unwrap(), "marker");
        assert!(read_text(temp.path()).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_text(&link).is_err());
        let fifo = temp.path().join("fifo");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_text(&fifo).is_err());
    }
}
