//! Git receives only the calling agent's current gateway credential.

use std::{
    ffi::OsString,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

use crate::{Error, Paths};

fn github_request(input: &str) -> bool {
    let mut protocol = None;
    let mut host = None;
    for line in input.lines().take_while(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let field = match key {
            "protocol" => &mut protocol,
            "host" => &mut host,
            _ => continue,
        };
        if field.replace(value).is_some() {
            return false;
        }
    }
    protocol == Some("https")
        && host.is_some_and(|host| {
            host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("github.com:443")
        })
}

fn password(services: &serde_json::Value) -> Option<&str> {
    let service = &services["authorized"]["github-git"];
    if !service["host"].as_str()?.eq_ignore_ascii_case("github.com") {
        return None;
    }
    service["token"]
        .as_str()
        .filter(|token| token.starts_with("sgw_") && !token.chars().any(char::is_whitespace))
}

fn read_services(token_path: &Path) -> Result<serde_json::Value, Error> {
    let token = std::fs::read_to_string(token_path)
        .map_err(|_| "Git helper cannot read the guest Agent API token")?;
    if token.trim().is_empty() || token.trim().contains(['\r', '\n']) {
        return Err("Git helper Agent API token is invalid".into());
    }
    let mut curl = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "--header",
            "@-",
            "http://_safeyolo.proxy.internal/gateway/services",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Git helper requires guest curl")?;
    curl.stdin
        .take()
        .ok_or("Git helper input unavailable")?
        .write_all(format!("Authorization: Bearer {}\n", token.trim()).as_bytes())?;
    let output = curl.wait_with_output()?;
    if !output.status.success() {
        return Err("Git helper could not read authorized services; check the Agent API and service authorization".into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Git helper received invalid service metadata".into())
}

pub fn run(paths: &Paths, args: &[OsString]) -> Result<i32, Error> {
    let [operation] = args else {
        return Err("git-credential requires get, store, or erase".into());
    };
    // Git may call store after success. Never save either the synthetic
    // password or a credential supplied by a different helper.
    if operation == "store" || operation == "erase" {
        return Ok(0);
    }
    if operation != "get" {
        return Err("git-credential requires get, store, or erase".into());
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    if !github_request(&input) {
        return Ok(0);
    }
    // The existing --context selects the staged config share. The host stages
    // agent_token beside host-launch-context.json for this guest only.
    let share = paths
        .context
        .parent()
        .ok_or("Git helper context has no parent")?;
    let services = read_services(&share.join("agent_token"))?;
    if let Some(password) = password(&services) {
        writeln!(
            std::io::stdout(),
            "username=x-access-token\npassword={password}\n"
        )?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_https_github_requests_use_the_gateway() {
        assert!(github_request(
            "protocol=https\nhost=github.com\npath=owner/repo.git\n\n"
        ));
        for input in [
            "protocol=http\nhost=github.com\n",
            "protocol=https\nhost=github.com.evil\n",
            "protocol=https\nhost=github.com:444\n",
            "protocol=https\nhost=github.com\nhost=evil\n",
        ] {
            assert!(!github_request(input));
        }
    }

    #[test]
    fn only_the_authorized_opaque_password_is_returned() {
        let mut services =
            json!({"authorized":{"github-git":{"host":"github.com","token":"sgw_fixture"}}});
        assert_eq!(password(&services), Some("sgw_fixture"));
        services["authorized"]["github-git"]["token"] = "real-pat".into();
        assert!(password(&services).is_none());
        services["authorized"]["github-git"]["token"] = "sgw_fixture\nextra".into();
        assert!(password(&services).is_none());
        assert!(password(&json!({"authorized":{}})).is_none());
    }
}
