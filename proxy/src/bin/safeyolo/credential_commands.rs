//! Native host credential setup and the existing operator service operations.

use std::{
    collections::BTreeMap,
    io::{IsTerminal, Read, Write},
    path::Path,
};

use hyper::Method;
use safeyolo_proxy::{
    Error,
    credentials::{self, Credential, ExternalReference, Secret},
    native_config,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const CREDENTIAL_HELP: &str = "safeyolo [--root ROOT] credentials add NAME [--type bearer|api_key|oauth2] [--value-file FILE | --value-env NAME | --stdin]\nsafeyolo [--root ROOT] credentials add NAME --type oauth2 --value-file FILE --refresh-token-file FILE --token-url URL [--client-id ID] [--client-secret-file FILE] [--expires-at TIME]\nsafeyolo [--root ROOT] credentials reference NAME --provider onepassword --reference op://VAULT/ITEM/FIELD [--type bearer|api_key]\nsafeyolo [--root ROOT] credentials provider --executable /absolute/host/path/to/op\nsafeyolo [--root ROOT] credentials approve FINGERPRINT --destination HOST\nsafeyolo [--root ROOT] credentials list\nsafeyolo [--root ROOT] credentials remove NAME\n\nWith no value source, add prompts without echo, or reads piped stdin. Values never appear in output or argv. Metadata shows names, types and external references. The host stores encrypted local values; external values are read only after request authorization and approval. Provider authentication stays in the host environment. If credential policy requires approval, inspect services approvals and approve its fingerprint for the reported destination; this is separate from a service risk grant. Restart the proxy after changing its configured provider executable.";

pub const SERVICE_HELP: &str = "safeyolo [--root ROOT] services list\nsafeyolo [--root ROOT] services show NAME\nsafeyolo [--root ROOT] services authorize AGENT SERVICE --capability NAME [--credential NAME] [--account NAME] [--host HOST] [--allow-host-network]\nsafeyolo [--root ROOT] services authorized AGENT\nsafeyolo [--root ROOT] services revoke AGENT SERVICE\nsafeyolo [--root ROOT] services bind AGENT SERVICE CAPABILITY --bindings FILE\nsafeyolo [--root ROOT] services approvals\nsafeyolo [--root ROOT] services approve AGENT SERVICE METHOD PATH [--lifetime once|session|remembered]\nsafeyolo [--root ROOT] services grants\nsafeyolo [--root ROOT] services revoke-grant ID\n\nlist/show read the running gateway's accepted catalogue. Operator definitions override builtins with the same name. authorize selects its capability, credential reference and account; --host maps the destination (default: the definition's host). --allow-host-network explicitly permits host-wide network access; service access remains agent-scoped; existing credential policy still applies. Credential-free services omit --credential. authorized shows only this agent's minted gateway credential and scope. bind approves contract values; approve permits a risky route. Neither replaces service authorization. Revocation removes access and keeps the credential for other uses.";

fn options(arguments: &[String]) -> Result<BTreeMap<&str, &str>, Error> {
    let mut fields = BTreeMap::new();
    let mut arguments = arguments.iter();
    while let Some(key) = arguments.next() {
        if !key.starts_with("--") {
            return Err("expected a named option".into());
        }
        let value = if matches!(key.as_str(), "--stdin" | "--allow-host-network") {
            "true"
        } else {
            arguments
                .next()
                .ok_or_else(|| format!("{key} requires a value"))?
        };
        if fields.insert(key.as_str(), value).is_some() {
            return Err("duplicate option".into());
        }
    }
    Ok(fields)
}

fn validate_options(fields: &BTreeMap<&str, &str>, allowed: &[&str]) -> Result<(), Error> {
    if fields.keys().any(|key| !allowed.contains(key)) {
        return Err("unknown option; see --help".into());
    }
    Ok(())
}

fn file_secret(path: &str) -> Result<Secret, Error> {
    let value = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|_| "cannot read credential input file")?,
    );
    Ok(Secret::new(value.trim_end_matches(['\r', '\n'])))
}

fn read_value(fields: &BTreeMap<&str, &str>) -> Result<Secret, Error> {
    if ["--value-file", "--value-env", "--stdin"]
        .iter()
        .filter(|key| fields.contains_key(**key))
        .count()
        > 1
    {
        return Err("select one value source".into());
    }
    if let Some(path) = fields.get("--value-file") {
        return file_secret(path);
    }
    if let Some(name) = fields.get("--value-env") {
        return Ok(Secret::new(
            std::env::var(name).map_err(|_| "credential environment variable is unavailable")?,
        ));
    }
    let mut value = Zeroizing::new(String::new());
    let terminal = std::io::stdin().is_terminal();
    let mut echo = None;
    if terminal {
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, mode.as_mut_ptr()) } != 0 {
            return Err("cannot disable terminal echo; use --value-file".into());
        }
        let original = unsafe { mode.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err("cannot disable terminal echo; use --value-file".into());
        }
        echo = Some(TerminalEcho(original));
        eprint!("Credential value: ");
        std::io::stderr().flush()?;
        std::io::stdin().read_line(&mut value)?;
    } else {
        std::io::stdin().read_to_string(&mut value)?;
    }
    drop(echo);
    Ok(Secret::new(value.trim_end_matches(['\r', '\n'])))
}

struct TerminalEcho(libc::termios);
impl Drop for TerminalEcho {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
        }
        eprintln!();
    }
}

pub async fn credentials(config_path: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments.is_empty() || arguments == ["--help"] {
        println!("{CREDENTIAL_HELP}");
        return Ok(());
    }
    if let [command, rest @ ..] = arguments
        && command == "provider"
    {
        let fields = options(rest)?;
        validate_options(&fields, &["--executable"])?;
        let executable = fields
            .get("--executable")
            .ok_or("--executable is required")?;
        if !Path::new(executable).is_absolute() {
            return Err("--executable must be an absolute host path".into());
        }
        let mut document: toml_edit::DocumentMut = std::fs::read_to_string(config_path)?.parse()?;
        document["onepassword_executable"] = toml_edit::value(*executable);
        let source = document.to_string();
        // Use the strict loader and same-directory paths before publication.
        let temporary =
            config_path.with_file_name(format!(".provider-{}.toml", uuid::Uuid::new_v4().simple()));
        use std::os::unix::fs::OpenOptionsExt;
        let result = (|| -> Result<(), Error> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(source.as_bytes())?;
            file.sync_all()?;
            native_config::read(&temporary)?;
            std::fs::rename(&temporary, config_path)?;
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        result?;
        println!("Host 1Password executable configured. Restart the proxy to activate it.");
        return Ok(());
    }
    if let [command, fingerprint, rest @ ..] = arguments
        && command == "approve"
    {
        let fields = options(rest)?;
        validate_options(&fields, &["--destination"])?;
        let destination = fields
            .get("--destination")
            .ok_or("--destination is required")?;
        let response = super::admin(
            config_path,
            "/admin/policy/baseline/approve",
            Method::POST,
            json!({"destination":destination,"cred_id":fingerprint}),
        )
        .await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    let config = native_config::read(config_path)?;
    let vault = credentials::open(
        config
            .data_dir
            .as_deref()
            .ok_or("credential data directory is unavailable")?,
    )?;
    match arguments {
        [command] if command == "list" => {
            println!("{}", serde_json::to_string_pretty(&vault.metadata()?)?)
        }
        [command, name] if command == "remove" => {
            if !vault.remove(name)? {
                return Err("credential not found".into());
            }
            println!("Credential removed: {name}");
        }
        [command, name, rest @ ..] if matches!(command.as_str(), "add" | "reference") => {
            let fields = options(rest)?;
            let allowed: &[&str] = if command == "reference" {
                &["--type", "--provider", "--reference"]
            } else {
                &[
                    "--type",
                    "--value-file",
                    "--value-env",
                    "--stdin",
                    "--refresh-token-file",
                    "--token-url",
                    "--client-id",
                    "--client-secret-file",
                    "--expires-at",
                ]
            };
            validate_options(&fields, allowed)?;
            let kind = *fields.get("--type").unwrap_or(&"bearer");
            if !matches!(kind, "bearer" | "api_key" | "oauth2") {
                return Err("type must be bearer, api_key, or oauth2".into());
            }
            if name.is_empty() {
                return Err("credential name is required".into());
            }
            let mut record = if command == "reference" {
                if fields.get("--provider") != Some(&"onepassword") {
                    return Err("provider must be onepassword".into());
                }
                let reference = ExternalReference::Onepassword(
                    fields
                        .get("--reference")
                        .ok_or("--reference is required")?
                        .to_string(),
                );
                reference.validate()?;
                let mut record = Credential::new(name, kind, Secret::new(""));
                record.reference = Some(reference);
                record
            } else {
                let value = read_value(&fields)?;
                if value.expose_secret().is_empty() {
                    return Err("credential value is empty".into());
                }
                Credential::new(name, kind, value)
            };
            record.refresh_token = fields
                .get("--refresh-token-file")
                .map(|path| file_secret(path))
                .transpose()?;
            record.client_secret = fields
                .get("--client-secret-file")
                .map(|path| file_secret(path))
                .transpose()?;
            record.token_url = fields.get("--token-url").map(|value| value.to_string());
            record.client_id = fields.get("--client-id").map(|value| value.to_string());
            record.expires_at = fields.get("--expires-at").map(|value| value.to_string());
            record.is_expired(time::OffsetDateTime::now_utc())?;
            vault.store(record)?;
            println!("Credential stored: {name} (type={kind})");
        }
        _ => return Err("invalid credentials command; see credentials --help".into()),
    }
    Ok(())
}

pub async fn services(config: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments.is_empty() || arguments == ["--help"] {
        println!("{SERVICE_HELP}");
        return Ok(());
    }
    let (path, method, body) = match arguments {
        [command] if command == "list" => ("/admin/services".to_owned(), Method::GET, Value::Null),
        [command, name] if command == "show" => {
            let catalogue =
                super::admin(config, "/admin/services", Method::GET, Value::Null).await?;
            let service = catalogue["services"]
                .as_array()
                .and_then(|services| {
                    services
                        .iter()
                        .find(|service| service["definition"]["name"] == *name)
                })
                .ok_or("service is not loaded in the running catalogue")?;
            println!("{}", serde_json::to_string_pretty(service)?);
            return Ok(());
        }
        [command, agent] if command == "authorized" => (
            format!("/admin/agents/{}/services", segment(agent)),
            Method::GET,
            Value::Null,
        ),
        [command, agent, service] if command == "revoke" => (
            format!(
                "/admin/agents/{}/services/{}",
                segment(agent),
                segment(service)
            ),
            Method::DELETE,
            Value::Null,
        ),
        [command, agent, service, rest @ ..] if command == "authorize" => {
            let fields = options(rest)?;
            validate_options(
                &fields,
                &[
                    "--capability",
                    "--credential",
                    "--account",
                    "--host",
                    "--allow-host-network",
                ],
            )?;
            let mut body = json!({"service": service, "capability":fields.get("--capability").ok_or("--capability is required")?});
            for (option, field) in [
                ("--credential", "credential"),
                ("--account", "account"),
                ("--host", "host"),
            ] {
                if let Some(value) = fields.get(option) {
                    body[field] = json!(value);
                }
            }
            body["allow_host_network"] = json!(fields.contains_key("--allow-host-network"));
            (
                format!("/admin/agents/{}/services", segment(agent)),
                Method::POST,
                body,
            )
        }
        [command, agent, service, capability, rest @ ..] if command == "bind" => {
            let fields = options(rest)?;
            validate_options(&fields, &["--bindings"])?;
            let bindings: Value = serde_json::from_slice(&std::fs::read(
                fields.get("--bindings").ok_or("--bindings is required")?,
            )?)?;
            let catalogue =
                super::admin(config, "/admin/services", Method::GET, Value::Null).await?;
            let definition = catalogue["services"]
                .as_array()
                .and_then(|services| {
                    services
                        .iter()
                        .find(|row| row["definition"]["name"] == *service)
                })
                .ok_or("service is not loaded in the running catalogue")?;
            let contract = definition["definition"]["capabilities"][capability]["contract"].clone();
            if contract.is_null() {
                return Err("capability has no contract to bind".into());
            }
            let contract: safeyolo_proxy::contracts::ContractTemplate =
                serde_json::from_value(contract)?;
            let operations = contract
                .grantable_operations()
                .map(|operation| &operation.name)
                .collect::<Vec<_>>();
            (
                "/admin/gateway/contract-binding".into(),
                Method::POST,
                json!({"agent":agent,"service":service,"capability":capability,"bindings":bindings,"template":contract.template,"grantable_operations":operations}),
            )
        }
        [command] if command == "approvals" => {
            ("/admin/approvals".into(), Method::GET, Value::Null)
        }
        [command, agent, service, method, path, rest @ ..] if command == "approve" => {
            let fields = options(rest)?;
            validate_options(&fields, &["--lifetime"])?;
            (
                "/admin/gateway/grant".into(),
                Method::POST,
                json!({"agent":agent,"service":service,"method":method,"path":path,"lifetime":fields.get("--lifetime").unwrap_or(&"once")}),
            )
        }
        [command] if command == "grants" => {
            ("/admin/gateway/grants".into(), Method::GET, Value::Null)
        }
        [command, id] if command == "revoke-grant" => (
            format!("/admin/gateway/grants/{}", segment(id)),
            Method::DELETE,
            Value::Null,
        ),
        _ => return Err("invalid services command; see services --help".into()),
    };
    let response = super::admin(config, &path, method, body).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("String write");
        }
    }
    encoded
}
