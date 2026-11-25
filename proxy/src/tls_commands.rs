//! Human paths for the current native TLS settings.

use crate::{Error, native_config, operator_output as out};
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use serde_json::json;
use std::{fs, io::Write, path::Path};

pub const HELP: &str = "safeyolo tls ca [--pem] [--json]\nsafeyolo tls upstream [FILE | --clear] [--json]\nsafeyolo tls passthrough list|add|remove [HOST] [--json]\n\nTLS trust and passthrough

  tls ca [--pem]                    Inspect this instance's public CA
  tls upstream                     Show the additional upstream CA selection
  tls upstream FILE                Trust a PEM CA bundle after proxy restart
  tls upstream --clear             Return to packaged public roots
  tls passthrough list              List saved TLS passthrough destinations
  tls passthrough add HOST[:PORT]    Save an exact passthrough destination
  tls passthrough remove HOST[:PORT] Remove a saved destination

Passthrough leaves TLS encrypted end to end. SafeYolo cannot inspect its HTTP
content or enforce HTTP credential/route rules there; network controls remain.
Changes are saved for the next proxy start; existing connections are unchanged.
Use --json for complete settings. --pem emits the requested public certificate.
Examples: safeyolo tls ca; safeyolo tls upstream ./company-ca.pem";

pub async fn run(config: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments.is_empty() || arguments.iter().any(|arg| arg == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let arguments = out::without_json(arguments);
    let read = native_config::read(config)?;
    match arguments.as_slice() {
        [kind] | [kind, _] if kind == "ca" => {
            let path = read
                .tls_ca_file
                .as_deref()
                .ok_or("this instance has no TLS CA selected")?;
            let ca = crate::tls::CertificateAuthority::load(path)?;
            let bytes = ca.certificate().as_ref();
            if arguments.get(1).is_some_and(|arg| arg == "--pem") {
                // The selected signing file also contains its private key.
                // Encode only the validated public certificate.
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                let mut output = std::io::stdout().lock();
                writeln!(output, "-----BEGIN CERTIFICATE-----")?;
                for line in encoded.as_bytes().chunks(64) {
                    output.write_all(line)?;
                    writeln!(output)?;
                }
                writeln!(output, "-----END CERTIFICATE-----")?;
            } else if arguments.len() != 1 {
                return Err("use tls ca or tls ca --pem".into());
            } else {
                let sha = ring::digest::digest(&ring::digest::SHA256, bytes);
                let sha: String = sha
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let value = json!({"signing_file":path,"sha256":sha,"fingerprint_encoding":"certificate DER","private_key":"withheld"});
                if out::json_requested() {
                    out::json(&value)?;
                } else {
                    out::field("CA signing file", &value["signing_file"]);
                    out::field("SHA-256", &value["sha256"]);
                    println!("Use tls ca --pem to export only the public certificate.");
                }
            }
            return Ok(());
        }
        [kind] if kind == "upstream" => {
            let value = json!({"upstream_ca_file":read.upstream_ca_file,"scope":"saved selection; active process may differ"});
            if out::json_requested() {
                out::json(&value)?;
            } else {
                println!(
                    "Additional upstream CA: {}",
                    out::text(&value["upstream_ca_file"])
                );
                println!("Packaged public roots remain trusted. This is saved configuration.");
            }
            return Ok(());
        }
        [kind, action] if kind == "passthrough" && action == "list" => {
            if out::json_requested() {
                out::json(&json!({"hosts":read.ignore_hosts,"scope":"saved configuration"}))?;
            } else if read.ignore_hosts.is_empty() {
                println!("No saved TLS passthrough destinations.");
            } else {
                for host in read.ignore_hosts {
                    println!("Passthrough: {}", out::text(&json!(host)));
                }
            }
            return Ok(());
        }
        _ => {}
    }
    let lock = config
        .parent()
        .ok_or("configuration has no directory")?
        .join("data/native-listeners.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock)).await??;
    let mut document: toml_edit::DocumentMut = fs::read_to_string(config)?.parse()?;
    match arguments.as_slice() {
        [kind, input] if kind == "upstream" => {
            if input == "--clear" {
                document.remove("upstream_ca_file");
            } else {
                let path = Path::new(input).canonicalize()?;
                let bytes = fs::read(&path)?;
                let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                if certs.is_empty() {
                    return Err("upstream CA bundle contains no PEM certificates".into());
                }
                let mut store = rustls::RootCertStore::empty();
                for cert in certs {
                    store.add(cert)?;
                }
                document["upstream_ca_file"] =
                    toml_edit::value(path.to_str().ok_or("CA path must be UTF-8")?);
            }
        }
        [kind, action, host]
            if kind == "passthrough" && matches!(action.as_str(), "add" | "remove") =>
        {
            let mut hosts = native_config::read(config)?.ignore_hosts;
            let normalized = crate::tunnels::Passthrough::normalize_hosts(&[host.clone()])?;
            hosts.retain(|host| !normalized.contains(host));
            if action == "add" {
                hosts.extend(normalized);
            }
            let mut array = toml_edit::Array::new();
            for host in hosts {
                array.push(host);
            }
            document["ignore_hosts"] = toml_edit::value(array);
        }
        _ => return Err("use tls --help to select a supported trust or passthrough action".into()),
    }
    let parent = config.parent().ok_or("configuration has no directory")?;
    let mut temporary = tempfile::Builder::new()
        .suffix(".toml")
        .tempfile_in(parent)?;
    temporary.write_all(document.to_string().as_bytes())?;
    native_config::read(temporary.path())?;
    temporary
        .as_file()
        .set_permissions(fs::metadata(config)?.permissions())?;
    temporary.as_file().sync_all()?;
    temporary.persist(config)?;
    fs::File::open(parent)?.sync_all()?;
    if out::json_requested() {
        out::json(&json!({"saved":true,"config":config,"activation":"next proxy start"}))?;
    } else {
        println!(
            "TLS settings saved in {}. Restart the proxy to activate them; existing connections are unchanged.",
            config.display()
        );
    }
    Ok(())
}
