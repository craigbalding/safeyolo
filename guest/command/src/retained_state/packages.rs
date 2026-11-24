use super::{GuestState, output};
use crate::{Error, now};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, fs, path::Path, process::Command};

const FORMAT: &str = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n";

fn parse_snapshot(input: &str) -> Result<Value, Error> {
    let mut result = Map::new();
    for line in input.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err("invalid dpkg-query snapshot".into());
        }
        result.insert(
            fields[0].into(),
            json!({"version":fields[1],"architecture":fields[2],"status":fields[3]}),
        );
    }
    Ok(Value::Object(result))
}

fn snapshot(store: &GuestState) -> Result<Value, Error> {
    parse_snapshot(&output(
        Command::new("dpkg-query")
            .arg(format!(
                "--admindir={}",
                store.actual("/var/lib/dpkg").display()
            ))
            .args(["-W", "-f", FORMAT]),
    )?)
}

fn package<'a>(snapshot: &'a Value, name: &str, architecture: &str) -> &'a Value {
    if !snapshot[name].is_null() {
        &snapshot[name]
    } else {
        &snapshot[format!("{name}:{architecture}")]
    }
}

fn architecture() -> Result<String, Error> {
    Ok(output(Command::new("dpkg").arg("--print-architecture"))?
        .trim()
        .to_string())
}

fn base_snapshot(store: &GuestState) -> Result<Value, Error> {
    let path = store.base().join("packages.tsv");
    if path.exists() {
        parse_snapshot(&fs::read_to_string(path)?)
    } else {
        Ok(json!({}))
    }
}

fn installed(value: &Value) -> bool {
    value["status"]
        .as_str()
        .is_some_and(|x| x.as_bytes().get(1) == Some(&b'i') && x.as_bytes().get(2) == Some(&b' '))
}
fn held(value: &Value) -> bool {
    value["status"].as_str().is_some_and(|x| x.starts_with('h'))
}

pub(super) fn capture(store: &GuestState, value: &mut Value) -> Result<(), Error> {
    let observed = snapshot(store)?;
    let base = base_snapshot(store)?;
    let previous = value["packages"].clone();
    let architecture = architecture()?;
    let auto = output(
        Command::new("apt-mark")
            .arg("-o")
            .arg(format!("Dir={}", store.root.display()))
            .arg("-o")
            .arg(format!(
                "Dir::State::status={}",
                store.actual("/var/lib/dpkg/status").display()
            ))
            .arg("showauto"),
    )?;
    let automatic: BTreeSet<_> = auto.lines().collect();
    let desired = value
        .as_object_mut()
        .ok_or("invalid retained state")?
        .entry("desired_packages")
        .or_insert(json!({}));
    for (name, state) in observed.as_object().ok_or("invalid observed packages")? {
        let prior = &previous[name];
        // Do not turn the old base's dependency closure into a frozen install list.
        if installed(state) && base[name].is_null() && !automatic.contains(name.as_str()) {
            let unqualified = name.split(':').next().unwrap_or(name);
            let intent = if !desired[unqualified].is_null() {
                unqualified
            } else {
                name
            };
            if desired[intent].is_null() {
                desired[intent] = json!({"action":"install"});
            }
            desired[intent]["hold"] = json!(held(state));
        } else if installed(&base[name]) && !installed(state) {
            desired[name] = json!({"action":"remove"});
        }
        if !prior.is_null() && held(prior) != held(state) {
            if desired[name].is_null() {
                desired[name] = json!({"action":"reuse"});
            }
            desired[name]["hold"] = json!(held(state));
        }
    }
    let names: Vec<_> = desired
        .as_object()
        .ok_or("invalid desired packages")?
        .keys()
        .cloned()
        .collect();
    for name in names {
        if !installed(package(&observed, &name, &architecture))
            && installed(package(&previous, &name, &architecture))
        {
            desired[&name] = json!({"action":"remove"});
        }
    }
    // Purge can remove the old entry entirely.
    for (name, old) in base.as_object().ok_or("invalid package baseline")? {
        if installed(old) && !installed(&observed[name]) {
            desired[name] = json!({"action":"remove"});
        }
    }
    value["packages"] = observed;
    value["package_observed_at"] = json!(now());
    for transaction in value["transactions"]
        .as_object_mut()
        .ok_or("invalid transactions")?
        .values_mut()
    {
        let owner = transaction["owner"]
            .as_str()
            .ok_or("missing transaction owner")?;
        let (pid, token) = owner.split_once('/').ok_or("invalid transaction owner")?;
        if crate::live_token(pid.parse()?)?.as_deref() != Some(token)
            && transaction["post_hook_seen"] != true
        {
            transaction["outcome"] = json!("interrupted_or_post_hook_absent");
        }
    }
    Ok(())
}

pub(super) fn require(
    value: &mut Value,
    package: &str,
    op: &str,
    version: &str,
    distro: &str,
    advisory: &str,
) -> Result<(), Error> {
    if !valid_package(package)
        || !matches!(op, "ge" | "gt" | "eq" | "le" | "lt")
        || version.starts_with('-')
        || version.contains(char::is_whitespace)
    {
        return Err("require expects PACKAGE ge|gt|eq|le|lt VERSION DISTRO ADVISORY".into());
    }
    let result = Command::new("dpkg")
        .args(["--validate-version", version])
        .status()?;
    if !result.success() {
        return Err("invalid Debian version".into());
    }
    value["requirements"][package] =
        json!({"operator":op,"version":version,"distribution":distro,"advisory":advisory});
    Ok(())
}

fn valid_package(value: &str) -> bool {
    let mut parts = value.split(':');
    let name = parts.next().unwrap_or("");
    let valid = |part: &str| {
        !part.is_empty()
            && part.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
    };
    valid(name) && parts.next().is_none_or(valid) && parts.next().is_none()
}

fn package_choices(args: &[String]) -> Vec<(String, Value)> {
    let Some(index) = args
        .iter()
        .position(|x| matches!(x.as_str(), "install" | "reinstall" | "remove" | "purge"))
    else {
        return Vec::new();
    };
    let action = if matches!(args[index].as_str(), "remove" | "purge") {
        "remove"
    } else {
        "install"
    };
    let mut choices = Vec::new();
    let mut option_value = false;
    for arg in &args[index + 1..] {
        if option_value {
            option_value = false;
            continue;
        }
        if matches!(arg.as_str(), "-o" | "--option" | "-t" | "--target-release") {
            option_value = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        let mut choice = json!({"action":action});
        let name = if let Some((name, version)) = arg.split_once('=') {
            if version.is_empty() || version.contains('/') {
                continue;
            }
            choice["version"] = json!(version);
            name
        } else if let Some((name, release)) = arg.split_once('/') {
            if !valid_package(release) {
                continue;
            }
            choice["release"] = json!(release);
            name
        } else {
            arg
        };
        if valid_package(name) {
            choices.push((name.into(), choice));
        }
    }
    choices
}

fn satisfies(version: &str, requirement: &Value) -> Result<bool, Error> {
    Ok(Command::new("dpkg")
        .args([
            "--compare-versions",
            version,
            requirement["operator"]
                .as_str()
                .ok_or("missing comparison")?,
            requirement["version"]
                .as_str()
                .ok_or("missing required version")?,
        ])
        .status()?
        .success())
}

fn distribution(store: &GuestState) -> Result<String, Error> {
    let text = fs::read_to_string(store.actual("/etc/os-release"))?;
    let field = |name: &str| {
        text.lines()
            .find_map(|x| {
                x.strip_prefix(&format!("{name}="))
                    .map(|x| x.trim_matches('"'))
            })
            .unwrap_or("")
    };
    Ok(format!("{}:{}", field("ID"), field("VERSION_CODENAME")))
}

fn parent_pid(pid: i32) -> Result<i32, Error> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit(')')
        .next()
        .ok_or("missing process fields")?
        .split_whitespace()
        .nth(1)
        .ok_or("missing parent pid")?
        .parse()?)
}

fn process_arguments(pid: i32) -> Result<Vec<String>, Error> {
    Ok(fs::read(format!("/proc/{pid}/cmdline"))?
        .split(|x| *x == 0)
        .filter(|x| !x.is_empty())
        .map(|x| String::from_utf8_lossy(x).into_owned())
        .collect())
}

fn process_owner() -> Result<(String, Vec<String>), Error> {
    // Walk past hook shells to the actual package process. Retain only identity and
    // package operands; command lines can contain repository passwords.
    let mut pid = unsafe { libc::getppid() };
    for _ in 0..6 {
        let args = process_arguments(pid)?;
        if args.first().is_some_and(|x| {
            matches!(
                Path::new(x).file_name().and_then(|x| x.to_str()),
                Some("apt" | "apt-get" | "dpkg")
            )
        }) {
            let token = crate::live_token(pid)?.ok_or("package process has exited")?;
            return Ok((format!("{pid}/{token}"), args));
        }
        pid = parent_pid(pid)?;
    }
    Err("cannot identify the package process".into())
}

fn enclosing_apt_arguments(owner: &str) -> Result<Vec<String>, Error> {
    let mut pid = owner
        .split_once('/')
        .ok_or("invalid package owner")?
        .0
        .parse()?;
    while pid > 1 {
        pid = parent_pid(pid)?;
        if pid <= 1 {
            break;
        }
        let args = process_arguments(pid)?;
        if args.first().is_some_and(|arg| {
            matches!(
                Path::new(arg).file_name().and_then(|name| name.to_str()),
                Some("apt" | "apt-get")
            )
        }) {
            return Ok(args);
        }
    }
    Ok(Vec::new())
}

pub(super) fn active(value: &Value) -> Result<bool, Error> {
    for transaction in value["transactions"]
        .as_object()
        .ok_or("invalid transactions")?
        .values()
    {
        let Some(owner) = transaction["owner"].as_str() else {
            continue;
        };
        let (pid, token) = owner.split_once('/').ok_or("invalid package owner")?;
        if crate::live_token(pid.parse()?)?.as_deref() == Some(token) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn apt_plan(input: &str) -> Result<Vec<Value>, Error> {
    let mut lines = input.lines();
    let version = lines.next().ok_or("APT hook has no protocol header")?;
    if !matches!(version, "VERSION 2" | "VERSION 3") {
        return Err("APT hook requires package protocol 2 or 3".into());
    }
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
    }
    let mut actions = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        let (name, old, new, architecture, action) = if version == "VERSION 3" && fields.len() == 9
        {
            (fields[0], fields[1], fields[5], fields[6], fields[8])
        } else if version == "VERSION 2" && fields.len() == 5 {
            (fields[0], fields[1], fields[3], "native", fields[4])
        } else {
            return Err("invalid APT planned package action".into());
        };
        if !valid_package(name) {
            return Err("invalid planned package name".into());
        }
        actions.push(json!({"package":name,"old_version":old,"version":new,"architecture":architecture,
            "action":if action=="**REMOVE**" {"remove"} else if action=="**CONFIGURE**" {"configure"} else {"unpack"}}));
    }
    Ok(actions)
}

pub(super) fn hook(
    store: &GuestState,
    value: &mut Value,
    event: &str,
    input: &str,
) -> Result<(), Error> {
    store.current_base(value)?;
    if value["reconcile_required"] == true {
        return Err("package capture paused until startup restoration is checked".into());
    }
    let (owner, args) = process_owner()?;
    let transactions = value["transactions"]
        .as_object_mut()
        .ok_or("invalid transactions")?;
    let transaction = transactions.entry(owner.clone()).or_insert_with(
        || json!({"owner":owner,"started":now(),"outcome":"incomplete","post_hook_seen":false}),
    );
    if event.ends_with("pre") {
        transaction["kind"] = json!(event);
        transaction["action"] = json!(std::env::var("DPKG_HOOK_ACTION").unwrap_or_default());
        if event == "dpkg-pre" {
            let mut archives = Vec::new();
            for arg in args.iter().skip(1).filter(|x| x.ends_with(".deb")) {
                let metadata = output(Command::new("dpkg-deb").args([
                    "--show",
                    "--showformat=${Package}\t${Version}\t${Architecture}\n",
                    arg,
                ]))?;
                let fields: Vec<_> = metadata.trim_end().split('\t').collect();
                if fields.len() != 3 || !valid_package(fields[0]) {
                    return Err("invalid requested Debian archive metadata".into());
                }
                archives.push(
                    json!({"package":fields[0],"version":fields[1],"architecture":fields[2]}),
                );
            }
            transaction["requested_archives"] = json!(archives);
        }
        if event == "apt-pre" {
            transaction["plan"] = json!(apt_plan(input)?);
            transaction["explicit_choices"] = json!(package_choices(&args));
        }
    } else if event.ends_with("post") {
        // A clean snapshot is observed package state, never process exit proof.
        transaction["post_hook_seen"] = json!(true);
        transaction["outcome"] = if transaction["error_seen"] == true {
            json!("error_observed")
        } else {
            json!("post_seen_exit_status_unknown")
        };
    } else if event == "dpkg-status" {
        if input.starts_with("status:") && input.contains(": error :") {
            transaction["error_seen"] = json!(true);
            transaction["outcome"] = json!("error_observed");
        }
        if input.starts_with("processing:") {
            transaction["last_processing"] = json!(input.trim());
        }
    }
    if event == "apt-pre" {
        for (package, choice) in package_choices(&args) {
            value["desired_packages"][&package] = choice;
        }
    }
    if event == "dpkg-pre" {
        // Read the enclosing request, independent of bounded transaction history.
        // Only parsed package choices are retained, never the raw command line.
        let apt_choices = package_choices(&enclosing_apt_arguments(&owner)?);
        let requested = value["transactions"][&owner]["requested_archives"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for archive in requested {
            let name = archive["package"]
                .as_str()
                .ok_or("missing archive package")?;
            let qualified = format!(
                "{name}:{}",
                archive["architecture"]
                    .as_str()
                    .ok_or("missing archive architecture")?
            );
            let explicit = apt_choices
                .iter()
                .find(|(package, _)| package == name || *package == qualified);
            let (name, mut choice) = if let Some(explicit) = explicit {
                (explicit.0.clone(), explicit.1.clone())
            } else {
                (name.to_owned(), json!({"action":"install"}))
            };
            // Keep the archive request beyond the bounded transaction history.
            // A nested dpkg observes APT's choice; a direct archive stays unpinned.
            choice["requested_archive"] = archive;
            value["desired_packages"][&name] = choice;
        }
    }
    let transactions = value["transactions"]
        .as_object_mut()
        .ok_or("invalid transactions")?;
    if transactions.len() > 16 {
        let oldest = transactions
            .iter()
            .filter(|(key, _)| *key != &owner)
            .min_by(|a, b| {
                a.1["started"]
                    .as_f64()
                    .partial_cmp(&b.1["started"].as_f64())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            transactions.remove(&key);
        }
    }
    value["status"] = json!("package_transaction");
    if event == "dpkg-status" {
        Ok(())
    } else {
        capture(store, value)
    }
}

pub(super) fn restore(store: &GuestState, value: &mut Value, apply: bool) -> Result<(), Error> {
    let actual = snapshot(store)?;
    let distro = distribution(store)?;
    let architecture = architecture()?;
    let mut desired = value["desired_packages"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for name in value["requirements"]
        .as_object()
        .ok_or("invalid requirements")?
        .keys()
    {
        if !desired.contains_key(name) {
            desired.insert(name.clone(), json!({"action":"install"}));
        }
    }
    let mut installs = Vec::new();
    let mut removes = Vec::new();
    let mut selections = Vec::new();
    let mut blockers = Vec::new();
    for (name, choice) in desired {
        if !valid_package(&name) {
            return Err("invalid retained package".into());
        }
        let requirement = &value["requirements"][&name];
        let observed = package(&actual, &name, &architecture);
        let present = installed(observed);
        if !requirement.is_null() && requirement["distribution"] != distro {
            blockers.push(format!(
                "{name}: retained requirement is for {}, actual {distro}",
                requirement["distribution"]
            ));
            continue;
        }
        if choice["action"] == "remove" {
            if !requirement.is_null() {
                blockers.push(format!(
                    "{name}: removal conflicts with the adopted requirement"
                ));
                continue;
            }
            if present {
                removes.push(name.clone());
            }
            continue;
        }
        let explicit_version = choice["version"].as_str();
        let satisfactory = present
            && explicit_version.is_none_or(|x| observed["version"] == x)
            && (requirement.is_null()
                || satisfies(
                    observed["version"]
                        .as_str()
                        .ok_or("missing package version")?,
                    requirement,
                )?);
        if !satisfactory {
            if held(observed) {
                blockers.push(format!(
                    "{name}: current hold conflicts with required installation"
                ));
                continue;
            }
            let candidate = output(
                Command::new("apt-cache")
                    .arg("-o")
                    .arg(format!("Dir={}", store.root.display()))
                    .args(["policy", &name]),
            )?;
            let version = explicit_version.unwrap_or_else(|| {
                candidate
                    .lines()
                    .find_map(|x| x.trim().strip_prefix("Candidate: "))
                    .unwrap_or("(none)")
            });
            if version == "(none)" || (!requirement.is_null() && !satisfies(version, requirement)?)
            {
                blockers.push(format!("{name}: APT candidate {version} does not satisfy the retained requirement; inspect sources/pins"));
                continue;
            }
            installs.push(if let Some(release) = choice["release"].as_str() {
                format!("{name}/{release}")
            } else {
                format!("{name}={version}")
            });
        }
        if let Some(hold) = choice["hold"].as_bool()
            && hold != held(observed)
        {
            selections.push((name.clone(), hold));
        }
    }
    value["restore"] = json!({"installs":installs,"removes":removes,"selections":selections,"package_blockers":blockers,"applied":false});
    store.save(value)?;
    if !blockers.is_empty() {
        println!("{}", value["restore"]);
        return Err("package restoration has unresolved requirements".into());
    }
    if apply && (!installs.is_empty() || !removes.is_empty() || !selections.is_empty()) {
        // The caller holds the recorder lock. Child hooks must not take it again.
        // Changes are observed after the native commands exit, also on failure.
        let execute = || -> Result<(), Error> {
            if !installs.is_empty() {
                output(
                    Command::new("apt-get")
                        .env("SAFEYOLO_RESTORE_ACTIVE", "1")
                        .args(["-y", "--no-install-recommends", "install"])
                        .args(&installs),
                )?;
            }
            if !removes.is_empty() {
                output(
                    Command::new("apt-get")
                        .env("SAFEYOLO_RESTORE_ACTIVE", "1")
                        .args(["-y", "remove"])
                        .args(&removes),
                )?;
            }
            for (name, hold) in &selections {
                output(
                    Command::new("apt-mark").args([if *hold { "hold" } else { "unhold" }, name]),
                )?;
            }
            Ok(())
        };
        let result = execute();
        let after = snapshot(store)?;
        let verification = || -> Result<(), Error> {
            for install in &installs {
                let (name, version) = install.split_once('=').map_or(
                    (install.split('/').next().unwrap_or(install), None),
                    |(n, v)| (n, Some(v)),
                );
                let observed = package(&after, name, &architecture);
                if !installed(observed) || version.is_some_and(|v| observed["version"] != v) {
                    return Err(format!("package restore verification failed: {name}").into());
                }
            }
            for name in &removes {
                if installed(package(&after, name, &architecture)) {
                    return Err(format!("package removal verification failed: {name}").into());
                }
            }
            for (name, hold) in &selections {
                if held(package(&after, name, &architecture)) != *hold {
                    return Err(format!("package selection verification failed: {name}").into());
                }
            }
            for (name, requirement) in value["requirements"]
                .as_object()
                .ok_or("invalid requirements")?
            {
                let observed = package(&after, name, &architecture);
                if !installed(observed)
                    || !satisfies(
                        observed["version"]
                            .as_str()
                            .ok_or("missing installed version")?,
                        requirement,
                    )?
                {
                    return Err(format!("adopted requirement verification failed: {name}").into());
                }
            }
            Ok(())
        };
        let result = result.and_then(|_| verification());
        value["restore"]["observed_packages"] = after;
        value["restore"]["applied"] = json!(result.is_ok());
        store.save(value)?;
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_architecture_and_explicit_choices() {
        let packages =
            parse_snapshot("libfoo:arm64\t1.0\tarm64\tii \nlibfoo:amd64\t0.9\tamd64\tii \n")
                .unwrap();
        assert_eq!(package(&packages, "libfoo", "arm64")["version"], "1.0");
        assert!(installed(package(&packages, "libfoo", "arm64")));
        let args = [
            "apt-get",
            "-o",
            "password=secret",
            "install",
            "-o",
            "ignored=option",
            "foo:arm64=2.0",
            "bar/trixie",
        ]
        .map(str::to_owned);
        let choices = package_choices(&args);
        assert_eq!(choices.len(), 2);
        assert_eq!(choices[0].0, "foo:arm64");
        assert_eq!(choices[1].1["release"], "trixie");
        assert!(!serde_json::to_string(&choices).unwrap().contains("secret"));
    }

    #[test]
    fn apt_protocol_and_private_configuration() {
        let plan=apt_plan("VERSION 3\nAcquire::https::Proxy=https://secret:password@proxy\n\nfoo - - none < 2.0 arm64 none /cache/foo.deb\nold 1.0 arm64 none > - - none **REMOVE**\n").unwrap();
        assert_eq!(plan[0]["version"], "2.0");
        assert_eq!(plan[1]["action"], "remove");
        assert!(!serde_json::to_string(&plan).unwrap().contains("password"));
        assert!(apt_plan("bad").is_err());
    }
}
