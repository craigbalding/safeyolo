//! Guest-local recovery information. This does not confer maintenance authority.
mod configuration;
mod maintenance;
mod packages;
mod watch;

use crate::{Error, now, read_json, write_json};
use serde_json::{Value, json};
use std::io::BufRead;
use std::{
    ffi::OsString, fs, io::Read, os::unix::fs::PermissionsExt, path::PathBuf, process::Command,
};

pub(super) struct GuestState {
    root: PathBuf,
    directory: PathBuf,
}

impl GuestState {
    fn actual(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }
    fn base(&self) -> PathBuf {
        self.actual("/usr/share/safeyolo/guest-base")
    }
    fn record(&self) -> PathBuf {
        self.directory.join("state.json")
    }
    fn read(&self) -> Result<Value, Error> {
        read_json(&self.record(), 16 * 1024 * 1024)
    }
    fn save(&self, value: &Value) -> Result<(), Error> {
        write_json(&self.record(), value)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    fn lock(&self) -> Result<fs::File, Error> {
        use std::os::fd::AsRawFd;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.directory.join("lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(file)
    }
    fn base_id(&self) -> Result<String, Error> {
        let baseline = self.base().join("packages.tsv");
        if !baseline.exists() {
            return Ok("unknown".into());
        }
        let mut identity = fs::read(baseline)?;
        identity.extend(serde_json::to_vec(&configuration::inventory(
            &self.base().join("configuration"),
            &["/etc".into(), "/usr/local/etc".into()],
        )?)?);
        Ok(configuration::digest(&identity))
    }
    fn initialize(&self) -> Result<Value, Error> {
        if self.record().exists() {
            return self.read();
        }
        let base_id = self.base_id()?;
        let coverage = json!(["/etc", "/usr/local/etc"]);
        let baseline = configuration::inventory(
            &self.base().join("configuration"),
            &["/etc".into(), "/usr/local/etc".into()],
        )?;
        let value = json!({"schema_version":1,"base_id":base_id,"baseline_known":base_id!="unknown",
            "coverage":coverage,"baseline":baseline,"configuration":{},"packages":{},"requirements":{},
            "transactions":{},"status":"initializing","last_completed_capture":null});
        self.save(&value)?;
        Ok(value)
    }
    fn current_base(&self, value: &Value) -> Result<(), Error> {
        if value["base_id"] != self.base_id()? {
            return Err(
                "guest base changed; inspect and restore retained state before capture".into(),
            );
        }
        Ok(())
    }
    fn capture(&self, value: &mut Value) -> Result<(), Error> {
        self.current_base(value)?;
        if value["reconcile_required"] == true {
            return Err(
                "startup restoration check required; retained captures were preserved".into(),
            );
        }
        value["status"] = json!("capturing");
        self.save(value)?;
        packages::capture(self, value)?;
        if packages::active(value)? {
            value["status"] = json!("package_transaction");
            return self.save(value);
        }
        configuration::capture(self, value)?;
        value["last_completed_capture"] = json!(now());
        value["status"] = json!("captured");
        value["capture_error"] = Value::Null;
        self.save(value)
    }
}

fn output(command: &mut Command) -> Result<String, Error> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "{} failed ({}): {}",
            command.get_program().to_string_lossy(),
            result.status,
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(result.stdout)?)
}

fn coverage(value: &Value) -> Result<Vec<String>, Error> {
    value["coverage"]
        .as_array()
        .ok_or("coverage is not an array")?
        .iter()
        .map(|path| {
            path.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "coverage path is not text".into())
        })
        .collect()
}

pub(super) fn run(args: &[OsString]) -> Result<i32, Error> {
    let mut args = args
        .iter()
        .map(|x| x.to_str().ok_or("retained-state arguments must be text"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut store = GuestState {
        root: "/".into(),
        directory: "/home/agent/.local/state/safeyolo-guest".into(),
    };
    // Explicit alternate roots support offline inspection and focused Linux fixtures.
    while args
        .first()
        .is_some_and(|x| matches!(*x, "--root" | "--directory"))
    {
        if args.len() < 2 {
            return Err("path option needs a value".into());
        }
        let path = PathBuf::from(args[1]);
        if args[0] == "--root" {
            store.root = path;
        } else {
            store.directory = path;
        }
        args.drain(..2);
    }
    if args.is_empty() || args == ["--help"] {
        println!(
            "safeyolo-guest-state status | capture | paths [add|remove /absolute/path] | require PACKAGE OP VERSION DISTRO ADVISORY | forget PACKAGE | resolve /path | restore [--apply] | history | maintain | maintenance-status OPERATION\nPersistent state: /home/agent/.local/state/safeyolo-guest. Use guest sudo for private contents. restore previews changes; --apply performs them within existing authority. maintain reads an adopted maintenance request from stdin; maintenance-status reads its retained result without repeating effects. OP is a dpkg comparison (ge, gt, eq, le, lt). DISTRO is ID:VERSION_CODENAME. No shutdown capture or security attestation."
        );
        return Ok(0);
    }
    if args == ["startup-allowed"] {
        let gate = store.actual("/safeyolo/startup-maintenance.json");
        if !gate.try_exists()? {
            return Ok(0);
        }
        let gate = read_json(&gate, 128 * 1024)?;
        let context = read_json(
            &store.actual("/safeyolo/host-launch-context.json"),
            128 * 1024,
        )?;
        return Ok(
            if gate["allowed"] == true && gate["run_id"] == context["generation"] {
                0
            } else {
                1
            },
        );
    }
    fs::create_dir_all(&store.directory)?;
    fs::set_permissions(&store.directory, fs::Permissions::from_mode(0o700))?;
    if args == ["maintain"] {
        return maintenance::run(&store);
    }
    if let ["maintenance-status", operation] = args.as_slice() {
        return maintenance::status(&store, operation);
    }
    if let ["maintenance-recover", operation] = args.as_slice() {
        return maintenance::recover_selected(&store, operation);
    }
    if args == ["watch"] {
        let result = watch::run(&store);
        if let Err(error) = &result {
            let _lock = store.lock()?;
            let mut value = store.initialize()?;
            value["status"] = json!("needs_attention");
            value["capture_error"] = json!(error.to_string());
            store.save(&value)?;
        }
        return result;
    }
    if args == ["dpkg-status"] {
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            let _lock = store.lock()?;
            let mut value = store.initialize()?;
            packages::hook(&store, &mut value, "dpkg-status", &line)?;
            store.save(&value)?;
        }
        return Ok(0);
    }
    let _lock = store.lock()?;
    let mut value = store.initialize()?;
    let result: Result<i32, Error> = (|| {
        match args.as_slice() {
            ["start"] => {
                if !value["last_completed_capture"].is_null() {
                    value["reconcile_required"] = json!(true);
                    value["status"] = json!("startup_restore_check_required");
                    store.save(&value)?;
                } else if value["base_id"] != store.base_id()? {
                    value["status"] = json!("base_changed_restore_required");
                    store.save(&value)?;
                } else {
                    store.capture(&mut value)?;
                }
                Ok(0)
            }
            ["status"] => {
                let live = value["watch"]["pid"]
                    .as_i64()
                    .map(|pid| crate::live_token(pid as i32))
                    .transpose()?
                    .flatten();
                value["watch_alive"] =
                    json!(live.is_some() && live.as_deref() == value["watch"]["owner"].as_str());
                // Summary deliberately excludes captured contents, source credentials and recipes.
                println!(
                    "{}",
                    json!({"directory":store.directory,"base_id":value["base_id"],
                    "actual_base_id":store.base_id()?,"baseline_known":value["baseline_known"],"reconcile_required":value["reconcile_required"],"status":value["status"],
                    "last_completed_capture":value["last_completed_capture"],"configuration_commit":value["configuration_commit"],"capture_error":value["capture_error"],
                    "coverage":value["coverage"],"paths_without_original_baseline":coverage(&value)?.iter().filter(|path|
                        value["baseline_known"] != true || !(path.as_str()=="/etc" || path.starts_with("/etc/") || path.as_str()=="/usr/local/etc" || path.starts_with("/usr/local/etc/"))).collect::<Vec<_>>(),"transactions":value["transactions"],"requirements":value["requirements"],
                    "restore":value["restore"],"maintenance":value["maintenance"],"watch":value["watch"],"watch_alive":value["watch_alive"]})
                );
                Ok(0)
            }
            ["capture"] => {
                store.capture(&mut value)?;
                Ok(0)
            }
            ["paths"] => {
                println!("{}", value["coverage"]);
                Ok(0)
            }
            ["paths", action @ ("add" | "remove"), path] => {
                let path = configuration::validate_path(path)?;
                let mut paths = coverage(&value)?;
                paths.retain(|x| x != &path);
                if *action == "add" {
                    paths.push(path);
                }
                configuration::validate_coverage(&store, &paths)?;
                value["coverage"] = json!(paths);
                store.save(&value)?;
                fs::write(store.directory.join("coverage.changed"), b"changed\n")?;
                store.capture(&mut value)?;
                Ok(0)
            }
            ["require", package, op, version, distro, advisory] => {
                packages::require(&mut value, package, op, version, distro, advisory)?;
                store.save(&value)?;
                Ok(0)
            }
            ["forget", package] => {
                value["requirements"]
                    .as_object_mut()
                    .ok_or("invalid requirements")?
                    .remove(*package);
                store.save(&value)?;
                Ok(0)
            }
            ["resolve", path] => {
                configuration::resolve(&store, &mut value, path)?;
                Ok(0)
            }
            ["restore"] | ["restore", "--apply"] => {
                let apply = args.len() == 2;
                if apply && store.root != std::path::Path::new("/") {
                    return Err("run restore --apply inside the selected guest root; --root only supports offline inspection".into());
                }
                packages::restore(&store, &mut value, false)?;
                configuration::restore(&store, &mut value, false)?;
                if apply {
                    configuration::restore(&store, &mut value, true)?;
                    packages::restore(&store, &mut value, true)?;
                }
                if apply {
                    value["reconcile_required"] = json!(false);
                    value["base_id"] = json!(store.base_id()?);
                    value["baseline"] = configuration::inventory(
                        &store.base().join("configuration"),
                        &["/etc".into(), "/usr/local/etc".into()],
                    )?;
                    value["baseline_known"] = json!(value["base_id"] != "unknown");
                    store.save(&value)?;
                    store.capture(&mut value)?;
                }
                Ok(0)
            }
            ["history"] => {
                print!(
                    "{}",
                    output(
                        Command::new("git")
                            .arg("-C")
                            .arg(store.directory.join("configuration"))
                            .args(["log", "--oneline", "-20"])
                    )?
                );
                Ok(0)
            }
            [event @ ("apt-pre" | "apt-post" | "dpkg-pre" | "dpkg-post" | "dpkg-status")] => {
                let mut input = String::new();
                if matches!(*event, "apt-pre" | "dpkg-status") {
                    std::io::stdin()
                        .take(4 * 1024 * 1024)
                        .read_to_string(&mut input)?;
                }
                packages::hook(&store, &mut value, event, &input)?;
                store.save(&value)?;
                Ok(0)
            }
            _ => Err("unknown retained-state command; use --help".into()),
        }
    })();
    if let Err(error) = &result {
        value["status"] = json!("needs_attention");
        value["capture_error"] = json!(error.to_string());
        store.save(&value)?;
    }
    result
}
