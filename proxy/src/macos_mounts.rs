//! Mac extra directories on the helper's existing VirtioFS devices.

use crate::{Error, host_boot, host_mounts, host_platform, host_runs};
use serde_json::{Value, json};

struct Run {
    name: String,
    generation: String,
    receipt: Value,
}

impl Run {
    fn open(name: &str, generation: &str) -> Result<Self, Error> {
        let run = Self {
            name: name.into(),
            generation: generation.into(),
            receipt: host_runs::read(name)?.ok_or("sandbox record is missing")?,
        };
        run.check()?;
        Ok(run)
    }

    fn check(&self) -> Result<Value, Error> {
        let current = host_runs::read(&self.name)?.ok_or("sandbox record disappeared")?;
        if current["run_id"] != self.generation
            || [
                "run_id",
                "agent_id",
                "backend_pid",
                "backend_token",
                "helper_instance",
            ]
            .iter()
            .any(|key| current[key] != self.receipt[key])
            || host_runs::id(&self.name)? != format!("safeyolo-{}", self.generation)
            || current["backend_pid"]
                .as_i64()
                .and_then(|pid| i32::try_from(pid).ok())
                .and_then(|pid| host_platform::vm_process_token(&self.name, pid))
                .as_deref()
                != current["backend_token"].as_str()
        {
            return Err("sandbox incarnation changed; no export was changed".into());
        }
        Ok(current)
    }

    async fn control(&self, share: Value) -> Result<Value, Error> {
        self.check()?;
        let response = host_runs::control(
            &self.name,
            json!({"operation":"extra-mount",
            "instance":self.receipt["helper_instance"],"share":share}),
        )
        .await?;
        self.check()?;
        if response["instance"] != self.receipt["helper_instance"] {
            return Err("helper instance changed; export outcome is unverified".into());
        }
        Ok(response)
    }

    async fn guest(&self, args: &[&str]) -> Result<Value, Error> {
        self.check()?;
        let response = host_mounts::guest(&self.name, &self.generation, args).await?;
        self.check()?;
        Ok(response)
    }

    fn save(&self, share: &Value) -> Result<(), Error> {
        let mut current = self.check()?;
        let shares = current["macos"]["extra_shares"]
            .as_array_mut()
            .ok_or("extra share receipts are missing")?;
        shares.retain(|entry| entry["state"] != "removed" || entry["id"] == share["id"]);
        if let Some(entry) = shares.iter_mut().find(|entry| entry["id"] == share["id"]) {
            *entry = share.clone();
        } else {
            shares.push(share.clone());
        }
        host_runs::save(&self.name, &current)
    }

    async fn shares(&self) -> Result<Vec<Value>, Error> {
        let mut current = self.check()?;
        if let Some(shares) = current["macos"]["extra_shares"].as_array() {
            return Ok(shares.clone());
        }
        let observed = self.control(json!({"operation":"list"})).await?;
        let context = crate::guest_commands::read_state(
            &host_platform::config_dir()
                .join("agents")
                .join(&self.name)
                .join("config-share/host-launch-context.json"),
        )?
        .ok_or("startup share inputs are missing")?;
        if context["generation"] != self.generation || context["agent_id"] != current["agent_id"] {
            return Err("startup share inputs identify another run".into());
        }
        let mut shares = Vec::new();
        for (index, entry) in context["extra_shares"]
            .as_array()
            .ok_or("startup share inputs are missing")?
            .iter()
            .enumerate()
        {
            let target = entry["guest_path"].as_str().ok_or("this run has old startup share inputs; use an explicit future stop/start with the current host")?;
            let tag = format!("extra{index}");
            let exported = observed["startup_tags"]
                .as_array()
                .is_some_and(|tags| tags.contains(&json!(tag)));
            let mount = self.guest(&["inspect", target]).await?;
            let matched = exported
                && mount["mount"]["source"] == tag
                && mount["mount"]["filesystem"] == "virtiofs";
            shares.push(json!({"id":tag,"tag":tag,"host_path":entry["host_path"],"read_only":entry["read_only"],
                "guest_path":target,"resolved_path":mount["resolved_path"],"mount_id":if matched {mount["mount"]["mount_id"].clone()} else {Value::Null},
                "state":if matched {"mounted"} else {"unknown"}}));
        }
        current["macos"] = json!({"extra_shares":shares});
        host_runs::save(&self.name, &current)?;
        Ok(shares)
    }
}

fn matches_export(mount: &Value, share: &Value) -> bool {
    mount["filesystem"] == "virtiofs"
        && mount["source"] == "safeyolo-extra"
        && share["id"]
            .as_str()
            .is_some_and(|id| mount["root"] == format!("/{id}"))
}

pub(crate) async fn attach(name: &str, generation: &str, spec: &str) -> Result<Value, Error> {
    let run = Run::open(name, generation)?;
    let (host, target, read_only) = host_boot::mount(spec)?;
    let shares = run.shares().await?;
    let existing = shares
        .iter()
        .rev()
        .find(|entry| entry["guest_path"] == target && entry["state"] != "removed");
    let mut share = if let Some(existing) = existing {
        if existing["host_path"] != json!(host) || existing["read_only"] != read_only {
            return Err(
                "extra mount destination is already in use by another directory or mode".into(),
            );
        }
        existing.clone()
    } else {
        let prepared = run.control(json!({"operation":"list"})).await?;
        if prepared["prepared"] != true {
            return Err("VM has no prepared extra-directory device; use an explicit future stop/start with the current helper. This run was left intact".into());
        }
        let observed = run.guest(&["prepare", &target]).await?;
        json!({"id":uuid::Uuid::new_v4().simple().to_string(),"host_path":host,"guest_path":target,
            "resolved_path":observed["resolved_path"],"read_only":read_only,"state":"exporting"})
    };
    let id = share["id"]
        .as_str()
        .ok_or("share ID is missing")?
        .to_owned();
    if !share["tag"].is_null() {
        let observed = run.guest(&["inspect", &target]).await?;
        if observed["mount"]["mount_id"] == share["mount_id"] && share["state"] == "mounted" {
            return Ok(share);
        }
        return Err("startup mount state changed; inspect agent status".into());
    }
    if matches!(share["state"].as_str(), Some("unmounting" | "unmounted")) {
        return Err("share removal is in progress; retry unmount first".into());
    }
    run.save(&share)?;
    run.control(json!({"operation":"add","id":id,"host_path":host,"read_only":read_only}))
        .await?;
    share["state"] = "exported".into();
    run.save(&share)?;
    let mut observed = run.guest(&["inspect", &target]).await?;
    if !matches_export(&observed["mount"], &share) {
        if !observed["mount"].is_null() {
            return Err("export is live, but the guest destination is occupied; retry unmount or use an explicit stop/start".into());
        }
        observed = run.guest(&["bind", &id, &target]).await?;
    }
    if !matches_export(&observed["mount"], &share) {
        return Err(
            "export is live, but its guest mount is unverified; inspect agent status".into(),
        );
    }
    share["resolved_path"] = observed["resolved_path"].clone();
    share["mount_id"] = observed["mount"]["mount_id"].clone();
    share["state"] = "mounted".into();
    run.save(&share)?;
    Ok(share)
}

pub(crate) async fn remove(name: &str, generation: &str, target: &str) -> Result<Value, Error> {
    let run = Run::open(name, generation)?;
    let mut share = run
        .shares()
        .await?
        .iter()
        .rev()
        .find(|entry| entry["guest_path"] == target)
        .cloned()
        .ok_or("this extra share is not recorded in the current run")?;
    if share["state"] == "removed" {
        return Ok(share);
    }
    if share["state"] == "unknown" {
        return Err("startup export or guest destination changed; restore the selected mount or use an explicit stop/start. Other shares were left intact".into());
    }
    let path = share["resolved_path"]
        .as_str()
        .ok_or("share destination is missing")?
        .to_owned();
    let mut inspect = vec!["inspect", path.as_str()];
    let id = share["mount_id"].as_u64().map(|id| id.to_string());
    if let Some(id) = &id {
        inspect.push(id);
    }
    let observed = run.guest(&inspect).await?;
    let mount = &observed["mount"];
    if let Some(id) = &id {
        if !observed["expected_mount"].is_null() {
            if mount["mount_id"] != share["mount_id"] {
                return Err(
                    "share mount identity or destination changed; removal was refused".into(),
                );
            }
            share["state"] = "unmounting".into();
            run.save(&share)?;
            let result = run.guest(&["unmount", &path, id]).await?;
            if !result["expected_mount"].is_null() {
                return Err("selected guest mount remains; its export was retained".into());
            }
        }
    } else if matches_export(mount, &share) {
        let id = mount["mount_id"]
            .as_u64()
            .ok_or("share mount ID is missing")?
            .to_string();
        share["mount_id"] = mount["mount_id"].clone();
        share["state"] = "unmounting".into();
        run.save(&share)?;
        let result = run.guest(&["unmount", &path, &id]).await?;
        if !result["expected_mount"].is_null() {
            return Err("selected guest mount remains; its export was retained".into());
        }
    }
    share["state"] = "unmounted".into();
    run.save(&share)?;
    run.control(json!({"operation":"remove","id":share["id"],"tag":share["tag"]}))
        .await?;
    share["state"] = "removed".into();
    run.save(&share)?;
    Ok(share)
}
