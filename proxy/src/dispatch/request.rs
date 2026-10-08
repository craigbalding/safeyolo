//! One explicit-date request through the existing operator Coord owner.
use super::{Error, parse_date, read_regular};
use crate::agent_api::coord::{OperatorCoord, PreparedMessage};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use time::{Date, Duration};

const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;
const MAX_TASKS: usize = 4096;
const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

pub const HELP: &str = "safeyolo [--root ROOT] coord dispatch-trigger ROOM --date YYYY-MM-DD [--weekly-on monday|tuesday|wednesday|thursday|friday|saturday|sunday] [--publication-mode manual|automatic]\n\nPost one operator-authored Dispatch request. The date is required; manual publication is the default. Retry the same command to reconcile the durable message. An unknown attempted publication is never automatically resent.";

pub fn render_task(day: Date, weekly_on: &str, mode: &str) -> Result<(String, String), Error> {
    let weekday = WEEKDAYS
        .iter()
        .position(|name| *name == weekly_on)
        .ok_or("invalid --weekly-on weekday")?;
    if !["manual", "automatic"].contains(&mode) {
        return Err("--publication-mode must be manual or automatic".into());
    }
    let key = format!("dispatch-production/{day}");
    let mut periods = vec![format!("daily {day}")];
    let actual = day.weekday().number_days_from_monday() as usize;
    if actual == weekday {
        let days = match (actual + 1) % 7 {
            0 => 7,
            days => days,
        };
        let end = day
            .checked_sub(Duration::days(days as i64))
            .filter(|day| day.year() > 0)
            .ok_or("preceding week is outside the supported calendar")?;
        let start = end
            .checked_sub(Duration::days(6))
            .filter(|day| day.year() > 0)
            .ok_or("preceding week is outside the supported calendar")?;
        let (year, week, _) = start.to_iso_week_date();
        periods.push(format!("weekly {year}-W{week:02} ({start} through {end})"));
    }
    if day.day() == 1 {
        let end = day
            .previous_day()
            .filter(|day| day.year() > 0)
            .ok_or("preceding month is outside the supported calendar")?;
        let start = Date::from_calendar_date(end.year(), end.month(), 1)?;
        periods.push(format!(
            "monthly {:04}-{:02} ({start} through {end})",
            start.year(),
            u8::from(start.month())
        ));
    }
    let publication = if mode == "manual" {
        "When content exists, generate deterministic repository Markdown, create one publication branch and PR limited to the documented site paths, and present the existing `dispatch-publication` request with publish/revise/defer. Do not merge or publish before the operator chooses publish."
    } else {
        "The operator explicitly selected automatic publication for this schedule. When content exists, generate deterministic repository Markdown and use the same fixed publication paths and CI-to-Pages lane without a publication PR or `dispatch-publication` decision. Do not broaden Relay's repository authority."
    };
    let body = format!(
        "TASK relay Produce SafeYolo Dispatch content for {}.\n\nSchedule key: `{key}`. This is one idempotent content-production task; a scheduler retry with the same key is not new work. The configured weekly boundary is {weekly_on}, and publication mode is {mode}.\n\nFollow the repository Dispatch generation contract. Give the operator the short pre-draft account required by that contract before writing substantive copy. It is valid to produce nothing when there is no substantive material; in that case, report completion without creating an artifact or publication PR.\n\n{publication} Publication is a separate, idempotent side lane: delay, revision, CI, build, or Pages trouble must not hold an issue delivery claim or occupy Forge or Lens.",
        periods.join("; ")
    );
    Ok((key, body))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    tasks: BTreeMap<String, Record>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    body_sha256: String,
    prepared: PreparedMessage,
    room: String,
    sequence: Option<u64>,
    status: String,
    attempted: bool,
}

fn hash(body: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, body.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Ledger {
    fn load(path: &Path) -> Result<Self, Error> {
        let source = match read_regular(path, MAX_LEDGER_BYTES) {
            Ok(source) => source,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(Self {
                    version: 1,
                    tasks: BTreeMap::new(),
                });
            }
            Err(error) => return Err(error),
        };
        let document = crate::policy::parse_json(&source, true)?;
        let ledger: Self = serde_json::from_value(document)?;
        if ledger.version != 1 || ledger.tasks.len() > MAX_TASKS {
            return Err("invalid Dispatch ledger version or task count".into());
        }
        for record in ledger.tasks.values() {
            if !matches!(record.status.as_str(), "pending" | "delivered")
                || record.sequence == Some(0)
                || (record.status == "delivered") != record.sequence.is_some()
                || (record.status == "delivered" && !record.attempted)
                || record.prepared.envelope["body"]
                    .as_str()
                    .is_none_or(|body| hash(body) != record.body_sha256)
            {
                return Err("Dispatch ledger contains an invalid record".into());
            }
        }
        Ok(ledger)
    }

    fn save(&self, path: &Path) -> Result<(), Error> {
        let mut payload = serde_json::to_vec(self)?;
        payload.push(b'\n');
        if payload.len() > MAX_LEDGER_BYTES || self.tasks.len() > MAX_TASKS {
            return Err("Dispatch ledger exceeds its size bound".into());
        }
        let parent = path.parent().ok_or("Dispatch ledger has no parent")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&payload)?;
        file.as_file().sync_all()?;
        file.persist(path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

async fn deliver(
    client: &OperatorCoord,
    ledger_path: &Path,
    room: &str,
    day: Date,
    weekly_on: &str,
    mode: &str,
) -> Result<(String, &'static str, u64), Error> {
    let (key, body) = render_task(day, weekly_on, mode)?;
    let body_sha256 = hash(&body);
    let _lock = crate::host_platform::lock_host_state(
        &ledger_path.with_file_name("dispatch-schedule.json.lock"),
    )?;
    let mut ledger = Ledger::load(ledger_path)?;
    if !ledger.tasks.contains_key(&key) {
        if ledger.tasks.len() >= MAX_TASKS {
            return Err("Dispatch supports at most 4096 period requests".into());
        }
        let prepared = client
            .prepare(room, &body, "text/markdown", json!(["relay"]))
            .await?;
        ledger.tasks.insert(
            key.clone(),
            Record {
                body_sha256: body_sha256.clone(),
                prepared,
                room: room.to_owned(),
                sequence: None,
                status: "pending".into(),
                attempted: false,
            },
        );
        ledger.save(ledger_path)?;
    }
    let record = ledger
        .tasks
        .get(&key)
        .ok_or("Dispatch request is missing")?;
    if record.room != room || record.body_sha256 != body_sha256 {
        return Err(
            format!("{key} is already bound to different room or schedule settings").into(),
        );
    }
    client.authorize_prepared(room, &record.prepared).await?;
    if let Some(sequence) = record.sequence {
        return Ok((key, "already-delivered", sequence));
    }
    let found = client.find_prepared(room, &record.prepared).await?;
    let (status, sequence) = if let Some(sequence) = found {
        ("reconciled", sequence)
    } else {
        if record.attempted {
            return Err("Dispatch publish outcome is unknown; retained history does not confirm it. No automatic resend was made. Retry the same command to reconcile safely when history is available.".into());
        }
        // Save uncertainty before crossing the publication boundary. A crash
        // here can under-deliver, but cannot replay an uncertain external write.
        let prepared = record.prepared.clone();
        ledger
            .tasks
            .get_mut(&key)
            .ok_or("Dispatch request is missing")?
            .attempted = true;
        ledger.save(ledger_path)?;
        let result = match client.publish_prepared(room, &prepared).await {
            Ok(result) => result,
            Err(error) => {
                if !error.unknown {
                    // The owner refused before publication. A later explicit
                    // invocation may retry this known unperformed write.
                    ledger
                        .tasks
                        .get_mut(&key)
                        .ok_or("Dispatch request is missing")?
                        .attempted = false;
                    ledger.save(ledger_path)?;
                }
                return Err(error.into());
            }
        };
        let sequence = result["sequence"]
            .as_u64()
            .filter(|s| *s > 0)
            .ok_or("Dispatch publication returned no valid sequence; delivery remains unknown")?;
        ("delivered", sequence)
    };
    let record = ledger
        .tasks
        .get_mut(&key)
        .ok_or("Dispatch request is missing")?;
    record.status = "delivered".into();
    record.attempted = true;
    record.sequence = Some(sequence);
    ledger.save(ledger_path)?;
    Ok((key, status, sequence))
}

pub async fn run(config: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments.iter().any(|argument| argument == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let room = arguments
        .first()
        .filter(|room| !room.starts_with('-'))
        .ok_or("Dispatch room is required")?;
    let mut date = None;
    let mut weekly_on = "monday".to_owned();
    let mut mode = "manual".to_owned();
    let mut seen = BTreeSet::new();
    let mut args = arguments[1..].iter();
    while let Some(option) = args.next() {
        if !seen.insert(option) {
            return Err(format!("duplicate {option} option").into());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--date" => date = Some(parse_date(value)?),
            "--weekly-on" => weekly_on = value.to_ascii_lowercase(),
            "--publication-mode" => mode = value.to_ascii_lowercase(),
            _ => return Err(format!("unknown Dispatch request option: {option}").into()),
        }
    }
    let day = date.ok_or("--date must supply an exact YYYY-MM-DD date")?;
    render_task(day, &weekly_on, &mode)?;
    let configuration = crate::native_config::read(config)?;
    let path: PathBuf = configuration
        .data_dir
        .ok_or("native data directory is missing")?
        .join("coord/dispatch-schedule.json");
    let client = OperatorCoord::open(config)?;
    let result = deliver(&client, &path, room, day, &weekly_on, &mode).await;
    client.shutdown().await;
    let (key, status, sequence) = result?;
    println!("{status}  task_key={key}  sequence={sequence}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_periods_and_explicit_mode() {
        let (key, body) =
            render_task(parse_date("2026-06-01").unwrap(), "monday", "manual").unwrap();
        assert_eq!(key, "dispatch-production/2026-06-01");
        assert!(body.contains("weekly 2026-W22 (2026-05-25 through 2026-05-31)"));
        assert!(body.contains("monthly 2026-05 (2026-05-01 through 2026-05-31)"));
        assert!(body.contains("Do not merge or publish before the operator chooses publish"));
        for (offset, weekday) in WEEKDAYS.iter().enumerate() {
            let day = parse_date("2026-06-01").unwrap() + Duration::days(offset as i64);
            let (_, body) = render_task(day, weekday, "manual").unwrap();
            assert!(body.contains("weekly 2026-W22 (2026-05-25 through 2026-05-31)"));
        }
        let (_, automatic) =
            render_task(parse_date("2026-06-02").unwrap(), "monday", "automatic").unwrap();
        assert!(automatic.contains("operator explicitly selected automatic publication"));
        for invalid in [
            "20260829",
            "2026-W35-6",
            "2026-8-29",
            "0000-01-01",
            "2026-02-29",
        ] {
            assert!(parse_date(invalid).is_err());
        }
    }
}
