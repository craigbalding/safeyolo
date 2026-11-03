//! Read-only observation of the existing supervisor checkpoint and agent room.

use std::{io::ErrorKind, path::PathBuf, time::Duration};

use crate::{Error, coord_supervisor, host_agents, host_platform};

pub(crate) const HELP: &str = "safeyolo [--root ROOT] agent watch NAME [--history COUNT] [--since SEQUENCE] [--once] [--max-text COUNT] [--plain]\n\nWatch the named supervised agent's configured room and checkpoint. The view is read-only, compact and redacted, with 30 recent messages and at most 600 characters per line by default. Ctrl-C detaches. Checkpoint observations are labelled separately from retained agent events. They do not prove supervisor liveness. Missing or damaged checkpoints remain visible while the room follows. Use agent diagnostics NAME to inspect runtime failures.";

fn failure(error: &Error) -> &'static str {
    match error.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
        Some(ErrorKind::NotFound) => "missing",
        Some(ErrorKind::PermissionDenied) => "unreadable",
        Some(_) => "unreadable or replaced",
        None => "malformed",
    }
}

pub(crate) struct Activity {
    agent: host_agents::Agent,
    directory: PathBuf,
    room: String,
    last: Vec<String>,
    thread: Option<String>,
}

impl Activity {
    pub(crate) fn open(agent: host_agents::Agent) -> Result<Self, Error> {
        let directory = host_platform::config_dir()
            .join("agents")
            .join(&agent.name)
            .join("home/.safeyolo");
        let config = coord_supervisor::Config::load(&directory.join("coord-supervisor.json"))
            .map_err(|error| {
                format!(
                    "supervisor configuration {}; check supervised setup for agent {}",
                    failure(&error),
                    agent.name
                )
            })?;
        if config.agent_name != agent.name {
            return Err("supervisor configuration identity differs from the selected agent".into());
        }
        let room = config
            .agent_room
            .ok_or("supervisor has no activity room configured")?;
        Ok(Self {
            agent,
            directory,
            room,
            last: Vec::new(),
            thread: None,
        })
    }

    pub(crate) fn room(&self) -> &str {
        &self.room
    }

    pub(crate) fn agent_id(&self) -> &str {
        &self.agent.id
    }

    pub(crate) fn label(&self) -> String {
        format!(
            "agent={} room={}; read-only; Ctrl-C detaches",
            self.agent.name, self.room
        )
    }

    pub(crate) fn observe(&mut self) -> Vec<String> {
        let lines = self
            .snapshot()
            .unwrap_or_else(|error| vec![error.to_string()]);
        if self.last == lines {
            return Vec::new();
        }
        self.last = lines.clone();
        lines
    }

    fn snapshot(&mut self) -> Result<Vec<String>, Error> {
        host_agents::refresh(&self.agent).map_err(
            |_| "agent configuration replaced, unreadable or removed; reattach after repair",
        )?;
        let config = coord_supervisor::Config::load(&self.directory.join("coord-supervisor.json"))
            .map_err(|error| {
                format!(
                    "supervisor configuration {}; current state unavailable",
                    failure(&error)
                )
            })?;
        if config.agent_name != self.agent.name || config.agent_room.as_deref() != Some(&self.room)
        {
            return Err("supervisor configuration replaced; room selection changed; reattach agent watch after checking setup".into());
        }
        let path = self.directory.join("coord-supervisor-state.json");
        // The ordinary loader validates the same bounded, regular, non-symlink
        // checkpoint as the supervisor. Never create a lock or a fresh state.
        let state = coord_supervisor::State::read_existing(&path).map_err(|error| {
            format!(
                "checkpoint {}; current state unavailable (room observation continues)",
                failure(&error)
            )
        })?;
        let age = std::fs::metadata(&path)?
            .modified()?
            .elapsed()
            .unwrap_or_default();
        let stale_after = config.wait_seconds
            + config.startup_timeout_seconds
            + config.work_timeout_seconds
            + config.completion_grace_seconds
            + config.backoff_max_seconds;
        let mut lines = vec![format!(
            "checkpoint {}: phase={} harness={} thread={} tasks={} handoffs={} failures={}; supervisor liveness unverified",
            if age > Duration::from_secs(stale_after) {
                "stale"
            } else {
                "observed"
            },
            state.phase,
            state.harness,
            state.thread_id.as_deref().unwrap_or("none"),
            state.in_flight.len(),
            state.awaiting_handoffs.len(),
            state.consecutive_failures,
        )];
        if self.thread != state.thread_id {
            if self.thread.is_some() {
                lines.push(format!(
                    "thread replaced: {} -> {}",
                    self.thread.as_deref().unwrap_or("none"),
                    state.thread_id.as_deref().unwrap_or("none")
                ));
            }
            self.thread = state.thread_id;
        }
        for pending in state.in_flight {
            if let Some((kind, fields)) = coord_supervisor::header(&pending.body) {
                lines.push(format!(
                    "pending {kind} target={} attention_id={}",
                    fields.get("target").map_or("unknown", String::as_str),
                    pending.attention_id
                ));
            }
        }
        for handoff in state.awaiting_handoffs {
            lines.push(format!(
                "waiting for {} reply from {} target={}",
                handoff.request,
                handoff.recipient_agent,
                handoff
                    .correlation
                    .get("target")
                    .map_or("unknown", String::as_str)
            ));
        }
        Ok(lines)
    }
}
