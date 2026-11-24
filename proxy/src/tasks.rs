//! Uploaded task policies and the exact selected task overlay.
//!
//! The operator facade owns authentication. Registration validates the shared
//! policy schema and retains the supplied document; it does not compile,
//! activate or add canonical defaults to that document. The native instance
//! retains registration and activation across restarts in its private data.

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde_json::Value;

/// Registry failures contain no task ID, document, or underlying error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidId,
    InvalidPolicy,
    NotFound,
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidId => "Invalid task ID",
            Self::InvalidPolicy => "Invalid policy document",
            Self::NotFound => "Task policy not found",
            Self::Poisoned => "Task registry unavailable",
        })
    }
}

impl std::error::Error for Error {}

/// Validated permission count returned by the source registration operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upsert {
    pub permission_count: usize,
}

/// An immutable raw document. Explicit response rendering may borrow its data.
/// The last registry/response owner wipes strings and object keys on drop.
///
/// ```compile_fail
/// use safeyolo_proxy::tasks::RawTask;
/// fn cannot_log(task: &RawTask) { println!("{task:?}"); }
/// ```
/// ```compile_fail
/// use safeyolo_proxy::tasks::RawTask;
/// fn cannot_serialize(task: &RawTask) { let _ = serde_json::to_string(task); }
/// ```
pub struct RawTask {
    document: Value,
}

impl RawTask {
    /// Raw operator input, without model defaults or a substituted task ID.
    /// The authorized caller owns protection of any bytes it renders or copies.
    pub fn document(&self) -> &Value {
        &self.document
    }
}

impl Drop for RawTask {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.document);
    }
}

/// One shared registry per proxy process. Clones share registration state.
/// Tests can use an ephemeral default; the native instance opens its own file.
#[derive(Clone, Default)]
pub struct Registry {
    state: Arc<Mutex<RegistryState>>,
    path: Option<PathBuf>,
}

#[derive(Clone, Default)]
struct RegistryState {
    entries: HashMap<String, Arc<RawTask>>,
    active: Option<(String, Arc<RawTask>)>,
}

impl Registry {
    pub(crate) fn install_active(&self, task_id: &str, document: Value) -> Result<(), Error> {
        crate::policy::validate_task_id(task_id).map_err(|_| Error::InvalidId)?;
        crate::policy::validate_task_document(&document).map_err(|_| Error::InvalidPolicy)?;
        let task = Arc::new(RawTask { document });
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut candidate = state.clone();
        candidate.entries.insert(task_id.to_owned(), task.clone());
        candidate.active = Some((task_id.to_owned(), task));
        self.save(&candidate)?;
        *state = candidate;
        Ok(())
    }
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let registry = Self {
            path: Some(path.to_owned()),
            ..Self::default()
        };
        let Some(document) = crate::guest_commands::read_state_bounded(path, u64::MAX)
            .map_err(|_| Error::Poisoned)?
        else {
            return Ok(registry);
        };
        let raw = RawTask { document };
        let document = raw.document();
        let mut restored = RegistryState::default();
        for (id, task) in document["entries"]
            .as_object()
            .ok_or(Error::InvalidPolicy)?
        {
            crate::policy::validate_task_id(id).map_err(|_| Error::InvalidId)?;
            crate::policy::validate_task_document(task).map_err(|_| Error::InvalidPolicy)?;
            restored.entries.insert(
                id.clone(),
                Arc::new(RawTask {
                    document: task.clone(),
                }),
            );
        }
        if !document["active"].is_null() {
            let id = document["active"]["id"].as_str().ok_or(Error::InvalidId)?;
            crate::policy::validate_task_id(id).map_err(|_| Error::InvalidId)?;
            let task = &document["active"]["document"];
            crate::policy::validate_task_document(task).map_err(|_| Error::InvalidPolicy)?;
            if !restored.entries.contains_key(id) {
                return Err(Error::InvalidId);
            }
            restored.active = Some((
                id.to_owned(),
                Arc::new(RawTask {
                    document: task.clone(),
                }),
            ));
        }
        *registry.state.lock().map_err(|_| Error::Poisoned)? = restored;
        Ok(registry)
    }

    fn save(&self, state: &RegistryState) -> Result<(), Error> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut document = serde_json::json!({
            "entries": state.entries.iter().map(|(id, task)| (id.clone(), task.document().clone())).collect::<serde_json::Map<_,_>>(),
            "active": state.active.as_ref().map(|(id, task)| serde_json::json!({"id":id,"document":task.document()}))
        });
        let saved = crate::guest_commands::write_json(path, &document).map_err(|_| Error::Poisoned);
        crate::credentials::wipe_json(&mut document);
        saved
    }

    /// Validate then replace one entry atomically. Every error preserves the
    /// previous entry; even rejected input stays in a wiping owner throughout.
    pub fn upsert(&self, task_id: &str, document: Value) -> Result<Upsert, Error> {
        let raw = RawTask { document };
        crate::policy::validate_task_id(task_id).map_err(|_| Error::InvalidId)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let permission_count = crate::policy::validate_task_document(raw.document())
            .map_err(|_| Error::InvalidPolicy)?;
        let mut candidate = state.clone();
        candidate.entries.insert(task_id.to_owned(), Arc::new(raw));
        self.save(&candidate)?;
        *state = candidate;
        Ok(Upsert { permission_count })
    }

    /// Select an already registered document at the explicit activation
    /// boundary. Registration alone never changes enforcement.
    pub(crate) fn activate(&self, task_id: &str) -> Result<Arc<RawTask>, Error> {
        crate::policy::validate_task_id(task_id).map_err(|_| Error::InvalidId)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let task = state.entries.get(task_id).cloned().ok_or(Error::NotFound)?;
        let mut candidate = state.clone();
        candidate.active = Some((task_id.to_owned(), task.clone()));
        self.save(&candidate)?;
        *state = candidate;
        Ok(task)
    }

    /// Remove a registered document. If it is active, the caller must publish
    /// the baseline-only policy at the same activation boundary.
    pub(crate) fn clear(&self, task_id: &str) -> Result<bool, Error> {
        crate::policy::validate_task_id(task_id).map_err(|_| Error::InvalidId)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        let mut candidate = state.clone();
        let removed = candidate.entries.remove(task_id).is_some();
        if removed
            && state
                .active
                .as_ref()
                .is_some_and(|(active_id, _)| active_id == task_id)
        {
            candidate.active = None;
        }
        self.save(&candidate)?;
        *state = candidate;
        Ok(removed)
    }

    /// Return the selected document for Runtime reload publication.
    pub(crate) fn active(&self) -> Result<Option<(String, Arc<RawTask>)>, Error> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(state
            .active
            .as_ref()
            .map(|(task_id, task)| (task_id.clone(), task.clone())))
    }

    /// Invalid IDs are absent, matching the source getter. A returned owner
    /// remains valid if another request replaces its registry entry.
    pub fn get(&self, task_id: &str) -> Result<Option<Arc<RawTask>>, Error> {
        if crate::policy::validate_task_id(task_id).is_err() {
            return Ok(None);
        }
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(state.entries.get(task_id).cloned())
    }

    pub fn count(&self) -> Result<usize, Error> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(state.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn restart_retains_exact_activation_and_explicit_clear() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.json");
        let original = json!({"permissions":[{"action":"network:request","resource":"original.invalid/*","effect":"deny"}]});
        let pending = json!({"permissions":[]});
        let registry = Registry::open(&path).unwrap();
        registry.upsert("task", original.clone()).unwrap();
        registry.activate("task").unwrap();
        registry.upsert("task", pending.clone()).unwrap();
        drop(registry);
        let registry = Registry::open(&path).unwrap();
        assert_eq!(registry.get("task").unwrap().unwrap().document(), &pending);
        assert_eq!(registry.active().unwrap().unwrap().1.document(), &original);
        registry.clear("task").unwrap();
        drop(registry);
        let registry = Registry::open(&path).unwrap();
        assert_eq!(registry.count().unwrap(), 0);
        assert!(registry.active().unwrap().is_none());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn failed_persistence_preserves_the_active_and_registered_task() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.json");
        let registry = Registry::open(&path).unwrap();
        let original = json!({"permissions":[]});
        registry.upsert("task", original.clone()).unwrap();
        registry.activate("task").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(registry.upsert("task", json!({})), Err(Error::Poisoned));
        assert_eq!(registry.clear("task"), Err(Error::Poisoned));
        assert_eq!(registry.get("task").unwrap().unwrap().document(), &original);
        assert_eq!(registry.active().unwrap().unwrap().1.document(), &original);
    }

    #[test]
    fn replacement_waits_for_activation_and_clear_drops_selected_snapshot() {
        let registry = Registry::default();
        let first = json!({
            "permissions":[{"action":"network:request","resource":"first.invalid/*","effect":"deny"}]
        });
        let replacement = json!({
            "permissions":[{"action":"network:request","resource":"second.invalid/*","effect":"deny"}]
        });
        registry.upsert("alpha", first.clone()).unwrap();
        registry.activate("alpha").unwrap();
        registry.upsert("alpha", replacement.clone()).unwrap();

        let (_, selected) = registry.active().unwrap().unwrap();
        assert_eq!(selected.document(), &first);
        assert_eq!(
            registry.get("alpha").unwrap().unwrap().document(),
            &replacement
        );

        registry.activate("alpha").unwrap();
        let (_, selected) = registry.active().unwrap().unwrap();
        assert_eq!(selected.document(), &replacement);
        assert!(registry.clear("alpha").unwrap());
        assert!(registry.active().unwrap().is_none());
        assert!(registry.get("alpha").unwrap().is_none());
    }

    #[test]
    fn invalid_replacement_preserves_registered_and_selected_documents() {
        let registry = Registry::default();
        let first = json!({"permissions":[]});
        registry.upsert("alpha", first.clone()).unwrap();
        registry.activate("alpha").unwrap();
        assert_eq!(
            registry.upsert("alpha", json!({"permissions":false})),
            Err(Error::InvalidPolicy)
        );
        assert_eq!(registry.get("alpha").unwrap().unwrap().document(), &first);
        assert_eq!(registry.active().unwrap().unwrap().1.document(), &first);
        assert_eq!(registry.clear("missing"), Ok(false));
    }
}
