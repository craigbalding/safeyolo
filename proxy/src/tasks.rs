//! Process-local uploaded task policies, separate from the active task overlay.
//!
//! The operator facade owns authentication. Registration validates the shared
//! policy schema and retains the supplied document; it does not compile,
//! activate, persist, or add canonical defaults to that document.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use serde_json::Value;

/// Registry failures contain no task ID, document, or underlying error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidId,
    InvalidPolicy,
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidId => "Invalid task ID",
            Self::InvalidPolicy => "Invalid policy document",
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
/// A fresh default registry is empty; there is no persistence or activation.
#[derive(Clone, Default)]
pub struct Registry {
    entries: Arc<Mutex<HashMap<String, Arc<RawTask>>>>,
}

impl Registry {
    /// Validate then replace one entry atomically. Every error preserves the
    /// previous entry; even rejected input stays in a wiping owner throughout.
    pub fn upsert(&self, task_id: &str, document: Value) -> Result<Upsert, Error> {
        let raw = RawTask { document };
        crate::policy::validate_task_id(task_id).map_err(|_| Error::InvalidId)?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let permission_count = crate::policy::validate_task_document(raw.document())
            .map_err(|_| Error::InvalidPolicy)?;
        entries.insert(task_id.to_owned(), Arc::new(raw));
        Ok(Upsert { permission_count })
    }

    /// Invalid IDs are absent, matching the source getter. A returned owner
    /// remains valid if another request replaces its registry entry.
    pub fn get(&self, task_id: &str) -> Result<Option<Arc<RawTask>>, Error> {
        if crate::policy::validate_task_id(task_id).is_err() {
            return Ok(None);
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        Ok(entries.get(task_id).cloned())
    }

    pub fn count(&self) -> Result<usize, Error> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        Ok(entries.len())
    }
}
