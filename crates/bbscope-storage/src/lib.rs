//! Scope database with change tracking.
//!
//! [`Store`] is the backend-agnostic interface used by the poller and the
//! CLI; [`SqliteStore`] is the bundled implementation. [`open`] picks a
//! backend from a connection string.

use std::collections::HashSet;

use bbscope_core::category::normalize_category;
use bbscope_core::normalize::{normalize_program_url, normalize_target};
use bbscope_core::{Change, Entry, ProgramData};
use chrono::{DateTime, Utc};

mod sqlite;

pub use sqlite::SqliteStore;

pub type Result<T, E = StorageError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The platform returned an empty scope for a program that has targets.
    #[error("aborting update to prevent wiping out all targets for a program")]
    ScopeWipe,
    #[error("{0}")]
    Other(String),
}

/// A target ready to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertEntry {
    pub target_raw: String,
    pub target_normalized: String,
    /// Unified category.
    pub category: String,
    pub description: String,
    pub in_scope: bool,
    pub is_bbp: bool,
}

/// Canonicalizes a program's scope into upsert entries.
pub fn build_entries(pd: &ProgramData) -> Vec<UpsertEntry> {
    let make = |e: &bbscope_core::ScopeElement, in_scope| UpsertEntry {
        target_raw: e.target.clone(),
        target_normalized: normalize_target(&e.target),
        category: normalize_category(&e.category),
        description: e.description.clone(),
        in_scope,
        is_bbp: e.is_bbp,
    };
    pd.in_scope.iter().map(|e| make(e, true)).chain(pd.out_of_scope.iter().map(|e| make(e, false))).collect()
}

/// Program URL identity used by the database.
pub fn program_key(url: &str) -> String {
    normalize_program_url(url)
}

/// Filters for [`Store::list_entries`].
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Comma-separated platform names; empty or `all` for every platform.
    pub platforms: String,
    /// Substring of the program URL.
    pub program_filter: String,
    pub since: Option<DateTime<Utc>>,
    pub include_oos: bool,
    pub include_ignored: bool,
    pub program_type: ProgramType,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProgramType {
    #[default]
    All,
    /// Programs with at least one bounty-eligible target.
    Bbp,
    /// Programs without any bounty-eligible target.
    Vdp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformStats {
    pub platform: String,
    pub programs: u64,
    pub in_scope: u64,
    pub out_of_scope: u64,
}

/// A scope database.
pub trait Store: Send + Sync {
    /// Active (not disabled, not ignored) programs of a platform.
    fn active_program_count(&self, platform: &str) -> Result<usize>;

    /// URLs of ignored programs of a platform.
    fn ignored_programs(&self, platform: &str) -> Result<HashSet<String>>;

    /// Replaces a program's targets and returns what changed.
    /// Fails with [`StorageError::ScopeWipe`] if `entries` is empty but the
    /// program has targets.
    fn upsert_program(&self, program_url: &str, platform: &str, handle: &str, entries: &[UpsertEntry])
        -> Result<Vec<Change>>;

    /// Disables programs of `platform` that were not polled and returns one
    /// "program removed" change per program.
    fn sync_platform_programs(&self, platform: &str, polled_urls: &[String]) -> Result<Vec<Change>>;

    /// Appends changes to the history.
    fn log_changes(&self, changes: &[Change]) -> Result<()>;

    /// Sets the ignored flag on programs whose URL contains `pattern`.
    /// Returns how many programs matched.
    fn set_program_ignored(&self, pattern: &str, ignored: bool) -> Result<usize>;

    fn list_entries(&self, opts: &ListOptions) -> Result<Vec<Entry>>;

    /// Adds a manual target. Returns `false` if it already existed.
    fn add_custom_target(&self, target: &str, category: &str, program_url: &str) -> Result<bool>;

    /// Most recent changes first. `limit == 0` means no limit.
    fn recent_changes(&self, limit: usize, since: Option<DateTime<Utc>>, until: Option<DateTime<Utc>>)
        -> Result<Vec<Change>>;

    fn stats(&self) -> Result<Vec<PlatformStats>>;

    /// Searches current targets and the change history (case-insensitive).
    fn search(&self, term: &str) -> Result<Vec<Entry>>;

    /// Command and arguments that open an interactive shell on the database.
    fn shell_command(&self) -> Option<(String, Vec<String>)> {
        None
    }
}

/// Opens a store from a connection string: a file path, `sqlite://path`
/// or `sqlite::memory:`.
pub fn open(conn: &str) -> Result<Box<dyn Store>> {
    let conn = conn.trim();
    if conn.starts_with("postgres://") || conn.starts_with("postgresql://") {
        return Err(StorageError::Other(
            "PostgreSQL is not supported by this build yet; set db_url to a SQLite file path".into(),
        ));
    }
    let path = conn.strip_prefix("sqlite://").or_else(|| conn.strip_prefix("sqlite:")).unwrap_or(conn);
    Ok(Box::new(SqliteStore::open(path)?))
}
