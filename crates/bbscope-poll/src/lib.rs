//! Polling engine: fetches every program of a platform concurrently and,
//! with a database, records what changed since the last poll.
//!
//! The engine only knows the [`Platform`] and [`Store`] traits, so any
//! platform works with any storage backend.

use bbscope_core::{Change, Platform, PollOptions, ProgramData, Result as CoreResult};
use bbscope_storage::{build_entries, StorageError, Store};
use futures::stream::{self, StreamExt};

pub const DEFAULT_CONCURRENCY: usize = 5;

/// Refuse to disable everything when a platform suddenly lists no programs
/// but the database knows more than this many.
const EMPTY_LISTING_GUARD: usize = 10;

/// Fetches all programs without storing anything. `on_program` receives each
/// result as it completes (in completion order).
pub async fn fetch_all(
    platform: &dyn Platform,
    opts: &PollOptions,
    concurrency: usize,
    mut on_program: impl FnMut(&str, CoreResult<ProgramData>),
) -> CoreResult<()> {
    let handles = platform.list_program_handles(opts).await?;
    let mut results = stream::iter(handles)
        .map(|h| async move {
            let res = platform.fetch_program_scope(&h, opts).await;
            (h, res)
        })
        .buffer_unordered(concurrency.max(1));
    while let Some((handle, res)) = results.next().await {
        on_program(&handle, res);
    }
    Ok(())
}

/// Outcome of [`poll_platform`].
#[derive(Debug, Default)]
pub struct PollReport {
    /// No programs of this platform were in the database before this poll.
    /// Changes are not logged on a first run (everything would be "added").
    pub first_run: bool,
    pub polled_urls: Vec<String>,
    pub changes: Vec<Change>,
    /// "Program removed" changes for programs the platform no longer lists.
    pub removed_programs: Vec<Change>,
    /// Programs that failed to fetch or store: `(handle, error)`.
    pub errors: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum PollError {
    Platform(bbscope_core::Error),
    Storage(StorageError),
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollError::Platform(e) => write!(f, "{e}"),
            PollError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PollError {}

/// Polls one platform into `store`.
///
/// `on_program` is called after each program is stored with its changes
/// and whether this is the platform's first run.
pub async fn poll_platform(
    platform: &dyn Platform,
    store: &dyn Store,
    opts: &PollOptions,
    concurrency: usize,
    mut on_program: impl FnMut(&str, &[Change], bool),
) -> Result<PollReport, PollError> {
    let name = platform.name();
    let known = store.active_program_count(name).map_err(PollError::Storage)?;
    let mut report = PollReport { first_run: known == 0, ..Default::default() };
    let ignored = store.ignored_programs(name).unwrap_or_else(|e| {
        tracing::warn!("Could not load ignored programs for {name}: {e}");
        Default::default()
    });

    let handles = platform.list_program_handles(opts).await.map_err(PollError::Platform)?;
    if handles.is_empty() && known > EMPTY_LISTING_GUARD {
        tracing::error!(
            "{name} returned 0 programs but the database has {known}. Skipping sync to prevent data loss."
        );
        return Ok(report);
    }
    if report.first_run && !handles.is_empty() {
        tracing::info!("First poll for {name}, populating database...");
    }

    let mut results = stream::iter(handles)
        .map(|h| async move {
            let res = platform.fetch_program_scope(&h, opts).await;
            (h, res)
        })
        .buffer_unordered(concurrency.max(1));

    while let Some((handle, res)) = results.next().await {
        let pd = match res {
            Ok(pd) => pd,
            Err(e) => {
                tracing::warn!("Failed to fetch scope for {handle}: {e}");
                report.errors.push((handle, e.to_string()));
                continue;
            }
        };
        if pd.url.is_empty() {
            continue;
        }
        if ignored.contains(&pd.url) {
            tracing::debug!("Skipping ignored program: {}", pd.url);
            continue;
        }

        let changes = match store.upsert_program(&pd.url, name, &handle, &build_entries(&pd)) {
            Ok(c) => c,
            Err(StorageError::ScopeWipe) => {
                tracing::warn!("Empty scope returned for {}, keeping the stored one.", pd.url);
                report.polled_urls.push(pd.url);
                continue;
            }
            Err(e) => {
                tracing::warn!("Database error for {}: {e}", pd.url);
                report.errors.push((handle, e.to_string()));
                continue;
            }
        };
        if !report.first_run {
            if let Err(e) = store.log_changes(&changes) {
                tracing::warn!("Could not log changes for {}: {e}", pd.url);
            }
        }
        on_program(&pd.url, &changes, report.first_run);
        report.polled_urls.push(pd.url);
        report.changes.extend(changes);
    }

    // Programs that failed to fetch are missing from polled_urls; syncing now
    // would report them as removed (and re-added next poll).
    if !report.errors.is_empty() {
        tracing::warn!(
            "{} {name} program(s) failed to fetch; skipping removed-program detection this run.",
            report.errors.len()
        );
    } else {
        match store.sync_platform_programs(name, &report.polled_urls) {
            Ok(removed) => {
                if !report.first_run {
                    if let Err(e) = store.log_changes(&removed) {
                        tracing::warn!("Could not log removed programs for {name}: {e}");
                    }
                }
                report.removed_programs = removed;
            }
            Err(e) => tracing::warn!("Failed to sync removed programs for {name}: {e}"),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bbscope_core::{ChangeType, ScopeElement};
    use bbscope_storage::SqliteStore;
    use std::sync::Mutex;

    /// In-memory platform whose programs can be changed between polls.
    struct Fake(Mutex<Vec<(&'static str, Vec<&'static str>)>>);

    #[async_trait]
    impl Platform for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        async fn list_program_handles(&self, _: &PollOptions) -> CoreResult<Vec<String>> {
            Ok(self.0.lock().unwrap().iter().map(|(h, _)| h.to_string()).collect())
        }
        async fn fetch_program_scope(&self, handle: &str, _: &PollOptions) -> CoreResult<ProgramData> {
            let programs = self.0.lock().unwrap();
            let (_, targets) = programs.iter().find(|(h, _)| *h == handle).unwrap();
            let mut pd = ProgramData::new(format!("https://fake/{handle}"));
            pd.in_scope = targets.iter().map(|t| ScopeElement::new(*t, "", "wildcard")).collect();
            Ok(pd)
        }
    }

    #[tokio::test]
    async fn detects_changes_across_polls() {
        let store = SqliteStore::open(":memory:").unwrap();
        let fake = Fake(Mutex::new(vec![("a", vec!["*.a.com"]), ("b", vec!["*.b.com"])]));
        let opts = PollOptions::default();

        let first = poll_platform(&fake, &store, &opts, 2, |_, _, _| {}).await.unwrap();
        assert!(first.first_run);
        assert_eq!(first.polled_urls.len(), 2);
        assert!(store.recent_changes(0, None, None).unwrap().is_empty(), "first run is not logged");

        *fake.0.lock().unwrap() = vec![("a", vec!["*.a.com", "*.a2.com"])];
        let mut streamed = 0;
        let second = poll_platform(&fake, &store, &opts, 2, |_, c, _| streamed += c.len()).await.unwrap();
        assert!(!second.first_run);
        assert_eq!(streamed, 1);
        assert_eq!(second.changes[0].change_type, ChangeType::Added);
        assert_eq!(second.removed_programs.len(), 1);
        assert_eq!(second.removed_programs[0].program_url, "https://fake/b");
        assert_eq!(store.recent_changes(0, None, None).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn fetch_all_streams_results() {
        let fake = Fake(Mutex::new(vec![("a", vec!["x.com"]), ("b", vec!["y.com"])]));
        let mut n = 0;
        fetch_all(&fake, &PollOptions::default(), 3, |_, r| n += r.unwrap().in_scope.len()).await.unwrap();
        assert_eq!(n, 2);
    }
}
