//! The trait every bug bounty platform implements.

use std::collections::BTreeSet;

use async_trait::async_trait;

use crate::{category, ProgramData, Result};

/// Filters applied while polling.
#[derive(Debug, Clone, Default)]
pub struct PollOptions {
    /// Only programs that pay bounties.
    pub bounty_only: bool,
    /// Only private / invite-only programs.
    pub private_only: bool,
    /// Comma-separated unified categories, or `all` / empty.
    pub categories: String,
}

impl PollOptions {
    /// Raw platform categories to keep; `None` keeps everything.
    pub fn category_filter(&self) -> Option<BTreeSet<&'static str>> {
        category::raw_strings_for(&self.categories)
    }
}

/// A bug bounty platform.
///
/// Implementations are built already authenticated (see each platform's
/// constructor), so polling only needs two calls: list the programs, then
/// fetch each program's scope. `fetch_program_scope` may be called
/// concurrently.
#[async_trait]
pub trait Platform: Send + Sync {
    /// Short identifier stored in the database (`h1`, `bc`, `it`, `ywh`, `immunefi`).
    fn name(&self) -> &'static str;

    /// Handles of every program matching `opts`.
    async fn list_program_handles(&self, opts: &PollOptions) -> Result<Vec<String>>;

    /// Scope of one program from [`Platform::list_program_handles`].
    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData>;
}
