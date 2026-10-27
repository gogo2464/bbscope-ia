use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single target as returned by a platform.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeElement {
    pub target: String,
    pub description: String,
    /// Raw platform category (see [`crate::category::normalize_category`]).
    pub category: String,
    pub is_bbp: bool,
}

impl ScopeElement {
    pub fn new(target: impl Into<String>, description: impl Into<String>, category: impl Into<String>) -> Self {
        Self { target: target.into(), description: description.into(), category: category.into(), is_bbp: false }
    }
}

/// The scope of one program.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramData {
    pub url: String,
    pub in_scope: Vec<ScopeElement>,
    pub out_of_scope: Vec<ScopeElement>,
}

impl ProgramData {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), ..Default::default() }
    }

    pub fn is_empty(&self) -> bool {
        self.in_scope.is_empty() && self.out_of_scope.is_empty()
    }

    pub fn set_bbp(&mut self, is_bbp: bool) {
        for e in self.in_scope.iter_mut().chain(self.out_of_scope.iter_mut()) {
            e.is_bbp = is_bbp;
        }
    }
}

/// A target as stored in (and read back from) the database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub program_url: String,
    pub platform: String,
    pub handle: String,
    pub target_raw: String,
    pub target_normalized: String,
    /// Unified category.
    pub category: String,
    pub description: String,
    pub in_scope: bool,
    pub is_bbp: bool,
    /// Program opted out of aggressive root-domain extraction.
    pub strict: bool,
    /// Found only in the change history, no longer in scope.
    pub is_historical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Added,
    Removed,
    Updated,
}

impl ChangeType {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeType::Added => "added",
            ChangeType::Removed => "removed",
            ChangeType::Updated => "updated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "added" => Some(ChangeType::Added),
            "removed" => Some(ChangeType::Removed),
            "updated" => Some(ChangeType::Updated),
            _ => None,
        }
    }
}

/// Category used for changes that concern a whole program rather than a target.
pub const PROGRAM_CATEGORY: &str = "program";

/// A scope change detected between two polls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub occurred_at: DateTime<Utc>,
    pub program_url: String,
    pub platform: String,
    pub handle: String,
    pub target_raw: String,
    pub target_normalized: String,
    pub category: String,
    pub in_scope: bool,
    pub is_bbp: bool,
    pub change_type: ChangeType,
}

impl Change {
    pub fn is_program_removal(&self) -> bool {
        self.change_type == ChangeType::Removed && self.category == PROGRAM_CATEGORY
    }
}
