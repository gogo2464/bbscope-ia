//! Formatting scope lines from `-o` field flags (`t`, `d`, `c`, `u`).

use crate::category::normalize_category;
use crate::{Error, ProgramData, Result, ScopeElement};

/// One output column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Target,
    Description,
    Category,
    ProgramUrl,
}

/// Parsed `-o` flags plus the delimiter between fields.
#[derive(Debug, Clone)]
pub struct LineFormat {
    pub fields: Vec<Field>,
    pub delimiter: String,
}

impl LineFormat {
    /// Parses flags like `tdu`. `allowed` restricts which letters are valid.
    pub fn parse_with(flags: &str, delimiter: &str, allowed: &str) -> Result<Self> {
        let fields = flags
            .chars()
            .map(|c| {
                if !allowed.contains(c) {
                    return Err(Error::other(format!("invalid output flag '{c}', supported flags: {allowed}")));
                }
                Ok(match c {
                    't' => Field::Target,
                    'd' => Field::Description,
                    'c' => Field::Category,
                    _ => Field::ProgramUrl,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { fields, delimiter: delimiter.to_string() })
    }

    pub fn parse(flags: &str, delimiter: &str) -> Result<Self> {
        Self::parse_with(flags, delimiter, "tdcu")
    }

    /// Builds one line from the given values.
    pub fn line(&self, target: &str, description: &str, category: &str, url: &str) -> String {
        self.fields
            .iter()
            .map(|f| match f {
                Field::Target => target,
                Field::Description => description,
                Field::Category => category,
                Field::ProgramUrl => url,
            })
            .collect::<Vec<_>>()
            .join(&self.delimiter)
    }

    pub fn element_line(&self, e: &ScopeElement, url: &str) -> String {
        self.line(&e.target, &e.description, &normalize_category(&e.category), url)
    }

    /// Lines for a whole program; out-of-scope ones are prefixed with `[OOS] `.
    pub fn program_lines(&self, pd: &ProgramData, include_oos: bool) -> Vec<String> {
        let mut out: Vec<String> =
            pd.in_scope.iter().map(|e| self.element_line(e, &pd.url)).filter(|l| !l.is_empty()).collect();
        if include_oos {
            out.extend(
                pd.out_of_scope
                    .iter()
                    .map(|e| self.element_line(e, &pd.url))
                    .filter(|l| !l.is_empty())
                    .map(|l| format!("[OOS] {l}")),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        let f = LineFormat::parse("tcu", " | ").unwrap();
        let e = ScopeElement::new("*.x.com", "desc", "WILDCARD");
        assert_eq!(f.element_line(&e, "https://p"), "*.x.com | wildcard | https://p");
        assert!(LineFormat::parse("tz", " ").is_err());
        assert!(LineFormat::parse_with("d", " ", "tu").is_err());
    }
}
