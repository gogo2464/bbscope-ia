//! Extracts specific target types from scope entries.
//!
//! - [`collect`] with a [`Kind`]: URLs, IPs, CIDRs / IP ranges, domains
//! - [`wildcards`]: root domains suitable for subdomain enumeration tools

use std::collections::BTreeSet;

use bbscope_core::normalize::{is_cidr, is_ip, is_ip_range, UrlParts};
use bbscope_core::Entry;

pub mod wildcards;

pub use wildcards::{collect_oos_wildcards, collect_wildcards, WildcardOptions, WildcardResult};

/// Simple target kinds selectable with [`collect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `http://` / `https://` targets.
    Urls,
    /// IP addresses, including IP hosts of URLs.
    Ips,
    /// CIDR ranges and `a-b` IP ranges.
    Cidrs,
    /// Anything with a dot that is not a URL (includes wildcards).
    Domains,
}

impl Kind {
    /// The value this kind extracts from a target, if any.
    pub fn extract(self, target: &str) -> Option<String> {
        let ok = match self {
            Kind::Urls => is_url(target),
            Kind::Cidrs => is_cidr(target) || is_ip_range(target),
            Kind::Domains => target.contains('.') && !is_url(target),
            Kind::Ips => return extract_ip(target),
        };
        ok.then(|| target.to_string())
    }
}

/// Unique, sorted values of `kind` among entries with the given scope status.
pub fn collect(entries: &[Entry], kind: Kind, in_scope: bool) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.in_scope == in_scope)
        .filter_map(|e| kind.extract(&e.target_normalized))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_url(t: &str) -> bool {
    t.starts_with("http://") || t.starts_with("https://")
}

fn extract_ip(target: &str) -> Option<String> {
    if is_ip(target) {
        return Some(target.to_string());
    }
    if is_url(target) {
        let host = UrlParts::parse(target)?.hostname();
        if is_ip(host) {
            return Some(host.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(t: &str, in_scope: bool) -> Entry {
        Entry { target_normalized: t.into(), in_scope, ..Default::default() }
    }

    #[test]
    fn kinds() {
        let es = vec![
            entry("https://a.com", true),
            entry("http://10.0.0.1:8080/x", true),
            entry("10.0.0.2", true),
            entry("10.0.0.0/24", true),
            entry("1.1.1.1-1.1.1.5", true),
            entry("*.b.com", true),
            entry("c.com", false),
            entry("https://a.com", true),
        ];
        assert_eq!(collect(&es, Kind::Urls, true), vec!["http://10.0.0.1:8080/x", "https://a.com"]);
        assert_eq!(collect(&es, Kind::Ips, true), vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(collect(&es, Kind::Cidrs, true), vec!["1.1.1.1-1.1.1.5", "10.0.0.0/24"]);
        assert_eq!(
            collect(&es, Kind::Domains, true),
            vec!["*.b.com", "1.1.1.1-1.1.1.5", "10.0.0.0/24", "10.0.0.2"]
        );
        assert_eq!(collect(&es, Kind::Domains, false), vec!["c.com"]);
    }
}
