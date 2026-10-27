//! Root-domain wildcards for subdomain enumeration.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use bbscope_core::normalize::{extract_root_domain, is_cidr, is_ip, is_ip_range, UrlParts};
use bbscope_core::Entry;
use regex::Regex;

/// Shared-hosting / cloud suffixes that are useless for subdomain enumeration.
pub const BLACKLISTED_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "amazoncognito.com",
    "azurewebsites.net",
    "azure.com",
    "cloudfront.net",
    "herokuapp.com",
    "appspot.com",
    "myshopify.com",
    "github.io",
    "netlify.app",
    "aivencloud.com",
    "pstmn.io",
    "googleapis.com",
    "amazon.com.be",
    "vercel.app",
    "webhosting.be",
    "firebase.app",
    "run.app",
    "adobeaemcloud.com",
    "firebaseapp.com",
    "web.app",
    "azurefd.net",
    "windows.net",
    "strapiapp.com",
    "forgeblocks.com",
];

/// Unified categories that never describe domains.
pub const NON_DOMAIN_CATEGORIES: &[&str] = &["android", "ios", "binary", "code", "ai", "hardware", "blockchain"];

#[derive(Debug, Clone, Copy, Default)]
pub struct WildcardOptions {
    /// Also extract root domains from plain domain / URL targets, unless the
    /// program is marked strict.
    pub aggressive: bool,
}

/// A domain and the programs it came from (both sorted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardResult {
    pub domain: String,
    pub program_urls: Vec<String>,
}

/// In-scope root domains, minus ones a program explicitly marks out of scope.
pub fn collect_wildcards(entries: &[Entry], opts: WildcardOptions) -> Vec<WildcardResult> {
    let mut oos_by_program: HashMap<&str, HashSet<String>> = HashMap::new();
    for e in entries.iter().filter(|e| !e.in_scope) {
        if let Some(d) = oos_wildcard(&e.target_normalized) {
            oos_by_program.entry(&e.program_url).or_default().insert(d);
        }
    }

    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.in_scope) {
        let target = &e.target_normalized;
        if target.contains(' ') {
            tracing::debug!("[skip-space] {target}");
            continue;
        }
        let clean = normalize_for_subdomain_tools(target);
        if clean.is_empty() || is_blacklisted_suffix(&clean) {
            continue;
        }

        let domain = if e.category == "wildcard" || target.contains('*') {
            let d = extract_root_domain(&clean);
            if d.is_none() {
                tracing::debug!("[skip] {target}");
            }
            d
        } else if opts.aggressive && !e.strict && looks_like_domain_target(e) {
            extract_root_domain(&normalize_for_subdomain_tools(&target.to_lowercase()))
        } else {
            None
        };
        let Some(domain) = domain else { continue };

        if oos_by_program.get(e.program_url.as_str()).is_some_and(|oos| oos.contains(&domain)) {
            continue;
        }
        found.entry(domain).or_default().insert(e.program_url.clone());
    }
    into_results(found)
}

/// Out-of-scope wildcard patterns. Partial wildcards are kept as written:
/// `*.sub.example.com` -> `sub.example.com`, not `example.com`.
pub fn collect_oos_wildcards(entries: &[Entry]) -> Vec<WildcardResult> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in entries.iter().filter(|e| !e.in_scope) {
        if let Some(d) = oos_wildcard(&e.target_normalized) {
            found.entry(d).or_default().insert(e.program_url.clone());
        }
    }
    into_results(found)
}

fn into_results(found: BTreeMap<String, BTreeSet<String>>) -> Vec<WildcardResult> {
    found
        .into_iter()
        .map(|(domain, programs)| WildcardResult { domain, program_urls: programs.into_iter().collect() })
        .collect()
}

fn oos_wildcard(target: &str) -> Option<String> {
    if !target.contains('*') || wildcard_has_path(target) {
        return None;
    }
    Some(normalize_for_subdomain_tools(target)).filter(|d| !d.is_empty())
}

/// Aggressive mode: skip mobile apps, binaries, IPs and the like.
fn looks_like_domain_target(e: &Entry) -> bool {
    let category = e.category.to_lowercase();
    if NON_DOMAIN_CATEGORIES.contains(&category.as_str()) {
        return false;
    }
    let t = e.target_normalized.to_lowercase();
    let app_like = t.starts_with("com.")
        || t.contains("apps.apple.com")
        || [".apk", ".ipa", ".ios", ".exe"].iter().any(|s| t.ends_with(s));
    !app_like && !is_cidr(&t) && !is_ip(&t) && !is_ip_range(&t)
}

/// True if there is a path after the host.
pub fn wildcard_has_path(target: &str) -> bool {
    let stripped = target.split_once("://").map(|(_, r)| r).unwrap_or(target);
    stripped.contains('/')
}

pub fn is_blacklisted_suffix(host: &str) -> bool {
    BLACKLISTED_SUFFIXES.iter().any(|s| host == *s || host.ends_with(&format!(".{s}")))
}

/// Cleans a scope string into a bare host for subdomain tools:
/// `https://*.example.com:443/x` -> `example.com`, `*.example.*` -> `example.com`.
pub fn normalize_for_subdomain_tools(scope: &str) -> String {
    static BRACKETS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[.*?\]").unwrap());

    let s = UrlParts::parse(scope).map(|u| u.authority).unwrap_or(scope);
    let s = s.split('/').next().unwrap_or("");
    let s = s.split(':').next().unwrap_or("");
    let s = match s.strip_suffix(".*").or_else(|| s.strip_suffix(".<tld>")) {
        Some(before) => format!("{before}.com"),
        None => s.to_string(),
    };
    let s = s.replace('*', "").replace(',', ".");
    let s = s.strip_prefix('.').unwrap_or(&s).replace(['(', ')'], "");
    BRACKETS.replace_all(&s, "").trim_matches(['.', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(program: &str, target: &str, category: &str, in_scope: bool) -> Entry {
        Entry {
            program_url: program.into(),
            target_normalized: target.into(),
            category: category.into(),
            in_scope,
            ..Default::default()
        }
    }

    #[test]
    fn subdomain_tool_normalization() {
        assert_eq!(normalize_for_subdomain_tools("https://*.example.com:443/x"), "example.com");
        assert_eq!(normalize_for_subdomain_tools("*.example.*"), "example.com");
        assert_eq!(normalize_for_subdomain_tools("*.example.<tld>"), "example.com");
        assert_eq!(normalize_for_subdomain_tools("*.(dev|prod).example.com"), "dev|prod.example.com");
        assert_eq!(normalize_for_subdomain_tools("*.[a].example.com"), "example.com");
    }

    #[test]
    fn oos_wildcards_keep_subdomain() {
        let es = vec![e("p", "*.something.test.com", "wildcard", false), e("p", "*.test.com", "wildcard", true)];
        let oos = collect_oos_wildcards(&es);
        assert_eq!(oos.len(), 1);
        assert_eq!(oos[0].domain, "something.test.com");
        assert!(collect_oos_wildcards(&[e("p", "*.example.com/api", "wildcard", false)]).is_empty());
        assert!(collect_oos_wildcards(&[e("p", "example.com", "url", false)]).is_empty());
    }

    #[test]
    fn wildcards_merge_programs_and_respect_oos() {
        let es = vec![
            e("p1", "*.internal.example.com", "wildcard", true),
            e("p2", "*.internal.example.com", "wildcard", true),
            e("p3", "*.example.org", "wildcard", true),
            e("p3", "*.example.org", "wildcard", false),
            e("p4", "*.foo.amazonaws.com", "wildcard", true),
        ];
        let got = collect_wildcards(&es, WildcardOptions::default());
        assert_eq!(got, vec![WildcardResult { domain: "example.com".into(), program_urls: vec!["p1".into(), "p2".into()] }]);
    }

    #[test]
    fn aggressive_and_strict() {
        let mut strict = e("s", "https://api.example.net", "url", true);
        strict.strict = true;
        let es = vec![
            strict,
            e("n", "app.example.org", "url", true),
            e("n", "com.example.app", "android", true),
            e("n", "10.0.0.1", "url", true),
        ];
        let normal = collect_wildcards(&es, WildcardOptions::default());
        assert!(normal.is_empty());
        let aggressive = collect_wildcards(&es, WildcardOptions { aggressive: true });
        assert_eq!(aggressive.iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(), vec!["example.org"]);
    }
}
