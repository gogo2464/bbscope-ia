//! Target / URL / domain normalization helpers.
//!
//! URLs are split by hand rather than with the `url` crate, because scope
//! targets are frequently not valid URLs (`https://*.example.com/*`) and we
//! want to keep them as written apart from simple canonicalization.

use std::net::IpAddr;

/// A loosely parsed `scheme://authority/rest` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts<'a> {
    pub scheme: &'a str,
    /// `host[:port]`, userinfo stripped.
    pub authority: &'a str,
    /// Path (may be empty).
    pub path: &'a str,
    /// Everything from the first `?` or `#` (may be empty).
    pub suffix: &'a str,
}

impl<'a> UrlParts<'a> {
    /// Splits `s` if it looks like `scheme://host...` with a non-empty host.
    pub fn parse(s: &'a str) -> Option<Self> {
        let (scheme, rest) = s.split_once("://")?;
        let mut chars = scheme.chars();
        if !chars.next()?.is_ascii_alphabetic() || !chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
            return None;
        }
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let mut authority = &rest[..auth_end];
        if let Some((_, after)) = authority.rsplit_once('@') {
            authority = after;
        }
        if authority.is_empty() || authority.contains(char::is_whitespace) {
            return None;
        }
        let tail = &rest[auth_end..];
        let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
        Some(UrlParts { scheme, authority, path: &tail[..path_end], suffix: &tail[path_end..] })
    }

    /// Host without port or IPv6 brackets.
    pub fn hostname(&self) -> &'a str {
        let a = self.authority;
        if let Some(stripped) = a.strip_prefix('[') {
            return stripped.split(']').next().unwrap_or(stripped);
        }
        match a.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => a,
        }
    }

    pub fn port(&self) -> Option<&'a str> {
        let a = self.authority;
        let after_host = if a.starts_with('[') { a.split_once(']').map(|(_, r)| r)? } else { a };
        after_host.rsplit_once(':').map(|(_, p)| p).filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    }
}

/// Canonicalizes a target for identity: lowercases hosts, drops default
/// ports and trailing slashes, lowercases bare domains.
pub fn normalize_target(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    if let Some(u) = UrlParts::parse(s) {
        let hostname = u.hostname().to_lowercase();
        if hostname.contains('*') {
            return hostname.trim_end_matches('.').to_string();
        }
        let mut authority = u.authority.to_lowercase();
        let scheme = u.scheme.to_lowercase();
        match (scheme.as_str(), u.port()) {
            ("http", Some("80")) => authority.truncate(authority.len() - 3),
            ("https", Some("443")) => authority.truncate(authority.len() - 4),
            _ => {}
        }
        let path = if u.path.len() > 1 && u.path.ends_with('/') { u.path.trim_end_matches('/') } else { u.path };
        return format!("{scheme}://{authority}{path}{}", u.suffix);
    }
    s.to_lowercase().trim_end_matches('.').trim_end_matches('/').to_string()
}

/// Canonicalizes a program URL (lowercase host, no trailing slash).
pub fn normalize_program_url(s: &str) -> String {
    let s = s.trim();
    match UrlParts::parse(s) {
        Some(u) => {
            let path = if u.path.len() > 1 && u.path.ends_with('/') { u.path.trim_end_matches('/') } else { u.path };
            format!("{}://{}{}{}", u.scheme, u.authority.to_lowercase(), path, u.suffix)
        }
        None => s.to_string(),
    }
}

/// Registrable domain (eTLD+1) of `host`, using the public suffix list.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    psl::domain_str(&host).map(str::to_string)
}

/// Turns a target into a root-domain wildcard: `sub.domain.com` -> `*.domain.com`.
/// IPs, wildcards and things that aren't domains are returned unchanged.
pub fn aggressive_transform(scope: &str) -> String {
    let scope = scope.trim();
    if scope.is_empty() {
        return String::new();
    }
    let host = UrlParts::parse(scope).map(|u| u.hostname()).unwrap_or(scope);
    if is_ip(host) || !host.contains('.') || host.contains('*') {
        return scope.to_string();
    }
    match registrable_domain(host) {
        Some(d) => format!("*.{d}"),
        None => scope.to_string(),
    }
}

/// Root domain of a scope string: `http://sub.foo.example.co.uk/x` -> `example.co.uk`.
pub fn extract_root_domain(scope: &str) -> Option<String> {
    let with_scheme;
    let scope = if !scope.contains("://") && scope.contains('.') {
        with_scheme = format!("http://{scope}");
        with_scheme.as_str()
    } else {
        scope
    };
    let host = match UrlParts::parse(scope) {
        Some(u) => u.hostname(),
        None => {
            let h = scope.split('/').next().unwrap_or("").split(':').next().unwrap_or("");
            if !h.contains('.') {
                return None;
            }
            h
        }
    };
    if host.contains('*') || is_ip(host) {
        return None;
    }
    registrable_domain(host)
}

/// IPv4 / IPv6 address, optionally in `[...]`.
pub fn is_ip(s: &str) -> bool {
    s.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok()
}

/// `addr/prefix` CIDR notation.
pub fn is_cidr(s: &str) -> bool {
    let Some((ip, prefix)) = s.split_once('/') else { return false };
    let Ok(ip) = ip.parse::<IpAddr>() else { return false };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) && prefix.parse::<u32>().is_ok_and(|p| p <= max)
}

/// `a.b.c.d-e.f.g.h` IP range.
pub fn is_ip_range(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 2 && parts.iter().all(|p| p.trim().parse::<IpAddr>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parts() {
        let u = UrlParts::parse("https://user@Example.com:8443/a/b?q=1#f").unwrap();
        assert_eq!(u.authority, "Example.com:8443");
        assert_eq!(u.hostname(), "Example.com");
        assert_eq!(u.port(), Some("8443"));
        assert_eq!(u.path, "/a/b");
        assert_eq!(u.suffix, "?q=1#f");
        assert_eq!(UrlParts::parse("http://[::1]:80/").unwrap().hostname(), "::1");
        assert!(UrlParts::parse("example.com/path").is_none());
        assert!(UrlParts::parse("example.com:443").is_none());
    }

    #[test]
    fn targets() {
        assert_eq!(normalize_target(" HTTPS://Example.COM:443/Path/ "), "https://example.com/Path");
        assert_eq!(normalize_target("http://a.com:80"), "http://a.com");
        assert_eq!(normalize_target("https://a.com/"), "https://a.com/");
        assert_eq!(normalize_target("https://*.Example.com./foo"), "*.example.com");
        assert_eq!(normalize_target("*.Example.COM."), "*.example.com");
        assert_eq!(normalize_target("example.com/"), "example.com");
        assert_eq!(normalize_program_url("https://HackerOne.com/foo/"), "https://hackerone.com/foo");
    }

    #[test]
    fn domains() {
        assert_eq!(aggressive_transform("sub.domain.com"), "*.domain.com");
        assert_eq!(aggressive_transform("https://a.b.example.co.uk/x"), "*.example.co.uk");
        assert_eq!(aggressive_transform("10.0.0.1"), "10.0.0.1");
        assert_eq!(aggressive_transform("*.foo.com"), "*.foo.com");
        assert_eq!(extract_root_domain("http://sub.foo.example.co.uk/path").as_deref(), Some("example.co.uk"));
        assert_eq!(extract_root_domain("api.example.com:8080/x").as_deref(), Some("example.com"));
        assert_eq!(extract_root_domain("*.example.com"), None);
        assert_eq!(extract_root_domain("1.2.3.4"), None);
        assert_eq!(extract_root_domain("localhost"), None);
    }

    #[test]
    fn ips() {
        assert!(is_ip("1.2.3.4") && is_ip("[::1]") && !is_ip("1.2.3"));
        assert!(is_cidr("10.0.0.0/8") && is_cidr("2001:db8::/32") && !is_cidr("10.0.0.0/33") && !is_cidr("10.0.0.0"));
        assert!(is_ip_range("1.1.1.1-1.1.1.9") && !is_ip_range("1.1.1.1-x"));
    }
}
