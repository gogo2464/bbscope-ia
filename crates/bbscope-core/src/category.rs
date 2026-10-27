//! Mapping raw, platform-specific categories to a small set of unified ones.

use std::collections::BTreeSet;

/// Source of truth: unified category -> raw platform strings that map to it.
pub const UNIFICATION: &[(&str, &[&str])] = &[
    ("ai", &["ai_model"]),
    ("android", &["android", "google_play_app_id", "other_apk", "mobile-application-android", "mobile-application"]),
    ("binary", &["windows_app_store_app_id", "downloadable_executables"]),
    ("blockchain", &["smart_contract"]),
    ("cidr", &["cidr", "iprange"]),
    ("code", &["source_code"]),
    ("hardware", &["hardware", "device", "iot"]),
    (
        "ios",
        &["ios", "apple", "apple_store_app_id", "other_ipa", "testflight", "mobile-application-ios", "apple-store"],
    ),
    ("other", &["other", "aws_cloud_config", "application", "network"]),
    ("url", &["url", "website", "web", "web-application", "api", "ip_address", "ip-address"]),
    ("wildcard", &["wildcard"]),
];

/// Alternate `--category` spellings, mapped to unified names.
const INPUT_ALIASES: &[(&str, &[&str])] = &[("apple", &["ios"]), ("device", &["hardware"]), ("mobile", &["android", "ios"])];

/// Maps a raw category to its unified name. Unknown categories are lowercased
/// with `_` replaced by spaces.
pub fn normalize_category(raw: &str) -> String {
    let lower = raw.to_lowercase();
    UNIFICATION
        .iter()
        .find(|(_, raws)| raws.contains(&lower.as_str()))
        .map(|(unified, _)| (*unified).to_string())
        .unwrap_or_else(|| lower.replace('_', " "))
}

/// Sorted list of unified category names.
pub fn unified_categories() -> Vec<&'static str> {
    UNIFICATION.iter().map(|(u, _)| *u).collect()
}

pub fn is_unified_category(category: &str) -> bool {
    let c = category.trim().to_lowercase();
    UNIFICATION.iter().any(|(u, _)| *u == c)
}

/// Expands a comma-separated `--category` value into the raw platform strings
/// it covers. `None` means "don't filter" (input was empty, `all`, or invalid).
pub fn raw_strings_for(input: &str) -> Option<BTreeSet<&'static str>> {
    let input = input.trim().to_lowercase();
    if input.is_empty() || input == "all" {
        return None;
    }

    let mut out = BTreeSet::new();
    for key in input.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        let unified: Vec<&str> = INPUT_ALIASES
            .iter()
            .find(|(alias, _)| *alias == key)
            .map(|(_, targets)| targets.to_vec())
            .unwrap_or_else(|| vec![key]);

        let mut matched = false;
        for u in unified {
            if let Some((_, raws)) = UNIFICATION.iter().find(|(name, _)| *name == u) {
                matched = true;
                out.extend(raws.iter().copied());
            }
        }
        if !matched {
            tracing::warn!("Invalid category '{key}' selected, it will be ignored.");
        }
    }

    if out.is_empty() {
        tracing::warn!(
            "No valid categories provided, defaulting to all. Available categories: {}",
            unified_categories().join(", ")
        );
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize_category("WEBSITE"), "url");
        assert_eq!(normalize_category("google_play_app_id"), "android");
        assert_eq!(normalize_category("some_new_thing"), "some new thing");
    }

    #[test]
    fn filter() {
        assert!(raw_strings_for("all").is_none());
        assert!(raw_strings_for("").is_none());
        assert!(raw_strings_for("bogus").is_none());
        let f = raw_strings_for("mobile, wildcard").unwrap();
        assert!(f.contains("other_apk") && f.contains("testflight") && f.contains("wildcard"));
        assert!(!f.contains("url"));
    }
}
