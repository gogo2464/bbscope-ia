//! Immunefi. No authentication; scope is scraped from the site's React
//! Server Components payloads.

use std::time::Duration;

use async_trait::async_trait;
use bbscope_core::json::{self, JsonExt};
use bbscope_core::{Error, HttpClient, Platform, PollOptions, ProgramData, Request, Response, Result, ScopeElement};

use crate::util::extract_json_array;

const BASE: &str = "https://immunefi.com";
const MAX_RETRIES: u32 = 20;
const WEB: &str = "websites_and_applications";
const CONTRACT: &str = "smart_contract";

pub struct Immunefi {
    http: HttpClient,
}

impl Immunefi {
    pub fn new(http: HttpClient) -> Self {
        Self { http }
    }

    /// GET with its own patient retry loop for Immunefi's aggressive 429s.
    async fn fetch(&self, url: &str) -> Result<Response> {
        let mut last_err = None;
        for attempt in 1..=MAX_RETRIES {
            let req = Request::get(url).header("Accept", "*/*").header("Rsc", "1");
            match self.http.send(req).await {
                Ok(res) if res.is_success() => return Ok(res),
                Ok(res) if res.status == 429 => {
                    tokio::time::sleep(Duration::from_secs((2 * attempt as u64).min(30))).await;
                }
                Ok(res) => last_err = Some(Error::Status { status: res.status, url: url.to_string() }),
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::other(format!("failed after {MAX_RETRIES} retries: {url}"))))
    }
}

/// Finds `"<key>":[...]` in an RSC payload and parses the array.
fn embedded_array(body: &str, key: &str) -> serde_json::Value {
    let needle = format!("\"{key}\":[");
    body.find(&needle)
        .and_then(|i| extract_json_array(&body[i + needle.len() - 1..]))
        .map(json::parse)
        .unwrap_or(serde_json::Value::Null)
}

/// Immunefi only distinguishes web assets and smart contracts.
fn selected_categories(input: &str) -> &'static [&'static str] {
    match input.to_lowercase().as_str() {
        "web" | "url" => &[WEB],
        "contracts" | "blockchain" => &[CONTRACT],
        _ => &[WEB, CONTRACT],
    }
}

#[async_trait]
impl Platform for Immunefi {
    fn name(&self) -> &'static str {
        "immunefi"
    }

    async fn list_program_handles(&self, _opts: &PollOptions) -> Result<Vec<String>> {
        let res = self.fetch(&format!("{BASE}/bug-bounty/")).await?;
        Ok(embedded_array(&res.body, "bounties")
            .arr_at("")
            .iter()
            .filter(|p| !p.bool_at("inviteOnly"))
            .map(|p| p.str_at("slug"))
            .filter(|slug| !slug.is_empty())
            .map(|slug| format!("{BASE}/bug-bounty/{slug}/information/"))
            .collect())
    }

    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData> {
        let mut pd = ProgramData::new(handle);
        let res = self.fetch(handle).await?;
        let cats = selected_categories(&opts.categories);
        for asset in embedded_array(&res.body, "assets").arr_at("") {
            let kind = asset.str_at("type");
            for cat in cats.iter().filter(|c| kind.contains(**c)) {
                pd.in_scope.push(ScopeElement::new(asset.str_at("url"), asset.str_at("description"), *cat));
            }
        }
        Ok(pd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsc_extraction() {
        let body = r#"1:["$","div",{"bounties":[{"slug":"a","inviteOnly":false},{"slug":"b","inviteOnly":true}]}]"#;
        let v = embedded_array(body, "bounties");
        assert_eq!(v.arr_at("").len(), 2);
        assert_eq!(v.str_at("0.slug"), "a");
        assert!(embedded_array(body, "assets").is_null());
    }
}
