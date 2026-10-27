//! HackerOne, through the official hacker API (username + API token).

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use bbscope_core::json::JsonExt;
use bbscope_core::{Error, HttpClient, Platform, PollOptions, ProgramData, Request, Result, ScopeElement};

use crate::util::one_line;

const API: &str = "https://api.hackerone.com/v1/hackers/programs";

pub struct HackerOne {
    http: HttpClient,
    auth: String,
}

impl HackerOne {
    pub fn new(http: HttpClient, username: &str, token: &str) -> Self {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
        Self { http, auth: format!("Basic {auth}") }
    }

    fn get(&self, url: &str) -> Request {
        Request::get(url).header("Authorization", self.auth.clone())
    }
}

#[async_trait]
impl Platform for HackerOne {
    fn name(&self) -> &'static str {
        "h1"
    }

    async fn list_program_handles(&self, opts: &PollOptions) -> Result<Vec<String>> {
        let mut handles = Vec::new();
        let mut url = format!("{API}?page%5Bsize%5D=100");
        loop {
            let res = self.http.send(self.get(&url)).await?;
            // The API refuses pages past its pagination limit; keep what we have.
            if res.status == 400 && res.body.contains("\"Invalid Parameter\"") {
                break;
            }
            if res.status == 401 {
                return Err(Error::Auth("invalid HackerOne username or token".into()));
            }
            if res.status != 200 {
                return Err(Error::Status { status: res.status, url });
            }
            let v = res.json();
            for p in v.arr_at("data") {
                if p.str_at("attributes.submission_state") != "open" {
                    continue;
                }
                let is_private = p.str_at("attributes.state") == "soft_launched";
                if opts.private_only && !is_private {
                    continue;
                }
                if opts.bounty_only && !p.bool_at("attributes.offers_bounties") {
                    continue;
                }
                handles.push(p.str_at("attributes.handle"));
            }
            url = v.str_at("links.next");
            if url.is_empty() {
                break;
            }
        }
        Ok(handles)
    }

    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData> {
        let mut pd = ProgramData::new(format!("https://hackerone.com/{handle}"));
        let filter = opts.category_filter();
        let mut url = format!("{API}/{handle}/structured_scopes?page%5Bnumber%5D=1&page%5Bsize%5D=100");

        loop {
            let mut page = None;
            let mut last_status = 0;
            for _ in 0..3 {
                match self.http.send(self.get(&url)).await {
                    Ok(res) if res.body.contains("\"data\":") => {
                        page = Some(res.json());
                        break;
                    }
                    Ok(res) => {
                        last_status = res.status;
                        if matches!(res.status, 400 | 403 | 404) {
                            break;
                        }
                    }
                    Err(e) => tracing::debug!("h1 {handle}: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            let Some(v) = page else {
                if !pd.is_empty() {
                    tracing::warn!("Partial data for {handle}: stopped at status {last_status}");
                    return Ok(pd);
                }
                return Err(Error::other(format!(
                    "failed to retrieve data for {handle} after 3 attempts (status {last_status})"
                )));
            };

            for asset in v.arr_at("data") {
                let category = asset.str_at("attributes.asset_type").to_lowercase();
                if filter.as_ref().is_some_and(|f| !f.contains(category.as_str())) {
                    continue;
                }
                let bounty = asset.bool_at("attributes.eligible_for_bounty");
                let elem = ScopeElement {
                    target: asset.str_at("attributes.asset_identifier"),
                    description: one_line(&asset.str_at("attributes.instruction")),
                    category,
                    is_bbp: bounty,
                };
                if asset.bool_at("attributes.eligible_for_submission") {
                    if !opts.bounty_only || bounty {
                        pd.in_scope.push(elem);
                    }
                } else {
                    pd.out_of_scope.push(elem);
                }
            }
            if opts.bounty_only && pd.in_scope.is_empty() {
                pd.out_of_scope.clear();
            }

            url = v.str_at("links.next");
            if url.is_empty() {
                break;
            }
        }
        Ok(pd)
    }
}
