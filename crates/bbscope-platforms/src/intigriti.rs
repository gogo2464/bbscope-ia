//! Intigriti, through the external researcher API (personal access token).

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bbscope_core::category::normalize_category;
use bbscope_core::json::JsonExt;
use bbscope_core::{Error, HttpClient, Platform, PollOptions, ProgramData, Request, Result, ScopeElement};

use crate::util::one_line;

const API: &str = "https://api.intigriti.com/external/researcher/v1/programs";
const STATUS_OPEN: i64 = 3;
const STATUS_SUSPENDED: i64 = 4;
const CONFIDENTIALITY_PUBLIC: i64 = 4;
const TIER_OUT_OF_SCOPE: i64 = 5;

#[derive(Clone)]
struct ProgramRef {
    id: String,
    url: String,
}

pub struct Intigriti {
    http: HttpClient,
    token: String,
    programs: Mutex<HashMap<String, ProgramRef>>,
}

impl Intigriti {
    pub fn new(http: HttpClient, token: impl Into<String>) -> Self {
        Self { http, token: token.into(), programs: Mutex::new(HashMap::new()) }
    }

    fn lookup(&self, handle: &str) -> Option<ProgramRef> {
        self.programs.lock().unwrap().get(handle).cloned()
    }
}

/// Unified category -> Intigriti `type.id`.
fn type_ids_for(unified: &str) -> &'static [i64] {
    match unified {
        "url" => &[1],
        "android" => &[2],
        "ios" => &[3],
        "cidr" => &[4],
        "hardware" => &[5],
        "other" => &[6],
        "wildcard" => &[7],
        _ => &[],
    }
}

/// `None` = no filtering.
fn allowed_type_ids(opts: &PollOptions) -> Option<BTreeSet<i64>> {
    let raws = opts.category_filter()?;
    Some(raws.iter().flat_map(|r| type_ids_for(&normalize_category(r)).iter().copied()).collect())
}

/// `.../researcher/programs/<company>/<program>/detail` -> `<company>/<program>`.
fn handle_from_url(url: &str) -> String {
    let parts: Vec<&str> = url.trim_end_matches("/detail").split('/').collect();
    match parts.as_slice() {
        [.., a, b] => format!("{a}/{b}"),
        _ => url.to_string(),
    }
}

#[async_trait]
impl Platform for Intigriti {
    fn name(&self) -> &'static str {
        "it"
    }

    async fn list_program_handles(&self, opts: &PollOptions) -> Result<Vec<String>> {
        let limit = 500;
        let (mut offset, mut total) = (0usize, 0usize);
        let mut handles = Vec::new();
        let mut programs = HashMap::new();

        loop {
            let url = format!("{API}?limit={limit}&offset={offset}");
            let res = self.http.send(Request::get(&url).bearer(&self.token)).await?;
            if res.status == 401 {
                return Err(Error::Auth("invalid Intigriti token".into()));
            }
            let v = res.json();
            if offset == 0 {
                total = v.i64_at("maxCount").max(0) as usize;
            }
            let records = v.arr_at("records");
            for r in records {
                let status = r.i64_at("status.id");
                if status != STATUS_OPEN && status != STATUS_SUSPENDED {
                    continue;
                }
                let detail = r.str_at("webLinks.detail");
                let Some(path) = detail.split('=').nth(1) else { continue };
                let url = format!("https://app.intigriti.com/researcher{path}");
                let handle = handle_from_url(&url);

                if opts.private_only && r.i64_at("confidentialityLevel.id") == CONFIDENTIALITY_PUBLIC {
                    continue;
                }
                if opts.bounty_only && r.i64_at("maxBounty.value") == 0 {
                    continue;
                }
                programs.insert(handle.clone(), ProgramRef { id: r.str_at("id"), url });
                handles.push(handle);
            }
            offset += records.len();
            if records.is_empty() || offset >= total {
                break;
            }
        }
        *self.programs.lock().unwrap() = programs;
        Ok(handles)
    }

    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData> {
        if self.lookup(handle).is_none() {
            self.list_program_handles(opts).await?;
        }
        let Some(program) = self.lookup(handle) else {
            return Ok(ProgramData::default());
        };
        let mut pd = ProgramData::new(program.url.clone());

        let res = loop {
            let res = self.http.send(Request::get(format!("{API}/{}", program.id)).bearer(&self.token)).await?;
            if res.status == 401 {
                return Err(Error::Auth("invalid Intigriti token".into()));
            }
            if !res.body.contains("Request blocked") {
                break res;
            }
            tracing::info!("Intigriti rate limited, retrying...");
            tokio::time::sleep(Duration::from_secs(2)).await;
        };

        // A program is BBP if any in-scope target has a tier other than "No Bounty".
        let allowed = allowed_type_ids(opts);
        let mut is_bbp = false;
        let v = res.json();
        for d in v.arr_at("domains.content") {
            let elem = ScopeElement::new(d.str_at("endpoint"), one_line(&d.str_at("description")), d.str_at("type.value"));
            if d.i64_at("tier.id") == TIER_OUT_OF_SCOPE {
                pd.out_of_scope.push(elem);
            } else if allowed.as_ref().is_none_or(|ids| ids.contains(&d.i64_at("type.id"))) {
                if d.str_at("tier.value") != "No Bounty" {
                    is_bbp = true;
                }
                pd.in_scope.push(elem);
            }
        }
        pd.set_bbp(is_bbp);
        Ok(pd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert_eq!(handle_from_url("https://app.intigriti.com/researcher/programs/acme/acmebb/detail"), "acme/acmebb");
    }

    #[test]
    fn category_ids() {
        let opts = PollOptions { categories: "wildcard,mobile".into(), ..Default::default() };
        assert_eq!(allowed_type_ids(&opts).unwrap().into_iter().collect::<Vec<_>>(), vec![2, 3, 7]);
        assert!(allowed_type_ids(&PollOptions::default()).is_none());
    }
}
