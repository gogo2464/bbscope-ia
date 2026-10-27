//! YesWeHack. Public programs work unauthenticated; private ones need a
//! bearer token or email + password + TOTP secret.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bbscope_core::json::JsonExt;
use bbscope_core::{otp, Error, HttpClient, Platform, PollOptions, ProgramData, Request, Result, ScopeElement};
use serde_json::json;

use crate::Credentials;

const API: &str = "https://api.yeswehack.com";
const OTP_ATTEMPTS: u32 = 5;

pub struct YesWeHack {
    http: HttpClient,
    token: String,
    bbp: Mutex<HashSet<String>>,
}

impl YesWeHack {
    /// Unauthenticated (public programs only) when `token` is empty.
    pub fn with_token(http: HttpClient, token: impl Into<String>) -> Self {
        Self { http, token: token.into(), bbp: Mutex::new(HashSet::new()) }
    }

    /// Logs in with email/password, completing the TOTP step if 2FA is on.
    pub async fn login(http: HttpClient, creds: &Credentials) -> Result<Self> {
        let res = http
            .send(Request::post(format!("{API}/login")).json(&json!({"email": creds.email, "password": creds.password})))
            .await?;
        if res.status != 200 {
            return Err(Error::Auth(format!("YesWeHack login failed with status {}", res.status)));
        }
        let v = res.json();
        let direct = v.str_at("token");
        if !direct.is_empty() {
            return Ok(Self::with_token(http, direct));
        }
        let totp_token = v.str_at("totp_token");
        if totp_token.is_empty() {
            return Err(Error::Auth("invalid login response: neither token nor totp_token found".into()));
        }
        if creds.otp_secret.is_empty() {
            return Err(Error::Auth("2FA is enabled but no OTP secret was provided".into()));
        }

        for attempt in 1..=OTP_ATTEMPTS {
            let code = otp::generate_totp_now(&creds.otp_secret)?;
            let res = http
                .send(Request::post(format!("{API}/account/totp")).json(&json!({"token": totp_token, "code": code})))
                .await?;
            match res.status {
                200 => {
                    let token = res.json().str_at("token");
                    if token.is_empty() {
                        return Err(Error::Auth("final token not found in TOTP response".into()));
                    }
                    return Ok(Self::with_token(http, token));
                }
                // 400 = code rejected (usually clock skew at a step boundary): wait and retry.
                400 if attempt < OTP_ATTEMPTS => tokio::time::sleep(Duration::from_secs(2)).await,
                400 => break,
                s => return Err(Error::Auth(format!("TOTP verification failed with status {s}"))),
            }
        }
        Err(Error::Auth(format!("TOTP verification failed after {OTP_ATTEMPTS} attempts")))
    }
}

#[async_trait]
impl Platform for YesWeHack {
    fn name(&self) -> &'static str {
        "ywh"
    }

    async fn list_program_handles(&self, opts: &PollOptions) -> Result<Vec<String>> {
        let mut handles = Vec::new();
        let mut bbp = HashSet::new();
        let (mut page, mut pages) = (1, 1);
        while page <= pages {
            let res = self.http.send(Request::get(format!("{API}/programs?page={page}")).bearer(&self.token)).await?;
            if res.status == 401 {
                return Err(Error::Auth("invalid YesWeHack token".into()));
            }
            let v = res.json();
            for p in v.arr_at("items") {
                if p.bool_at("disabled") {
                    continue;
                }
                let bounty = p.bool_at("bounty");
                if (opts.private_only && p.bool_at("public")) || (opts.bounty_only && !bounty) {
                    continue;
                }
                let slug = p.str_at("slug");
                if bounty {
                    bbp.insert(slug.clone());
                }
                handles.push(slug);
            }
            pages = v.i64_at("pagination.nb_pages");
            page += 1;
        }
        *self.bbp.lock().unwrap() = bbp;
        Ok(handles)
    }

    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData> {
        let mut pd = ProgramData::new(format!("https://yeswehack.com/programs/{handle}"));
        let res = self.http.send(Request::get(format!("{API}/programs/{handle}")).bearer(&self.token)).await?;
        let v = res.json();
        let filter = opts.category_filter();

        for s in v.arr_at("scopes") {
            let kind = s.str_at("scope_type");
            if filter.as_ref().is_none_or(|f| f.contains(kind.as_str())) {
                pd.in_scope.push(ScopeElement::new(s.str_at("scope"), "", kind));
            }
        }
        for item in v.arr_at("out_of_scope") {
            let target = item.as_str().map(str::to_string).unwrap_or_else(|| item.to_string());
            pd.out_of_scope.push(ScopeElement::new(target, "", "other"));
        }
        pd.set_bbp(self.bbp.lock().unwrap().contains(handle));
        Ok(pd)
    }
}
