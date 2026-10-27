//! Bugcrowd. Works unauthenticated (public programs), with a session cookie,
//! or with email + password + TOTP through the Okta IDX login flow.
//!
//! Bugcrowd's WAF bans clients that go faster than about one request per
//! second, so every request goes through a process-wide rate limiter.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bbscope_core::http::RateLimiter;
use bbscope_core::json::{self, JsonExt};
use bbscope_core::{otp, Error, HttpClient, Platform, PollOptions, ProgramData, Request, Response, Result, ScopeElement};
use regex::Regex;
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;

use crate::Credentials;

const BASE: &str = "https://bugcrowd.com";
const OKTA: &str = "https://login.hackers.bugcrowd.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0";
const LOGIN_PAGE: &str =
    "https://identity.bugcrowd.com/login?user_hint=researcher&returnTo=https%3A%2F%2Fbugcrowd.com%2Fdashboard";
const SIGN_IN: &str =
    "https://identity.bugcrowd.com/login/hacker/oauth2/authorization/hacker?returnTo=https://bugcrowd.com/dashboard";
const KEEPALIVE_EVERY: Duration = Duration::from_secs(5 * 60);

static LIMITER: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(1)));

/// Rate-limited send that maps WAF blocks to [`Error::WafBanned`].
async fn send(http: &HttpClient, req: Request) -> Result<Response> {
    LIMITER.wait().await;
    let res = http.send(req.header("User-Agent", USER_AGENT)).await?;
    if res.status == 403 || res.status == 406 {
        return Err(Error::WafBanned);
    }
    Ok(res)
}

pub struct Bugcrowd {
    http: HttpClient,
    /// Full `Cookie` header value; empty when unauthenticated.
    cookie: String,
    bbp: Mutex<HashSet<String>>,
    keepalive: Option<JoinHandle<()>>,
}

impl Drop for Bugcrowd {
    fn drop(&mut self) {
        if let Some(h) = self.keepalive.take() {
            h.abort();
        }
    }
}

impl Bugcrowd {
    /// Public programs only, no authentication.
    pub fn public(http: HttpClient) -> Self {
        Self { http, cookie: String::new(), bbp: Mutex::new(HashSet::new()), keepalive: None }
    }

    /// Uses an existing session: either a full cookie string or the raw
    /// `_bugcrowd_session` value.
    pub fn with_token(http: HttpClient, token: &str) -> Self {
        let cookie = if token.contains('=') { token.to_string() } else { format!("_bugcrowd_session={token}") };
        let keepalive = Some(spawn_keepalive(http.clone(), cookie.clone()));
        Self { http, cookie, bbp: Mutex::new(HashSet::new()), keepalive }
    }

    /// Full login: email, password, then the TOTP challenge.
    pub async fn login(http: HttpClient, creds: &Credentials) -> Result<Self> {
        let cookie = login(&http, creds).await?;
        tracing::info!("Bugcrowd login OK. Fetching programs, please wait...");
        Ok(Self::with_token(http, &cookie))
    }

    fn get(&self, url: impl Into<String>) -> Request {
        let req = Request::get(url).header("Accept", "*/*");
        if self.cookie.is_empty() {
            req
        } else {
            req.header("Cookie", self.cookie.clone())
        }
    }

    async fn list_engagements(&self, category: &str, private_only: bool) -> Result<Vec<String>> {
        let mut seen = HashSet::new();
        let mut handles = Vec::new();
        let mut total = 0usize;
        for page in 1.. {
            let url = format!(
                "{BASE}/engagements.json?category={category}&sort_by=promoted&sort_direction=desc&page={page}"
            );
            let v = send(&self.http, self.get(url)).await?.json();
            if total == 0 {
                total = v.i64_at("paginationMeta.totalCount").max(0) as usize;
            }
            let engagements = v.arr_at("engagements");
            if engagements.is_empty() {
                break;
            }
            for e in engagements {
                let handle = normalize_handle(&e.str_at("briefUrl"));
                if handle.is_empty() || !seen.insert(handle.clone()) {
                    continue;
                }
                if !private_only || e.str_at("accessStatus") != "open" {
                    handles.push(handle);
                }
            }
            if seen.len() >= total {
                break;
            }
        }
        Ok(handles)
    }

    async fn scope_from_target_groups(&self, pd: &mut ProgramData, opts: &PollOptions) -> Result<()> {
        let res = send(&self.http, self.get(format!("{}/target_groups", pd.url))).await?;
        if res.status == 404 {
            return Ok(()); // program is gone
        }
        let filter = opts.category_filter();
        let groups = res.json();
        let groups = groups.arr_at("groups");
        if groups.is_empty() {
            pd.in_scope.push(ScopeElement::new("NO_IN_SCOPE_TABLE", "", ""));
        }
        for g in groups {
            let in_scope = g.bool_at("in_scope");
            let table = send(&self.http, self.get(format!("{BASE}{}", g.str_at("targets_url")))).await?.json();
            for t in table.arr_at("targets") {
                let category = t.str_at("category");
                if filter.as_ref().is_some_and(|f| !f.contains(category.as_str())) {
                    continue;
                }
                let elem = target_element(t, category);
                if in_scope { pd.in_scope.push(elem) } else { pd.out_of_scope.push(elem) }
            }
        }
        Ok(())
    }

    async fn scope_from_engagement(&self, pd: &mut ProgramData) -> Result<()> {
        let res = send(&self.http, self.get(pd.url.clone())).await?;
        if res.status == 404 {
            return Ok(());
        }
        let Some(doc_url) = brief_document_url(&res.body) else {
            if res.body.contains("ResearcherEngagementCompliance") {
                tracing::warn!("Compliance required! Skipping: {}", pd.url);
            } else {
                tracing::warn!("data-api-endpoints attribute not found at {} ({})", pd.url, res.status);
            }
            pd.in_scope.push(ScopeElement::new(
                "2FA_REQUIRED",
                "Two-Factor Authentication is required to access this program.",
                "",
            ));
            return Ok(());
        };
        let v = send(&self.http, self.get(format!("{BASE}{doc_url}"))).await?.json();
        for group in v.arr_at("data.scope") {
            let in_scope = group.bool_at("inScope");
            for t in group.arr_at("targets") {
                let elem = target_element(t, t.str_at("category"));
                if in_scope { pd.in_scope.push(elem) } else { pd.out_of_scope.push(elem) }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Platform for Bugcrowd {
    fn name(&self) -> &'static str {
        "bc"
    }

    async fn list_program_handles(&self, opts: &PollOptions) -> Result<Vec<String>> {
        let mut handles = self.list_engagements("bug_bounty", opts.private_only).await?;
        *self.bbp.lock().unwrap() = handles.iter().cloned().collect();
        if !opts.bounty_only {
            match self.list_engagements("vdp", opts.private_only).await {
                Ok(vdp) => handles.extend(vdp),
                Err(e) => tracing::warn!("Bugcrowd: could not list VDPs: {e}"),
            }
        }
        Ok(handles)
    }

    async fn fetch_program_scope(&self, handle: &str, opts: &PollOptions) -> Result<ProgramData> {
        let normalized = normalize_handle(handle);
        let mut pd = ProgramData::new(format!("{BASE}/{}", normalized.trim_start_matches('/')));
        if normalized.starts_with("/engagements/") {
            self.scope_from_engagement(&mut pd).await?;
        } else {
            self.scope_from_target_groups(&mut pd, opts).await?;
        }
        pd.set_bbp(self.bbp.lock().unwrap().contains(handle));
        Ok(pd)
    }
}

fn target_element(t: &Value, category: String) -> ScopeElement {
    let mut target = t.str_at("uri").trim().to_string();
    if target.is_empty() {
        target = t.str_at("name").trim().to_string();
    }
    ScopeElement::new(target, t.str_at("description"), category)
}

/// Absolute bugcrowd.com URLs and `bugcrowd.com/...` become `/path[?query]`.
pub fn normalize_handle(handle: &str) -> String {
    let handle = handle.trim();
    if let Ok(u) = url::Url::parse(handle) {
        if !u.host_str().is_some_and(|h| h.eq_ignore_ascii_case("bugcrowd.com")) {
            return handle.to_string();
        }
        return match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        };
    }
    match handle.strip_prefix("bugcrowd.com/") {
        Some(rest) => format!("/{rest}"),
        None => handle.to_string(),
    }
}

/// Finds the brief document API path in an engagement page.
fn brief_document_url(html: &str) -> Option<String> {
    let doc = scraper::Html::parse_document(html);
    let sel = scraper::Selector::parse("div[data-react-class='ResearcherEngagementBrief']").ok()?;
    let endpoints = doc.select(&sel).next()?.value().attr("data-api-endpoints")?;
    let path = json::parse(endpoints).str_at("engagementBriefApi.getBriefVersionDocument");
    (!path.is_empty()).then(|| format!("{path}.json"))
}

fn spawn_keepalive(http: HttpClient, cookie: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(KEEPALIVE_EVERY);
        tick.tick().await; // first tick is immediate
        loop {
            tick.tick().await;
            let req = Request::get(format!("{BASE}/auth/session?update_activity=false"))
                .header("Cookie", cookie.clone())
                .header("Accept", "*/*");
            match send(&http, req).await {
                Ok(res) => tracing::debug!(
                    "Bugcrowd session keepalive OK, {} seconds remaining",
                    res.json().i64_at("secondsRemaining")
                ),
                Err(e) => tracing::debug!("Bugcrowd session keepalive failed: {e}"),
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Okta IDX login
// ---------------------------------------------------------------------------

#[derive(Default)]
struct OktaState {
    token: String,
    handle: String,
}

impl OktaState {
    fn update(&mut self, body: &Value) {
        let h = body.str_at("stateHandle");
        if !h.is_empty() {
            self.handle = decode_okta_escapes(&h);
        }
        let t = body.str_at("stateToken");
        if !t.is_empty() {
            self.token = decode_okta_escapes(&t);
        }
        if self.token.is_empty() {
            let t = body.str_at("token");
            if !t.is_empty() {
                self.token = decode_okta_escapes(&t);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.token.is_empty() && self.handle.is_empty()
    }

    fn apply(&self, mut body: Value) -> Value {
        if let Some(m) = body.as_object_mut() {
            if !self.handle.is_empty() {
                m.insert("stateHandle".into(), self.handle.clone().into());
            }
            if !self.token.is_empty() {
                m.insert("stateToken".into(), self.token.clone().into());
            }
        }
        body
    }
}

fn okta_post(url: &str, referer: &str, body: &Value) -> Request {
    Request::post(url)
        .header("Accept", "application/json")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Origin", OKTA)
        .header("Referer", referer)
        .json(body)
}

async fn login(http: &HttpClient, creds: &Credentials) -> Result<String> {
    let session = http.session()?;

    send(&session, Request::get(LOGIN_PAGE)).await?;
    // Follows the OAuth2 redirect chain to the Okta sign-in widget page.
    let sign_in = send(&session, Request::get(SIGN_IN).header("Referer", LOGIN_PAGE)).await?;

    let authorize_url = Regex::new(r#"https://login\.hackers\.bugcrowd\.com/oauth2/[^"'\s]+"#)
        .unwrap()
        .find(&sign_in.body)
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| SIGN_IN.to_string());

    if sign_in.status >= 400 {
        let v = sign_in.json();
        let (err, desc) = (v.str_at("error"), v.str_at("error_description"));
        if !err.is_empty() || !desc.is_empty() {
            return Err(Error::Auth(format!("okta error: {err} - {desc}")));
        }
        return Err(Error::Auth(format!("okta authorize endpoint returned {}: {}", sign_in.status, preview(&sign_in.body))));
    }
    if sign_in.body.contains("unexpected internal error") || sign_in.body.contains("Something went wrong") {
        return Err(Error::Auth(format!("okta returned an error: {}", preview(&sign_in.body))));
    }

    let mut state = OktaState::default();
    let mut intro_body = Map::new();
    if let Some(tok) = extract_state_token(&sign_in.body) {
        intro_body.insert("stateToken".into(), tok.into());
    }
    let intro = send(&session, okta_post(&format!("{OKTA}/idp/idx/introspect"), &authorize_url, &Value::Object(intro_body)))
        .await?
        .json();
    state.update(&intro);
    if state.is_empty() {
        return Err(Error::Auth("state token/handle not found in Okta introspect response".into()));
    }
    let mut needs_password = requires_password(&intro);

    if remediation_exists(&intro, "identify") {
        let body = state.apply(json!({"identifier": creds.email}));
        let res = send(&session, okta_post(&format!("{OKTA}/idp/idx/identify"), &authorize_url, &body)).await?.json();
        state.update(&res);
        if state.is_empty() {
            return Err(Error::Auth("state token/handle not found in Okta identify response".into()));
        }
        needs_password = requires_password(&res);
    }

    let answer_url = format!("{OKTA}/idp/idx/challenge/answer");
    if needs_password {
        let body = state.apply(json!({"credentials": {"passcode": creds.password}}));
        let res = send(&session, okta_post(&answer_url, &authorize_url, &body)).await?.json();
        let summary = res.str_at("errorSummary");
        if !summary.is_empty() {
            return Err(Error::Auth(format!("password verification failed: {summary}")));
        }
        state.update(&res);
        if state.is_empty() {
            return Err(Error::Auth("state token/handle not found in Okta password response".into()));
        }

        if remediation_exists(&res, "select-authenticator-authenticate") {
            let (href, id) = find_otp_authenticator(&res);
            let id = id.ok_or_else(|| Error::Auth("Okta OTP authenticator option not found".into()))?;
            let body = state.apply(json!({"authenticator": {"id": id}}));
            let sel = send(&session, okta_post(&href, &authorize_url, &body)).await?;
            if sel.status >= 400 {
                return Err(Error::Auth(format!(
                    "OTP authenticator selection failed: {}",
                    okta_error(&sel.json(), sel.status)
                )));
            }
            state.update(&sel.json());
            if state.is_empty() {
                return Err(Error::Auth("state token/handle not found in Okta OTP selection response".into()));
            }
        }
    }

    let code = otp::generate_totp_now(&creds.otp_secret)?;
    let body = state.apply(json!({"credentials": {"passcode": code}}));
    let challenge = send(&session, okta_post(&answer_url, &authorize_url, &body)).await?;
    let cv = challenge.json();
    if challenge.status >= 400 {
        return Err(Error::Auth(format!("OTP verification failed: {}", okta_error(&cv, challenge.status))));
    }
    let summary = cv.str_at("errorSummary");
    if !summary.is_empty() {
        return Err(Error::Auth(format!("OTP verification failed: {summary}")));
    }

    let mut redirect = cv.str_at("success.href");
    if redirect.is_empty() {
        state.update(&cv);
        let mut tok = cv.str_at("sessionToken");
        if tok.is_empty() {
            tok = if !state.token.is_empty() {
                state.token.clone()
            } else {
                // Only the part before `~c.` of a stateHandle is the stateToken.
                state.handle.split('~').next().unwrap_or_default().to_string()
            };
        }
        redirect = format!(
            "{OKTA}/login/token/redirect?stateToken={}",
            url::form_urlencoded::byte_serialize(tok.as_bytes()).collect::<String>()
        );
    }
    send(&session, Request::get(redirect).header("Referer", &authorize_url)).await?;

    if let Some(c) = session.cookies_for(BASE) {
        return Ok(c);
    }
    send(&session, Request::get(format!("{BASE}/dashboard")).header("Referer", "https://identity.bugcrowd.com/")).await?;
    session
        .cookies_for(BASE)
        .ok_or_else(|| Error::Auth("unable to obtain session cookie after completing login flow".into()))
}

fn preview(s: &str) -> &str {
    let mut end = s.len().min(500);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn remediations(body: &Value) -> &[Value] {
    body.arr_at("remediation.value")
}

fn remediation_exists(body: &Value, name: &str) -> bool {
    remediations(body).iter().any(|r| r.str_at("name").eq_ignore_ascii_case(name))
}

fn requires_password(body: &Value) -> bool {
    let kind = body.str_at("currentAuthenticatorEnrollment.type").to_lowercase();
    let key = body.str_at("currentAuthenticatorEnrollment.key").to_lowercase();
    if kind == "password" || key == "password" || key == "okta_password" {
        return true;
    }
    remediations(body)
        .iter()
        .filter(|r| r.str_at("name").eq_ignore_ascii_case("challenge-authenticator"))
        .flat_map(|r| r.arr_at("value"))
        .filter(|f| f.str_at("name") == "credentials")
        .flat_map(|f| f.arr_at("form.value"))
        .any(|ff| ff.str_at("label").to_lowercase().contains("password"))
}

/// `(href, authenticator id)` of the TOTP option in a select-authenticator step.
fn find_otp_authenticator(body: &Value) -> (String, Option<String>) {
    let mut href = String::new();
    for rem in remediations(body).iter().filter(|r| r.str_at("name").eq_ignore_ascii_case("select-authenticator-authenticate")) {
        href = rem.str_at("href");
        let id = rem
            .arr_at("value")
            .iter()
            .filter(|f| f.str_at("name") == "authenticator")
            .flat_map(|f| f.arr_at("options"))
            .filter(|o| option_is_otp(o))
            .map(authenticator_id)
            .find(|id| !id.is_empty());
        if id.is_some() {
            return (if href.is_empty() { format!("{OKTA}/idp/idx/challenge") } else { href }, id);
        }
    }
    if href.is_empty() {
        href = format!("{OKTA}/idp/idx/challenge");
    }
    (href, None)
}

/// Okta labels the TOTP factor "Google Authenticator" (key `google_otp`), so
/// match on the key or the `methodType` form field before the label.
fn option_is_otp(o: &Value) -> bool {
    if o.str_at("relatesTo.key").eq_ignore_ascii_case("google_otp") {
        return true;
    }
    if o.arr_at("value.form.value")
        .iter()
        .any(|f| f.str_at("name") == "methodType" && f.str_at("value").eq_ignore_ascii_case("otp"))
    {
        return true;
    }
    let label = o.str_at("label").to_lowercase();
    label.contains("otp") || label.contains("google authenticator")
}

fn authenticator_id(o: &Value) -> String {
    for path in ["value.id", "relatesTo.id"] {
        let id = o.str_at(path);
        if !id.is_empty() {
            return id;
        }
    }
    o.arr_at("value.form.value").iter().find(|f| f.str_at("name") == "id").map(|f| f.str_at("value")).unwrap_or_default()
}

fn okta_error(body: &Value, status: u16) -> String {
    ["errorSummary", "messages.value.0.message", "error_description", "error"]
        .iter()
        .map(|p| body.str_at(p))
        .find(|m| !m.is_empty())
        .unwrap_or_else(|| format!("Okta returned status {status}"))
}

fn extract_state_token(html: &str) -> Option<String> {
    Regex::new(r#""stateToken":"([^"]+)""#)
        .unwrap()
        .captures(html)
        .map(|c| decode_okta_escapes(&c[1]))
}

/// Okta embeds JS strings with `\xHH` escapes; turn them into real characters.
fn decode_okta_escapes(input: &str) -> String {
    let hex = Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap();
    let as_json = hex.replace_all(input, r"\u00$1");
    serde_json::from_str::<String>(&format!("\"{as_json}\"")).unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert_eq!(normalize_handle("https://bugcrowd.com/engagements/acme"), "/engagements/acme");
        assert_eq!(normalize_handle("https://bugcrowd.com/acme?x=1"), "/acme?x=1");
        assert_eq!(normalize_handle("bugcrowd.com/acme"), "/acme");
        assert_eq!(normalize_handle("/acme"), "/acme");
        assert_eq!(normalize_handle("https://other.com/acme"), "https://other.com/acme");
    }

    #[test]
    fn okta_escapes() {
        assert_eq!(decode_okta_escapes(r"abc\x2Ddef"), "abc-def");
        assert_eq!(extract_state_token(r#"var x = {"stateToken":"00a\x2Db"};"#).as_deref(), Some("00a-b"));
    }

    #[test]
    fn brief_url() {
        let html = r#"<div data-react-class="ResearcherEngagementBrief" data-api-endpoints="{&quot;engagementBriefApi&quot;:{&quot;getBriefVersionDocument&quot;:&quot;/engagements/x/brief/1&quot;}}"></div>"#;
        assert_eq!(brief_document_url(html).as_deref(), Some("/engagements/x/brief/1.json"));
        assert_eq!(brief_document_url("<html></html>"), None);
    }

    #[test]
    fn otp_option() {
        let body = json!({"remediation": {"value": [{
            "name": "select-authenticator-authenticate",
            "href": "https://h/x",
            "value": [{"name": "authenticator", "options": [
                {"label": "Password", "value": {"form": {"value": [{"name": "id", "value": "pw"}]}}},
                {"label": "Google Authenticator", "relatesTo": {"key": "google_otp", "id": "otp1"}}
            ]}]
        }]}});
        assert_eq!(find_otp_authenticator(&body), ("https://h/x".to_string(), Some("otp1".to_string())));
    }
}
