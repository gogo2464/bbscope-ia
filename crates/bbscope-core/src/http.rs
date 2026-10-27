//! A small retrying HTTP client shared by all platforms.

use std::sync::Arc;
use std::time::Duration;

use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use serde_json::Value;

use crate::{Error, Result};

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0 bbscope";

/// Client settings.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// HTTP(S) proxy URL. TLS verification is disabled when set (for Burp & co).
    pub proxy: Option<String>,
    /// Print every request and response to stderr.
    pub debug: bool,
    pub timeout: Duration,
    /// Retries on network errors, 429 and 5xx responses.
    pub max_retries: u32,
    /// Keep cookies between requests (used for login flows).
    pub cookie_store: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self { proxy: None, debug: false, timeout: Duration::from_secs(30), max_retries: 8, cookie_store: false }
    }
}

/// An outgoing request.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl Request {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self { method, url: url.into(), headers: Vec::new(), body: None }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self::new(Method::POST, url)
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Adds `Authorization: Bearer <token>` unless the token is empty.
    pub fn bearer(self, token: &str) -> Self {
        if token.is_empty() {
            self
        } else {
            self.header("Authorization", format!("Bearer {token}"))
        }
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets a JSON body and the matching `Content-Type`.
    pub fn json(self, value: &Value) -> Self {
        self.header("Content-Type", "application/json").body(value.to_string())
    }
}

/// A fully-read response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
    /// Final URL after redirects.
    pub url: String,
}

impl Response {
    pub fn json(&self) -> Value {
        crate::json::parse(&self.body)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
    }
}

/// Cheap to clone; clones share the connection pool and cookie jar.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    jar: Option<Arc<Jar>>,
    cfg: Arc<HttpConfig>,
}

impl HttpClient {
    pub fn new(cfg: HttpConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", HeaderValue::from_static(DEFAULT_USER_AGENT));
        headers.insert("Cache-Control", HeaderValue::from_static("no-transform"));
        headers.insert("Accept-Language", HeaderValue::from_static("en"));

        let mut builder = reqwest::Client::builder().default_headers(headers).timeout(cfg.timeout).gzip(true);
        if let Some(proxy) = cfg.proxy.as_deref().filter(|p| !p.is_empty()) {
            let proxy = reqwest::Proxy::all(proxy).map_err(|e| Error::other(format!("invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy).danger_accept_invalid_certs(true);
        }
        let jar = cfg.cookie_store.then(|| Arc::new(Jar::default()));
        if let Some(jar) = &jar {
            builder = builder.cookie_provider(jar.clone());
        }
        Ok(Self { inner: builder.build()?, jar, cfg: Arc::new(cfg) })
    }

    /// A client with the same proxy/debug settings but its own cookie jar
    /// and no retries (login flows have side effects).
    pub fn session(&self) -> Result<Self> {
        Self::new(HttpConfig { cookie_store: true, max_retries: 0, ..(*self.cfg).clone() })
    }

    pub fn config(&self) -> &HttpConfig {
        &self.cfg
    }

    /// `Cookie` header value the jar would send to `url`.
    pub fn cookies_for(&self, url: &str) -> Option<String> {
        let jar = self.jar.as_ref()?;
        let url = url::Url::parse(url).ok()?;
        jar.cookies(&url).and_then(|v| v.to_str().ok().map(str::to_string)).filter(|s| !s.is_empty())
    }

    pub async fn get(&self, url: impl Into<String>) -> Result<Response> {
        self.send(Request::get(url)).await
    }

    /// Sends a request, retrying network errors, 429 and 5xx with exponential
    /// backoff. After the last attempt the final response is returned as is.
    pub async fn send(&self, req: Request) -> Result<Response> {
        let mut attempt = 0u32;
        loop {
            let retry_left = attempt < self.cfg.max_retries;
            match self.send_once(&req).await {
                Ok(res) if retry_left && (res.status == 429 || (res.status >= 500 && res.status != 501)) => {
                    tracing::debug!("{} {} -> {}, retrying", req.method, req.url, res.status);
                }
                Ok(res) => return Ok(res),
                Err(e) if retry_left => tracing::debug!("{} {} failed: {e}, retrying", req.method, req.url),
                Err(e) => return Err(e),
            }
            tokio::time::sleep(backoff(attempt)).await;
            attempt += 1;
        }
    }

    async fn send_once(&self, req: &Request) -> Result<Response> {
        let mut builder = self.inner.request(req.method.clone(), &req.url);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }

        if self.cfg.debug {
            eprintln!("********** HTTP REQUEST **********\n{} {}", req.method, req.url);
            for (k, v) in &req.headers {
                eprintln!("{k}: {v}");
            }
            if let Some(body) = &req.body {
                eprintln!("\n{body}");
            }
            eprintln!("**********************************");
        }

        let res = builder.send().await?;
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let url = res.url().to_string();
        let body = res.text().await?;

        if self.cfg.debug {
            eprintln!("********** HTTP RESPONSE **********\nStatus: {status}");
            for (k, v) in &headers {
                eprintln!("{k}: {}", v.to_str().unwrap_or("<binary>"));
            }
            eprintln!("\n{body}\n***********************************");
        }

        Ok(Response { status, headers, body, url })
    }
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.min(5)).min(30))
}

/// Spaces calls out so at most one goes through per `interval`.
pub struct RateLimiter {
    interval: Duration,
    next: tokio::sync::Mutex<tokio::time::Instant>,
}

impl RateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self { interval, next: tokio::sync::Mutex::new(tokio::time::Instant::now()) }
    }

    pub async fn wait(&self) {
        let mut next = self.next.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + self.interval;
    }
}
