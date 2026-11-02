//! HTTP transport. A trait so tests can use recorded responses.

use std::future::Future;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

/// Responses larger than this are rejected (a lying provider can't make us
/// allocate unbounded memory).
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpError {
    #[error("network error: {0}")]
    Network(String),
    #[error("provider returned HTTP {0}")]
    Status(u16),
    #[error("provider is rate-limiting us (HTTP 429)")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("response too large")]
    TooLarge,
    #[error("response is not valid JSON/text")]
    Body,
}

pub trait HttpClient: Send + Sync {
    fn get_text(&self, url: &str) -> impl Future<Output = Result<String, HttpError>> + Send;
    fn post_json(
        &self,
        url: &str,
        body: &Value,
    ) -> impl Future<Output = Result<Value, HttpError>> + Send;
}

/// Explain a network failure with its underlying cause (timeout, refused,
/// DNS, TLS…), not just "error sending request".
fn describe(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else {
        "request failed"
    };
    let mut cause = None;
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        cause = Some(s.to_string());
        src = s.source();
    }
    match cause {
        Some(c) if !c.is_empty() => format!("{kind}: {}", c.chars().take(160).collect::<String>()),
        _ => kind.to_owned(),
    }
}

/// Real client: HTTPS only, no redirects, short timeouts, size-limited bodies.
#[derive(Clone)]
pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new() -> Result<Self, HttpError> {
        let inner = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(6))
            .timeout(Duration::from_secs(12))
            .user_agent("watch-only-wallet/0.1")
            .build()
            .map_err(|e| HttpError::Network(e.to_string()))?;
        Ok(Self { inner })
    }

    async fn read_body(resp: reqwest::Response) -> Result<Vec<u8>, HttpError> {
        let status = resp.status();
        if status.as_u16() == 429 {
            // Retry-After in seconds, if the provider sent it (capped later).
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            return Err(HttpError::RateLimited { retry_after_secs });
        }
        if !status.is_success() {
            return Err(HttpError::Status(status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(HttpError::TooLarge);
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| HttpError::Network(describe(&e)))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        Ok(bytes.to_vec())
    }
}

impl HttpClient for ReqwestClient {
    async fn get_text(&self, url: &str) -> Result<String, HttpError> {
        let resp = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| HttpError::Network(describe(&e)))?;
        let body = Self::read_body(resp).await?;
        String::from_utf8(body).map_err(|_| HttpError::Body)
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, HttpError> {
        let resp = self
            .inner
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| HttpError::Network(describe(&e)))?;
        let body = Self::read_body(resp).await?;
        serde_json::from_slice(&body).map_err(|_| HttpError::Body)
    }
}
