//! Where a key set comes from: the issuer's `jwks_uri`, fetched over https with a deadline and a size ceiling. Plain
//! http is spoken only to a loopback address, which is how a test or a sidecar on the same host serves one.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::CACHE_CONTROL;
use reqwest::{StatusCode, Url};

use crate::{Error, Result};

/// The most one fetch may take, from connecting to the last byte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest key set read; an issuer publishing more is refused rather than buffered.
const MAX_KEY_SET_BYTES: usize = 64 * 1024;

/// A key set as fetched: its JSON and the lifetime the issuer gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The key set's JSON.
    pub body: String,
    /// `max-age` from the answer's `Cache-Control`, when it gave one.
    pub max_age: Option<Duration>,
}

/// Something that answers with the issuer's current key set.
pub trait KeySource: Send + Sync {
    /// Fetch the key set now.
    fn fetch(&self) -> impl Future<Output = Result<Fetched>> + Send;
}

/// The key set at an issuer's `jwks_uri`.
pub struct HttpsKeySource {
    url: Url,
    client: reqwest::Client,
}

pub(crate) fn loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

/// Why an answer's body was not read.
pub(crate) enum Unread {
    /// It announced, or sent, more than the limit.
    TooLarge,
    /// The connection failed before the body was whole.
    Broken,
}

/// The body of `answer`, refused past `limit` bytes whether or not it announced its length.
pub(crate) async fn read_limited(
    mut answer: reqwest::Response,
    limit: usize,
) -> std::result::Result<Vec<u8>, Unread> {
    if answer
        .content_length()
        .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        return Err(Unread::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await.map_err(|_| Unread::Broken)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(Unread::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The `max-age` of a `Cache-Control` value.
fn max_age(cache_control: &str) -> Option<Duration> {
    cache_control
        .split(',')
        .filter_map(|directive| directive.trim().strip_prefix("max-age="))
        .find_map(|seconds| seconds.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

impl HttpsKeySource {
    /// The key set at `jwks_uri`.
    ///
    /// # Errors
    ///
    /// [`Error::Fetch`] when the address is not https (or http to a loopback address), or no client can be built.
    pub fn new(jwks_uri: &str) -> Result<Self> {
        let url =
            Url::parse(jwks_uri).map_err(|_| Error::Fetch("the key set address is not a URL"))?;
        let allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback(&url));
        if !allowed || url.username() != "" || url.password().is_some() {
            return Err(Error::Fetch(
                "the key set address must be https, with no credentials",
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Fetch("no https client could be built"))?;
        Ok(Self { url, client })
    }
}

impl KeySource for HttpsKeySource {
    async fn fetch(&self) -> Result<Fetched> {
        let answer = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(|_| Error::Fetch("the issuer did not answer"))?;
        if answer.status() != StatusCode::OK {
            return Err(Error::Fetch("the issuer answered with an error"));
        }
        let max_age = answer
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .and_then(max_age);
        let body =
            read_limited(answer, MAX_KEY_SET_BYTES)
                .await
                .map_err(|unread| match unread {
                    Unread::TooLarge => {
                        Error::Fetch("the key set is larger than this client reads")
                    }
                    Unread::Broken => Error::Fetch("the key set did not arrive whole"),
                })?;
        let body = String::from_utf8(body).map_err(|_| Error::Fetch("the key set is not text"))?;
        Ok(Fetched { body, max_age })
    }
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
