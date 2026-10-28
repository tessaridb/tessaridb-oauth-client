//! Issuer discovery (OpenID Connect Discovery 1.0): the endpoints an issuer publishes at
//! `{issuer}/.well-known/openid-configuration`, read once and checked before anything is sent to them.
//!
//! The document is fetched over https (plain http only to a loopback address), with a deadline, no redirects and a
//! size ceiling. Its `issuer` must be the configured issuer exactly (§4.3): an issuer that answers for another name
//! is refused, so a misconfigured or impersonated issuer cannot hand over endpoints of its choosing. Each endpoint it
//! names must itself be https, or http to a loopback address, with no credentials in it.

use std::time::Duration;

use reqwest::{StatusCode, Url};
use serde::Deserialize;

use crate::resource::{Unread, loopback, read_limited};
use crate::{Error, Result};

/// The most one fetch may take, from connecting to the last byte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest document read.
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// What an issuer publishes that signing a user in needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The issuer, exactly as configured and as the document names it.
    pub issuer: String,
    /// Where users are sent to sign in.
    pub authorization_endpoint: String,
    /// Where codes are exchanged.
    pub token_endpoint: String,
    /// The issuer's key set.
    pub jwks_uri: String,
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

const fn refuse(reason: &'static str) -> Error {
    Error::Discovery(reason)
}

/// Whether `text` is an address this client sends to: https, or http to a loopback address, with no credentials.
fn acceptable(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    let allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback(&url));
    (allowed && url.username().is_empty() && url.password().is_none()).then_some(url)
}

/// The metadata `issuer` publishes.
///
/// # Errors
///
/// [`Error::Discovery`] naming why: the issuer is not an acceptable address; no answer, an error answer or one larger
/// than this client reads; a document that is not JSON of the required shape; a document for another issuer; an
/// endpoint that is not an acceptable address.
pub async fn discover(issuer: &str) -> Result<Metadata> {
    let base = acceptable(issuer).ok_or(refuse(
        "the issuer must be https (or http to a loopback address), with no credentials",
    ))?;
    if base.query().is_some() || base.fragment().is_some() {
        return Err(refuse("the issuer has no query or fragment"));
    }
    let address = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| refuse("no https client could be built"))?;
    let answer = client
        .get(&address)
        .send()
        .await
        .map_err(|_| refuse("the issuer did not answer"))?;
    if answer.status() != StatusCode::OK {
        return Err(refuse("the issuer answered with an error"));
    }
    let body = read_limited(answer, MAX_DOCUMENT_BYTES)
        .await
        .map_err(|unread| match unread {
            Unread::TooLarge => refuse("the document is larger than this client reads"),
            Unread::Broken => refuse("the connection failed before the document was whole"),
        })?;
    let document: Document = serde_json::from_slice(&body)
        .map_err(|_| refuse("the document is not JSON of the required shape"))?;
    if document.issuer != issuer {
        return Err(refuse("the document is for another issuer"));
    }
    for endpoint in [
        &document.authorization_endpoint,
        &document.token_endpoint,
        &document.jwks_uri,
    ] {
        if acceptable(endpoint).is_none() {
            return Err(refuse(
                "an endpoint is not https (or http to a loopback address), or carries credentials",
            ));
        }
    }
    Ok(Metadata {
        issuer: document.issuer,
        authorization_endpoint: document.authorization_endpoint,
        token_endpoint: document.token_endpoint,
        jwks_uri: document.jwks_uri,
    })
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
