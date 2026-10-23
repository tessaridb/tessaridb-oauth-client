//! The token endpoint (OAuth 2.1 section 3.2): a sign-in's code exchanged for tokens (RFC 6749 section 4.1.3,
//! RFC 7636 section 4.5) and a refresh token for the next set (RFC 6749 section 6), each for a `resource` when named
//! (RFC 8707). A failure is classified for the caller and never retried here: an answer that ends the session must
//! send the user back to sign in, because retrying it hides the very event a reused refresh token raises.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use super::dpop::DpopKey;
use super::flow::{Client, Pending};
use super::tokens::{TokenSet, TokenType};
use crate::resource::{Unread, loopback, read_limited};
use crate::{Error, Result};

/// The most one call may take, from connecting to the last byte.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer read; a token answer is a few kilobytes.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// Error codes after which the grant cannot be used again (RFC 6749 section 5.2).
const SESSION_ENDING: [&str; 3] = ["invalid_grant", "invalid_client", "unauthorized_client"];
/// Error codes that refuse this request without ending the grant (RFC 6749 section 5.2, RFC 8707 section 2).
const REQUEST_REFUSALS: [&str; 4] = [
    "invalid_request",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
];

/// Why the token endpoint did not issue tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeRefusal {
    /// The code or refresh token, or the client, is no longer good: the user signs in again; never retried.
    #[error("the session is over: {0}")]
    SessionOver(&'static str),
    /// No answer, an overloaded issuer or a server error: the same request may be tried again later.
    #[error("the issuer could not answer now")]
    Retryable,
    /// The request was refused for this code (`other` for one outside the specifications); retrying cannot help.
    #[error("the issuer refused the request: {0}")]
    Rejected(&'static str),
    /// An answer that cannot be read as a token answer.
    #[error("the issuer's answer is malformed")]
    Malformed,
    /// No DPoP proof could be made, so nothing was sent.
    #[error("no proof of the client's key could be made")]
    Proof,
}

#[derive(Deserialize)]
struct Issued {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct Refused {
    error: String,
}

/// An issuer's token endpoint.
pub struct TokenEndpoint {
    url: Url,
    client: reqwest::Client,
}

fn known(codes: &[&'static str], code: &str) -> Option<&'static str> {
    codes.iter().copied().find(|known| *known == code)
}

fn issued(body: &[u8]) -> std::result::Result<TokenSet, ExchangeRefusal> {
    let issued: Issued = serde_json::from_slice(body).map_err(|_| ExchangeRefusal::Malformed)?;
    let token_type = if issued.token_type.eq_ignore_ascii_case("bearer") {
        TokenType::Bearer
    } else if issued.token_type.eq_ignore_ascii_case("dpop") {
        TokenType::DPoP
    } else {
        return Err(ExchangeRefusal::Malformed);
    };
    if issued.access_token.is_empty() {
        return Err(ExchangeRefusal::Malformed);
    }
    Ok(TokenSet {
        access_token: issued.access_token,
        token_type,
        expires_in: issued.expires_in,
        refresh_token: issued.refresh_token,
        id_token: issued.id_token,
        scope: issued.scope,
    })
}

fn refused(body: &[u8]) -> ExchangeRefusal {
    let Ok(refused) = serde_json::from_slice::<Refused>(body) else {
        return ExchangeRefusal::Malformed;
    };
    if let Some(code) = known(&SESSION_ENDING, &refused.error) {
        return ExchangeRefusal::SessionOver(code);
    }
    ExchangeRefusal::Rejected(known(&REQUEST_REFUSALS, &refused.error).unwrap_or("other"))
}

impl TokenEndpoint {
    /// The token endpoint at `url`.
    ///
    /// # Errors
    ///
    /// [`Error::Client`] when the address is not https (or http to a loopback address), carries credentials, or no
    /// client can be built.
    pub fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url).map_err(|_| Error::Client("the token endpoint is not a URL"))?;
        let allowed = url.scheme() == "https" || (url.scheme() == "http" && loopback(&url));
        if !allowed || url.username() != "" || url.password().is_some() {
            return Err(Error::Client(
                "the token endpoint must be https, with no credentials",
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(EXCHANGE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Client("no https client could be built"))?;
        Ok(Self { url, client })
    }

    /// Exchange the `code` of `pending`'s return for tokens, for `resource` when named, bound to `dpop` when given.
    ///
    /// # Errors
    ///
    /// The [`ExchangeRefusal`] the answer falls in.
    pub async fn exchange(
        &self,
        client: &Client,
        pending: &Pending,
        code: &str,
        resource: Option<&str>,
        dpop: Option<&DpopKey>,
    ) -> std::result::Result<TokenSet, ExchangeRefusal> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", client.redirect_uri.as_str()),
            ("client_id", client.client_id.as_str()),
            ("code_verifier", pending.verifier()),
        ];
        form.extend(resource.map(|resource| ("resource", resource)));
        self.post(&form, dpop).await
    }

    /// Exchange `refresh_token` for the next set, for `resource` when named, proving `dpop` when the tokens are
    /// bound to it. The answer's refresh token replaces the one presented, which the issuer has now retired.
    ///
    /// # Errors
    ///
    /// The [`ExchangeRefusal`] the answer falls in; [`ExchangeRefusal::SessionOver`] for a reused or revoked token.
    pub async fn refresh(
        &self,
        client: &Client,
        refresh_token: &str,
        resource: Option<&str>,
        dpop: Option<&DpopKey>,
    ) -> std::result::Result<TokenSet, ExchangeRefusal> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client.client_id.as_str()),
        ];
        form.extend(resource.map(|resource| ("resource", resource)));
        self.post(&form, dpop).await
    }

    async fn post(
        &self,
        form: &[(&str, &str)],
        dpop: Option<&DpopKey>,
    ) -> std::result::Result<TokenSet, ExchangeRefusal> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = self
            .client
            .post(self.url.clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json");
        if let Some(key) = dpop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ExchangeRefusal::Proof)?
                .as_secs();
            let proof = key
                .proof("POST", self.url.as_str(), None, now)
                .map_err(|_| ExchangeRefusal::Proof)?;
            request = request.header("DPoP", proof);
        }
        let answer = request
            .body(body)
            .send()
            .await
            .map_err(|_| ExchangeRefusal::Retryable)?;
        let status = answer.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(ExchangeRefusal::Retryable);
        }
        let body = read_limited(answer, MAX_ANSWER_BYTES)
            .await
            .map_err(|unread| match unread {
                Unread::TooLarge => ExchangeRefusal::Malformed,
                Unread::Broken => ExchangeRefusal::Retryable,
            })?;
        match status {
            StatusCode::OK => issued(&body),
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => Err(refused(&body)),
            _ => Err(ExchangeRefusal::Malformed),
        }
    }
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod tests;
