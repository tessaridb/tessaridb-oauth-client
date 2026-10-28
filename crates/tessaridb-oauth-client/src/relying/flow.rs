//! The authorization request (OAuth 2.1 section 4.1, RFC 7636, OpenID Connect Core 3.1.2) and the checks on its return.
//! A flow starts with a fresh `state`, `nonce` and PKCE verifier kept by the caller for this one request, and its
//! return is accepted only when it carries that `state` and names the issuer the flow went to (RFC 9207); an error
//! answer is classified by its code and its free text is never carried, so it cannot be echoed into a page.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{Error, Result};

/// Random bytes in a `state` and a `nonce`: 128 bits each.
const STATE_BYTES: usize = 16;
/// Random bytes in a PKCE verifier: 32, which encode to the 43 characters RFC 7636 section 4.1 asks for at least.
const VERIFIER_BYTES: usize = 32;

/// The error codes an authorization answer may carry (RFC 6749 section 4.1.2.1, OpenID Connect Core 3.1.2.6).
const ERROR_CODES: [&str; 11] = [
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    "interaction_required",
    "login_required",
    "account_selection_required",
    "consent_required",
];

/// A client registered at one issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    issuer: String,
    authorization_endpoint: Url,
    pub(super) client_id: String,
    pub(super) redirect_uri: Url,
}

/// What one in-flight request keeps until its return: the caller stores it under [`Pending::state`]. It serializes,
/// so a server can keep it in its own store between the two legs; it holds the PKCE verifier, so that store is as
/// private as the code it protects, and short-lived.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pending {
    state: String,
    nonce: String,
    verifier: String,
    issuer: String,
}

/// Why a return was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReturnRefusal {
    /// No `state`, or another request's.
    #[error("the return is not for this request")]
    StateMismatch,
    /// No `iss`, or another issuer than the one this request went to.
    #[error("the return is from another issuer")]
    WrongIssuer,
    /// The issuer answered with this error code (`other` for a code outside the specifications).
    #[error("the issuer answered {0}")]
    Denied(&'static str),
    /// A parameter given twice, or no code.
    #[error("the return is malformed")]
    Malformed,
}

fn random(bytes: usize) -> Result<String> {
    let mut buffer = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| Error::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn loopback(url: &Url) -> bool {
    url.host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

impl Client {
    /// The client `client_id` of `issuer`, sending users to `authorization_endpoint` and back to `redirect_uri`.
    ///
    /// # Errors
    ///
    /// [`Error::Client`] for an empty issuer or client id, an authorization endpoint that is not https, or a redirect
    /// that is neither https nor http to a loopback address (RFC 8252 section 7.3).
    pub fn new(
        issuer: &str,
        authorization_endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<Self> {
        let endpoint = Url::parse(authorization_endpoint)
            .map_err(|_| Error::Client("the authorization endpoint is not a URL"))?;
        let redirect =
            Url::parse(redirect_uri).map_err(|_| Error::Client("the redirect is not a URL"))?;
        if issuer.is_empty() || client_id.is_empty() {
            return Err(Error::Client("a client names its issuer and its id"));
        }
        if endpoint.scheme() != "https" {
            return Err(Error::Client("the authorization endpoint must be https"));
        }
        if !(redirect.scheme() == "https" || (redirect.scheme() == "http" && loopback(&redirect))) {
            return Err(Error::Client(
                "the redirect must be https, or http to a loopback address",
            ));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            authorization_endpoint: endpoint,
            client_id: client_id.to_owned(),
            redirect_uri: redirect,
        })
    }
}

/// Start a sign-in at `client`'s issuer for `scope`, for `resource` when named: the address to send the user to and
/// what to keep until they return.
///
/// # Errors
///
/// [`Error::Random`] when the system's random source fails.
pub fn begin(client: &Client, scope: &str, resource: Option<&str>) -> Result<(Url, Pending)> {
    let pending = Pending {
        state: random(STATE_BYTES)?,
        nonce: random(STATE_BYTES)?,
        verifier: random(VERIFIER_BYTES)?,
        issuer: client.issuer.clone(),
    };
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, pending.verifier.as_bytes()));
    let mut url = client.authorization_endpoint.clone();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", client.redirect_uri.as_str())
            .append_pair("scope", scope)
            .append_pair("state", &pending.state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(resource) = resource {
            query.append_pair("resource", resource);
        }
    }
    Ok((url, pending))
}

impl Pending {
    /// The request's `state`, under which the caller keeps it.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The `nonce` the ID token must carry.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The PKCE verifier the code is exchanged with.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The code of a return whose query is `query`, when it is this request's return.
    ///
    /// # Errors
    ///
    /// The [`ReturnRefusal`] of the first check it fails, in the order malformed, state, issuer, error answer, code.
    pub fn accept(&self, query: &str) -> std::result::Result<String, ReturnRefusal> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if pairs.iter().any(|(seen, _)| *seen == name) {
                return Err(ReturnRefusal::Malformed);
            }
            pairs.push((name.into_owned(), value.into_owned()));
        }
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        let state = get("state").unwrap_or_default();
        if !bool::from(state.as_bytes().ct_eq(self.state.as_bytes())) {
            return Err(ReturnRefusal::StateMismatch);
        }
        if get("iss") != Some(self.issuer.as_str()) {
            return Err(ReturnRefusal::WrongIssuer);
        }
        if let Some(error) = get("error") {
            let code = ERROR_CODES
                .into_iter()
                .find(|known| *known == error)
                .unwrap_or("other");
            return Err(ReturnRefusal::Denied(code));
        }
        get("code")
            .filter(|code| !code.is_empty())
            .map(str::to_owned)
            .ok_or(ReturnRefusal::Malformed)
    }
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
