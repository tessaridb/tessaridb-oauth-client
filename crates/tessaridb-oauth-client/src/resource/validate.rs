//! An access token checked in the order that makes each check mean something: its type, the algorithm this resource
//! accepts, the issuer's key by `kid`, the signature, and only then the claims the signature vouches for: issuer,
//! audience and time. The algorithm and the key come from this resource's configuration and the issuer's key set,
//! never from the token, which is only ever asked which of them it claims.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;

use super::expectations::LEEWAY_SECS;
use super::keys::PublicKey;
use super::{AccessToken, Algorithm, Expectations, KeySet, Refusal};

/// The `typ` of an access token (RFC 9068 section 2.1), compared without case and with or without `application/`.
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: Option<String>,
    kid: Option<String>,
    crit: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Confirmation {
    jkt: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    aud: Option<Audience>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    sub: Option<String>,
    client_id: Option<String>,
    jti: Option<String>,
    scope: Option<String>,
    cnf: Option<Confirmation>,
}

pub(super) fn decoded<T: serde::de::DeserializeOwned>(part: &str) -> Result<T, Refusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Refusal::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| Refusal::Malformed)
}

fn is_access_token(typ: Option<&str>) -> bool {
    typ.is_some_and(|typ| {
        let typ = typ.to_ascii_lowercase();
        typ == ACCESS_TOKEN_TYPE || typ.strip_prefix("application/") == Some(ACCESS_TOKEN_TYPE)
    })
}

pub(super) fn verified(key: &PublicKey, input: &str, signature: &str) -> Result<(), Refusal> {
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Refusal::Malformed)?;
    let scheme: &'static dyn VerificationAlgorithm = match key.algorithm {
        Algorithm::Es256 => &ECDSA_P256_SHA256_FIXED,
        Algorithm::EdDsa => &ED25519,
    };
    UnparsedPublicKey::new(scheme, &key.bytes)
        .verify(input.as_bytes(), &signature)
        .map_err(|_| Refusal::BadSignature)
}

fn names(audience: &Audience, expected: &str) -> bool {
    match audience {
        Audience::One(one) => one == expected,
        Audience::Many(many) => many.iter().any(|one| one == expected),
    }
}

/// The payload of compact JWS `token` once its header names a type `is_type` accepts, an algorithm among
/// `algorithms` and a key of `keys` for it, and its signature verifies under that key; the claims are the caller's.
///
/// # Errors
///
/// [`Refusal::Malformed`], [`Refusal::WrongType`], [`Refusal::AlgorithmNotAllowed`], [`Refusal::UnknownKey`] or
/// [`Refusal::BadSignature`], for the first of those checks it fails, in that order.
pub(crate) fn verified_payload(
    token: &str,
    keys: &KeySet,
    algorithms: &[Algorithm],
    is_type: fn(Option<&str>) -> bool,
) -> Result<Vec<u8>, Refusal> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::Malformed);
    };
    let head: Header = decoded(header)?;
    if head.crit.is_some() {
        return Err(Refusal::Malformed);
    }
    if !is_type(head.typ.as_deref()) {
        return Err(Refusal::WrongType);
    }
    let algorithm = algorithms
        .iter()
        .copied()
        .find(|algorithm| algorithm.name() == head.alg)
        .ok_or(Refusal::AlgorithmNotAllowed)?;
    let key = head
        .kid
        .as_deref()
        .and_then(|kid| keys.find(kid, algorithm))
        .ok_or(Refusal::UnknownKey)?;
    let signed = token
        .rsplit_once('.')
        .map(|(input, _)| input)
        .ok_or(Refusal::Malformed)?;
    verified(key, signed, signature)?;
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Refusal::Malformed)
}

/// `token`, verified under `keys` and judged against `expect` at `now` (Unix seconds).
///
/// # Errors
///
/// The [`Refusal`] of the first check it fails.
pub fn validate(
    token: &str,
    keys: &KeySet,
    expect: &Expectations,
    now: u64,
) -> Result<AccessToken, Refusal> {
    let payload = verified_payload(token, keys, &expect.algorithms, is_access_token)?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| Refusal::Malformed)?;
    let (Some(iss), Some(aud), Some(exp), Some(iat), Some(sub), Some(client_id), Some(jti)) = (
        claims.iss,
        claims.aud,
        claims.exp,
        claims.iat,
        claims.sub,
        claims.client_id,
        claims.jti,
    ) else {
        return Err(Refusal::Malformed);
    };
    if iss != expect.issuer {
        return Err(Refusal::WrongIssuer);
    }
    if !names(&aud, &expect.audience) {
        return Err(Refusal::WrongAudience);
    }
    if now > exp.saturating_add(LEEWAY_SECS) {
        return Err(Refusal::Expired);
    }
    let soonest = now.saturating_add(LEEWAY_SECS);
    if iat > soonest || claims.nbf.is_some_and(|nbf| nbf > soonest) {
        return Err(Refusal::NotYetValid);
    }
    Ok(AccessToken {
        issuer: iss,
        subject: sub,
        client_id,
        scopes: claims
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        expires_at: exp,
        issued_at: iat,
        jti,
        confirmation: claims.cnf.and_then(|cnf| cnf.jkt),
    })
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
