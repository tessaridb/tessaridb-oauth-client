//! The ID token of a sign-in (OpenID Connect Core 3.1.3.7): signed by the issuer's key, from that issuer, for this
//! client, current, and carrying the `nonce` of the request it answers. An access token or a DPoP proof never passes
//! as one, because its `typ` says what it is.

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::resource::{Expectations, KeySet, LEEWAY_SECS, Refusal, verified_payload};

/// What a valid ID token says about the sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdToken {
    /// The user, as this client knows them.
    pub subject: String,
    /// Unix seconds when the user signed in.
    pub auth_time: Option<u64>,
    /// The assurance the sign-in reached.
    pub acr: Option<String>,
    /// How the user signed in.
    pub amr: Vec<String>,
    /// The issuer's session, which a logout names.
    pub sid: Option<String>,
    /// Unix seconds after which it is no longer valid.
    pub expires_at: u64,
}

/// Why an ID token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdRefusal {
    /// A check it shares with an access token failed.
    #[error(transparent)]
    Token(Refusal),
    /// Not the `nonce` of the request it answers, or none.
    #[error("the ID token answers another request")]
    NonceMismatch,
    /// Addressed to several clients without naming this one as the party it was issued to, or naming another.
    #[error("the ID token was issued to another party")]
    WrongParty,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<u64>,
    iat: Option<u64>,
    azp: Option<String>,
    auth_time: Option<u64>,
    nonce: Option<String>,
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    sid: Option<String>,
}

/// An ID token's `typ`, when it has one: `JWT`, never an access token's or a proof's.
fn is_id_token(typ: Option<&str>) -> bool {
    typ.is_none_or(|typ| typ.eq_ignore_ascii_case("JWT"))
}

/// `token` verified under `keys`, judged against `expect` (whose audience is this client's id) at `now`, and matched to
/// the request whose `nonce` it must carry.
///
/// # Errors
///
/// The [`IdRefusal`] of the first check it fails.
pub fn validate_id_token(
    token: &str,
    keys: &KeySet,
    expect: &Expectations,
    nonce: &str,
    now: u64,
) -> Result<IdToken, IdRefusal> {
    let payload =
        verified_payload(token, keys, &expect.algorithms, is_id_token).map_err(IdRefusal::Token)?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| IdRefusal::Token(Refusal::Malformed))?;
    let (Some(iss), Some(sub), Some(aud), Some(exp), Some(iat)) =
        (claims.iss, claims.sub, claims.aud, claims.exp, claims.iat)
    else {
        return Err(IdRefusal::Token(Refusal::Malformed));
    };
    if iss != expect.issuer {
        return Err(IdRefusal::Token(Refusal::WrongIssuer));
    }
    let client = expect.audience.as_str();
    let audiences = match &aud {
        Audience::One(one) => vec![one.as_str()],
        Audience::Many(many) => many.iter().map(String::as_str).collect(),
    };
    if !audiences.contains(&client) {
        return Err(IdRefusal::Token(Refusal::WrongAudience));
    }
    let party = claims.azp.as_deref();
    if party.is_some_and(|party| party != client) || (audiences.len() > 1 && party.is_none()) {
        return Err(IdRefusal::WrongParty);
    }
    if now > exp.saturating_add(LEEWAY_SECS) {
        return Err(IdRefusal::Token(Refusal::Expired));
    }
    if iat > now.saturating_add(LEEWAY_SECS) {
        return Err(IdRefusal::Token(Refusal::NotYetValid));
    }
    let matches = claims
        .nonce
        .as_deref()
        .is_some_and(|carried| bool::from(carried.as_bytes().ct_eq(nonce.as_bytes())));
    if !matches {
        return Err(IdRefusal::NonceMismatch);
    }
    Ok(IdToken {
        subject: sub,
        auth_time: claims.auth_time,
        acr: claims.acr,
        amr: claims.amr,
        sid: claims.sid,
        expires_at: exp,
    })
}

#[cfg(test)]
#[path = "id_token_tests.rs"]
mod tests;
