//! A DPoP-bound access token at a resource (RFC 9449 section 7): the token is accepted only with a proof, signed by
//! the key the token names in `cnf.jkt`, for this request, made now, and carrying this token's hash. A token whose
//! [`AccessToken::confirmation`] is set is refused without such a proof; accepting it as a bearer token is the
//! downgrade the binding exists to prevent. The proof's `jti` is handed back for the caller's replay store.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use url::Url;

use super::expectations::LEEWAY_SECS;
use super::keys::{PublicKey, UNCOMPRESSED, coordinate};
use super::validate::{decoded, verified};
use super::{AccessToken, Algorithm, Refusal};

/// The `typ` of a DPoP proof (RFC 9449 section 4.2).
const PROOF_TYPE: &str = "dpop+jwt";

/// The check a proof failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofRefusal {
    /// Not a compact JWS, an unreadable part, a private key in its header, or a required claim missing.
    #[error("the proof is malformed")]
    Malformed,
    /// A `typ` other than a proof's.
    #[error("not a DPoP proof")]
    WrongType,
    /// An algorithm outside the ones this resource accepts, or a key of another kind than it names.
    #[error("the proof's algorithm is not accepted")]
    AlgorithmNotAllowed,
    /// The signature does not verify under the key the proof carries.
    #[error("the proof's signature does not verify")]
    BadSignature,
    /// The token is not bound to a key, so it is presented as a bearer token and not with a proof.
    #[error("the token is not bound to a key")]
    NotBound,
    /// Signed by another key than the one the token is bound to.
    #[error("the proof is signed by another key than the token's")]
    KeyMismatch,
    /// Made for another method or address.
    #[error("the proof is for another request")]
    WrongRequest,
    /// Made more than the leeway away from now.
    #[error("the proof is not fresh")]
    Stale,
    /// No `ath`, or the hash of another access token.
    #[error("the proof is for another access token")]
    WrongToken,
}

/// What an accepted proof leaves for the caller: its `jti`, to be remembered until `issued_at` plus the leeway has
/// passed and refused if it comes again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The proof's unique identifier.
    pub jti: String,
    /// Unix seconds when it was made.
    pub issued_at: u64,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct Header {
    typ: Option<String>,
    alg: String,
    jwk: Option<Jwk>,
}

#[derive(Deserialize)]
struct Claims {
    jti: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<u64>,
    ath: Option<String>,
}

/// The key `jwk` as the verifier takes it, and its RFC 7638 thumbprint input.
fn read(jwk: &Jwk, algorithm: Algorithm) -> Result<(PublicKey, String), ProofRefusal> {
    if jwk.d.is_some() {
        return Err(ProofRefusal::Malformed);
    }
    let x = jwk.x.as_ref();
    let malformed = |_| ProofRefusal::Malformed;
    match (algorithm, jwk.kty.as_str(), jwk.crv.as_deref()) {
        (Algorithm::Es256, "EC", Some("P-256")) => {
            let mut point = vec![UNCOMPRESSED];
            point.extend(coordinate(x).map_err(malformed)?);
            point.extend(coordinate(jwk.y.as_ref()).map_err(malformed)?);
            let (Some(x), Some(y)) = (&jwk.x, &jwk.y) else {
                return Err(ProofRefusal::Malformed);
            };
            let members = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
            Ok((key(algorithm, point), members))
        }
        (Algorithm::EdDsa, "OKP", Some("Ed25519")) => {
            let bytes = coordinate(x).map_err(malformed)?;
            let Some(x) = &jwk.x else {
                return Err(ProofRefusal::Malformed);
            };
            let members = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
            Ok((key(algorithm, bytes), members))
        }
        _ => Err(ProofRefusal::AlgorithmNotAllowed),
    }
}

fn key(algorithm: Algorithm, bytes: Vec<u8>) -> PublicKey {
    PublicKey {
        kid: String::new(),
        algorithm,
        bytes,
    }
}

/// The RFC 7638 thumbprint of the members of a key, in lexicographic order with no whitespace.
fn thumbprint(members: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, members.as_bytes()))
}

/// `url` with its query and fragment removed, normalised as a URL parser reads it.
fn target(url: &str) -> Option<String> {
    let mut url = Url::parse(url).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
}

/// The `proof` of a `method` request to `url` presenting `access_token`, already validated as `token`, accepted at
/// `now` (Unix seconds) when it is signed with an algorithm of `algorithms` by the key the token is bound to.
///
/// # Errors
///
/// The [`ProofRefusal`] of the first check it fails, in the order: shape, type, algorithm and key, signature,
/// binding, request, time, token hash.
pub fn validate_proof(
    proof: &str,
    token: &AccessToken,
    access_token: &str,
    method: &str,
    url: &str,
    algorithms: &[Algorithm],
    now: u64,
) -> Result<Proof, ProofRefusal> {
    let mut parts = proof.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ProofRefusal::Malformed);
    };
    let head: Header = decoded(header).map_err(|_| ProofRefusal::Malformed)?;
    if !head
        .typ
        .as_deref()
        .is_some_and(|typ| typ.eq_ignore_ascii_case(PROOF_TYPE))
    {
        return Err(ProofRefusal::WrongType);
    }
    let algorithm = algorithms
        .iter()
        .copied()
        .find(|algorithm| algorithm.name() == head.alg)
        .ok_or(ProofRefusal::AlgorithmNotAllowed)?;
    let jwk = head.jwk.as_ref().ok_or(ProofRefusal::Malformed)?;
    let (public, members) = read(jwk, algorithm)?;
    let signed = proof
        .rsplit_once('.')
        .map(|(input, _)| input)
        .ok_or(ProofRefusal::Malformed)?;
    verified(&public, signed, signature).map_err(|refusal| match refusal {
        Refusal::BadSignature => ProofRefusal::BadSignature,
        _ => ProofRefusal::Malformed,
    })?;
    let bound = token
        .confirmation
        .as_deref()
        .ok_or(ProofRefusal::NotBound)?;
    if thumbprint(&members) != bound {
        return Err(ProofRefusal::KeyMismatch);
    }
    let claims: Claims = decoded(payload).map_err(|_| ProofRefusal::Malformed)?;
    let (Some(jti), Some(htm), Some(htu), Some(iat)) =
        (claims.jti, claims.htm, claims.htu, claims.iat)
    else {
        return Err(ProofRefusal::Malformed);
    };
    if jti.is_empty() {
        return Err(ProofRefusal::Malformed);
    }
    if htm != method || target(&htu).is_none() || target(&htu) != target(url) {
        return Err(ProofRefusal::WrongRequest);
    }
    if now.abs_diff(iat) > LEEWAY_SECS {
        return Err(ProofRefusal::Stale);
    }
    let expected = URL_SAFE_NO_PAD.encode(digest(&SHA256, access_token.as_bytes()));
    if claims.ath.as_deref() != Some(expected.as_str()) {
        return Err(ProofRefusal::WrongToken);
    }
    Ok(Proof {
        jti,
        issued_at: iat,
    })
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
