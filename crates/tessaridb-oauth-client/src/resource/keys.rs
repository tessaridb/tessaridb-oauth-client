//! The issuer's published key set (RFC 7517), read once into the public keys tokens are verified with. A key of a
//! kind this crate does not verify with is skipped; a key of a kind it does, but malformed, refuses the whole set,
//! because a half-read set would quietly stop verifying the tokens of the key it dropped.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::Algorithm;
use crate::{Error, Result};

/// Bytes of one P-256 coordinate, and of an Ed25519 public key.
const COORDINATE_LEN: usize = 32;
/// The SEC 1 tag of an uncompressed elliptic-curve point.
pub(super) const UNCOMPRESSED: u8 = 0x04;

/// One public key of the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PublicKey {
    pub(super) kid: String,
    pub(super) algorithm: Algorithm,
    /// The key as the verifier takes it: an uncompressed P-256 point, or the 32 Ed25519 bytes.
    pub(super) bytes: Vec<u8>,
}

/// The keys an issuer publishes, by `kid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    keys: Vec<PublicKey>,
}

#[derive(Deserialize)]
struct Document {
    keys: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

pub(super) fn coordinate(value: Option<&String>) -> Result<Vec<u8>> {
    let bytes = value
        .map(|text| URL_SAFE_NO_PAD.decode(text))
        .ok_or(Error::KeySet("a coordinate is missing"))?
        .map_err(|_| Error::KeySet("a coordinate is not base64url"))?;
    if bytes.len() == COORDINATE_LEN {
        Ok(bytes)
    } else {
        Err(Error::KeySet("a coordinate has the wrong length"))
    }
}

/// `entry` as a key this crate verifies with, `None` for a kind it does not.
fn read(entry: &Entry) -> Result<Option<PublicKey>> {
    let algorithm = match (entry.kty.as_str(), entry.crv.as_deref()) {
        ("EC", Some("P-256")) => Algorithm::Es256,
        ("OKP", Some("Ed25519")) => Algorithm::EdDsa,
        _ => return Ok(None),
    };
    if entry.usage.as_deref().is_some_and(|usage| usage != "sig") {
        return Ok(None);
    }
    if entry
        .alg
        .as_deref()
        .is_some_and(|alg| alg != algorithm.name())
    {
        return Err(Error::KeySet(
            "a key names another algorithm than its curve",
        ));
    }
    let kid = entry
        .kid
        .clone()
        .filter(|kid| !kid.is_empty())
        .ok_or(Error::KeySet("a key has no kid"))?;
    let bytes = match algorithm {
        Algorithm::Es256 => {
            let mut point = vec![UNCOMPRESSED];
            point.extend(coordinate(entry.x.as_ref())?);
            point.extend(coordinate(entry.y.as_ref())?);
            point
        }
        Algorithm::EdDsa => coordinate(entry.x.as_ref())?,
    };
    Ok(Some(PublicKey {
        kid,
        algorithm,
        bytes,
    }))
}

impl KeySet {
    /// The key set `json`, as the issuer's `jwks_uri` serves it.
    ///
    /// # Errors
    ///
    /// [`Error::KeySet`] when it is not a key set, or a key of a kind this crate verifies with cannot be read.
    pub fn parse(json: &str) -> Result<Self> {
        let document: Document =
            serde_json::from_str(json).map_err(|_| Error::KeySet("not a JSON key set"))?;
        let mut keys = Vec::with_capacity(document.keys.len());
        for entry in &document.keys {
            if let Some(key) = read(entry)? {
                keys.push(key);
            }
        }
        Ok(Self { keys })
    }

    /// Whether the set holds a key of this `kid`.
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key.kid == kid)
    }

    /// The key of `kid` that verifies `algorithm`.
    pub(super) fn find(&self, kid: &str, algorithm: Algorithm) -> Option<&PublicKey> {
        self.keys
            .iter()
            .find(|key| key.kid == kid && key.algorithm == algorithm)
    }
}
