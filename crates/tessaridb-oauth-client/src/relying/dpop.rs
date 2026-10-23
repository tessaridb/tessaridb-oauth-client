//! DPoP proofs (RFC 9449): a key the client holds, and for each request a signed statement that the holder of that
//! key is making this request now. The issuer binds the tokens it issues to the key, so a stolen token is useless
//! without it; a proof presenting an access token also carries its hash, so it cannot be paired with another one.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Serialize;
use url::Url;

use crate::{Error, Result};

/// Random bytes in a proof's `jti`: 128 bits.
const JTI_BYTES: usize = 16;

/// The public half of the key, as a proof carries it (RFC 7518 section 6.2.1).
#[derive(Serialize)]
struct PublicKey {
    kty: &'static str,
    crv: &'static str,
    x: String,
    y: String,
}

#[derive(Serialize)]
struct Header<'a> {
    typ: &'static str,
    alg: &'static str,
    jwk: &'a PublicKey,
}

#[derive(Serialize)]
struct Claims<'a> {
    jti: String,
    htm: &'a str,
    htu: &'a str,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

/// A client's proof-of-possession key: ES256, held in this process's memory and never written out.
pub struct DpopKey {
    pair: EcdsaKeyPair,
    public: PublicKey,
    random: SystemRandom,
}

impl fmt::Debug for DpopKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopKey(ES256)")
    }
}

impl DpopKey {
    /// A fresh key.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the system's random source fails.
    pub fn generate() -> Result<Self> {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| Error::Random)?;
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .map_err(|_| Error::Random)?;
        // An uncompressed P-256 point: the tag 0x04, then x and y of 32 bytes each.
        let point = pair.public_key().as_ref();
        let (Some(x), Some(y)) = (point.get(1..33), point.get(33..65)) else {
            return Err(Error::Random);
        };
        let public = PublicKey {
            kty: "EC",
            crv: "P-256",
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        };
        Ok(Self {
            pair,
            public,
            random,
        })
    }

    /// A proof for a `method` request to `url` at `now` (Unix seconds), presenting `access_token` when given.
    ///
    /// # Errors
    ///
    /// [`Error::Client`] when `url` is not a URL; [`Error::Random`] when no `jti` or signature can be made.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: u64,
    ) -> Result<String> {
        let mut target =
            Url::parse(url).map_err(|_| Error::Client("the request address is not a URL"))?;
        target.set_query(None);
        target.set_fragment(None);
        let mut jti = [0_u8; JTI_BYTES];
        self.random.fill(&mut jti).map_err(|_| Error::Random)?;
        let header = Header {
            typ: "dpop+jwt",
            alg: "ES256",
            jwk: &self.public,
        };
        let claims = Claims {
            jti: URL_SAFE_NO_PAD.encode(jti),
            htm: method,
            htu: target.as_str(),
            iat: now,
            ath: access_token
                .map(|token| URL_SAFE_NO_PAD.encode(digest(&SHA256, token.as_bytes()))),
        };
        let header = serde_json::to_vec(&header)
            .map_err(|_| Error::Client("the proof cannot be encoded"))?;
        let claims = serde_json::to_vec(&claims)
            .map_err(|_| Error::Client("the proof cannot be encoded"))?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = self
            .pair
            .sign(&self.random, signing_input.as_bytes())
            .map_err(|_| Error::Random)?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

#[cfg(test)]
#[path = "dpop_tests.rs"]
pub(crate) mod tests;
