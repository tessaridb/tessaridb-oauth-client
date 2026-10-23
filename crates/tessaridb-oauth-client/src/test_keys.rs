//! Keys that sign the way the issuer does, for this crate's tests.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

/// A key that signs the way the issuer does, with its key-set entry.
pub(crate) enum Signer {
    Es256(EcdsaKeyPair),
    EdDsa(Ed25519KeyPair),
}

impl Signer {
    pub(crate) fn es256() -> Self {
        let random = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).expect("a key");
        Self::Es256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .expect("a key pair"),
        )
    }

    pub(crate) fn eddsa() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key");
        Self::EdDsa(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key pair"))
    }

    pub(crate) fn jwk(&self, kid: &str) -> String {
        match self {
            Self::Es256(pair) => {
                let point = pair.public_key().as_ref();
                format!(
                    r#"{{"kty":"EC","crv":"P-256","kid":"{kid}","use":"sig","alg":"ES256","x":"{}","y":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode(&point[1..33]),
                    URL_SAFE_NO_PAD.encode(&point[33..65])
                )
            }
            Self::EdDsa(pair) => format!(
                r#"{{"kty":"OKP","crv":"Ed25519","kid":"{kid}","use":"sig","alg":"EdDSA","x":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())
            ),
        }
    }

    pub(crate) fn sign(&self, header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = match self {
            Self::Es256(pair) => pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .expect("signed")
                .as_ref()
                .to_vec(),
            Self::EdDsa(pair) => pair.sign(input.as_bytes()).as_ref().to_vec(),
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}
