use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde_json::Value;

use super::DpopKey;

const NOW: u64 = 1_800_000_000;

fn decode(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
}

/// The header and claims of `proof`, once its signature verifies with the key its header carries.
pub(crate) fn verified(proof: &str) -> (Value, Value) {
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWS");
    let header = decode(parts[0]);
    let coordinate = |name: &str| {
        URL_SAFE_NO_PAD
            .decode(header["jwk"][name].as_str().expect("a coordinate"))
            .expect("base64url")
    };
    let mut point = vec![4_u8];
    point.extend(coordinate("x"));
    point.extend(coordinate("y"));
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("signed by the key it carries");
    (header, decode(parts[1]))
}

#[test]
fn a_proof_is_signed_by_the_public_key_it_carries_and_names_this_request() {
    let key = DpopKey::generate().expect("a key");
    let proof = key
        .proof(
            "POST",
            "https://id.example.com/acme/oauth2/token",
            None,
            NOW,
        )
        .expect("a proof");
    let (header, claims) = verified(&proof);
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-256");
    assert!(
        header["jwk"].get("d").is_none(),
        "the private part never leaves"
    );
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], "https://id.example.com/acme/oauth2/token");
    assert_eq!(claims["iat"], NOW);
    assert_eq!(
        claims["jti"].as_str().map(str::len),
        Some(22),
        "128 random bits"
    );
    assert!(claims.get("ath").is_none(), "no token presented, no hash");
    let again = key
        .proof(
            "POST",
            "https://id.example.com/acme/oauth2/token",
            None,
            NOW,
        )
        .expect("a proof");
    assert_ne!(
        verified(&again).1["jti"],
        claims["jti"],
        "one jti per proof"
    );
    assert_eq!(
        verified(&again).0["jwk"],
        header["jwk"],
        "one key across proofs"
    );
}

#[test]
fn a_proof_names_the_address_without_its_query_or_fragment() {
    let key = DpopKey::generate().expect("a key");
    let proof = key
        .proof(
            "GET",
            "https://api.example.com/v1/orders?page=2#top",
            None,
            NOW,
        )
        .expect("a proof");
    assert_eq!(
        verified(&proof).1["htu"],
        "https://api.example.com/v1/orders"
    );
    assert!(key.proof("GET", "not a url", None, NOW).is_err());
}

#[test]
fn a_proof_presenting_an_access_token_carries_its_hash() {
    let key = DpopKey::generate().expect("a key");
    let proof = key
        .proof(
            "GET",
            "https://api.example.com/v1/orders",
            Some("at-1"),
            NOW,
        )
        .expect("a proof");
    let expected = URL_SAFE_NO_PAD.encode(digest(&SHA256, b"at-1"));
    assert_eq!(verified(&proof).1["ath"], expected.as_str());
}

#[test]
fn a_key_never_prints_its_material() {
    let key = DpopKey::generate().expect("a key");
    let proof = key
        .proof("GET", "https://a.example/", None, NOW)
        .expect("a proof");
    let x = verified(&proof).0["jwk"]["x"]
        .as_str()
        .map(str::to_owned)
        .expect("x");
    assert_eq!(format!("{key:?}"), "DpopKey(ES256)");
    assert!(!format!("{key:?}").contains(&x));
}
