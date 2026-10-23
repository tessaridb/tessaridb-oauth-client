use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};

use super::{Jwk, Proof, ProofRefusal, read, thumbprint, validate_proof};
use crate::relying::DpopKey;
use crate::resource::{AccessToken, Algorithm};
use crate::test_keys::Signer;

const NOW: u64 = 1_800_000_000;
const URL: &str = "https://api.example.com/v1/orders";
const TOKEN: &str = "at-1";
const BOTH: [Algorithm; 2] = [Algorithm::Es256, Algorithm::EdDsa];

/// The thumbprint of the key in the header of `proof`.
fn bound_key(proof: &str) -> String {
    let header = proof.split('.').next().expect("a header");
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64url")).expect("JSON");
    let algorithm = if header["alg"] == "EdDSA" {
        Algorithm::EdDsa
    } else {
        Algorithm::Es256
    };
    let jwk: Jwk = serde_json::from_value(header["jwk"].clone()).expect("a jwk");
    thumbprint(&read(&jwk, algorithm).expect("a key").1)
}

fn token(confirmation: Option<String>) -> AccessToken {
    AccessToken {
        issuer: "https://id.example.com/acme".to_owned(),
        subject: "p-7f3a".to_owned(),
        client_id: "portal".to_owned(),
        scopes: vec!["api:read".to_owned()],
        expires_at: NOW + 300,
        issued_at: NOW,
        jti: "t-1".to_owned(),
        confirmation,
    }
}

fn ath(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, token.as_bytes()))
}

/// A proof by `signer` with `typ` and `claims`, its header carrying the signer's public key.
fn signed(signer: &Signer, alg: &str, typ: &str, claims: &str) -> String {
    signer.sign(
        &format!(
            r#"{{"typ":"{typ}","alg":"{alg}","jwk":{}}}"#,
            signer.jwk("k")
        ),
        claims,
    )
}

fn claims(htm: &str, htu: &str, iat: u64, ath: &str) -> String {
    format!(r#"{{"jti":"p-1","htm":"{htm}","htu":"{htu}","iat":{iat},"ath":"{ath}"}}"#)
}

fn check(proof: &str, bound: Option<String>) -> Result<Proof, ProofRefusal> {
    validate_proof(proof, &token(bound), TOKEN, "GET", URL, &BOTH, NOW)
}

#[test]
fn the_thumbprint_is_rfc_7638_over_the_required_members() {
    let jwk: Jwk = serde_json::from_str(
        r#"{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","kid":"ignored"}"#,
    )
    .expect("a jwk");
    let (_, members) = read(&jwk, Algorithm::Es256).expect("a key");
    assert_eq!(
        thumbprint(&members),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
    assert_eq!(
        ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
        "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
        "RFC 9449 section 7.1"
    );
}

#[test]
fn a_proof_from_the_bound_key_for_this_request_and_token_is_accepted() {
    let key = DpopKey::generate().expect("a key");
    let proof = key
        .proof(
            "GET",
            "https://api.example.com/v1/orders?page=2",
            Some(TOKEN),
            NOW,
        )
        .expect("a proof");
    let accepted = check(&proof, Some(bound_key(&proof))).expect("accepted");
    assert_eq!(accepted.issued_at, NOW);
    assert_eq!(accepted.jti.len(), 22);
    let signer = Signer::eddsa();
    let proof = signed(
        &signer,
        "EdDSA",
        "dpop+jwt",
        &claims("GET", URL, NOW, &ath(TOKEN)),
    );
    assert_eq!(
        check(&proof, Some(bound_key(&proof))).map(|proof| proof.jti),
        Ok("p-1".to_owned())
    );
}

#[test]
fn a_bound_token_with_another_keys_proof_or_an_unbound_token_is_refused() {
    let signer = Signer::es256();
    let proof = signed(
        &signer,
        "ES256",
        "dpop+jwt",
        &claims("GET", URL, NOW, &ath(TOKEN)),
    );
    let other = signed(
        &Signer::es256(),
        "ES256",
        "dpop+jwt",
        &claims("GET", URL, NOW, &ath(TOKEN)),
    );
    assert_eq!(
        check(&proof, Some(bound_key(&other))),
        Err(ProofRefusal::KeyMismatch)
    );
    assert_eq!(check(&proof, None), Err(ProofRefusal::NotBound));
}

#[test]
fn a_proof_for_another_request_time_or_token_is_refused() {
    let signer = Signer::es256();
    let make = |htm: &str, htu: &str, iat: u64, hash: &str| {
        let proof = signed(&signer, "ES256", "dpop+jwt", &claims(htm, htu, iat, hash));
        check(&proof, Some(bound_key(&proof)))
    };
    let hash = ath(TOKEN);
    assert_eq!(
        make("POST", URL, NOW, &hash),
        Err(ProofRefusal::WrongRequest)
    );
    assert_eq!(
        make("GET", "https://api.example.com/v1/admin", NOW, &hash),
        Err(ProofRefusal::WrongRequest)
    );
    assert_eq!(
        make("GET", "not a url", NOW, &hash),
        Err(ProofRefusal::WrongRequest)
    );
    assert!(
        make("GET", "HTTPS://API.example.com:443/v1/orders", NOW, &hash).is_ok(),
        "normalised"
    );
    assert_eq!(make("GET", URL, NOW - 61, &hash), Err(ProofRefusal::Stale));
    assert_eq!(make("GET", URL, NOW + 61, &hash), Err(ProofRefusal::Stale));
    assert!(
        make("GET", URL, NOW - 60, &hash).is_ok(),
        "within the leeway"
    );
    assert_eq!(
        make("GET", URL, NOW, &ath("at-2")),
        Err(ProofRefusal::WrongToken)
    );
    let no_hash = signed(
        &signer,
        "ES256",
        "dpop+jwt",
        &format!(r#"{{"jti":"p-1","htm":"GET","htu":"{URL}","iat":{NOW}}}"#),
    );
    assert_eq!(
        check(&no_hash, Some(bound_key(&no_hash))),
        Err(ProofRefusal::WrongToken)
    );
}

#[test]
fn a_proof_of_another_type_algorithm_or_a_forged_one_is_refused() {
    let signer = Signer::es256();
    let body = claims("GET", URL, NOW, &ath(TOKEN));
    let typed = signed(&signer, "ES256", "JWT", &body);
    assert_eq!(
        check(&typed, Some(bound_key(&typed))),
        Err(ProofRefusal::WrongType)
    );
    let proof = signed(&signer, "ES256", "dpop+jwt", &body);
    let bound = Some(bound_key(&proof));
    assert_eq!(
        validate_proof(
            &proof,
            &token(bound.clone()),
            TOKEN,
            "GET",
            URL,
            &[Algorithm::EdDsa],
            NOW
        ),
        Err(ProofRefusal::AlgorithmNotAllowed)
    );
    let named_wrong = signed(&signer, "EdDSA", "dpop+jwt", &body);
    assert_eq!(
        check(&named_wrong, bound.clone()),
        Err(ProofRefusal::AlgorithmNotAllowed)
    );
    let (input, _) = proof.rsplit_once('.').expect("a JWS");
    let forged = format!("{input}.{}", URL_SAFE_NO_PAD.encode([7_u8; 64]));
    assert_eq!(
        check(&forged, bound.clone()),
        Err(ProofRefusal::BadSignature)
    );
    let with_private = signer.sign(
        &format!(
            r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#,
            signer.jwk("k").replacen('{', r#"{"d":"AAAA","#, 1)
        ),
        &body,
    );
    assert_eq!(check(&with_private, bound), Err(ProofRefusal::Malformed));
    assert_eq!(check("a.b", None), Err(ProofRefusal::Malformed));
}
