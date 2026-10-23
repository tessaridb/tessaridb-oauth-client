use serde_json::json;

use super::{IdRefusal, validate_id_token};
use crate::resource::{Algorithm, Expectations, KeySet, Refusal};
use crate::test_keys::Signer;

const ISSUER: &str = "https://id.example.com/acme";
const CLIENT: &str = "portal";
const NONCE: &str = "n-0S6_WzA2Mj";
const NOW: u64 = 1_800_000_000;

fn keys(signer: &Signer) -> KeySet {
    KeySet::parse(&format!(r#"{{"keys":[{}]}}"#, signer.jwk("k1"))).expect("a key set")
}

fn expect() -> Expectations {
    Expectations::new(ISSUER, CLIENT, &[Algorithm::Es256]).expect("expectations")
}

/// An ID token claim set for this client with `changes` applied; a `null` change leaves the claim out.
fn claims(changes: serde_json::Value) -> String {
    let mut base = json!({
        "iss": ISSUER, "sub": "p-7f3a", "aud": CLIENT, "exp": NOW + 300, "iat": NOW, "auth_time": NOW - 20,
        "nonce": NONCE, "acr": "urn:tessaridb:acr:2fa", "amr": ["pwd", "otp"], "sid": "s-1",
    });
    if let (Some(fields), Some(changes)) = (base.as_object_mut(), changes.as_object()) {
        for (name, value) in changes {
            if value.is_null() {
                fields.remove(name);
            } else {
                fields.insert(name.clone(), value.clone());
            }
        }
    }
    base.to_string()
}

fn signed(signer: &Signer, typ: &str, changes: serde_json::Value) -> String {
    signer.sign(
        &format!(r#"{{"alg":"ES256","typ":{typ},"kid":"k1"}}"#),
        &claims(changes),
    )
}

#[test]
fn an_id_token_for_this_client_and_this_request_is_read() {
    let signer = Signer::es256();
    let token = signed(&signer, r#""JWT""#, json!({}));
    let read = validate_id_token(&token, &keys(&signer), &expect(), NONCE, NOW).expect("valid");
    assert_eq!(read.subject, "p-7f3a");
    assert_eq!(read.auth_time, Some(NOW - 20));
    assert_eq!(read.acr.as_deref(), Some("urn:tessaridb:acr:2fa"));
    assert_eq!(read.amr, ["pwd", "otp"]);
    assert_eq!(read.sid.as_deref(), Some("s-1"));
    let untyped = signed(&signer, "null", json!({}));
    assert!(validate_id_token(&untyped, &keys(&signer), &expect(), NONCE, NOW).is_ok());
}

#[test]
fn another_requests_nonce_or_none_is_refused() {
    let signer = Signer::es256();
    let other = signed(&signer, r#""JWT""#, json!({"nonce": "n-other"}));
    assert_eq!(
        validate_id_token(&other, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::NonceMismatch)
    );
    let none = signed(&signer, r#""JWT""#, json!({"nonce": null}));
    assert_eq!(
        validate_id_token(&none, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::NonceMismatch)
    );
}

#[test]
fn an_id_token_for_another_client_or_issuer_is_refused() {
    let signer = Signer::es256();
    let elsewhere = signed(&signer, r#""JWT""#, json!({"aud": "kiosk"}));
    assert_eq!(
        validate_id_token(&elsewhere, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::Token(Refusal::WrongAudience))
    );
    let mixed_up = signed(
        &signer,
        r#""JWT""#,
        json!({"iss": "https://evil.example.com/acme"}),
    );
    assert_eq!(
        validate_id_token(&mixed_up, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::Token(Refusal::WrongIssuer))
    );
    let shared = signed(&signer, r#""JWT""#, json!({"aud": [CLIENT, "kiosk"]}));
    assert_eq!(
        validate_id_token(&shared, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::WrongParty),
        "several audiences and no azp naming this client"
    );
    let named = signed(
        &signer,
        r#""JWT""#,
        json!({"aud": [CLIENT, "kiosk"], "azp": CLIENT}),
    );
    assert!(validate_id_token(&named, &keys(&signer), &expect(), NONCE, NOW).is_ok());
    let other_party = signed(&signer, r#""JWT""#, json!({"azp": "kiosk"}));
    assert_eq!(
        validate_id_token(&other_party, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::WrongParty)
    );
}

#[test]
fn an_access_token_or_a_proof_never_passes_as_an_id_token() {
    let signer = Signer::es256();
    for typ in [r#""at+jwt""#, r#""dpop+jwt""#] {
        let token = signed(&signer, typ, json!({}));
        assert_eq!(
            validate_id_token(&token, &keys(&signer), &expect(), NONCE, NOW),
            Err(IdRefusal::Token(Refusal::WrongType)),
            "{typ}"
        );
    }
}

#[test]
fn an_expired_or_forged_id_token_is_refused() {
    let signer = Signer::es256();
    let expired = signed(&signer, r#""JWT""#, json!({"exp": NOW - 61}));
    assert_eq!(
        validate_id_token(&expired, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::Token(Refusal::Expired))
    );
    let forged = signed(&Signer::es256(), r#""JWT""#, json!({}));
    assert_eq!(
        validate_id_token(&forged, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::Token(Refusal::BadSignature))
    );
    let no_subject = signed(&signer, r#""JWT""#, json!({"sub": null}));
    assert_eq!(
        validate_id_token(&no_subject, &keys(&signer), &expect(), NONCE, NOW),
        Err(IdRefusal::Token(Refusal::Malformed))
    );
}
