use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use serde_json::json;

use super::{Algorithm, Expectations, KeySet, Refusal, validate};
use crate::test_keys::Signer;

const ISSUER: &str = "https://id.example.com/acme";
const AUDIENCE: &str = "https://api.example.com";
const NOW: u64 = 1_800_000_000;

fn set(entries: &[String]) -> KeySet {
    KeySet::parse(&format!(r#"{{"keys":[{}]}}"#, entries.join(","))).expect("a key set")
}

fn header(alg: &str, kid: &str) -> String {
    format!(r#"{{"alg":"{alg}","typ":"at+jwt","kid":"{kid}"}}"#)
}

fn claims(iss: &str, aud: &str, exp: u64) -> String {
    json!({
        "iss": iss, "exp": exp, "aud": aud, "sub": "p-7f3a", "client_id": "portal", "iat": NOW - 10, "jti": "j-1",
        "scope": "api:read api:write",
    })
    .to_string()
}

/// A claim set for this issuer and audience with `changes` applied; a `null` change leaves the claim out.
fn with(changes: serde_json::Value) -> String {
    let mut base = json!({
        "iss": ISSUER, "exp": NOW + 300, "aud": AUDIENCE, "sub": "s", "client_id": "c", "iat": NOW, "jti": "j",
        "scope": "a",
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

fn expect(algorithms: &[Algorithm]) -> Expectations {
    Expectations::new(ISSUER, AUDIENCE, algorithms).expect("expectations")
}

#[test]
fn a_token_the_issuer_signed_for_this_audience_is_read() {
    for (signer, alg, algorithm) in [
        (Signer::es256(), "ES256", Algorithm::Es256),
        (Signer::eddsa(), "EdDSA", Algorithm::EdDsa),
    ] {
        let keys = set(&[signer.jwk("k1")]);
        let token = signer.sign(&header(alg, "k1"), &claims(ISSUER, AUDIENCE, NOW + 300));
        let read = validate(&token, &keys, &expect(&[algorithm]), NOW).expect("valid");
        assert_eq!(read.issuer, ISSUER);
        assert_eq!(read.subject, "p-7f3a");
        assert_eq!(read.client_id, "portal");
        assert_eq!(read.scopes, ["api:read", "api:write"]);
        assert_eq!(read.expires_at, NOW + 300);
        assert_eq!(read.jti, "j-1");
        assert_eq!(read.confirmation, None);
    }
}

#[test]
fn the_algorithm_comes_from_the_expectations_never_from_the_token() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let body = claims(ISSUER, AUDIENCE, NOW + 300);
    let only_eddsa = expect(&[Algorithm::EdDsa]);
    let token = signer.sign(&header("ES256", "k1"), &body);
    assert_eq!(
        validate(&token, &keys, &only_eddsa, NOW),
        Err(Refusal::AlgorithmNotAllowed)
    );
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"at+jwt","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(&body)
    );
    assert_eq!(
        validate(&none, &keys, &expect(&[Algorithm::Es256]), NOW),
        Err(Refusal::AlgorithmNotAllowed)
    );
    let hmac = signer.sign(r#"{"alg":"HS256","typ":"at+jwt","kid":"k1"}"#, &body);
    assert_eq!(
        validate(&hmac, &keys, &expect(&[Algorithm::Es256]), NOW),
        Err(Refusal::AlgorithmNotAllowed)
    );
    // A key set entry for one algorithm never verifies a token claiming the other.
    let eddsa = Signer::eddsa();
    let mixed = set(&[signer.jwk("k1"), eddsa.jwk("k2")]);
    let crossed = signer.sign(&header("EdDSA", "k1"), &body);
    let both = expect(&[Algorithm::Es256, Algorithm::EdDsa]);
    assert_eq!(
        validate(&crossed, &mixed, &both, NOW),
        Err(Refusal::UnknownKey)
    );
}

#[test]
fn only_an_access_token_is_taken() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let body = claims(ISSUER, AUDIENCE, NOW + 300);
    for typ in [r#""JWT""#, r#""dpop+jwt""#, "null"] {
        let token = signer.sign(
            &format!(r#"{{"alg":"ES256","typ":{typ},"kid":"k1"}}"#),
            &body,
        );
        assert_eq!(
            validate(&token, &keys, &expect(&[Algorithm::Es256]), NOW),
            Err(Refusal::WrongType),
            "{typ}"
        );
    }
    let token = signer.sign(
        r#"{"alg":"ES256","typ":"application/at+jwt","kid":"k1"}"#,
        &body,
    );
    assert!(validate(&token, &keys, &expect(&[Algorithm::Es256]), NOW).is_ok());
}

#[test]
fn the_key_is_found_only_in_the_issuers_set() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let body = claims(ISSUER, AUDIENCE, NOW + 300);
    let expectations = expect(&[Algorithm::Es256]);
    let unknown = signer.sign(&header("ES256", "k9"), &body);
    assert_eq!(
        validate(&unknown, &keys, &expectations, NOW),
        Err(Refusal::UnknownKey)
    );
    let no_kid = signer.sign(r#"{"alg":"ES256","typ":"at+jwt"}"#, &body);
    assert_eq!(
        validate(&no_kid, &keys, &expectations, NOW),
        Err(Refusal::UnknownKey)
    );
    // A key the token carries is never used, even when it is the signer's own.
    let carried = signer.sign(
        &format!(
            r#"{{"alg":"ES256","typ":"at+jwt","kid":"k9","jwk":{}}}"#,
            signer.jwk("k9")
        ),
        &body,
    );
    assert_eq!(
        validate(&carried, &keys, &expectations, NOW),
        Err(Refusal::UnknownKey)
    );
    let other = Signer::es256();
    let forged = other.sign(&header("ES256", "k1"), &body);
    assert_eq!(
        validate(&forged, &keys, &expectations, NOW),
        Err(Refusal::BadSignature)
    );
}

#[test]
fn a_tampered_or_malformed_token_is_refused() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let expectations = expect(&[Algorithm::Es256]);
    let token = signer.sign(&header("ES256", "k1"), &claims(ISSUER, AUDIENCE, NOW + 300));
    let mut parts: Vec<&str> = token.split('.').collect();
    let widened = URL_SAFE_NO_PAD.encode(claims(ISSUER, AUDIENCE, NOW + 99_999));
    parts[1] = &widened;
    assert_eq!(
        validate(&parts.join("."), &keys, &expectations, NOW),
        Err(Refusal::BadSignature)
    );
    for bad in ["", "a.b", "a.b.c.d", "!!.??.**", &format!("{token}x")] {
        assert!(validate(bad, &keys, &expectations, NOW).is_err(), "{bad}");
    }
    let critical = signer.sign(
        r#"{"alg":"ES256","typ":"at+jwt","kid":"k1","crit":["exp"]}"#,
        &claims(ISSUER, AUDIENCE, NOW + 300),
    );
    assert_eq!(
        validate(&critical, &keys, &expectations, NOW),
        Err(Refusal::Malformed)
    );
}

#[test]
fn the_issuer_must_be_this_tenants_and_the_audience_this_resource() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let expectations = expect(&[Algorithm::Es256]);
    let other_tenant = signer.sign(
        &header("ES256", "k1"),
        &claims("https://id.example.com/initech", AUDIENCE, NOW + 300),
    );
    assert_eq!(
        validate(&other_tenant, &keys, &expectations, NOW),
        Err(Refusal::WrongIssuer)
    );
    let prefix = signer.sign(
        &header("ES256", "k1"),
        &claims("https://id.example.com/acme2", AUDIENCE, NOW + 300),
    );
    assert_eq!(
        validate(&prefix, &keys, &expectations, NOW),
        Err(Refusal::WrongIssuer)
    );
    let elsewhere = signer.sign(
        &header("ES256", "k1"),
        &claims(ISSUER, "https://billing.example.com", NOW + 300),
    );
    assert_eq!(
        validate(&elsewhere, &keys, &expectations, NOW),
        Err(Refusal::WrongAudience)
    );
    let listed = signer.sign(
        &header("ES256", "k1"),
        &with(json!({"exp": NOW + 300, "aud": ["https://billing.example.com", AUDIENCE]})),
    );
    assert!(
        validate(&listed, &keys, &expectations, NOW).is_ok(),
        "aud as a list naming this resource"
    );
}

#[test]
fn time_is_judged_with_a_bounded_leeway() {
    let signer = Signer::es256();
    let keys = set(&[signer.jwk("k1")]);
    let expectations = expect(&[Algorithm::Es256]);
    let expired = signer.sign(&header("ES256", "k1"), &claims(ISSUER, AUDIENCE, NOW - 61));
    assert_eq!(
        validate(&expired, &keys, &expectations, NOW),
        Err(Refusal::Expired)
    );
    let just = signer.sign(&header("ES256", "k1"), &claims(ISSUER, AUDIENCE, NOW - 30));
    assert!(
        validate(&just, &keys, &expectations, NOW).is_ok(),
        "within the leeway"
    );
    let early = signer.sign(
        &header("ES256", "k1"),
        &with(json!({"exp": NOW + 900, "nbf": NOW + 300})),
    );
    assert_eq!(
        validate(&early, &keys, &expectations, NOW),
        Err(Refusal::NotYetValid)
    );
    let future = signer.sign(
        &header("ES256", "k1"),
        &with(json!({"exp": NOW + 900, "iat": NOW + 300})),
    );
    assert_eq!(
        validate(&future, &keys, &expectations, NOW),
        Err(Refusal::NotYetValid)
    );
    let no_exp = signer.sign(&header("ES256", "k1"), &with(json!({"exp": null})));
    assert_eq!(
        validate(&no_exp, &keys, &expectations, NOW),
        Err(Refusal::Malformed)
    );
}

#[test]
fn a_bound_token_names_its_key_for_the_proof_check() {
    let signer = Signer::eddsa();
    let keys = set(&[signer.jwk("k1")]);
    let token = signer.sign(
        &header("EdDSA", "k1"),
        &with(json!({"exp": NOW + 300, "cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}})),
    );
    let read = validate(&token, &keys, &expect(&[Algorithm::EdDsa]), NOW).expect("valid");
    assert_eq!(
        read.confirmation.as_deref(),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
    );
}

#[test]
fn a_key_set_is_read_whole_or_refused() {
    let signer = Signer::es256();
    let unknown_kind = r#"{"kty":"RSA","kid":"r1","n":"AQAB","e":"AQAB"}"#.to_owned();
    let keys = set(&[unknown_kind, signer.jwk("k1")]);
    assert!(
        keys.contains("k1") && !keys.contains("r1"),
        "a kind it cannot use is skipped"
    );
    for bad in [
        "",
        "{}",
        r#"{"keys":{}}"#,
        r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":"AA","y":"AA"}]}"#,
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}"#,
    ] {
        assert!(KeySet::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn expectations_name_one_issuer_one_audience_and_at_least_one_algorithm() {
    assert!(Expectations::new(ISSUER, AUDIENCE, &[]).is_err());
    assert!(Expectations::new("", AUDIENCE, &[Algorithm::Es256]).is_err());
    assert!(Expectations::new(ISSUER, "", &[Algorithm::Es256]).is_err());
}
