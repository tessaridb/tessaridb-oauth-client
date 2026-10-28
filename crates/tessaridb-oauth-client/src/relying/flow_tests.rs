use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use url::Url;

use super::{Client, Pending, ReturnRefusal, begin};

const ISSUER: &str = "https://id.example.com/acme";

fn client() -> Client {
    Client::new(
        ISSUER,
        "https://id.example.com/acme/oauth2/authorize",
        "portal",
        "https://app.example.com/callback",
    )
    .expect("a client")
}

fn query(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn started() -> (Url, Pending) {
    begin(
        &client(),
        "openid api:read",
        Some("https://api.example.com"),
    )
    .expect("begun")
}

fn returned(pending: &Pending, extra: &str) -> String {
    format!(
        "code=c-1&state={}&iss={}{extra}",
        pending.state(),
        urlencode(ISSUER)
    )
}

fn urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

#[test]
fn the_request_carries_pkce_s256_a_state_and_a_nonce() {
    let (url, pending) = started();
    assert!(
        url.as_str()
            .starts_with("https://id.example.com/acme/oauth2/authorize?")
    );
    assert_eq!(query(&url, "response_type").as_deref(), Some("code"));
    assert_eq!(query(&url, "client_id").as_deref(), Some("portal"));
    assert_eq!(
        query(&url, "redirect_uri").as_deref(),
        Some("https://app.example.com/callback")
    );
    assert_eq!(query(&url, "scope").as_deref(), Some("openid api:read"));
    assert_eq!(
        query(&url, "resource").as_deref(),
        Some("https://api.example.com")
    );
    assert_eq!(
        query(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, pending.verifier().as_bytes()));
    assert_eq!(query(&url, "code_challenge"), Some(challenge));
    assert_eq!(query(&url, "state").as_deref(), Some(pending.state()));
    assert_eq!(query(&url, "nonce").as_deref(), Some(pending.nonce()));
    assert_eq!(pending.verifier().len(), 43, "32 random bytes");
    assert!(
        pending.state().len() >= 22 && pending.nonce().len() >= 22,
        "at least 128 bits each"
    );
    let (_, other) = started();
    assert_ne!(other.state(), pending.state());
    assert_ne!(other.nonce(), pending.nonce());
    assert_ne!(other.verifier(), pending.verifier());
}

#[test]
fn a_return_with_this_flows_state_and_issuer_gives_the_code() {
    let (_, pending) = started();
    assert_eq!(
        pending.accept(&returned(&pending, "")),
        Ok("c-1".to_owned())
    );
}

#[test]
fn a_return_with_another_state_or_none_is_refused_before_any_exchange() {
    let (_, pending) = started();
    let (_, other) = started();
    assert_eq!(
        pending.accept(&returned(&other, "")),
        Err(ReturnRefusal::StateMismatch)
    );
    assert_eq!(
        pending.accept(&format!("code=c-1&iss={}", urlencode(ISSUER))),
        Err(ReturnRefusal::StateMismatch)
    );
    let truncated = &pending.state()[..pending.state().len() - 1];
    assert_eq!(
        pending.accept(&format!(
            "code=c-1&state={truncated}&iss={}",
            urlencode(ISSUER)
        )),
        Err(ReturnRefusal::StateMismatch)
    );
}

#[test]
fn a_return_from_another_issuer_or_naming_none_is_refused() {
    let (_, pending) = started();
    let mixed_up = format!(
        "code=c-1&state={}&iss={}",
        pending.state(),
        urlencode("https://evil.example.com/acme")
    );
    assert_eq!(pending.accept(&mixed_up), Err(ReturnRefusal::WrongIssuer));
    let unnamed = format!("code=c-1&state={}", pending.state());
    assert_eq!(pending.accept(&unnamed), Err(ReturnRefusal::WrongIssuer));
}

#[test]
fn an_error_answer_is_classified_and_never_echoed() {
    let (_, pending) = started();
    let denied = format!(
        "error=access_denied&error_description=%3Cscript%3E&state={}&iss={}",
        pending.state(),
        urlencode(ISSUER)
    );
    let refused = pending.accept(&denied);
    assert_eq!(refused, Err(ReturnRefusal::Denied("access_denied")));
    assert!(
        !format!("{refused:?}").contains("script"),
        "the description is not carried"
    );
    let unknown = format!(
        "error=%3Cb%3Ex&state={}&iss={}",
        pending.state(),
        urlencode(ISSUER)
    );
    assert_eq!(
        pending.accept(&unknown),
        Err(ReturnRefusal::Denied("other"))
    );
}

#[test]
fn a_malformed_return_is_refused() {
    let (_, pending) = started();
    assert_eq!(
        pending.accept(&returned(&pending, "&code=c-2")),
        Err(ReturnRefusal::Malformed),
        "a parameter given twice"
    );
    assert_eq!(
        pending.accept(&format!(
            "state={}&iss={}",
            pending.state(),
            urlencode(ISSUER)
        )),
        Err(ReturnRefusal::Malformed),
        "no code"
    );
}

#[test]
fn a_client_is_registered_with_https_addresses() {
    assert!(
        Client::new(
            ISSUER,
            "http://id.example.com/authorize",
            "portal",
            "https://a/cb"
        )
        .is_err()
    );
    assert!(
        Client::new(
            ISSUER,
            "https://id.example.com/authorize",
            "",
            "https://a/cb"
        )
        .is_err()
    );
    assert!(
        Client::new(
            ISSUER,
            "https://id.example.com/authorize",
            "portal",
            "not a url"
        )
        .is_err()
    );
    assert!(
        Client::new(
            ISSUER,
            "https://id.example.com/authorize",
            "portal",
            "http://127.0.0.1:8080/cb"
        )
        .is_ok(),
        "a loopback redirect for a native app"
    );
}

#[test]
fn a_request_kept_in_a_store_between_the_legs_accepts_its_own_return_only() {
    let (_, pending) = started();
    let kept = serde_json::to_string(&pending).expect("serialized");
    let restored: Pending = serde_json::from_str(&kept).expect("read back");
    assert_eq!(restored, pending);
    let state = pending.state().to_owned();
    assert_eq!(
        restored.accept(&format!("code=abc&state={state}&iss={ISSUER}")),
        Ok("abc".to_owned())
    );
    assert_eq!(
        restored.accept(&format!("code=abc&state=another&iss={ISSUER}")),
        Err(ReturnRefusal::StateMismatch)
    );
}
