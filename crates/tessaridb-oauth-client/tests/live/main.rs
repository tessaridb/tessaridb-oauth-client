//! The library against a running TessariDB OAuth server, over its published endpoints only: a user signs in, the
//! tokens are bound to a DPoP key, an API accepts the bound token with its proof, the tokens are refreshed, and a
//! refresh token presented again after rotation ends the session.
//!
//! Needs `TESSARIDB_OAUTH_E2E_ISSUER` (`https://<host>/<company>`), `TESSARIDB_OAUTH_E2E_ADMIN`
//! (`<console>/admin/<company>`), `TESSARIDB_OAUTH_E2E_OPERATOR` and `TESSARIDB_OAUTH_E2E_PASSWORD` (an operator of
//! that company with the `users` and `clients` roles, whose password is set and who holds no authenticator app yet,
//! which the run adds), and, for a server whose certificate a private authority signed, `SSL_CERT_FILE` naming that
//! authority. Run with `cargo test --test live -- --ignored`; each run registers a client and a user of its own and
//! needs a fresh operator.

mod browser;
mod totp;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tessaridb_oauth_client::relying::{
    Client, DpopKey, ExchangeRefusal, ReturnRefusal, TokenEndpoint, TokenType, begin,
    validate_id_token,
};
use tessaridb_oauth_client::resource::{
    Algorithm, Expectations, HttpsKeySource, KeyCache, ProofRefusal, Refusal, validate,
    validate_proof,
};
use url::Url;

use browser::{Browser, random};

const ALGORITHMS: [Algorithm; 2] = [Algorithm::Es256, Algorithm::EdDsa];
const REDIRECT: &str = "https://app.e2e.example/callback";
const RESOURCE: &str = "https://api.e2e.example/";
const CALL: &str = "https://api.e2e.example/v1/orders";

struct Server {
    issuer: String,
    admin: String,
    operator: String,
    password: String,
}

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// The `kid` a compact JWS names.
fn kid(token: &str) -> String {
    let header = token.split('.').next().expect("a header");
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64url")).expect("JSON");
    header["kid"].as_str().expect("a kid").to_owned()
}

/// The operator adds an authenticator app to its account, which the console asks for: the app's secret.
async fn second_factor(browser: &Browser, server: &Server) -> Vec<u8> {
    let begin = json!({"account": true});
    browser
        .sign_in(
            &server.issuer,
            begin,
            &server.operator,
            &server.password,
            None,
        )
        .await;
    let account = format!("{}/account/api/totp", server.issuer);
    let (status, begun) = browser
        .post(&format!("{account}/begin"), &json!({}), &[])
        .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    let secret = totp::decoded(begun["secret"].as_str().expect("a secret"));
    let enrolled_at = totp::step();
    let code = json!({"code": totp::code(&secret, enrolled_at)});
    let (status, enrolled) = browser
        .post(&format!("{account}/confirm"), &code, &[])
        .await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    // A code is accepted once per 30-second step (RFC 6238 section 5.2), so the sign-in waits for the next step.
    let next = (enrolled_at + 1) * totp::STEP_SECS;
    let wait = next.saturating_sub(now()) + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    secret
}

/// The console signs `server`'s operator in, registers a public client and opens a user with a password: the
/// client's id and the user's address and password.
async fn prepared(browser: &Browser, server: &Server) -> (String, String, String) {
    let app = second_factor(browser, server).await;
    let signin = browser.location(&format!("{}/signin", server.admin)).await;
    let operator = (server.operator.as_str(), server.password.as_str());
    let callback = browser
        .authorize(&server.issuer, &signin, operator, Some(&app))
        .await;
    assert!(
        callback.starts_with(&format!("{}/callback?", server.admin)),
        "{callback}"
    );
    browser.location(&callback).await;
    let client_id = format!(
        "e2e-{}",
        random(6).to_ascii_lowercase().replace(['-', '_'], "x")
    );
    let (status, registered) = browser
        .change(
            &server.admin,
            "clients",
            &json!({
                "client_id": client_id,
                "redirect_uris": [REDIRECT],
                "scope_ceiling": ["openid", "api:read"],
                "resources": [RESOURCE],
                "auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "reason": "client library end-to-end run",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let email = format!("{}@acme.e2e.example", client_id);
    let (status, opened) = browser
        .change(
            &server.admin,
            "users",
            &json!({"email": email, "reason": "end-to-end run"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
    let user = opened["user"].as_str().expect("a user");
    let (status, issued) = browser
        .change(
            &server.admin,
            &format!("users/{user}/enrolment"),
            &json!({"reason": "end-to-end run"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let password = random(18);
    browser
        .enroll(
            &server.issuer,
            issued["code"].as_str().expect("a code"),
            &password,
        )
        .await;
    (client_id, email, password)
}

#[tokio::test]
#[ignore = "needs a running TessariDB OAuth server: see the module documentation"]
async fn a_user_signs_in_and_an_api_accepts_the_bound_token_until_its_refresh_is_reused() {
    let server = Server {
        issuer: variable("TESSARIDB_OAUTH_E2E_ISSUER"),
        admin: variable("TESSARIDB_OAUTH_E2E_ADMIN"),
        operator: variable("TESSARIDB_OAUTH_E2E_OPERATOR"),
        password: variable("TESSARIDB_OAUTH_E2E_PASSWORD"),
    };
    let browser = Browser::new();
    let metadata = browser
        .read(&format!(
            "{}/.well-known/oauth-authorization-server",
            server.issuer
        ))
        .await;
    let endpoint = |name: &str| metadata[name].as_str().expect(name).to_owned();
    let (client_id, email, password) = prepared(&browser, &server).await;

    let client = Client::new(
        &server.issuer,
        &endpoint("authorization_endpoint"),
        &client_id,
        REDIRECT,
    )
    .expect("a client");
    let (authorize, pending) = begin(&client, "openid api:read", Some(RESOURCE)).expect("begun");
    let back = browser
        .authorize(
            &server.issuer,
            authorize.as_str(),
            (&email, &password),
            None,
        )
        .await;
    assert!(back.starts_with(REDIRECT), "{back}");
    let returned = Url::parse(&back).expect("a URL");
    let returned = returned.query().expect("a query");
    let (_, other) = begin(&client, "openid api:read", Some(RESOURCE)).expect("begun");
    assert_eq!(other.accept(returned), Err(ReturnRefusal::StateMismatch));
    let code = pending.accept(returned).expect("this request's return");

    let tokens_at = TokenEndpoint::new(&endpoint("token_endpoint")).expect("an endpoint");
    let key = DpopKey::generate().expect("a key");
    let tokens = tokens_at
        .exchange(&client, &pending, &code, Some(RESOURCE), Some(&key))
        .await
        .expect("issued");
    assert_eq!(tokens.token_type(), TokenType::DPoP);

    let cache = KeyCache::new(HttpsKeySource::new(&endpoint("jwks_uri")).expect("a source"));
    let id_token = tokens.id_token().expect("an ID token");
    let keys = cache
        .keys_for(&kid(id_token))
        .await
        .expect("the issuer's keys");
    let signed_in = validate_id_token(
        id_token,
        &keys,
        &Expectations::new(&server.issuer, &client_id, &ALGORITHMS).expect("expectations"),
        pending.nonce(),
        now(),
    )
    .expect("this sign-in's ID token");
    assert!(
        signed_in.amr.iter().any(|method| method == "pwd"),
        "{:?}",
        signed_in.amr
    );

    let at_api = Expectations::new(&server.issuer, RESOURCE, &ALGORITHMS).expect("expectations");
    let access = tokens.access_token();
    let keys = cache
        .keys_for(&kid(access))
        .await
        .expect("the issuer's keys");
    let token = validate(access, &keys, &at_api, now()).expect("an access token for this API");
    assert!(token.confirmation.is_some(), "bound to the key");
    let proof = key
        .proof("GET", CALL, Some(access), now())
        .expect("a proof");
    validate_proof(&proof, &token, access, "GET", CALL, &ALGORITHMS, now())
        .expect("the bound key's proof");
    let stranger = DpopKey::generate().expect("a key");
    let foreign = stranger
        .proof("GET", CALL, Some(access), now())
        .expect("a proof");
    assert_eq!(
        validate_proof(&foreign, &token, access, "GET", CALL, &ALGORITHMS, now()),
        Err(ProofRefusal::KeyMismatch)
    );
    let elsewhere = Expectations::new(&server.issuer, "https://other.e2e.example", &ALGORITHMS)
        .expect("expectations");
    assert_eq!(
        validate(access, &keys, &elsewhere, now()),
        Err(Refusal::WrongAudience)
    );

    let first = tokens.refresh_token().expect("a refresh token");
    let refreshed = tokens_at
        .refresh(&client, first, Some(RESOURCE), Some(&key))
        .await
        .expect("refreshed");
    let keys = cache
        .keys_for(&kid(refreshed.access_token()))
        .await
        .expect("the issuer's keys");
    validate(refreshed.access_token(), &keys, &at_api, now()).expect("the refreshed token");
    assert_eq!(
        tokens_at
            .refresh(&client, first, Some(RESOURCE), Some(&key))
            .await,
        Err(ExchangeRefusal::SessionOver("invalid_grant")),
        "a rotated refresh token presented again"
    );
    let second = refreshed.refresh_token().expect("a rotated refresh token");
    assert_eq!(
        tokens_at
            .refresh(&client, second, Some(RESOURCE), Some(&key))
            .await,
        Err(ExchangeRefusal::SessionOver("invalid_grant")),
        "the reuse revoked the whole family"
    );
    assert_eq!(
        tokens_at
            .exchange(&client, &pending, &code, Some(RESOURCE), Some(&key))
            .await,
        Err(ExchangeRefusal::SessionOver("invalid_grant")),
        "a code redeems once, and its replay revokes what it started"
    );
}
