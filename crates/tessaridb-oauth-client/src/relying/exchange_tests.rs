use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::{ExchangeRefusal, TokenEndpoint};
use crate::relying::DpopKey;
use crate::relying::TokenType;
use crate::relying::dpop::tests::verified;
use crate::relying::{Client, Pending, begin};

const ISSUER: &str = "https://id.example.com/acme";
const RESOURCE: &str = "https://api.example.com";

fn client() -> Client {
    Client::new(
        ISSUER,
        "https://id.example.com/acme/oauth2/authorize",
        "portal",
        "https://app.example.com/callback",
    )
    .expect("a client")
}

fn pending() -> Pending {
    begin(&client(), "openid api:read", Some(RESOURCE))
        .expect("begun")
        .1
}

/// A loopback token endpoint answering one request with `status` and `body`, and the request it received.
async fn serving(status: &str, body: &str) -> (TokenEndpoint, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (sent, received) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !whole(&request) {
            let read = socket.read(&mut buffer).await.expect("read");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        socket.write_all(answer.as_bytes()).await.expect("answered");
        socket.shutdown().await.expect("closed");
        let _ = sent.send(String::from_utf8_lossy(&request).into_owned());
    });
    let endpoint =
        TokenEndpoint::new(&format!("http://{address}/acme/oauth2/token")).expect("an endpoint");
    (endpoint, received)
}

/// Whether `request` holds its headers and the body they announce.
fn whole(request: &[u8]) -> bool {
    let text = String::from_utf8_lossy(request);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

/// The request's form, as pairs in order.
fn form(request: &str) -> Vec<(String, String)> {
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

const ISSUED: &str = r#"{"access_token":"at-1","token_type":"bearer","expires_in":300,"refresh_token":"rt-2",
    "id_token":"id-1","scope":"openid api:read"}"#;

#[tokio::test]
async fn a_code_is_exchanged_with_its_verifier_redirect_and_resource() {
    let pending = pending();
    let (endpoint, request) = serving("200 OK", ISSUED).await;
    let tokens = endpoint
        .exchange(&client(), &pending, "c-1", Some(RESOURCE), None)
        .await
        .expect("issued");
    let request = request.await.expect("a request");
    assert!(request.starts_with("POST /acme/oauth2/token "), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded")
    );
    assert_eq!(
        form(&request),
        pairs(&[
            ("grant_type", "authorization_code"),
            ("code", "c-1"),
            ("redirect_uri", "https://app.example.com/callback"),
            ("client_id", "portal"),
            ("code_verifier", pending.verifier()),
            ("resource", RESOURCE),
        ])
    );
    assert_eq!(tokens.access_token(), "at-1");
    assert_eq!(tokens.token_type(), TokenType::Bearer);
    assert_eq!(tokens.expires_in(), Some(300));
    assert_eq!(tokens.refresh_token(), Some("rt-2"));
    assert_eq!(tokens.id_token(), Some("id-1"));
    assert_eq!(tokens.scope(), Some("openid api:read"));
}

#[tokio::test]
async fn a_refresh_presents_the_token_and_the_client_and_nothing_of_the_sign_in() {
    let (endpoint, request) = serving(
        "200 OK",
        r#"{"access_token":"at-2","token_type":"DPoP","refresh_token":"rt-3"}"#,
    )
    .await;
    let tokens = endpoint
        .refresh(&client(), "rt-2", None, None)
        .await
        .expect("issued");
    assert_eq!(
        form(&request.await.expect("a request")),
        pairs(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "rt-2"),
            ("client_id", "portal"),
        ])
    );
    assert_eq!(tokens.token_type(), TokenType::DPoP);
    assert_eq!(tokens.refresh_token(), Some("rt-3"));
    assert_eq!(tokens.id_token(), None);
}

#[tokio::test]
async fn a_spent_grant_or_a_refused_client_ends_the_session() {
    for (status, code) in [
        ("400 Bad Request", "invalid_grant"),
        ("401 Unauthorized", "invalid_client"),
        ("400 Bad Request", "unauthorized_client"),
    ] {
        let body = format!(r#"{{"error":"{code}","error_description":"<script>"}}"#);
        let (endpoint, _request) = serving(status, &body).await;
        let refused = endpoint.refresh(&client(), "rt-2", None, None).await;
        assert_eq!(refused, Err(ExchangeRefusal::SessionOver(code)), "{code}");
        assert!(
            !format!("{refused:?}").contains("script"),
            "the description is not carried"
        );
    }
}

#[tokio::test]
async fn a_refused_request_is_named_and_an_unknown_code_is_other() {
    let (endpoint, _request) = serving("400 Bad Request", r#"{"error":"invalid_scope"}"#).await;
    assert_eq!(
        endpoint.refresh(&client(), "rt-2", None, None).await,
        Err(ExchangeRefusal::Rejected("invalid_scope"))
    );
    let (endpoint, _request) = serving("400 Bad Request", r#"{"error":"<b>x"}"#).await;
    assert_eq!(
        endpoint.refresh(&client(), "rt-2", None, None).await,
        Err(ExchangeRefusal::Rejected("other"))
    );
}

#[tokio::test]
async fn an_overloaded_or_absent_issuer_is_retryable() {
    for status in [
        "503 Service Unavailable",
        "500 Internal Server Error",
        "429 Too Many Requests",
    ] {
        let (endpoint, _request) = serving(status, r#"{"error":"invalid_grant"}"#).await;
        assert_eq!(
            endpoint.refresh(&client(), "rt-2", None, None).await,
            Err(ExchangeRefusal::Retryable),
            "{status}"
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    let absent = TokenEndpoint::new(&format!("http://{address}/token")).expect("an endpoint");
    assert_eq!(
        absent.refresh(&client(), "rt-2", None, None).await,
        Err(ExchangeRefusal::Retryable)
    );
}

#[tokio::test]
async fn an_answer_that_is_not_a_token_answer_is_malformed() {
    for (status, body) in [
        ("200 OK", "not json"),
        ("200 OK", r#"{"token_type":"Bearer"}"#),
        ("200 OK", r#"{"access_token":"","token_type":"Bearer"}"#),
        ("200 OK", r#"{"access_token":"at-1","token_type":"mac"}"#),
        ("400 Bad Request", "no error code"),
        ("302 Found", ""),
    ] {
        let (endpoint, _request) = serving(status, body).await;
        assert_eq!(
            endpoint.refresh(&client(), "rt-2", None, None).await,
            Err(ExchangeRefusal::Malformed),
            "{status} {body}"
        );
    }
    let huge = format!(
        r#"{{"access_token":"{}","token_type":"Bearer"}}"#,
        "x".repeat(65 * 1024)
    );
    let (endpoint, _request) = serving("200 OK", &huge).await;
    assert_eq!(
        endpoint.refresh(&client(), "rt-2", None, None).await,
        Err(ExchangeRefusal::Malformed),
        "an answer past the ceiling is not read"
    );
}

#[test]
fn only_https_or_loopback_http_carries_a_code() {
    for refused in [
        "http://id.example.com/acme/oauth2/token",
        "https://user:secret@id.example.com/acme/oauth2/token",
        "not a url",
    ] {
        assert!(TokenEndpoint::new(refused).is_err(), "{refused}");
    }
    for accepted in [
        "https://id.example.com/acme/oauth2/token",
        "http://127.0.0.1:47915/acme/oauth2/token",
        "http://[::1]:47915/acme/oauth2/token",
    ] {
        assert!(TokenEndpoint::new(accepted).is_ok(), "{accepted}");
    }
}

#[tokio::test]
async fn a_bound_exchange_carries_a_proof_for_the_token_endpoint() {
    let key = DpopKey::generate().expect("a key");
    let (endpoint, request) = serving("200 OK", ISSUED).await;
    endpoint
        .exchange(&client(), &pending(), "c-1", None, Some(&key))
        .await
        .expect("issued");
    let request = request.await.expect("a request");
    let proof = request
        .lines()
        .find_map(|line| line.strip_prefix("dpop: "))
        .expect("a DPoP header");
    let (_, claims) = verified(proof);
    assert_eq!(claims["htm"], "POST");
    let address = request
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("a host");
    assert_eq!(
        claims["htu"],
        format!("http://{address}/acme/oauth2/token").as_str()
    );
    assert!(
        claims.get("ath").is_none(),
        "the token endpoint is shown no access token"
    );
    let (endpoint, request) = serving("200 OK", ISSUED).await;
    endpoint
        .refresh(&client(), "rt-2", None, None)
        .await
        .expect("issued");
    assert!(
        !request
            .await
            .expect("a request")
            .to_ascii_lowercase()
            .contains("\r\ndpop:"),
        "an unbound call sends no proof"
    );
}
