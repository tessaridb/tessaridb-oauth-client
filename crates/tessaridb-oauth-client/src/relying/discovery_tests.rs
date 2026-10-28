use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::discover;
use crate::Error;

/// A loopback listener answering one request with the `status` and `body`, and the issuer address it serves.
async fn issuer(status: &str, body: impl Fn(&str) -> String + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let issuer = format!("http://{}/acme", listener.local_addr().expect("an address"));
    let named = issuer.clone();
    let status = status.to_owned();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut request = [0_u8; 2048];
        let read = socket.read(&mut request).await.unwrap_or(0);
        let line = String::from_utf8_lossy(&request[..read]);
        assert!(
            line.starts_with("GET /acme/.well-known/openid-configuration "),
            "{line}"
        );
        let body = body(&named);
        let answer = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(answer.as_bytes()).await.expect("answered");
        socket.shutdown().await.expect("closed");
    });
    issuer
}

fn document(issuer: &str, token_endpoint: &str) -> String {
    format!(
        r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{token_endpoint}","jwks_uri":"{issuer}/jwks","response_types_supported":["code"]}}"#
    )
}

fn refused(result: crate::Result<super::Metadata>) -> &'static str {
    match result {
        Err(Error::Discovery(reason)) => reason,
        other => panic!("not a discovery refusal: {other:?}"),
    }
}

#[tokio::test]
async fn the_endpoints_of_the_named_issuer_are_read() {
    let issuer = issuer("200 OK", |issuer| {
        document(issuer, &format!("{issuer}/token"))
    })
    .await;
    let metadata = discover(&issuer).await.expect("discovered");
    assert_eq!(metadata.issuer, issuer);
    assert_eq!(
        metadata.authorization_endpoint,
        format!("{issuer}/authorize")
    );
    assert_eq!(metadata.token_endpoint, format!("{issuer}/token"));
    assert_eq!(metadata.jwks_uri, format!("{issuer}/jwks"));
}

#[tokio::test]
async fn a_document_for_another_issuer_is_refused() {
    let issuer = issuer("200 OK", |issuer| {
        document(&format!("{issuer}/other"), &format!("{issuer}/token"))
    })
    .await;
    assert_eq!(
        refused(discover(&issuer).await),
        "the document is for another issuer"
    );
    let slashed = issuer_with_slash().await;
    assert_eq!(
        refused(discover(&slashed).await),
        "the document is for another issuer"
    );
}

/// An issuer configured with a trailing slash whose document names it without one: not the same string.
async fn issuer_with_slash() -> String {
    let issuer = issuer("200 OK", |issuer| {
        document(issuer, &format!("{issuer}/token"))
    })
    .await;
    format!("{issuer}/")
}

#[tokio::test]
async fn an_endpoint_that_is_not_https_or_carries_credentials_is_refused() {
    for token_endpoint in [
        "http://example.com/token",
        "https://user:secret@example.com/token",
        "not a url",
    ] {
        let issuer = issuer("200 OK", move |issuer| document(issuer, token_endpoint)).await;
        assert_eq!(
            refused(discover(&issuer).await),
            "an endpoint is not https (or http to a loopback address), or carries credentials",
            "{token_endpoint}"
        );
    }
}

#[tokio::test]
async fn an_error_answer_a_shapeless_document_or_an_oversized_one_is_refused() {
    let issuer_ = issuer("404 Not Found", |_| "{}".to_owned()).await;
    assert_eq!(
        refused(discover(&issuer_).await),
        "the issuer answered with an error"
    );
    let issuer_ = issuer("200 OK", |issuer| format!(r#"{{"issuer":"{issuer}"}}"#)).await;
    assert_eq!(
        refused(discover(&issuer_).await),
        "the document is not JSON of the required shape"
    );
    let issuer_ = issuer("200 OK", |_| "x".repeat(64 * 1024 + 1)).await;
    assert_eq!(
        refused(discover(&issuer_).await),
        "the document is larger than this client reads"
    );
}

#[tokio::test]
async fn an_issuer_that_is_not_an_acceptable_address_is_refused_before_any_request() {
    for issuer in [
        "http://example.com/acme",
        "https://a:b@example.com",
        "https://example.com/acme?x=1",
        "nonsense",
    ] {
        assert!(
            matches!(discover(issuer).await, Err(Error::Discovery(_))),
            "{issuer}"
        );
    }
}
