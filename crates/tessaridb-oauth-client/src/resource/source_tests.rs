use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{HttpsKeySource, KeySource};
use crate::Error;

/// A listener on loopback answering one request with `answer`, and its address.
async fn serving(answer: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("a connection");
        let mut request = [0_u8; 2048];
        let _ = socket.read(&mut request).await;
        socket.write_all(answer.as_bytes()).await.expect("answered");
        socket.shutdown().await.expect("closed");
    });
    format!("http://{address}/acme/jwks")
}

fn ok(cache_control: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\n{cache_control}Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn the_set_is_fetched_with_the_lifetime_the_issuer_gives_it() {
    let body = r#"{"keys":[]}"#;
    let url = serving(ok("Cache-Control: public, max-age=120\r\n", body)).await;
    let fetched = HttpsKeySource::new(&url)
        .expect("a source")
        .fetch()
        .await
        .expect("fetched");
    assert_eq!(fetched.body, body);
    assert_eq!(fetched.max_age, Some(Duration::from_secs(120)));
    let url = serving(ok("", body)).await;
    let fetched = HttpsKeySource::new(&url)
        .expect("a source")
        .fetch()
        .await
        .expect("fetched");
    assert_eq!(fetched.max_age, None);
}

#[tokio::test]
async fn an_error_answer_or_an_oversized_set_is_refused() {
    let url = serving(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned(),
    )
    .await;
    assert!(matches!(
        HttpsKeySource::new(&url).expect("a source").fetch().await,
        Err(Error::Fetch(_))
    ));
    let huge = "x".repeat(65 * 1024);
    let url = serving(ok("", &huge)).await;
    assert_eq!(
        HttpsKeySource::new(&url).expect("a source").fetch().await,
        Err(Error::Fetch("the key set is larger than this client reads"))
    );
    let unannounced = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{huge}");
    let url = serving(unannounced).await;
    assert_eq!(
        HttpsKeySource::new(&url).expect("a source").fetch().await,
        Err(Error::Fetch("the key set is larger than this client reads")),
        "a set sent with no length is cut off at the ceiling"
    );
    let url = serving(
        "HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n"
            .to_owned(),
    )
    .await;
    assert!(
        HttpsKeySource::new(&url)
            .expect("a source")
            .fetch()
            .await
            .is_err(),
        "a redirect is not followed"
    );
}

#[test]
fn only_https_or_loopback_http_is_spoken() {
    for refused in [
        "http://id.example.com/acme/jwks",
        "https://user:secret@id.example.com/acme/jwks",
        "ftp://id.example.com/jwks",
        "not a url",
    ] {
        assert!(HttpsKeySource::new(refused).is_err(), "{refused}");
    }
    for accepted in [
        "https://id.example.com/acme/jwks",
        "http://127.0.0.1:47915/acme/jwks",
        "http://[::1]:47915/acme/jwks",
        "http://localhost:47915/acme/jwks",
    ] {
        assert!(HttpsKeySource::new(accepted).is_ok(), "{accepted}");
    }
}
