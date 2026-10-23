//! A browser as far as the server's pages need one: cookies kept, redirects read rather than followed, and the
//! JSON calls the sign-in and consent pages make.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use reqwest::header::{LOCATION, ORIGIN};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use url::Url;

use super::totp;

/// `bytes` random bytes, base64url: a password, an idempotency key, a name nobody else uses.
pub fn random(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    SystemRandom::new().fill(&mut buffer).expect("random bytes");
    URL_SAFE_NO_PAD.encode(buffer)
}

/// One browser: one cookie jar across the issuer and the console.
pub struct Browser {
    http: reqwest::Client,
}

fn query(url: &str, name: &str) -> String {
    Url::parse(url)
        .expect("a URL")
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("no {name} in {url}"))
}

impl Browser {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        Self { http }
    }

    /// Where a GET of `url` sends the browser.
    pub async fn location(&self, url: &str) -> String {
        let answer = self.http.get(url).send().await.expect("an answer");
        assert!(
            answer.status().is_redirection(),
            "{url}: {}",
            answer.status()
        );
        let target = answer
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("a Location");
        Url::parse(url)
            .and_then(|base| base.join(target))
            .expect("a target")
            .into()
    }

    /// A JSON GET of `url`.
    pub async fn read(&self, url: &str) -> Value {
        let answer = self.http.get(url).send().await.expect("an answer");
        assert_eq!(answer.status(), StatusCode::OK, "{url}");
        answer.json().await.expect("JSON")
    }

    /// A JSON POST of `body` to `url` with `headers`: the status and the answer, `null` when it has no body.
    pub async fn post(
        &self,
        url: &str,
        body: &Value,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut request = self.http.post(url).json(body);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let answer = request.send().await.expect("an answer");
        let status = answer.status();
        let text = answer.text().await.expect("a body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Set the first password of the account `code` was issued for.
    pub async fn enroll(&self, issuer: &str, code: &str, password: &str) {
        let url = format!("{issuer}/login/api/enroll");
        let (status, _) = self
            .post(&url, &json!({"code": code, "password": password}), &[])
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "enrolment");
    }

    /// Sign in as `email` from the sign-in `begin` names, with the authenticator app `app` when the account holds
    /// one: where the completed sign-in continues.
    pub async fn sign_in(
        &self,
        issuer: &str,
        begin: Value,
        email: &str,
        password: &str,
        app: Option<&[u8]>,
    ) -> String {
        let api = format!("{issuer}/login/api");
        let first = if app.is_some() {
            "second_factor"
        } else {
            "complete"
        };
        let mut steps = vec![
            ("begin", begin, "identify"),
            ("identify", json!({"email": email}), "first_factor"),
            ("password", json!({"password": password}), first),
        ];
        if let Some(secret) = app {
            steps.push(("totp", json!({"code": totp::now(secret)}), "complete"));
        }
        let mut answer = Value::Null;
        for (step, body, next) in steps {
            let (status, read) = self.post(&format!("{api}/{step}"), &body, &[]).await;
            assert_eq!(
                (status, read["next"].as_str()),
                (StatusCode::OK, Some(next)),
                "{step}: {read}"
            );
            answer = read;
        }
        answer["continue"]
            .as_str()
            .expect("where to continue")
            .to_owned()
    }

    /// Sign in as `email` for the authorization request at `authorize` and allow what it asks: the address the
    /// browser is sent back to, at the client.
    pub async fn authorize(
        &self,
        issuer: &str,
        authorize: &str,
        (email, password): (&str, &str),
        app: Option<&[u8]>,
    ) -> String {
        let login = self.location(authorize).await;
        assert!(login.starts_with(&format!("{issuer}/login?")), "{login}");
        let api = format!("{issuer}/login/api");
        let begin = json!({"interaction": query(&login, "interaction")});
        let resumed = self.sign_in(issuer, begin, email, password, app).await;
        let after = self.location(&resumed).await;
        if !after.starts_with(&format!("{issuer}/consent?")) {
            return after;
        }
        let interaction = query(&after, "interaction");
        let asked = self
            .read(&format!("{api}/consent?interaction={interaction}"))
            .await;
        assert!(asked["scopes"].is_array(), "{asked}");
        let (status, onward) = self
            .post(
                &format!("{api}/consent"),
                &json!({"interaction": interaction, "decision": "allow"}),
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "consent: {onward}");
        onward["redirect"].as_str().expect("a redirect").to_owned()
    }

    /// A change at the console `admin` (`.../admin/<company>`), as the console makes it: its origin and an
    /// idempotency key. The status and the answer.
    pub async fn change(&self, admin: &str, path: &str, body: &Value) -> (StatusCode, Value) {
        let origin = Url::parse(admin)
            .expect("a URL")
            .origin()
            .ascii_serialization();
        let key = random(16);
        self.post(
            &format!("{admin}/api/{path}"),
            body,
            &[
                (ORIGIN.as_str(), origin.as_str()),
                ("idempotency-key", key.as_str()),
            ],
        )
        .await
    }
}
