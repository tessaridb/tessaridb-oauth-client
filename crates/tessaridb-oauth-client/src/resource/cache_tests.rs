use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;

use super::{KeyCache, REFRESH_FLOOR, STALE_LIMIT};
use crate::Error;
use crate::resource::{Fetched, KeySource};

/// A source answering whatever its script holds next, counting how often it is asked.
#[derive(Clone, Default)]
struct Scripted {
    answers: Arc<Mutex<Vec<Result<Fetched, Error>>>>,
    asked: Arc<AtomicUsize>,
}

impl Scripted {
    async fn then(&self, answer: Result<Fetched, Error>) {
        self.answers.lock().await.push(answer);
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl KeySource for Scripted {
    async fn fetch(&self) -> crate::Result<Fetched> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().await;
        if answers.is_empty() {
            Err(Error::Fetch("the script ran out"))
        } else {
            answers.remove(0)
        }
    }
}

fn set_with(kids: &[&str], max_age: Option<u64>) -> Result<Fetched, Error> {
    // Ed25519 keys whose bytes do not matter to the cache: it looks keys up by kid.
    let entries: Vec<String> = kids
        .iter()
        .map(|kid| {
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","kid":"{kid}","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}"#
            )
        })
        .collect();
    Ok(Fetched {
        body: format!(r#"{{"keys":[{}]}}"#, entries.join(",")),
        max_age: max_age.map(Duration::from_secs),
    })
}

#[tokio::test(start_paused = true)]
async fn the_set_is_fetched_once_and_kept_for_its_max_age() {
    let source = Scripted::default();
    source.then(set_with(&["k1"], Some(300))).await;
    source.then(set_with(&["k1", "k2"], Some(300))).await;
    let cache = KeyCache::new(source.clone());
    assert!(cache.keys_for("k1").await.expect("keys").contains("k1"));
    assert!(cache.keys_for("k1").await.expect("keys").contains("k1"));
    assert_eq!(source.asked(), 1, "served from the cache");
    tokio::time::advance(Duration::from_secs(301)).await;
    let renewed = cache.keys_for("k1").await.expect("keys");
    assert!(renewed.contains("k2"), "fetched again after its max-age");
    assert_eq!(source.asked(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_unknown_kid_refreshes_once_and_a_flood_of_them_does_not() {
    let source = Scripted::default();
    source.then(set_with(&["k1"], Some(300))).await;
    source.then(set_with(&["k1", "k2"], Some(300))).await;
    let cache = KeyCache::new(source.clone());
    cache.keys_for("k1").await.expect("keys");
    tokio::time::advance(REFRESH_FLOOR).await;
    assert!(
        cache.keys_for("k2").await.expect("keys").contains("k2"),
        "a rotated key is picked up at once"
    );
    assert_eq!(source.asked(), 2);
    for invented in 0..50 {
        let keys = cache
            .keys_for(&format!("invented-{invented}"))
            .await
            .expect("keys");
        assert!(keys.contains("k2"));
    }
    assert_eq!(
        source.asked(),
        2,
        "an invented kid never reaches the issuer within the floor"
    );
    tokio::time::advance(REFRESH_FLOOR).await;
    source.then(set_with(&["k2"], Some(300))).await;
    cache.keys_for("invented-again").await.expect("keys");
    assert_eq!(source.asked(), 3, "one refresh per floor");
}

#[tokio::test(start_paused = true)]
async fn a_failed_fetch_keeps_the_last_good_set_for_a_bounded_time() {
    let source = Scripted::default();
    source.then(set_with(&["k1"], Some(60))).await;
    let cache = KeyCache::new(source.clone());
    cache.keys_for("k1").await.expect("keys");
    tokio::time::advance(Duration::from_secs(61)).await;
    source.then(Err(Error::Fetch("the issuer is down"))).await;
    assert!(
        cache
            .keys_for("k1")
            .await
            .expect("last good")
            .contains("k1"),
        "an outage does not stop verification under keys already held"
    );
    tokio::time::advance(STALE_LIMIT).await;
    source.then(Err(Error::Fetch("still down"))).await;
    assert_eq!(
        cache.keys_for("k1").await,
        Err(Error::Fetch("still down")),
        "past the stale limit the old set is not trusted"
    );
}

#[tokio::test(start_paused = true)]
async fn with_nothing_fetched_yet_a_failure_is_the_answer() {
    let source = Scripted::default();
    source.then(Err(Error::Fetch("unreachable"))).await;
    let cache = KeyCache::new(source.clone());
    assert_eq!(cache.keys_for("k1").await, Err(Error::Fetch("unreachable")));
}

#[tokio::test(start_paused = true)]
async fn a_set_without_max_age_is_kept_for_the_default() {
    let source = Scripted::default();
    source.then(set_with(&["k1"], None)).await;
    let cache = KeyCache::new(source.clone());
    cache.keys_for("k1").await.expect("keys");
    tokio::time::advance(Duration::from_secs(299)).await;
    cache.keys_for("k1").await.expect("keys");
    assert_eq!(source.asked(), 1);
}
