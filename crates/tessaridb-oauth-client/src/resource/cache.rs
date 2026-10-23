//! The issuer's key set held between requests: fetched once, kept for the lifetime the issuer advertises, fetched again
//! early when a token names a `kid` the set does not hold (which is how a rotated key is picked up), never more often
//! than a floor allows (so tokens carrying invented `kid`s cannot turn into requests to the issuer), and kept through
//! an issuer outage for a bounded time (so verification under keys already held does not stop).

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

use super::{KeySet, KeySource};
use crate::Result;

/// The least time between two fetches of the set, whatever tokens arrive.
pub const REFRESH_FLOOR: Duration = Duration::from_secs(10);
/// How long a set is used after its fetch when every later fetch fails.
pub const STALE_LIMIT: Duration = Duration::from_secs(86_400);
/// How long a set is fresh when the issuer advertises no lifetime.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);
/// The longest lifetime taken from the issuer, so a misconfigured one cannot pin a set for a year.
const MAX_AGE_CEILING: Duration = Duration::from_secs(86_400);

/// A set as it was fetched.
struct Held {
    keys: Arc<KeySet>,
    fetched_at: Instant,
    fresh_until: Instant,
}

/// The key set of one issuer, fetched from `source` as tokens need it.
pub struct KeyCache<S> {
    source: S,
    /// The set requests read; replaced whole by a refresh, never held across an `.await`.
    held: RwLock<Option<Arc<Held>>>,
    /// The time of the last fetch attempt; holding it is what makes one caller the refresher.
    attempt: Mutex<Option<Instant>>,
}

impl<S: KeySource> KeyCache<S> {
    /// A cache that has fetched nothing yet.
    pub fn new(source: S) -> Self {
        Self {
            source,
            held: RwLock::new(None),
            attempt: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> Option<Arc<Held>> {
        self.held
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The set to verify a token naming `kid` with: the held one while it is fresh and holds `kid`, otherwise the
    /// set fetched now when the floor allows, otherwise the held one.
    ///
    /// # Errors
    ///
    /// The fetch's failure when no set is held, or the held one is older than [`STALE_LIMIT`].
    pub async fn keys_for(&self, kid: &str) -> Result<Arc<KeySet>> {
        let usable = |held: &Held, now: Instant| now < held.fresh_until && held.keys.contains(kid);
        if let Some(held) = self.snapshot().filter(|held| usable(held, Instant::now())) {
            return Ok(Arc::clone(&held.keys));
        }
        let mut attempt = self.attempt.lock().await;
        let now = Instant::now();
        let held = self.snapshot();
        if let Some(held) = held.as_ref().filter(|held| usable(held, now)) {
            return Ok(Arc::clone(&held.keys));
        }
        let allowed =
            attempt.is_none_or(|last| last.checked_add(REFRESH_FLOOR).is_none_or(|due| now >= due));
        if !allowed && let Some(held) = held.as_ref() {
            return Ok(Arc::clone(&held.keys));
        }
        *attempt = Some(now);
        let fetched = self
            .source
            .fetch()
            .await
            .and_then(|fetched| Ok((KeySet::parse(&fetched.body)?, fetched.max_age)));
        match fetched {
            Ok((keys, max_age)) => {
                let lifetime = max_age.unwrap_or(DEFAULT_MAX_AGE).min(MAX_AGE_CEILING);
                let keys = Arc::new(keys);
                let fresh = Arc::new(Held {
                    keys: Arc::clone(&keys),
                    fetched_at: now,
                    fresh_until: now.checked_add(lifetime).unwrap_or(now),
                });
                *self.held.write().unwrap_or_else(PoisonError::into_inner) = Some(fresh);
                Ok(keys)
            }
            Err(failure) => match held {
                Some(held)
                    if held
                        .fetched_at
                        .checked_add(STALE_LIMIT)
                        .is_some_and(|limit| now < limit) =>
                {
                    Ok(Arc::clone(&held.keys))
                }
                _ => Err(failure),
            },
        }
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
