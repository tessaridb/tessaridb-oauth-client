//! What a resource accepts: one issuer, its own audience, and the algorithms it verifies under.

use crate::{Error, Result};

use super::Algorithm;

/// Seconds of clock difference forgiven on `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: u64 = 60;

/// The issuer a token must come from, the audience it must name and the algorithms it may be signed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations {
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) algorithms: Vec<Algorithm>,
}

impl Expectations {
    /// Tokens from `issuer`, for `audience`, signed with one of `algorithms`.
    ///
    /// # Errors
    ///
    /// [`Error::Expectations`] when the issuer or the audience is empty or no algorithm is named.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        algorithms: &[Algorithm],
    ) -> Result<Self> {
        let (issuer, audience) = (issuer.into(), audience.into());
        if issuer.is_empty() || audience.is_empty() || algorithms.is_empty() {
            return Err(Error::Expectations);
        }
        Ok(Self {
            issuer,
            audience,
            algorithms: algorithms.to_vec(),
        })
    }
}
