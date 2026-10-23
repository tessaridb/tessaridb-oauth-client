//! Why a token was refused: one reason per check, precise for the log. A resource answers every one of them the same
//! way outward (RFC 6750 `invalid_token`), so the reasons never become an oracle.

/// The check a token failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Not a compact JWS, an unreadable part, a critical header this crate does not know, or a required claim missing.
    #[error("the token is malformed")]
    Malformed,
    /// A `typ` other than an access token's.
    #[error("the token is not an access token")]
    WrongType,
    /// An algorithm outside the ones this resource accepts, `none` included.
    #[error("the token's algorithm is not accepted")]
    AlgorithmNotAllowed,
    /// No key of that `kid` and algorithm in the issuer's key set.
    #[error("the token names no key the issuer publishes")]
    UnknownKey,
    /// The signature does not verify under the issuer's key.
    #[error("the token's signature does not verify")]
    BadSignature,
    /// Issued by another issuer than the one this resource trusts.
    #[error("the token is from another issuer")]
    WrongIssuer,
    /// Addressed to another resource.
    #[error("the token is for another audience")]
    WrongAudience,
    /// Past its expiry.
    #[error("the token has expired")]
    Expired,
    /// Before its `nbf`, or issued in the future.
    #[error("the token is not valid yet")]
    NotYetValid,
}
