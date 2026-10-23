//! Failures of `tessaridb-oauth-client`.

/// A failure of this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Expectations with no issuer, no audience or no algorithm.
    #[error("a resource expects one issuer, one audience and at least one algorithm")]
    Expectations,
    /// A key set that is not JSON of the RFC 7517 shape, or holds a key of a known kind that cannot be read.
    #[error("the key set is malformed: {0}")]
    KeySet(&'static str),
    /// The key set could not be fetched: refused address, no answer, an error answer, or more than this client reads.
    #[error("the key set could not be fetched: {0}")]
    Fetch(&'static str),
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
