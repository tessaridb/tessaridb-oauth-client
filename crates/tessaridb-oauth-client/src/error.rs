//! Failures of `tessaridb-oauth-client`.

/// A failure of this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
