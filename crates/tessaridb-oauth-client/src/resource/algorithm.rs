//! The signature algorithms a token may be verified under.

/// An algorithm the issuer signs access tokens with; which ones a resource accepts is its own configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ECDSA over P-256 with SHA-256 (RFC 7518 section 3.4).
    Es256,
    /// Ed25519 (RFC 8037).
    EdDsa,
}

impl Algorithm {
    /// The name a JOSE header and a key set use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }
}
