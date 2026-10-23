//! An access token's claims (RFC 9068 section 2.2) once every check passed.

/// What a valid access token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The issuer, equal to the one this resource trusts.
    pub issuer: String,
    /// The subject as this client knows it: a user's identifier, or the client's own id for its own token.
    pub subject: String,
    /// The client the token was issued to.
    pub client_id: String,
    /// The scopes granted, in the order the token lists them.
    pub scopes: Vec<String>,
    /// Unix seconds after which it is no longer valid.
    pub expires_at: u64,
    /// Unix seconds when it was issued.
    pub issued_at: u64,
    /// The token's unique identifier.
    pub jti: String,
    /// The thumbprint of the key a DPoP proof must be signed with (RFC 9449 section 6), when the token is bound; such a
    /// token is accepted only with [`validate_proof`](super::validate_proof), never as a bearer token.
    pub confirmation: Option<String>,
}
