//! What the token endpoint issues: the tokens of a sign-in or a refresh, which never print their values.

use std::fmt;

/// How the access token is presented (RFC 6750, RFC 9449).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// In an `Authorization: Bearer` header.
    Bearer,
    /// In an `Authorization: DPoP` header with a proof of the bound key.
    DPoP,
}

/// What the token endpoint issued. Its `Debug` names which tokens it holds and never their values.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSet {
    pub(super) access_token: String,
    pub(super) token_type: TokenType,
    pub(super) expires_in: Option<u64>,
    pub(super) refresh_token: Option<String>,
    pub(super) id_token: Option<String>,
    pub(super) scope: Option<String>,
}

impl TokenSet {
    /// The access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// How the access token is presented.
    #[must_use]
    pub fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Seconds the access token lives, when the issuer said.
    #[must_use]
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// The refresh token, when one was issued; it replaces the one presented.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The ID token, for a sign-in that asked for `openid`; it is validated before it is believed.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    /// The scopes granted, when the issuer listed them.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = |token: &Option<String>| {
            if token.is_some() {
                "[redacted]"
            } else {
                "none"
            }
        };
        formatter
            .debug_struct("TokenSet")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &held(&self.refresh_token))
            .field("id_token", &held(&self.id_token))
            .field("scope", &self.scope)
            .finish()
    }
}

#[cfg(test)]
#[path = "tokens_tests.rs"]
mod tests;
