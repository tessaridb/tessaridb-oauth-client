use super::{TokenSet, TokenType};

#[test]
fn a_token_set_never_prints_its_tokens() {
    let tokens = TokenSet {
        access_token: "at-1".to_owned(),
        token_type: TokenType::Bearer,
        expires_in: Some(300),
        refresh_token: Some("rt-2".to_owned()),
        id_token: Some("id-1".to_owned()),
        scope: Some("openid api:read".to_owned()),
    };
    let printed = format!("{tokens:?}");
    for secret in ["at-1", "rt-2", "id-1"] {
        assert!(!printed.contains(secret), "{printed}");
    }
    assert!(
        printed.contains("Bearer") && printed.contains("openid api:read"),
        "{printed}"
    );
}
