# TessariDB OAuth client

A Rust library for applications that use a TessariDB OAuth issuer: an API checks the access tokens it is handed, and
a web application signs its users in. It talks to the issuer over the published protocol (OAuth 2.1, OpenID
Connect, RFC 9068 access tokens, RFC 7517 key sets) and depends on no server code.

## Status

In development, no release. What works: `resource::validate` checks an access token against a key set the caller
has fetched and parsed with `resource::KeySet::parse`, in this order: its type (`at+jwt`), an algorithm the resource
accepts (ES256 or EdDSA, never `none`), the key by `kid` in the issuer's set, the signature, the issuer, the
audience, and expiry with 60 seconds of leeway. The first check that fails is the refusal.

`resource::KeyCache` over `resource::HttpsKeySource` holds the issuer's key set: fetched over https (plain http only
to a loopback address), at most 64 KiB, kept for the `max-age` the issuer sends (five minutes when it sends none),
fetched again at once when a token names a key the set does not hold, never more than once every 10 seconds, and
used for up to a day while the issuer cannot be reached.

`relying::begin` starts a sign-in: the address to send the user to, with PKCE (S256), a 128-bit `state` and a
`nonce`, and the `Pending` request to keep under its `state`. `Pending::accept` takes the query the user returns with
and gives the code only when it carries this request's `state` (compared in constant time) and names this issuer in
`iss`; an error answer comes back as its code alone, never its text. `relying::validate_id_token` checks the ID token
of the sign-in: the issuer's signature, a `typ` that is not an access token's or a proof's, the issuer, this client
in `aud` (and in `azp` when there are several audiences), its time, and the `nonce` of the request it answers.

`relying::TokenEndpoint` exchanges the code for tokens (with the request's PKCE verifier, the redirect address and
the resource) and a refresh token for the next set. A failure comes back classified: `SessionOver` when the code,
the refresh token or the client is no longer good, so the user signs in again; `Retryable` when the issuer did not
answer or was overloaded; `Rejected` or `Malformed` otherwise. The library never retries a call itself, and a
`TokenSet` never prints its tokens. DPoP comes next.

## Building and checking

```sh
cargo test --workspace --tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo deny check
```

## Licence

Apache-2.0, see [LICENSE](LICENSE).
