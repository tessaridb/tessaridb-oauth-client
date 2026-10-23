# TessariDB OAuth client

A Rust library for applications that use a TessariDB OAuth issuer: an API checks the access tokens it is handed, and
a web application signs its users in. It talks to the issuer over the published protocol (OAuth 2.1, OpenID
Connect, RFC 9068 access tokens, RFC 7517 key sets) and depends on no server code.

## Status

In development, no release. What works: `resource::validate` checks an access token against a key set the caller
has fetched and parsed with `resource::KeySet::parse`, in this order: its type (`at+jwt`), an algorithm the resource
accepts (ES256 or EdDSA, never `none`), the key by `kid` in the issuer's set, the signature, the issuer, the
audience, and expiry with 60 seconds of leeway. The first check that fails is the refusal. Fetching and caching the
key set, and signing users in, come next.

## Building and checking

```sh
cargo test --workspace --tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo deny check
```

## Licence

Apache-2.0, see [LICENSE](LICENSE).
