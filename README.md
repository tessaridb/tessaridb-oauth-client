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
used for up to a day while the issuer cannot be reached. Signing users in comes next.

## Building and checking

```sh
cargo test --workspace --tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo deny check
```

## Licence

Apache-2.0, see [LICENSE](LICENSE).
