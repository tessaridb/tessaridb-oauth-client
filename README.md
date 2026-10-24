<div align="center">

<img src="assets/logo/tessaridb-oauth-mark-256.png" alt="" width="112" height="112">

# TessariDB OAuth client

**The application side of TessariDB OAuth: check the tokens your API is handed, and sign your users in.**

A Rust library for applications that use a TessariDB OAuth issuer. An API validates the access tokens it receives;
a web application signs its users in and keeps their tokens. It talks to the issuer over the published protocol
(OAuth 2.1, OpenID Connect, RFC 9068 access tokens, RFC 7517 key sets) and depends on no server code.

[![status](https://img.shields.io/badge/status-in%20development-6B5FD1?style=flat-square)](#status)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-6B5FD1?style=flat-square)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.98%2B-6B5FD1?style=flat-square)](#building-and-checking)

[oauth.tessaridb.com](https://oauth.tessaridb.com) · [docs](https://docs.tessaridb.com/oauth) ·
[tessaridb.com](https://tessaridb.com) · [TessariDB OAuth](https://github.com/tessaridb/tessaridb-oauth)

</div>

> [!NOTE]
> **No release yet.** Everything listed under [Status](#status) is covered by tests, including a run against a
> running server; the API may change before the first release.

## What it is for

- **An API that accepts access tokens** checks each one in a fixed order against the issuer's published key set,
  which the library fetches, caches and refreshes when a token names a key it has not seen.
- **A web application that signs users in** starts the request with PKCE, checks what comes back, exchanges the code,
  validates the ID token and refreshes the tokens.
- **Tokens bound to a key** (DPoP): the client proves it holds the key, and the API accepts such a token only with
  the proof.

## Status

In development, no release. What works: `resource::validate` checks an access token against a key set the caller
has fetched and parsed with `resource::KeySet::parse`, in this order: its type (`at+jwt`), an algorithm the resource
accepts (ES256 or EdDSA, never `none`), the key by `kid` in the issuer's set, the signature, the issuer, the
audience, and expiry with 60 seconds of leeway. The first check that fails is the refusal.

`resource::KeyCache` over `resource::HttpsKeySource` holds the issuer's key set: fetched over https (plain http only
to a loopback address), at most 64 KiB, kept for the `max-age` the issuer sends (five minutes when it sends none),
fetched again at once when a token names a key the set does not hold, never more than once every 10 seconds, and
used for up to a day while the issuer cannot be reached. `resource::key_id` reads the `kid` a token names, so an API
asks the cache for the set that holds it before calling `validate`; it checks nothing itself.

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
`TokenSet` never prints its tokens.

`relying::DpopKey` is the client's DPoP key (RFC 9449): an ES256 key held in memory and never written out. Passed
to an exchange or a refresh, it binds the tokens to the key with a proof for the token endpoint; `DpopKey::proof`
makes the proof for a call to an API, carrying the hash of the access token it presents. Proofs name the method and
the address without its query or fragment, and each has its own `jti`.

At an API, a token whose `confirmation` is set is bound to a key and is accepted only through
`resource::validate_proof`, never as a bearer token. The proof must be a `dpop+jwt` signed with an accepted algorithm
by the key it carries, that key's RFC 7638 thumbprint must be the token's, and it must name this method and address,
be no more than 60 seconds from now, and carry this token's hash. The proof's `jti` comes back for the API to
remember and refuse if it is used again; keeping that record is the API's job.

## Building and checking

```sh
cargo test --workspace --tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo deny check
```

The end-to-end test runs the library against a running TessariDB OAuth server, over its published endpoints only:
it registers a public client and a user through the admin console, signs the user in, binds the tokens to a DPoP
key, checks them as an API would, refreshes them, and checks that a refresh token or code presented again ends the
session. It needs an operator of the company with the `users` and `clients` roles whose password is set and who has
no authenticator app yet (the test adds one, which the console asks for), so each run needs a fresh operator:

```sh
TESSARIDB_OAUTH_E2E_ISSUER=https://localhost:8443/acme \
TESSARIDB_OAUTH_E2E_ADMIN=http://127.0.0.1:9443/admin/acme \
TESSARIDB_OAUTH_E2E_OPERATOR=ops@acme.example TESSARIDB_OAUTH_E2E_PASSWORD="$OPERATOR_PASSWORD" \
SSL_CERT_FILE=ca.pem cargo test --test live -- --ignored
```

`SSL_CERT_FILE` names the authority of a server certificate that the system does not already trust.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
