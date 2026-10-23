//! Codes of an authenticator app (RFC 6238 with the RFC 4226 truncation): HMAC-SHA-1 over the 30-second step, six
//! digits, from a secret given in base32 (RFC 4648 section 6).

use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const STEP_SECS: u64 = 30;

/// The bytes of base32 `text`, padding and case ignored.
pub fn decoded(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for symbol in text.trim_end_matches('=').bytes() {
        let value = ALPHABET
            .iter()
            .position(|known| *known == symbol.to_ascii_uppercase())
            .expect("base32");
        buffer = (buffer << 5) | u32::try_from(value).expect("five bits");
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).expect("a byte"));
        }
    }
    bytes
}

/// The current step.
pub fn step() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
        / STEP_SECS
}

/// The code of `secret` at `step`.
pub fn code(secret: &[u8], step: u64) -> String {
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret),
        &step.to_be_bytes(),
    );
    let tag = tag.as_ref();
    let offset = usize::from(tag[19] & 0x0f);
    let word = u32::from_be_bytes([
        tag[offset],
        tag[offset + 1],
        tag[offset + 2],
        tag[offset + 3],
    ]) & 0x7fff_ffff;
    format!("{:06}", word % 1_000_000)
}

/// The code of `secret` now.
pub fn now(secret: &[u8]) -> String {
    code(secret, step())
}

#[test]
fn the_rfc_6238_sha1_vectors_hold() {
    // Appendix B, T = 59 and 1111111109 (steps 1 and 37037036); six digits are the eight modulo 10^6.
    let secret = b"12345678901234567890";
    assert_eq!(code(secret, 1), "287082");
    assert_eq!(code(secret, 37_037_036), "081804");
    assert_eq!(decoded("GEZDGNBVGY3TQOJQ"), b"1234567890");
}
