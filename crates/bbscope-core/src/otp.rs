//! RFC 6238 TOTP (HMAC-SHA1, 30s step) used for platform 2FA logins.

use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::{BASE32, BASE32HEX, BASE32HEX_NOPAD, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::{Error, Result};

/// Generates the current TOTP code for `secret`.
pub fn generate_totp_now(secret: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    generate_totp(secret, now)
}

/// Generates a TOTP code for `secret` at unix time `unix_secs`.
///
/// Accepted secret formats: raw base32 (with or without padding, std or hex
/// alphabet), `"<digits> <base32>"`, or an `otpauth://` URI.
pub fn generate_totp(secret: &str, unix_secs: u64) -> Result<String> {
    let (key, digits) = parse_secret(secret)?;
    let digits = if digits == 0 { 6 } else { digits.min(9) };
    let step = unix_secs / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|e| Error::other(e.to_string()))?;
    mac.update(&step.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let offset = (sum[sum.len() - 1] & 0x0f) as usize;
    let code = (u32::from(sum[offset]) & 0x7f) << 24
        | u32::from(sum[offset + 1]) << 16
        | u32::from(sum[offset + 2]) << 8
        | u32::from(sum[offset + 3]);
    let code = code % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

fn parse_secret(s: &str) -> Result<(Vec<u8>, u32)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::other("empty TOTP secret"));
    }
    if s.to_lowercase().starts_with("otpauth://") {
        let u = url::Url::parse(s).map_err(|e| Error::other(format!("invalid otpauth URI: {e}")))?;
        let mut secret = String::new();
        let mut digits = 6;
        for (k, v) in u.query_pairs() {
            match k.as_ref() {
                "secret" => secret = v.into_owned(),
                "digits" => digits = v.parse().unwrap_or(6),
                _ => {}
            }
        }
        return Ok((decode_base32(&secret)?, digits));
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        if let Ok(d) = parts[0].parse::<u32>() {
            return Ok((decode_base32(&parts[1..].concat())?, d));
        }
    }
    Ok((decode_base32(&parts.concat())?, 6))
}

fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    let up = secret.trim().to_uppercase();
    if up.is_empty() {
        return Err(Error::other("empty TOTP secret"));
    }
    let nopad = up.trim_end_matches('=');
    [
        BASE32.decode(up.as_bytes()),
        BASE32_NOPAD.decode(nopad.as_bytes()),
        BASE32HEX.decode(up.as_bytes()),
        BASE32HEX_NOPAD.decode(nopad.as_bytes()),
    ]
    .into_iter()
    .flatten()
    .find(|k| !k.is_empty())
    .ok_or_else(|| Error::other("unsupported TOTP secret format"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector: secret "12345678901234567890" (ASCII), SHA1.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors() {
        assert_eq!(generate_totp(&format!("8 {SECRET}"), 59).unwrap(), "94287082");
        assert_eq!(generate_totp(&format!("8 {SECRET}"), 1111111109).unwrap(), "07081804");
        assert_eq!(generate_totp(SECRET, 59).unwrap(), "287082");
    }

    #[test]
    fn otpauth_uri() {
        let uri = format!("otpauth://totp/x?secret={SECRET}&digits=8");
        assert_eq!(generate_totp(&uri, 59).unwrap(), "94287082");
    }

    #[test]
    fn lowercase_and_spaces() {
        assert_eq!(generate_totp(&SECRET.to_lowercase(), 59).unwrap(), "287082");
    }
}
