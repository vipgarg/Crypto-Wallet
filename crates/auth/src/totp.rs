//! RFC 6238 time-based one-time codes (SHA-1, 30-second steps, 6 digits):
//! the format every authenticator app supports.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
pub const SECRET_LEN: usize = 20;
/// Accept the previous and next 30-second step too (clock drift).
pub const WINDOW: u64 = 1;

/// The code for a given 30-second step (`unix_time / 30`).
pub fn code_at_step(secret: &[u8], step: u64, digits: u32) -> u32 {
    let mut mac = match Hmac::<Sha1>::new_from_slice(secret) {
        Ok(m) => m,
        // HMAC accepts keys of any length; this can't happen.
        Err(_) => return 0,
    };
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = usize::from(h[19] & 0x0f);
    let bin = (u32::from(h[offset]) & 0x7f) << 24
        | u32::from(h[offset + 1]) << 16
        | u32::from(h[offset + 2]) << 8
        | u32::from(h[offset + 3]);
    bin % 10u32.pow(digits)
}

/// Check a 6-digit code. Returns the matched step, which must be strictly
/// greater than `last_used_step` so a code can't be used twice.
pub fn verify(secret: &[u8], code: &str, now_unix: u64, last_used_step: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let given: u32 = code.parse().ok()?;
    let now_step = now_unix / STEP_SECS;
    let first = now_step.saturating_sub(WINDOW);
    (first..=now_step + WINDOW)
        .filter(|s| *s > last_used_step)
        .find(|s| code_at_step(secret, *s, DIGITS) == given)
}

/// A new random secret.
pub fn new_secret() -> Result<Zeroizing<Vec<u8>>, getrandom::Error> {
    let mut s = Zeroizing::new(vec![0u8; SECRET_LEN]);
    crate::random_bytes(&mut s)?;
    Ok(s)
}

/// Base32 text form, as typed into an authenticator app by hand.
pub fn secret_base32(secret: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(BASE32_NOPAD.encode(secret))
}

pub fn secret_from_base32(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    BASE32_NOPAD.decode(s.as_bytes()).ok().map(Zeroizing::new)
}

/// `otpauth://` link shown as a QR code for the authenticator app. The label
/// is generic on purpose (no wallet names or amounts).
pub fn otpauth_uri(secret: &[u8], account: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "otpauth://totp/Watch-Only%20Wallet:{account}?secret={}&issuer=Watch-Only%20Wallet&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        BASE32_NOPAD.encode(secret)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA-1 secret "12345678901234567890").
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vectors() {
        for (time, expected8) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
        ] {
            assert_eq!(
                code_at_step(RFC_SECRET, time / STEP_SECS, 8),
                expected8,
                "t={time}"
            );
            assert_eq!(
                code_at_step(RFC_SECRET, time / STEP_SECS, 6),
                expected8 % 1_000_000
            );
        }
    }

    #[test]
    fn verify_window_and_replay() {
        let now = 1_234_567_890;
        let step = now / STEP_SECS;
        let code = format!("{:06}", code_at_step(RFC_SECRET, step, 6));
        assert_eq!(verify(RFC_SECRET, &code, now, 0), Some(step));
        // Still accepted 30 s later (clock drift), not 90 s later.
        assert_eq!(verify(RFC_SECRET, &code, now + 30, 0), Some(step));
        assert_eq!(verify(RFC_SECRET, &code, now + 90, 0), None);
        // Replay: once step `step` was used, the same code is refused.
        assert_eq!(verify(RFC_SECRET, &code, now, step), None);
        // Malformed input.
        for bad in ["", "12345", "1234567", "12a456", " 12 456"] {
            assert_eq!(verify(RFC_SECRET, bad, now, 0), None, "{bad:?}");
        }
    }

    #[test]
    fn base32_and_uri() {
        let s = secret_base32(RFC_SECRET);
        assert_eq!(s.as_str(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(
            secret_from_base32(&s).map(|v| v.to_vec()),
            Some(RFC_SECRET.to_vec())
        );
        let uri = otpauth_uri(RFC_SECRET, "pc");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert_eq!(new_secret().map(|s| s.len()).ok(), Some(SECRET_LEN));
    }
}
