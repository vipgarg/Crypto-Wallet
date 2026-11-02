//! Login for the watch-only PC app (ARCHITECTURE.md §9.8).
//!
//! - `store`: the app's local data (wallet list, TOTP secret) encrypted with a
//!   key derived from the password (Argon2id → XChaCha20-Poly1305).
//! - `totp`: RFC 6238 six-digit codes from an authenticator app.
//! - `lockout`: increasing delays and a 30-minute lock after repeated failures.
//!
//! Honest scope: this protects the wallet list and app access from someone
//! using the PC. No keys exist on this PC, so it does not protect funds, and
//! malware running as you can capture the password when you type it.

pub mod lockout;
pub mod store;
pub mod totp;

/// Fill `buf` from the operating system's secure random generator.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}
