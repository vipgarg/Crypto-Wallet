//! Test or real networks (ARCHITECTURE-MOBILE.md, release gates).
//!
//! Every wallet is one or the other, decided when it is created (or
//! restored), and recorded inside its encrypted vault:
//! - wallets made by a **test build** are test wallets: they sign only on
//!   test networks (TRON Nile, Ethereum Sepolia, Bitcoin signet);
//! - wallets made by a **real-networks build** (Cargo feature
//!   `real-networks`, built only on request and only with the app's signing
//!   key pinned) are real wallets: they sign only on real networks.
//!
//! A test build never signs with a real wallet. Keeping the two apart means
//! a test wallet's signature can't be passed off as a real payment (TRON
//! transactions carry no network id), and a real wallet is never used for
//! practice.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Test,
    Real,
}

impl Mode {
    /// The mode of wallets this build creates.
    pub fn of_this_build() -> Self {
        if cfg!(feature = "real-networks") {
            Mode::Real
        } else {
            Mode::Test
        }
    }

    pub fn from_real(real: bool) -> Self {
        if real {
            Mode::Real
        } else {
            Mode::Test
        }
    }

    /// Whether this build may sign in this mode.
    pub fn allowed(self) -> bool {
        match self {
            Mode::Test => true,
            Mode::Real => cfg!(feature = "real-networks"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builds_never_sign_real() {
        assert!(Mode::Test.allowed());
        assert_eq!(Mode::Real.allowed(), cfg!(feature = "real-networks"));
    }
}
