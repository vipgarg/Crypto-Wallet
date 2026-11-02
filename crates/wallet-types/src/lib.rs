//! Types shared by every crate in the wallet.
//!
//! Security rules enforced here (ARCHITECTURE.md §3):
//! - P9 integers only: every amount is a `u128` count of the asset's base units
//!   (sats, wei, sun, USDT micro-units). There is no floating point anywhere.
//! - Arithmetic is checked; overflow is an error, never a wrap.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A blockchain network supported by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Bitcoin,
    Ethereum,
    Tron,
}

impl Network {
    pub const ALL: [Network; 3] = [Network::Bitcoin, Network::Ethereum, Network::Tron];

    pub fn display_name(self) -> &'static str {
        match self {
            Network::Bitcoin => "Bitcoin",
            Network::Ethereum => "Ethereum",
            Network::Tron => "TRON",
        }
    }
}

/// An asset the wallet tracks. Tokens are identified by network *and* contract
/// (the contract is pinned in the network config, never taken from a provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Asset {
    /// Native bitcoin, base unit = satoshi.
    Btc,
    /// Native ether (gas), base unit = wei.
    Eth,
    /// Native TRX (energy/bandwidth), base unit = sun.
    Trx,
    /// Tether USD on Ethereum (ERC-20), base unit = 10^-6 USDT.
    UsdtErc20,
    /// Tether USD on TRON (TRC-20), base unit = 10^-6 USDT.
    UsdtTrc20,
}

impl Asset {
    pub const ALL: [Asset; 5] = [
        Asset::Btc,
        Asset::Eth,
        Asset::Trx,
        Asset::UsdtErc20,
        Asset::UsdtTrc20,
    ];

    pub fn network(self) -> Network {
        match self {
            Asset::Btc => Network::Bitcoin,
            Asset::Eth | Asset::UsdtErc20 => Network::Ethereum,
            Asset::Trx | Asset::UsdtTrc20 => Network::Tron,
        }
    }

    /// Number of decimal places between the display unit and the base unit.
    pub fn decimals(self) -> u8 {
        match self {
            Asset::Btc => 8,
            Asset::Eth => 18,
            Asset::Trx => 6,
            Asset::UsdtErc20 | Asset::UsdtTrc20 => 6,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Asset::Btc => "BTC",
            Asset::Eth => "ETH",
            Asset::Trx => "TRX",
            Asset::UsdtErc20 | Asset::UsdtTrc20 => "USDT",
        }
    }

    /// Label that always states the network, so "USDT" is never ambiguous.
    pub fn label(self) -> &'static str {
        match self {
            Asset::Btc => "BTC (Bitcoin)",
            Asset::Eth => "ETH (Ethereum, for fees)",
            Asset::Trx => "TRX (TRON, for fees)",
            Asset::UsdtErc20 => "USDT on Ethereum (ERC-20)",
            Asset::UsdtTrc20 => "USDT on TRON (TRC-20)",
        }
    }

    /// Assets held on a given network.
    pub fn on_network(network: Network) -> &'static [Asset] {
        match network {
            Network::Bitcoin => &[Asset::Btc],
            Network::Ethereum => &[Asset::Eth, Asset::UsdtErc20],
            Network::Tron => &[Asset::Trx, Asset::UsdtTrc20],
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AmountError {
    #[error("amount arithmetic overflowed")]
    Overflow,
    #[error("cannot combine amounts of different assets ({0:?} and {1:?})")]
    AssetMismatch(Asset, Asset),
}

/// An amount of one asset, in base units. Never a float.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Amount {
    asset: Asset,
    #[serde(with = "u128_string")]
    base_units: u128,
}

impl Amount {
    pub const fn new(asset: Asset, base_units: u128) -> Self {
        Self { asset, base_units }
    }

    pub const fn zero(asset: Asset) -> Self {
        Self::new(asset, 0)
    }

    pub fn asset(&self) -> Asset {
        self.asset
    }

    pub fn base_units(&self) -> u128 {
        self.base_units
    }

    pub fn checked_add(self, other: Amount) -> Result<Amount, AmountError> {
        if self.asset != other.asset {
            return Err(AmountError::AssetMismatch(self.asset, other.asset));
        }
        let sum = self
            .base_units
            .checked_add(other.base_units)
            .ok_or(AmountError::Overflow)?;
        Ok(Amount::new(self.asset, sum))
    }

    /// Exact decimal string in display units, e.g. `1.5` BTC or `0.000001` USDT.
    /// Pure integer formatting; trailing zeros are trimmed.
    pub fn to_decimal_string(&self) -> String {
        format_base_units(self.base_units, self.asset.decimals())
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.to_decimal_string(), self.asset.symbol())
    }
}

/// Format an integer count of base units as a decimal string without floats.
pub fn format_base_units(base_units: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(u32::from(decimals));
    let whole = base_units / divisor;
    let frac = base_units % divisor;
    if decimals == 0 || frac == 0 {
        return whole.to_string();
    }
    let mut frac_str = format!("{:0width$}", frac, width = usize::from(decimals));
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{whole}.{frac_str}")
}

/// Serialize `u128` as a decimal string so the UI (JavaScript) never turns it
/// into a lossy floating-point number.
mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(serde::de::Error::custom(
                "expected a decimal integer string",
            ));
        }
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

/// Wallet tier (ARCHITECTURE.md §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Vault,
    Savings,
    Spending,
    WatchOnly,
}

impl Tier {
    pub fn display_name(self) -> &'static str {
        match self {
            Tier::Vault => "T-0 Vault",
            Tier::Savings => "T-1 Savings",
            Tier::Spending => "T-2 Spending",
            Tier::WatchOnly => "T-W Watch-only",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("wallet id must be 1-32 characters of a-z, 0-9 and '-', starting with a letter")]
pub struct InvalidWalletId;

/// Wallet identifier such as `savings-01`. Restricted alphabet so it is safe in
/// file names, logs and QR payloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WalletId(String);

impl WalletId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for WalletId {
    type Err = InvalidWalletId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        let valid_len = (1..=32).contains(&bytes.len());
        let starts_with_letter = bytes.first().is_some_and(u8::is_ascii_lowercase);
        let valid_chars = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if valid_len && starts_with_letter && valid_chars {
            Ok(WalletId(s.to_owned()))
        } else {
            Err(InvalidWalletId)
        }
    }
}

impl TryFrom<String> for WalletId {
    type Error = InvalidWalletId;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<WalletId> for String {
    fn from(id: WalletId) -> String {
        id.0
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shorten an address for logs and alerts (§10.0): first 4 + last 4 characters.
/// Never use this for comparison or display on the signing path.
pub fn short_address(addr: &str) -> String {
    let chars: Vec<char> = addr.chars().collect();
    if chars.len() <= 10 {
        return addr.to_owned();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_without_floats() {
        assert_eq!(format_base_units(0, 8), "0");
        assert_eq!(format_base_units(1, 8), "0.00000001");
        assert_eq!(format_base_units(150_000_000, 8), "1.5");
        assert_eq!(format_base_units(100_000_000, 8), "1");
        assert_eq!(format_base_units(1_234_567, 6), "1.234567");
        assert_eq!(format_base_units(1_000_000_000_000_000_000, 18), "1");
        assert_eq!(format_base_units(u128::MAX, 0), u128::MAX.to_string());
    }

    #[test]
    fn checked_add_rejects_overflow_and_mixed_assets() {
        let a = Amount::new(Asset::Btc, u128::MAX);
        assert_eq!(
            a.checked_add(Amount::new(Asset::Btc, 1)),
            Err(AmountError::Overflow)
        );
        assert_eq!(
            Amount::zero(Asset::Btc).checked_add(Amount::zero(Asset::UsdtTrc20)),
            Err(AmountError::AssetMismatch(Asset::Btc, Asset::UsdtTrc20))
        );
        assert_eq!(
            Amount::new(Asset::UsdtTrc20, 5)
                .checked_add(Amount::new(Asset::UsdtTrc20, 7))
                .map(|a| a.base_units()),
            Ok(12)
        );
    }

    #[test]
    fn amount_serializes_base_units_as_string() {
        let a = Amount::new(Asset::Eth, 1_000_000_000_000_000_000_000);
        let json = serde_json::to_string(&a).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"asset":"eth","base_units":"1000000000000000000000"}"#
        );
        let back: Amount = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back, a);
        assert!(serde_json::from_str::<Amount>(r#"{"asset":"eth","base_units":"1.5"}"#).is_err());
        assert!(serde_json::from_str::<Amount>(r#"{"asset":"eth","base_units":"-1"}"#).is_err());
    }

    #[test]
    fn wallet_id_validation() {
        for ok in ["savings-01", "spend-01", "v", "vault-btc-2of3"] {
            assert!(ok.parse::<WalletId>().is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Savings",
            "01-savings",
            "a b",
            "a/b",
            "a_b",
            &"x".repeat(33),
        ] {
            assert!(bad.parse::<WalletId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn usdt_is_always_labelled_with_its_network() {
        assert!(Asset::UsdtErc20.label().contains("Ethereum"));
        assert!(Asset::UsdtTrc20.label().contains("TRON"));
        assert_eq!(Asset::UsdtTrc20.network(), Network::Tron);
    }

    #[test]
    fn short_address_keeps_ends() {
        assert_eq!(
            short_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            "TR7N…Lj6t"
        );
        assert_eq!(short_address("abc"), "abc");
    }
}
