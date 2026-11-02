//! Bitcoin watch-only support: address parsing, BIP-84 address derivation from
//! an account xpub/zpub, gap-limit scanning, and Esplora API parsing.
//!
//! Privacy rule (ARCHITECTURE.md §8.1): the xpub never leaves this machine.
//! Providers are only ever asked about individual addresses.

use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BIP-84 gap limit: stop after this many consecutive unused addresses.
pub const GAP_LIMIT: u32 = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BtcError {
    #[error("not a valid Bitcoin address")]
    InvalidAddress,
    #[error("not a Bitcoin mainnet address (testnet/regtest addresses are rejected)")]
    WrongNetwork,
    #[error("not a valid extended public key (expected xpub… or zpub…)")]
    InvalidXpub,
    #[error("extended public key must be an account key at depth 3 (m/84'/0'/account')")]
    WrongDepth,
    #[error("private extended keys are never accepted by the watch-only app")]
    PrivateKey,
    #[error("index must be below 2^31")]
    BadIndex,
    #[error("key derivation failed")]
    Derivation,
}

/// A Bitcoin mainnet address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BtcAddress(Address);

impl BtcAddress {
    pub fn inner(&self) -> &Address {
        &self.0
    }
}

impl FromStr for BtcAddress {
    type Err = BtcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unchecked = Address::from_str(s).map_err(|_| BtcError::InvalidAddress)?;
        let checked = unchecked
            .require_network(Network::Bitcoin)
            .map_err(|_| BtcError::WrongNetwork)?;
        Ok(Self(checked))
    }
}

impl fmt::Display for BtcAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for BtcAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.to_string();
        write!(
            f,
            "BtcAddress({}…{})",
            &s[..6.min(s.len())],
            &s[s.len().saturating_sub(4)..]
        )
    }
}

impl Serialize for BtcAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for BtcAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Version bytes (BIP-32 / SLIP-132).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
const XPRV_PREFIXES: [&str; 4] = ["xprv", "yprv", "zprv", "tprv"];

/// A BIP-84 (native SegWit) account extended public key.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountXpub(Xpub);

impl AccountXpub {
    pub fn xpub(&self) -> &Xpub {
        &self.0
    }

    /// Short fingerprint of this key, safe to show and log.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint().to_string()
    }

    /// P2WPKH address at `<account>/<chain>/<index>` (chain 0 = receive, 1 = change).
    pub fn derive_address(&self, chain: Chain, index: u32) -> Result<BtcAddress, BtcError> {
        let secp = Secp256k1::verification_only();
        let path = [
            ChildNumber::from_normal_idx(chain as u32).map_err(|_| BtcError::BadIndex)?,
            ChildNumber::from_normal_idx(index).map_err(|_| BtcError::BadIndex)?,
        ];
        let child = self
            .0
            .derive_pub(&secp, &path)
            .map_err(|_| BtcError::Derivation)?;
        let pk = CompressedPublicKey(child.public_key);
        Ok(BtcAddress(Address::p2wpkh(&pk, Network::Bitcoin)))
    }
}

impl FromStr for AccountXpub {
    type Err = BtcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if XPRV_PREFIXES.iter().any(|p| s.starts_with(p)) {
            return Err(BtcError::PrivateKey);
        }
        let mut data = bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|_| BtcError::InvalidXpub)?;
        if data.len() != 78 {
            return Err(BtcError::InvalidXpub);
        }
        match [data[0], data[1], data[2], data[3]] {
            XPUB_VERSION => {}
            ZPUB_VERSION => data[..4].copy_from_slice(&XPUB_VERSION),
            _ => return Err(BtcError::InvalidXpub),
        }
        let xpub = Xpub::decode(&data).map_err(|_| BtcError::InvalidXpub)?;
        if xpub.depth != 3 {
            return Err(BtcError::WrongDepth);
        }
        Ok(Self(xpub))
    }
}

impl fmt::Debug for AccountXpub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the xpub itself (privacy, §8.1).
        write!(f, "AccountXpub(fingerprint {})", self.fingerprint())
    }
}

impl Serialize for AccountXpub {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for AccountXpub {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Receive = 0,
    Change = 1,
}

/// Tracks the BIP-44 gap limit while scanning addresses in order.
#[derive(Debug, Clone)]
pub struct GapScanner {
    limit: u32,
    consecutive_unused: u32,
    next_index: u32,
}

impl GapScanner {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            consecutive_unused: 0,
            next_index: 0,
        }
    }

    /// The next index to query, or `None` once the gap limit is reached.
    pub fn next(&self) -> Option<u32> {
        (self.consecutive_unused < self.limit).then_some(self.next_index)
    }

    /// Record whether the address at the current index has ever been used.
    pub fn record(&mut self, used: bool) {
        self.consecutive_unused = if used { 0 } else { self.consecutive_unused + 1 };
        self.next_index += 1;
    }
}

/// Esplora (`GET /address/:address`) response parsing.
pub mod esplora {
    use serde::Deserialize;
    use thiserror::Error;

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum EsploraError {
        #[error("provider response is malformed")]
        Malformed,
        #[error("provider reports more spent than funded")]
        Inconsistent,
    }

    #[derive(Debug, Deserialize)]
    struct Stats {
        funded_txo_sum: u64,
        spent_txo_sum: u64,
        tx_count: u64,
    }

    #[derive(Debug, Deserialize)]
    struct AddressResponse {
        chain_stats: Stats,
        mempool_stats: Stats,
    }

    /// Facts about one address. Only `confirmed_sats` and `tx_count` are
    /// cross-checked between providers; mempool numbers are informational.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AddressStats {
        pub confirmed_sats: u64,
        pub tx_count: u64,
        pub mempool_incoming_sats: u64,
        pub mempool_outgoing_sats: u64,
        pub mempool_tx_count: u64,
    }

    impl AddressStats {
        pub fn ever_used(&self) -> bool {
            self.tx_count > 0 || self.mempool_tx_count > 0
        }
    }

    pub fn parse_address(body: &str) -> Result<AddressStats, EsploraError> {
        let r: AddressResponse = serde_json::from_str(body).map_err(|_| EsploraError::Malformed)?;
        let confirmed = r
            .chain_stats
            .funded_txo_sum
            .checked_sub(r.chain_stats.spent_txo_sum)
            .ok_or(EsploraError::Inconsistent)?;
        Ok(AddressStats {
            confirmed_sats: confirmed,
            tx_count: r.chain_stats.tx_count,
            mempool_incoming_sats: r.mempool_stats.funded_txo_sum,
            mempool_outgoing_sats: r.mempool_stats.spent_txo_sum,
            mempool_tx_count: r.mempool_stats.tx_count,
        })
    }

    /// `GET /blocks/tip/height` returns a bare integer.
    pub fn parse_tip_height(body: &str) -> Result<u64, EsploraError> {
        body.trim()
            .parse::<u64>()
            .map_err(|_| EsploraError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from BIP-84 (mnemonic "abandon … about", account 0).
    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn bip84_vectors() {
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        assert_eq!(
            acct.derive_address(Chain::Receive, 0)
                .expect("r0")
                .to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            acct.derive_address(Chain::Receive, 1)
                .expect("r1")
                .to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            acct.derive_address(Chain::Change, 0)
                .expect("c0")
                .to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }

    #[test]
    fn xpub_form_gives_same_addresses() {
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let as_xpub = acct.xpub().to_string();
        assert!(as_xpub.starts_with("xpub"));
        let again: AccountXpub = as_xpub.parse().expect("xpub");
        assert_eq!(
            again.derive_address(Chain::Receive, 0).expect("a"),
            acct.derive_address(Chain::Receive, 0).expect("b")
        );
    }

    #[test]
    fn rejects_private_keys_and_bad_input() {
        assert_eq!(
            "xprv9s21ZrQH143K".parse::<AccountXpub>(),
            Err(BtcError::PrivateKey)
        );
        assert_eq!(
            "zprvAWgYBBk7JR8Gj".parse::<AccountXpub>(),
            Err(BtcError::PrivateKey)
        );
        assert_eq!("hello".parse::<AccountXpub>(), Err(BtcError::InvalidXpub));
        let mut typo = ZPUB.to_owned();
        typo.replace_range(20..21, "x");
        assert_eq!(typo.parse::<AccountXpub>(), Err(BtcError::InvalidXpub));
    }

    #[test]
    fn address_network_is_enforced() {
        assert!("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            .parse::<BtcAddress>()
            .is_ok());
        assert_eq!(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".parse::<BtcAddress>(),
            Err(BtcError::WrongNetwork)
        );
        assert_eq!(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv".parse::<BtcAddress>(),
            Err(BtcError::InvalidAddress)
        );
        assert_eq!(
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse::<BtcAddress>(),
            Err(BtcError::InvalidAddress)
        );
    }

    #[test]
    fn debug_hides_xpub() {
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let dbg = format!("{acct:?}");
        assert!(!dbg.contains("pub6"));
    }

    #[test]
    fn gap_scanner_stops_after_limit() {
        let mut g = GapScanner::new(3);
        let used = [true, false, true, false, false, false, true];
        let mut queried = vec![];
        let mut i = 0;
        while let Some(idx) = g.next() {
            queried.push(idx);
            g.record(used.get(i).copied().unwrap_or(false));
            i += 1;
        }
        // Index 6 is never reached: indexes 3,4,5 were three unused in a row.
        assert_eq!(queried, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn esplora_parsing() {
        let body = r#"{"address":"bc1q...","chain_stats":{"funded_txo_count":2,"funded_txo_sum":150000,"spent_txo_count":1,"spent_txo_sum":50000,"tx_count":3},"mempool_stats":{"funded_txo_count":1,"funded_txo_sum":1000,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":1}}"#;
        let s = esplora::parse_address(body).expect("parse");
        assert_eq!(s.confirmed_sats, 100_000);
        assert_eq!(s.tx_count, 3);
        assert_eq!(s.mempool_incoming_sats, 1000);
        assert!(s.ever_used());

        let bad = r#"{"chain_stats":{"funded_txo_sum":1,"spent_txo_sum":2,"tx_count":1},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}"#;
        assert_eq!(
            esplora::parse_address(bad),
            Err(esplora::EsploraError::Inconsistent)
        );
        assert_eq!(
            esplora::parse_address("{}"),
            Err(esplora::EsploraError::Malformed)
        );
        assert_eq!(esplora::parse_tip_height("870123\n"), Ok(870_123));
        assert!(esplora::parse_tip_height("abc").is_err());
    }
}
