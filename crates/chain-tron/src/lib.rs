//! TRON: address handling and read-only HTTP API encoding for the watch-only app.
//!
//! Security rules (ARCHITECTURE.md §7 ②, §8.3):
//! - Addresses are Base58Check with the mainnet `0x41` prefix; anything else is
//!   rejected. The `Base58 → hex → Base58` round trip must reproduce the input.
//! - Contract addresses are compared as bytes (`41` + 20 bytes), never by name.
//! - Only read-only endpoints are used: `getaccount` and
//!   `triggerconstantcontract`. Node-built transactions are never used.

use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::Xpub;
use chain_eth::{derive_receive_pubkey, DeriveError, EthAddress};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Mainnet address prefix byte.
pub const MAINNET_PREFIX: u8 = 0x41;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TronAddressError {
    #[error("not a valid TRON address (Base58Check, starts with T, 34 characters)")]
    Format,
    #[error("Base58Check checksum is wrong: the address has a typo or was altered")]
    BadChecksum,
    #[error("not a TRON mainnet address")]
    WrongPrefix,
}

/// A TRON mainnet address: `0x41` followed by 20 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TronAddress([u8; 20]);

impl TronAddress {
    pub fn from_hash20(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// TRON uses the same 20-byte keccak hash of the public key as Ethereum.
    pub fn from_eth_address(eth: &EthAddress) -> Self {
        Self(*eth.as_bytes())
    }

    pub fn hash20(&self) -> &[u8; 20] {
        &self.0
    }

    /// The 21-byte form used inside transactions and by node APIs.
    pub fn to_bytes21(&self) -> [u8; 21] {
        let mut out = [0u8; 21];
        out[0] = MAINNET_PREFIX;
        out[1..].copy_from_slice(&self.0);
        out
    }

    /// Lower-case hex of the 21-byte form, e.g. `41a614…`.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes21())
    }

    pub fn from_hex(s: &str) -> Result<Self, TronAddressError> {
        let mut bytes = [0u8; 21];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| TronAddressError::Format)?;
        if bytes[0] != MAINNET_PREFIX {
            return Err(TronAddressError::WrongPrefix);
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes[1..]);
        Ok(Self(h))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes21()).with_check().into_string()
    }
}

impl FromStr for TronAddress {
    type Err = TronAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 34 || !s.starts_with('T') {
            return Err(TronAddressError::Format);
        }
        let decoded = bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|e| match e {
                bs58::decode::Error::InvalidChecksum { .. } => TronAddressError::BadChecksum,
                _ => TronAddressError::Format,
            })?;
        if decoded.len() != 21 {
            return Err(TronAddressError::Format);
        }
        if decoded[0] != MAINNET_PREFIX {
            return Err(TronAddressError::WrongPrefix);
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&decoded[1..]);
        let addr = Self(h);
        // Round-trip rule from §8.3.
        if addr.to_base58() != s {
            return Err(TronAddressError::Format);
        }
        Ok(addr)
    }
}

impl fmt::Display for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for TronAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_base58();
        write!(f, "TronAddress({}…{})", &s[..4], &s[s.len() - 4..])
    }
}

impl Serialize for TronAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base58())
    }
}

impl<'de> Deserialize<'de> for TronAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// TRON address at `m/44'/195'/account'/0/index`, from the account xpub.
pub fn derive_address(account: &Xpub, index: u32) -> Result<TronAddress, DeriveError> {
    let pk = derive_receive_pubkey(account, index)?;
    Ok(TronAddress::from_eth_address(&EthAddress::from_public_key(
        &pk,
    )))
}

/// Read-only HTTP API helpers (`/wallet/...` endpoints). Transport lives in
/// `data-sources`.
pub mod api {
    use super::TronAddress;
    use serde_json::{json, Value};
    use thiserror::Error;

    pub const GET_ACCOUNT_PATH: &str = "/wallet/getaccount";
    pub const TRIGGER_CONSTANT_PATH: &str = "/wallet/triggerconstantcontract";
    pub const GET_NOW_BLOCK_PATH: &str = "/wallet/getnowblock";

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum ApiError {
        #[error("node returned an error: {0}")]
        Node(String),
        #[error("node response is malformed")]
        Malformed,
        #[error("value does not fit in 128 bits")]
        Overflow,
    }

    pub fn get_account(addr: &TronAddress) -> Value {
        json!({"address": addr.to_hex()})
    }

    /// Parse TRX balance (sun) from a `getaccount` response. An account that
    /// has never received anything is returned as `{}`: balance 0.
    pub fn parse_trx_balance(resp: &Value) -> Result<u128, ApiError> {
        let obj = resp.as_object().ok_or(ApiError::Malformed)?;
        if let Some(err) = obj.get("Error").or_else(|| obj.get("error")) {
            return Err(ApiError::Node(err.to_string().chars().take(200).collect()));
        }
        match obj.get("balance") {
            None => Ok(0),
            Some(v) => {
                let n = v.as_u64().ok_or(ApiError::Malformed)?;
                Ok(u128::from(n))
            }
        }
    }

    /// `triggerconstantcontract` call of `balanceOf(holder)` on a TRC-20 token.
    /// Read-only: it executes locally on the node and is never broadcast.
    pub fn trc20_balance_of(token: &TronAddress, holder: &TronAddress) -> Value {
        let mut param = String::with_capacity(64);
        param.push_str(&"0".repeat(24));
        param.push_str(&hex::encode(holder.hash20()));
        json!({
            "owner_address": holder.to_hex(),
            "contract_address": token.to_hex(),
            "function_selector": "balanceOf(address)",
            "parameter": param,
        })
    }

    /// Parse the `constant_result[0]` uint256 word of a `balanceOf` call.
    pub fn parse_trc20_balance(resp: &Value) -> Result<u128, ApiError> {
        let ok = resp
            .get("result")
            .and_then(|r| r.get("result"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !ok {
            let msg = resp
                .get("result")
                .and_then(|r| r.get("message"))
                .map(|m| m.to_string())
                .unwrap_or_else(|| "call failed".to_owned());
            return Err(ApiError::Node(msg.chars().take(200).collect()));
        }
        let results = resp
            .get("constant_result")
            .and_then(Value::as_array)
            .ok_or(ApiError::Malformed)?;
        if results.len() != 1 {
            return Err(ApiError::Malformed);
        }
        let word = results[0].as_str().ok_or(ApiError::Malformed)?;
        if word.len() != 64 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::Malformed);
        }
        let (high, low) = word.split_at(32);
        if high.bytes().any(|b| b != b'0') {
            return Err(ApiError::Overflow);
        }
        u128::from_str_radix(low, 16).map_err(|_| ApiError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use serde_json::json;

    /// Pinned USDT TRC-20 contract (ARCHITECTURE.md §8.3).
    const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    #[test]
    fn usdt_contract_round_trips() {
        let a: TronAddress = USDT.parse().expect("usdt");
        assert_eq!(a.to_base58(), USDT);
        assert_eq!(a.to_hex(), "41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
        assert_eq!(TronAddress::from_hex(&a.to_hex()), Ok(a));
    }

    #[test]
    fn rejects_bad_addresses() {
        // One character changed → checksum fails.
        let typo = USDT.replacen('7', "8", 1);
        assert_eq!(
            typo.parse::<TronAddress>(),
            Err(TronAddressError::BadChecksum)
        );
        assert_eq!("TR7N".parse::<TronAddress>(), Err(TronAddressError::Format));
        // A Bitcoin address is not a TRON address.
        assert_eq!(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse::<TronAddress>(),
            Err(TronAddressError::Format)
        );
        // Correct checksum but wrong prefix (0x42) → rejected.
        let mut bytes = [0u8; 21];
        bytes[0] = 0x42;
        let other = bs58::encode(bytes).with_check().into_string();
        assert!(other.parse::<TronAddress>().is_err());
        assert_eq!(
            TronAddress::from_hex("42a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
            Err(TronAddressError::WrongPrefix)
        );
    }

    #[test]
    fn derivation_matches_ethereum_hash_with_tron_prefix() {
        let m = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("mnemonic");
        let seed = m.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &seed).expect("master");
        let path: DerivationPath = "m/44'/195'/0'".parse().expect("path");
        let acct = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).expect("d"));
        let addr = derive_address(&acct, 0).expect("derive");
        let s = addr.to_base58();
        assert!(s.starts_with('T') && s.len() == 34);
        assert_eq!(s.parse::<TronAddress>(), Ok(addr));
        // NOTE: an external vector (address shown by an independent wallet for
        // this mnemonic) must be added in Phase 2 (ARCHITECTURE.md §6.2 exit test).
    }

    #[test]
    fn trc20_balance_request_and_parse() {
        let token: TronAddress = USDT.parse().expect("t");
        let req = api::trc20_balance_of(&token, &token);
        assert_eq!(req["function_selector"], "balanceOf(address)");
        assert_eq!(
            req["parameter"],
            "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        );
        assert_eq!(
            req["contract_address"],
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        );

        let ok = json!({
            "result": {"result": true},
            "energy_used": 900,
            "constant_result": [format!("{}{}", "0".repeat(56), "000f4240")],
        });
        assert_eq!(api::parse_trc20_balance(&ok), Ok(1_000_000));

        let failed = json!({"result": {"code": "CONTRACT_VALIDATE_ERROR", "message": "x"}});
        assert!(matches!(
            api::parse_trc20_balance(&failed),
            Err(api::ApiError::Node(_))
        ));
        let two = json!({"result": {"result": true}, "constant_result": ["00", "00"]});
        assert_eq!(
            api::parse_trc20_balance(&two),
            Err(api::ApiError::Malformed)
        );
    }

    #[test]
    fn trx_balance_parse() {
        assert_eq!(api::parse_trx_balance(&json!({})), Ok(0));
        assert_eq!(
            api::parse_trx_balance(&json!({"address": "41..", "balance": 2_500_000})),
            Ok(2_500_000)
        );
        assert_eq!(
            api::parse_trx_balance(&json!({"balance": "12"})),
            Err(api::ApiError::Malformed)
        );
        assert_eq!(
            api::parse_trx_balance(&json!([1])),
            Err(api::ApiError::Malformed)
        );
        assert!(matches!(
            api::parse_trx_balance(&json!({"Error": "bad"})),
            Err(api::ApiError::Node(_))
        ));
    }
}
