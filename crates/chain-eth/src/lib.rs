//! Ethereum: address handling and read-only JSON-RPC encoding for the
//! watch-only app.
//!
//! No transaction building or signing lives here yet (that's Phase 2).
//! Security rules (ARCHITECTURE.md §7 ②, §8.2):
//! - Addresses must carry a valid EIP-55 checksum. All-lowercase or
//!   all-uppercase input is rejected (fail closed, P5), because it can't be
//!   checked for typos.
//! - The USDT contract address comes from the pinned network config, never
//!   from a provider.

use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use bitcoin::bip32::Xpub as AccountXpub;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EthAddressError {
    #[error("an Ethereum address starts with 0x followed by 40 hex characters")]
    Format,
    #[error("address has no EIP-55 checksum (all lower- or upper-case); use the checksummed form")]
    NoChecksum,
    #[error("EIP-55 checksum is wrong: the address has a typo or was altered")]
    BadChecksum,
    #[error("the zero address is not a valid recipient or wallet")]
    Zero,
}

/// A 20-byte Ethereum address that passed EIP-55 validation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EthAddress([u8; 20]);

impl EthAddress {
    pub fn from_bytes(bytes: [u8; 20]) -> Result<Self, EthAddressError> {
        if bytes == [0u8; 20] {
            return Err(EthAddressError::Zero);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Address from a secp256k1 public key: last 20 bytes of keccak256 over the
    /// 64-byte uncompressed point (without the 0x04 prefix).
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let uncompressed = pk.serialize_uncompressed();
        let hash = keccak256(&uncompressed[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        Self(out)
    }

    /// EIP-55 mixed-case checksum encoding, with `0x` prefix.
    pub fn to_checksum(&self) -> String {
        let lower = hex::encode(self.0);
        let hash = keccak256(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower.chars().enumerate() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if c.is_ascii_alphabetic() && nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
        out
    }
}

impl FromStr for EthAddress {
    type Err = EthAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix("0x").ok_or(EthAddressError::Format)?;
        if body.len() != 40 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EthAddressError::Format);
        }
        let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(body, &mut bytes).map_err(|_| EthAddressError::Format)?;
        let addr = EthAddress::from_bytes(bytes)?;
        let only_digits = !has_lower && !has_upper;
        if !only_digits && !(has_lower && has_upper) {
            return Err(EthAddressError::NoChecksum);
        }
        if addr.to_checksum() != s {
            return Err(EthAddressError::BadChecksum);
        }
        Ok(addr)
    }
}

impl fmt::Display for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

/// Debug is shortened so full addresses don't end up in logs (§9.2).
impl fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_checksum();
        write!(f, "EthAddress({}…{})", &s[..6], &s[s.len() - 4..])
    }
}

impl Serialize for EthAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_checksum())
    }
}

impl<'de> Deserialize<'de> for EthAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error("account xpub must be at depth 3 (m/44'/coin'/account')")]
    WrongDepth,
    #[error("index must be below 2^31 (non-hardened)")]
    BadIndex,
    #[error("key derivation failed")]
    Derivation,
}

/// Derive the public key at `<account xpub>/0/<index>` (BIP-44 external chain).
/// Works for any BIP-44 coin, so TRON reuses it with its own account xpub.
pub fn derive_receive_pubkey(account: &Xpub, index: u32) -> Result<PublicKey, DeriveError> {
    if account.depth != 3 {
        return Err(DeriveError::WrongDepth);
    }
    let idx = ChildNumber::from_normal_idx(index).map_err(|_| DeriveError::BadIndex)?;
    let secp = Secp256k1::verification_only();
    let child = account
        .derive_pub(
            &secp,
            &[
                ChildNumber::from_normal_idx(0).map_err(|_| DeriveError::BadIndex)?,
                idx,
            ],
        )
        .map_err(|_| DeriveError::Derivation)?;
    Ok(child.public_key)
}

/// Ethereum address at `m/44'/60'/account'/0/index`, from the account xpub.
pub fn derive_address(account: &Xpub, index: u32) -> Result<EthAddress, DeriveError> {
    Ok(EthAddress::from_public_key(&derive_receive_pubkey(
        account, index,
    )?))
}

/// Read-only JSON-RPC helpers. These build request bodies and parse results;
/// the HTTP transport lives in `data-sources`.
pub mod rpc {
    use super::EthAddress;
    use serde_json::{json, Value};
    use thiserror::Error;

    /// `balanceOf(address)` selector.
    pub const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum RpcError {
        #[error("provider returned an error: {0}")]
        Provider(String),
        #[error("provider response is malformed")]
        Malformed,
        #[error("value does not fit in 128 bits")]
        Overflow,
    }

    pub fn eth_get_balance(addr: &EthAddress) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [addr.to_checksum(), "latest"],
        })
    }

    /// `eth_call` of `balanceOf(holder)` on a token contract.
    pub fn erc20_balance_of(token: &EthAddress, holder: &EthAddress) -> Value {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&BALANCE_OF_SELECTOR);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(holder.as_bytes());
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                {"to": token.to_checksum(), "data": format!("0x{}", hex::encode(data))},
                "latest"
            ],
        })
    }

    /// Latest block header (without transactions), for its timestamp.
    pub fn eth_latest_block() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": ["latest", false]})
    }

    /// Unix timestamp (seconds) of a block returned by `eth_getBlockByNumber`.
    pub fn parse_block_timestamp(resp: &Value) -> Result<u64, RpcError> {
        if let Some(err) = resp.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(RpcError::Provider(msg.chars().take(200).collect()));
        }
        let ts = resp
            .get("result")
            .and_then(|r| r.get("timestamp"))
            .and_then(Value::as_str)
            .ok_or(RpcError::Malformed)?;
        let body = ts.strip_prefix("0x").ok_or(RpcError::Malformed)?;
        if body.is_empty() || body.len() > 16 {
            return Err(RpcError::Malformed);
        }
        u64::from_str_radix(body, 16).map_err(|_| RpcError::Malformed)
    }

    pub fn eth_block_number() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})
    }

    fn result_str(resp: &Value) -> Result<&str, RpcError> {
        if let Some(err) = resp.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(RpcError::Provider(msg.chars().take(200).collect()));
        }
        resp.get("result")
            .and_then(Value::as_str)
            .ok_or(RpcError::Malformed)
    }

    /// Parse a JSON-RPC QUANTITY result (`0x` + minimal hex), e.g. a balance.
    pub fn parse_quantity(resp: &Value) -> Result<u128, RpcError> {
        let s = result_str(resp)?;
        let body = s.strip_prefix("0x").ok_or(RpcError::Malformed)?;
        if body.is_empty() || body.len() > 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RpcError::Malformed);
        }
        let trimmed = body.trim_start_matches('0');
        if trimmed.len() > 32 {
            return Err(RpcError::Overflow);
        }
        if trimmed.is_empty() {
            return Ok(0);
        }
        u128::from_str_radix(trimmed, 16).map_err(|_| RpcError::Malformed)
    }

    /// Parse an `eth_call` result that must be exactly one ABI `uint256` word.
    pub fn parse_uint256_word(resp: &Value) -> Result<u128, RpcError> {
        let s = result_str(resp)?;
        let body = s.strip_prefix("0x").ok_or(RpcError::Malformed)?;
        if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RpcError::Malformed);
        }
        let (high, low) = body.split_at(32);
        if high.bytes().any(|b| b != b'0') {
            return Err(RpcError::Overflow);
        }
        u128::from_str_radix(low, 16).map_err(|_| RpcError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use serde_json::json;

    // Test vectors from the EIP-55 specification.
    const EIP55: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_vectors_round_trip() {
        for v in EIP55 {
            let a: EthAddress = v.parse().expect(v);
            assert_eq!(a.to_checksum(), v);
        }
    }

    #[test]
    fn rejects_bad_or_missing_checksum() {
        let good = EIP55[0];
        let lower = good.to_lowercase();
        assert_eq!(
            lower.parse::<EthAddress>(),
            Err(EthAddressError::NoChecksum)
        );
        // Flip the case of one letter.
        let tampered = good.replacen('a', "A", 1);
        assert_eq!(
            tampered.parse::<EthAddress>(),
            Err(EthAddressError::BadChecksum)
        );
        assert_eq!(
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".parse::<EthAddress>(),
            Err(EthAddressError::Format)
        );
        assert_eq!("0x1234".parse::<EthAddress>(), Err(EthAddressError::Format));
        assert_eq!(
            "0x0000000000000000000000000000000000000000".parse::<EthAddress>(),
            Err(EthAddressError::Zero)
        );
    }

    #[test]
    fn pinned_usdt_contract_has_valid_checksum() {
        let usdt: EthAddress = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .expect("usdt");
        assert_eq!(
            usdt.to_checksum(),
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );
    }

    /// Public BIP-39 test mnemonic. Only used in tests to produce an account
    /// xpub; the watch-only app itself never sees a mnemonic.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    pub(crate) fn account_xpub(path: &str) -> Xpub {
        let m = bip39::Mnemonic::parse(TEST_MNEMONIC).expect("mnemonic");
        let seed = m.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &seed).expect("master");
        let path: DerivationPath = path.parse().expect("path");
        let acct = master.derive_priv(&secp, &path).expect("derive");
        Xpub::from_priv(&secp, &acct)
    }

    #[test]
    fn derives_well_known_test_address() {
        // Widely published first address for the test mnemonic at m/44'/60'/0'/0/0.
        let xpub = account_xpub("m/44'/60'/0'");
        let addr = derive_address(&xpub, 0).expect("derive");
        assert_eq!(
            addr.to_checksum(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn derivation_requires_account_level_xpub() {
        let xpub = account_xpub("m/44'/60'");
        assert_eq!(derive_address(&xpub, 0), Err(DeriveError::WrongDepth));
        let acct = account_xpub("m/44'/60'/0'");
        assert_eq!(derive_address(&acct, 1 << 31), Err(DeriveError::BadIndex));
    }

    #[test]
    fn debug_does_not_print_full_address() {
        let a: EthAddress = EIP55[0].parse().expect("addr");
        let dbg = format!("{a:?}");
        assert!(!dbg.contains(EIP55[0]));
    }

    #[test]
    fn balance_of_calldata_is_exact() {
        let token: EthAddress = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .expect("t");
        let holder: EthAddress = EIP55[0].parse().expect("h");
        let req = rpc::erc20_balance_of(&token, &holder);
        let data = req["params"][0]["data"].as_str().expect("data");
        assert_eq!(
            data,
            "0x70a082310000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        );
        assert_eq!(req["params"][1], "latest");
    }

    #[test]
    fn parses_block_timestamp() {
        assert_eq!(
            rpc::parse_block_timestamp(&json!({"result": {"timestamp": "0x6553f100"}})),
            Ok(1_700_000_000)
        );
        assert_eq!(
            rpc::parse_block_timestamp(&json!({"result": {}})),
            Err(rpc::RpcError::Malformed)
        );
        assert_eq!(
            rpc::parse_block_timestamp(&json!({"result": {"timestamp": "12"}})),
            Err(rpc::RpcError::Malformed)
        );
        assert_eq!(rpc::eth_latest_block()["params"][0], "latest");
    }

    #[test]
    fn parses_rpc_results_strictly() {
        assert_eq!(rpc::parse_quantity(&json!({"result": "0x0"})), Ok(0));
        assert_eq!(
            rpc::parse_quantity(&json!({"result": "0xde0b6b3a7640000"})),
            Ok(1_000_000_000_000_000_000)
        );
        assert_eq!(
            rpc::parse_quantity(&json!({"result": "12"})),
            Err(rpc::RpcError::Malformed)
        );
        assert_eq!(
            rpc::parse_quantity(&json!({"result": 12})),
            Err(rpc::RpcError::Malformed)
        );
        assert_eq!(
            rpc::parse_quantity(&json!({"result": format!("0x1{}", "0".repeat(32))})),
            Err(rpc::RpcError::Overflow)
        );
        assert!(matches!(
            rpc::parse_quantity(&json!({"error": {"code": -32000, "message": "rate limited"}})),
            Err(rpc::RpcError::Provider(_))
        ));
        let word = format!("0x{}{}", "0".repeat(56), "05f5e100"); // 100_000_000
        assert_eq!(
            rpc::parse_uint256_word(&json!({"result": word})),
            Ok(100_000_000)
        );
        assert_eq!(
            rpc::parse_uint256_word(&json!({"result": "0x"})),
            Err(rpc::RpcError::Malformed)
        );
        let huge = format!("0x1{}", "0".repeat(63));
        assert_eq!(
            rpc::parse_uint256_word(&json!({"result": huge})),
            Err(rpc::RpcError::Overflow)
        );
    }
}
