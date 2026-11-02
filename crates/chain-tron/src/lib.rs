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

/// TRC-20 transfer history from TronGrid's `/v1` indexer API. Everything in
/// these responses is attacker-influenced (token names, symbols, amounts), so
/// it is parsed strictly and treated as display data only.
pub mod history {
    use super::TronAddress;
    use serde::Deserialize;
    use serde_json::Value;
    use thiserror::Error;

    /// Most recent transfers fetched per request.
    pub const LIMIT: u32 = 50;

    pub fn trc20_history_path(addr: &TronAddress) -> String {
        format!(
            "/v1/accounts/{}/transactions/trc20?limit={LIMIT}&only_confirmed=true",
            addr.to_base58()
        )
    }

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum HistoryError {
        #[error("history response is malformed")]
        Malformed,
        #[error("history provider reported failure")]
        NotSuccessful,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventKind {
        Transfer,
        Approval,
        Other,
    }

    /// One TRC-20 event touching the watched address.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Trc20Event {
        pub txid: String,
        pub token: TronAddress,
        /// Symbol as claimed by the token itself: untrusted, sanitised.
        pub claimed_symbol: String,
        pub claimed_decimals: u8,
        pub timestamp_ms: u64,
        pub from: TronAddress,
        pub to: TronAddress,
        pub kind: EventKind,
        /// `None` if the value doesn't fit in 128 bits (only fake tokens do that).
        pub value: Option<u128>,
    }

    #[derive(Deserialize)]
    struct RawToken {
        address: String,
        #[serde(default)]
        symbol: Option<String>,
        #[serde(default)]
        decimals: Option<Value>,
    }

    #[derive(Deserialize)]
    struct RawEvent {
        transaction_id: String,
        token_info: RawToken,
        block_timestamp: u64,
        from: String,
        to: String,
        #[serde(rename = "type")]
        kind: String,
        value: String,
    }

    /// Keep only printable ASCII and at most 16 characters: token symbols are
    /// chosen by whoever deployed the token.
    pub fn sanitize_symbol(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(16)
            .collect()
    }

    fn parse_event(v: &Value) -> Option<Trc20Event> {
        let raw: RawEvent = serde_json::from_value(v.clone()).ok()?;
        let txid = raw.transaction_id.to_ascii_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let decimals = match &raw.token_info.decimals {
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(s)) => s.parse::<u64>().ok(),
            _ => Some(0),
        }
        .and_then(|d| u8::try_from(d).ok())
        .filter(|d| *d <= 36)
        .unwrap_or(0);
        let value = if !raw.value.is_empty() && raw.value.bytes().all(|b| b.is_ascii_digit()) {
            raw.value.parse::<u128>().ok()
        } else {
            return None;
        };
        Some(Trc20Event {
            txid,
            token: raw.token_info.address.parse().ok()?,
            claimed_symbol: sanitize_symbol(raw.token_info.symbol.as_deref().unwrap_or("")),
            claimed_decimals: decimals,
            timestamp_ms: raw.block_timestamp,
            from: raw.from.parse().ok()?,
            to: raw.to.parse().ok()?,
            kind: match raw.kind.as_str() {
                "Transfer" => EventKind::Transfer,
                "Approval" => EventKind::Approval,
                _ => EventKind::Other,
            },
            value,
        })
    }

    /// Returns the readable events and how many entries couldn't be read.
    pub fn parse_trc20_history(body: &Value) -> Result<(Vec<Trc20Event>, usize), HistoryError> {
        if body.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(HistoryError::NotSuccessful);
        }
        let data = body
            .get("data")
            .and_then(Value::as_array)
            .ok_or(HistoryError::Malformed)?;
        let mut events = Vec::with_capacity(data.len());
        let mut unreadable = 0;
        for v in data.iter().take(LIMIT as usize * 2) {
            match parse_event(v) {
                Some(e) => events.push(e),
                None => unreadable += 1,
            }
        }
        Ok((events, unreadable))
    }

    // ---------------------------------------------------------------------
    // Account transactions (Tronscan's "Transactions" tab).
    // ---------------------------------------------------------------------

    pub fn transactions_path(addr: &TronAddress) -> String {
        format!(
            "/v1/accounts/{}/transactions?limit={LIMIT}&only_confirmed=true&search_internal=false",
            addr.to_base58()
        )
    }

    /// A decoded call to a TRC-20 contract.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CallKind {
        Transfer {
            to: TronAddress,
            amount: Option<u128>,
        },
        TransferFrom {
            from: TronAddress,
            to: TronAddress,
            amount: Option<u128>,
        },
        Approve {
            spender: TronAddress,
            amount: Option<u128>,
        },
        /// Anything else; the 4-byte function selector in hex.
        Unknown { selector: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TxAction {
        /// Plain TRX transfer, amount in sun.
        TrxTransfer {
            from: TronAddress,
            to: TronAddress,
            amount_sun: u128,
        },
        /// Smart-contract call (e.g. USDT transfer or approve).
        ContractCall {
            owner: TronAddress,
            contract: TronAddress,
            call: CallKind,
            call_value_sun: u128,
        },
        /// Owner/active permissions changed: critical (ARCHITECTURE.md §8.5).
        PermissionUpdate { owner: TronAddress },
        /// TRC-10 token transfer (mostly spam).
        Trc10Transfer {
            from: TronAddress,
            to: TronAddress,
            amount: u128,
        },
        /// Staking, unstaking, resource delegation, voting, reward withdrawal.
        Resource {
            owner: TronAddress,
            what: &'static str,
        },
        /// Any other contract type, by name.
        Other {
            owner: Option<TronAddress>,
            contract_type: String,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TronTx {
        pub txid: String,
        pub timestamp_ms: u64,
        pub success: bool,
        pub action: TxAction,
    }

    /// Node APIs return addresses as hex (`41…`) unless asked for Base58.
    fn addr_any(v: &Value) -> Option<TronAddress> {
        let s = v.as_str()?;
        if s.starts_with('T') {
            s.parse().ok()
        } else {
            TronAddress::from_hex(&s.to_ascii_lowercase()).ok()
        }
    }

    fn u128_any(v: Option<&Value>) -> Option<u128> {
        match v {
            None => Some(0),
            Some(Value::Number(n)) => n.as_u64().map(u128::from),
            Some(Value::String(s)) => s.parse::<u128>().ok(),
            _ => None,
        }
    }

    /// ABI word → address (last 20 bytes). The upper 12 bytes must be zero.
    fn word_address(word: &str) -> Option<TronAddress> {
        if word.len() != 64 || !word[..24].bytes().all(|b| b == b'0') {
            return None;
        }
        let mut b = [0u8; 20];
        hex::decode_to_slice(&word[24..], &mut b).ok()?;
        Some(TronAddress::from_hash20(b))
    }

    /// ABI word → amount; `None` if above 128 bits (e.g. "unlimited" approvals).
    fn word_amount(word: &str) -> Option<u128> {
        if word.len() != 64 {
            return None;
        }
        let (high, low) = word.split_at(32);
        if high.bytes().any(|b| b != b'0') {
            return None;
        }
        u128::from_str_radix(low, 16).ok()
    }

    pub fn decode_call(data_hex: &str) -> CallKind {
        let d = data_hex.trim_start_matches("0x").to_ascii_lowercase();
        if d.len() < 8 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
            return CallKind::Unknown {
                selector: String::new(),
            };
        }
        let (sel, args) = d.split_at(8);
        let w = |i: usize| args.get(i * 64..(i + 1) * 64);
        let unknown = || CallKind::Unknown {
            selector: sel.to_owned(),
        };
        match sel {
            "a9059cbb" if args.len() == 128 => match (w(0).and_then(word_address), w(1)) {
                (Some(to), Some(a)) => CallKind::Transfer {
                    to,
                    amount: word_amount(a),
                },
                _ => unknown(),
            },
            "095ea7b3" if args.len() == 128 => match (w(0).and_then(word_address), w(1)) {
                (Some(spender), Some(a)) => CallKind::Approve {
                    spender,
                    amount: word_amount(a),
                },
                _ => unknown(),
            },
            "23b872dd" if args.len() == 192 => match (
                w(0).and_then(word_address),
                w(1).and_then(word_address),
                w(2),
            ) {
                (Some(from), Some(to), Some(a)) => CallKind::TransferFrom {
                    from,
                    to,
                    amount: word_amount(a),
                },
                _ => unknown(),
            },
            _ => unknown(),
        }
    }

    fn resource_label(contract_type: &str) -> Option<&'static str> {
        Some(match contract_type {
            "FreezeBalanceContract" | "FreezeBalanceV2Contract" => "Stake TRX (freeze)",
            "UnfreezeBalanceContract" | "UnfreezeBalanceV2Contract" => "Unstake TRX (unfreeze)",
            "WithdrawExpireUnfreezeContract" => "Withdraw unstaked TRX",
            "CancelAllUnfreezeV2Contract" => "Cancel unstaking",
            "DelegateResourceContract" => "Delegate energy/bandwidth",
            "UnDelegateResourceContract" => "Reclaim delegated energy/bandwidth",
            "VoteWitnessContract" => "Vote for super representatives",
            "WithdrawBalanceContract" => "Claim voting rewards",
            _ => return None,
        })
    }

    fn parse_tx(v: &Value) -> Option<TronTx> {
        if v.get("internal_tx_id").is_some() {
            return None;
        }
        let txid = v.get("txID")?.as_str()?.to_ascii_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let timestamp_ms = v.get("block_timestamp")?.as_u64()?;
        let success = v
            .get("ret")
            .and_then(Value::as_array)
            .and_then(|r| r.first())
            .and_then(|r| r.get("contractRet"))
            .and_then(Value::as_str)
            .is_none_or(|s| s == "SUCCESS");
        let contracts = v.get("raw_data")?.get("contract")?.as_array()?;
        if contracts.len() != 1 {
            return None;
        }
        let c = &contracts[0];
        let ty = c.get("type")?.as_str()?;
        let val = c.get("parameter")?.get("value")?;
        let owner = val.get("owner_address").and_then(addr_any);
        let action = match ty {
            "TransferContract" => TxAction::TrxTransfer {
                from: owner?,
                to: addr_any(val.get("to_address")?)?,
                amount_sun: u128_any(val.get("amount"))?,
            },
            "TriggerSmartContract" => TxAction::ContractCall {
                owner: owner?,
                contract: addr_any(val.get("contract_address")?)?,
                call: decode_call(val.get("data").and_then(Value::as_str).unwrap_or("")),
                call_value_sun: u128_any(val.get("call_value"))?,
            },
            "AccountPermissionUpdateContract" => TxAction::PermissionUpdate { owner: owner? },
            "TransferAssetContract" => TxAction::Trc10Transfer {
                from: owner?,
                to: addr_any(val.get("to_address")?)?,
                amount: u128_any(val.get("amount"))?,
            },
            other => match resource_label(other) {
                Some(what) => TxAction::Resource {
                    owner: owner?,
                    what,
                },
                None => TxAction::Other {
                    owner,
                    contract_type: other
                        .chars()
                        .filter(char::is_ascii_alphanumeric)
                        .take(48)
                        .collect(),
                },
            },
        };
        Some(TronTx {
            txid,
            timestamp_ms,
            success,
            action,
        })
    }

    /// Returns the readable transactions and how many entries couldn't be read.
    pub fn parse_transactions(body: &Value) -> Result<(Vec<TronTx>, usize), HistoryError> {
        if body.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(HistoryError::NotSuccessful);
        }
        let data = body
            .get("data")
            .and_then(Value::as_array)
            .ok_or(HistoryError::Malformed)?;
        let mut txs = Vec::with_capacity(data.len());
        let mut unreadable = 0;
        for v in data.iter().take(LIMIT as usize * 2) {
            match parse_tx(v) {
                Some(t) => txs.push(t),
                None => unreadable += 1,
            }
        }
        Ok((txs, unreadable))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
        const ME: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

        fn ev(kind: &str, value: &str, symbol: &str) -> Value {
            json!({
                "transaction_id": "ab".repeat(32),
                "token_info": {"symbol": symbol, "address": USDT, "decimals": 6, "name": "Tether USD"},
                "block_timestamp": 1_700_000_000_000u64,
                "from": ME,
                "to": ME,
                "type": kind,
                "value": value,
            })
        }

        #[test]
        fn parses_and_sanitises() {
            let body = json!({"success": true, "data": [
                ev("Transfer", "1000000", "USDT"),
                ev("Approval", "115792089237316195423570985008687907853269984665640564039457584007913129639935", "USDT"),
                ev("Transfer", "5", "U\u{0007}SDT<script>alert(1)</script>"),
            ], "meta": {}});
            let (events, unreadable) = parse_trc20_history(&body).expect("parse");
            assert_eq!(unreadable, 0);
            assert_eq!(events[0].value, Some(1_000_000));
            assert_eq!(events[0].kind, EventKind::Transfer);
            assert_eq!(events[1].kind, EventKind::Approval);
            assert_eq!(events[1].value, None, "max-uint approval doesn't fit u128");
            assert!(events[2].claimed_symbol.len() <= 16);
            assert!(!events[2].claimed_symbol.contains('\u{0007}'));
        }

        #[test]
        fn skips_unreadable_entries_and_rejects_failure() {
            let mut bad = ev("Transfer", "-1", "USDT");
            let mut bad_tx = ev("Transfer", "1", "USDT");
            bad_tx["transaction_id"] = json!("xyz");
            let mut bad_addr = ev("Transfer", "1", "USDT");
            bad_addr["from"] = json!("not-an-address");
            bad["extra"] = json!(1);
            let body = json!({"success": true, "data": [bad, bad_tx, bad_addr, ev("Transfer", "1", "USDT")]});
            let (events, unreadable) = parse_trc20_history(&body).expect("parse");
            assert_eq!((events.len(), unreadable), (1, 3));
            assert_eq!(
                parse_trc20_history(&json!({"success": false})),
                Err(HistoryError::NotSuccessful)
            );
            assert_eq!(
                parse_trc20_history(&json!({"success": true})),
                Err(HistoryError::Malformed)
            );
        }

        fn tx(ty: &str, value: Value, ret: &str) -> Value {
            json!({
                "txID": "ef".repeat(32),
                "block_timestamp": 1_700_000_000_000u64,
                "ret": [{"contractRet": ret}],
                "raw_data": {"contract": [{"type": ty, "parameter": {"value": value}}]},
            })
        }

        const USDT_HEX: &str = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

        #[test]
        fn parses_transaction_types() {
            let me = USDT_HEX;
            let word_addr = format!("{}{}", "0".repeat(24), &USDT_HEX[2..]);
            let transfer_data = format!("a9059cbb{word_addr}{:064x}", 2_000_000u64);
            let approve_data = format!("095ea7b3{word_addr}{}", "f".repeat(64));
            let body = json!({"success": true, "data": [
                tx("TransferContract", json!({"owner_address": me, "to_address": me, "amount": 5}), "SUCCESS"),
                tx("TriggerSmartContract", json!({"owner_address": me, "contract_address": USDT_HEX, "data": transfer_data}), "SUCCESS"),
                tx("TriggerSmartContract", json!({"owner_address": me, "contract_address": USDT_HEX, "data": approve_data}), "SUCCESS"),
                tx("AccountPermissionUpdateContract", json!({"owner_address": me}), "SUCCESS"),
                tx("FreezeBalanceV2Contract", json!({"owner_address": me, "frozen_balance": 1}), "SUCCESS"),
                tx("TransferContract", json!({"owner_address": me, "to_address": me, "amount": 1}), "REVERT"),
                tx("SomethingNewContract", json!({"owner_address": me}), "SUCCESS"),
                json!({"internal_tx_id": "x", "data": {}}),
                json!({"txID": "short"}),
            ]});
            let (txs, unreadable) = parse_transactions(&body).expect("parse");
            assert_eq!(unreadable, 2);
            assert!(matches!(
                txs[0].action,
                TxAction::TrxTransfer { amount_sun: 5, .. }
            ));
            assert!(matches!(
                &txs[1].action,
                TxAction::ContractCall {
                    call: CallKind::Transfer {
                        amount: Some(2_000_000),
                        ..
                    },
                    ..
                }
            ));
            assert!(matches!(
                &txs[2].action,
                TxAction::ContractCall {
                    call: CallKind::Approve { amount: None, .. },
                    ..
                }
            ));
            assert!(matches!(txs[3].action, TxAction::PermissionUpdate { .. }));
            assert!(matches!(
                txs[4].action,
                TxAction::Resource {
                    what: "Stake TRX (freeze)",
                    ..
                }
            ));
            assert!(!txs[5].success);
            assert!(
                matches!(&txs[6].action, TxAction::Other { contract_type, .. } if contract_type == "SomethingNewContract")
            );
        }

        #[test]
        fn decode_call_is_strict() {
            assert!(matches!(decode_call("a9059cbb"), CallKind::Unknown { .. }));
            assert!(matches!(decode_call("zz"), CallKind::Unknown { .. }));
            // Dirty upper bytes in an address word → not decoded as a transfer.
            let dirty = format!("a9059cbb{}{}", "1".repeat(64), "0".repeat(64));
            assert!(matches!(decode_call(&dirty), CallKind::Unknown { .. }));
            assert!(
                matches!(decode_call("12345678"), CallKind::Unknown { selector } if selector == "12345678")
            );
        }

        #[test]
        fn path_is_confirmed_only_and_limited() {
            let a: TronAddress = USDT.parse().expect("a");
            assert_eq!(
                trc20_history_path(&a),
                format!("/v1/accounts/{USDT}/transactions/trc20?limit=50&only_confirmed=true")
            );
        }
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
