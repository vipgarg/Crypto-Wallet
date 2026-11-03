//! Ethereum history from a Blockscout indexer (`/api/v2`), read-only.
//!
//! Two lists, like a block explorer's two tabs:
//! - **token transfers** (ERC-20 `Transfer` events in or out of the address),
//! - the address's own **transactions** (ETH transfers, contract calls such
//!   as `approve`).
//!
//! History comes from one indexer and isn't cross-checked; it is shown for
//! information and never feeds a balance or a payment. Token symbols and
//! decimals are the token's own claims and are untrusted: only the pinned
//! USDT contract (from the compiled-in config) is treated as USDT.

use serde_json::Value;

use crate::EthAddress;

/// `/api/v2/addresses/{addr}/token-transfers?type=ERC-20` (newest first, one page).
pub fn token_transfers_path(addr: &EthAddress) -> String {
    format!(
        "/api/v2/addresses/{}/token-transfers?type=ERC-20",
        addr.to_checksum()
    )
}

/// `/api/v2/addresses/{addr}/transactions` (newest first, one page).
pub fn transactions_path(addr: &EthAddress) -> String {
    format!("/api/v2/addresses/{}/transactions", addr.to_checksum())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20Transfer {
    pub txid: String,
    pub time_ms: u64,
    pub token: EthAddress,
    /// The token's own claimed symbol (untrusted).
    pub claimed_symbol: String,
    /// The token's own claimed decimals (untrusted; 0 if missing).
    pub claimed_decimals: u8,
    pub from: EthAddress,
    pub to: EthAddress,
    /// `None` if the value doesn't fit (absurd amounts are spam anyway).
    pub value: Option<u128>,
}

/// What an Ethereum transaction did, decoded from its input data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthCall {
    /// Plain ETH transfer (no input data).
    EthTransfer,
    /// `transfer(to, amount)` on a token contract.
    TokenTransfer {
        to: EthAddress,
        amount: Option<u128>,
    },
    /// `transferFrom(from, to, amount)`.
    TokenTransferFrom {
        from: EthAddress,
        to: EthAddress,
        amount: Option<u128>,
    },
    /// `approve(spender, amount)`; `None` amount = unlimited (or too large).
    Approve {
        spender: EthAddress,
        amount: Option<u128>,
    },
    /// `increaseAllowance(spender, added)`.
    IncreaseAllowance {
        spender: EthAddress,
        amount: Option<u128>,
    },
    /// `setApprovalForAll(operator, approved)` (NFT-style "spend everything").
    SetApprovalForAll {
        operator: EthAddress,
        approved: bool,
    },
    /// Anything else; `selector` is the first 4 bytes as hex (if any).
    Other { selector: Option<String> },
    /// Contract creation (no `to`).
    Create,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthTx {
    pub txid: String,
    pub time_ms: u64,
    /// `false` for a failed (reverted) transaction. Pending ones are left out.
    pub success: bool,
    pub from: EthAddress,
    /// `None` for contract creation.
    pub to: Option<EthAddress>,
    /// ETH sent with the transaction, in wei (`None` if absurdly large).
    pub value_wei: Option<u128>,
    pub call: EthCall,
}

/// A page from the indexer: items, entries that couldn't be read, and
/// whether more (older) entries exist beyond this page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub unreadable: usize,
    pub more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HistoryError {
    #[error("the indexer's answer has no item list")]
    Malformed,
}

fn items(json: &Value) -> Result<(&Vec<Value>, bool), HistoryError> {
    let list = json
        .get("items")
        .and_then(Value::as_array)
        .ok_or(HistoryError::Malformed)?;
    let more = json.get("next_page_params").is_some_and(|v| !v.is_null());
    Ok((list, more))
}

fn addr_field(v: &Value, key: &str) -> Option<EthAddress> {
    v.get(key)?
        .get("hash")?
        .as_str()
        .and_then(EthAddress::parse_any_case)
}

fn decimal_u128(v: Option<&Value>) -> Option<u128> {
    match v? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// Days from 1970-01-01 to the given date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an ISO-8601 UTC timestamp such as `2023-07-03T20:09:59.000000Z`
/// into Unix milliseconds.
pub fn parse_timestamp_ms(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    let (h, mi, se) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let ms: i64 = frac
        .chars()
        .chain("000".chars())
        .take(3)
        .collect::<String>()
        .parse()
        .ok()?;
    let secs = days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + se;
    u64::try_from(secs * 1000 + ms).ok()
}

/// Parse `/token-transfers`. ERC-20 only; anything else is skipped.
pub fn parse_token_transfers(json: &Value) -> Result<Page<Erc20Transfer>, HistoryError> {
    let (list, more) = items(json)?;
    let mut out = Vec::new();
    let mut unreadable = 0;
    for it in list {
        match parse_transfer(it) {
            Some(t) => out.push(t),
            None => unreadable += 1,
        }
    }
    Ok(Page {
        items: out,
        unreadable,
        more,
    })
}

fn parse_transfer(it: &Value) -> Option<Erc20Transfer> {
    let token = it.get("token")?;
    // Newer Blockscout uses "address_hash"; older versions "address".
    let token_addr = token
        .get("address_hash")
        .or_else(|| token.get("address"))?
        .as_str()
        .and_then(EthAddress::parse_any_case)?;
    let txid = it
        .get("transaction_hash")
        .or_else(|| it.get("tx_hash"))?
        .as_str()?
        .to_owned();
    if txid.len() != 66 || !txid.starts_with("0x") {
        return None;
    }
    let symbol: String = token
        .get("symbol")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .chars()
        .filter(|c| !c.is_control())
        .take(20)
        .collect();
    let total = it.get("total")?;
    let decimals = decimal_u128(total.get("decimals").or_else(|| token.get("decimals")))
        .and_then(|d| u8::try_from(d).ok())
        .filter(|d| *d <= 36)
        .unwrap_or(0);
    Some(Erc20Transfer {
        txid,
        time_ms: it
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp_ms)
            .unwrap_or(0),
        token: token_addr,
        claimed_symbol: symbol,
        claimed_decimals: decimals,
        from: addr_field(it, "from")?,
        to: addr_field(it, "to")?,
        value: decimal_u128(total.get("value")),
    })
}

/// Parse `/transactions`. Pending transactions are left out.
pub fn parse_transactions(json: &Value) -> Result<Page<EthTx>, HistoryError> {
    let (list, more) = items(json)?;
    let mut out = Vec::new();
    let mut unreadable = 0;
    for it in list {
        let status = it.get("status").and_then(Value::as_str);
        if status.is_none() {
            continue; // pending
        }
        match parse_tx(it) {
            Some(t) => out.push(t),
            None => unreadable += 1,
        }
    }
    Ok(Page {
        items: out,
        unreadable,
        more,
    })
}

fn parse_tx(it: &Value) -> Option<EthTx> {
    let txid = it.get("hash")?.as_str()?.to_owned();
    if txid.len() != 66 || !txid.starts_with("0x") {
        return None;
    }
    let to = addr_field(it, "to");
    let input = it.get("raw_input").and_then(Value::as_str).unwrap_or("0x");
    Some(EthTx {
        txid,
        time_ms: it
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp_ms)
            .unwrap_or(0),
        success: it.get("status").and_then(Value::as_str) == Some("ok"),
        from: addr_field(it, "from")?,
        to,
        value_wei: decimal_u128(it.get("value")),
        call: if to.is_none() {
            EthCall::Create
        } else {
            decode_input(input)
        },
    })
}

fn word(data: &[u8], i: usize) -> Option<&[u8]> {
    data.get(4 + 32 * i..4 + 32 * (i + 1))
}

fn word_addr(data: &[u8], i: usize) -> Option<EthAddress> {
    let w = word(data, i)?;
    if w[..12].iter().any(|b| *b != 0) {
        return None;
    }
    let mut b = [0u8; 20];
    b.copy_from_slice(&w[12..]);
    Some(EthAddress(b))
}

/// `None` when the 256-bit value doesn't fit in u128 (e.g. "unlimited" = 2^256-1).
fn word_u128(data: &[u8], i: usize) -> Option<Option<u128>> {
    let w = word(data, i)?;
    if w[..16].iter().any(|b| *b != 0) {
        return Some(None);
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..]);
    Some(Some(u128::from_be_bytes(b)))
}

/// Decode the common token calls from raw transaction input (`0x…`).
pub fn decode_input(input: &str) -> EthCall {
    let hex_body = input.strip_prefix("0x").unwrap_or(input);
    if hex_body.is_empty() {
        return EthCall::EthTransfer;
    }
    let Ok(data) = hex::decode(hex_body) else {
        return EthCall::Other { selector: None };
    };
    let Some(sel) = data.get(..4) else {
        return EthCall::Other { selector: None };
    };
    let other = || EthCall::Other {
        selector: Some(hex::encode(sel)),
    };
    let decoded = match sel {
        [0xa9, 0x05, 0x9c, 0xbb] => (|| {
            Some(EthCall::TokenTransfer {
                to: word_addr(&data, 0)?,
                amount: word_u128(&data, 1)?,
            })
        })(),
        [0x23, 0xb8, 0x72, 0xdd] => (|| {
            Some(EthCall::TokenTransferFrom {
                from: word_addr(&data, 0)?,
                to: word_addr(&data, 1)?,
                amount: word_u128(&data, 2)?,
            })
        })(),
        [0x09, 0x5e, 0xa7, 0xb3] => (|| {
            Some(EthCall::Approve {
                spender: word_addr(&data, 0)?,
                amount: word_u128(&data, 1)?,
            })
        })(),
        [0x39, 0x50, 0x93, 0x51] => (|| {
            Some(EthCall::IncreaseAllowance {
                spender: word_addr(&data, 0)?,
                amount: word_u128(&data, 1)?,
            })
        })(),
        [0xa2, 0x2c, 0xb4, 0x65] => (|| {
            Some(EthCall::SetApprovalForAll {
                operator: word_addr(&data, 0)?,
                approved: word_u128(&data, 1)?.is_some_and(|v| v != 0),
            })
        })(),
        _ => None,
    };
    decoded.unwrap_or_else(other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USDT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const ME: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const OTHER: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    fn hash(n: u8) -> String {
        format!("0x{}", hex::encode([n; 32]))
    }

    #[test]
    fn timestamps() {
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_timestamp_ms("2023-07-03T20:09:59.000000Z"),
            Some(1_688_414_999_000)
        );
        assert_eq!(
            parse_timestamp_ms("2024-02-29T12:00:00.5Z"),
            Some(1_709_208_000_500)
        );
        assert_eq!(parse_timestamp_ms("2023-13-01T00:00:00Z"), None);
        assert_eq!(parse_timestamp_ms("yesterday"), None);
    }

    #[test]
    fn parses_token_transfers_both_versions() {
        let body = json!({
            "items": [
                {   // current format: token.address_hash, transaction_hash
                    "transaction_hash": hash(1),
                    "timestamp": "2023-07-03T20:09:59.000000Z",
                    "from": {"hash": OTHER}, "to": {"hash": ME.to_lowercase()},
                    "token": {"address_hash": USDT, "symbol": "USDT", "decimals": "6", "type": "ERC-20"},
                    "total": {"value": "2500000", "decimals": "6"},
                    "type": "token_transfer"
                },
                {   // older format: token.address, tx_hash
                    "tx_hash": hash(2),
                    "timestamp": "2023-07-03T20:10:00Z",
                    "from": {"hash": ME}, "to": {"hash": OTHER},
                    "token": {"address": OTHER, "symbol": "USDT\u{0007}", "decimals": "6"},
                    "total": {"value": "0", "decimals": "6"}
                },
                {"transaction_hash": "0xshort", "token": {}, "total": {}}
            ],
            "next_page_params": {"block_number": 1}
        });
        let page = parse_token_transfers(&body).expect("page");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.unreadable, 1);
        assert!(page.more);
        let t = &page.items[0];
        assert_eq!(t.token.to_checksum(), USDT);
        assert_eq!(
            t.to.to_checksum(),
            ME,
            "any letter case is accepted from the indexer"
        );
        assert_eq!(t.value, Some(2_500_000));
        assert_eq!(t.claimed_decimals, 6);
        assert_eq!(
            page.items[1].claimed_symbol, "USDT",
            "control characters removed"
        );
        assert!(parse_token_transfers(&json!({"oops": 1})).is_err());
    }

    fn input(sel: &str, words: &[String]) -> String {
        format!("0x{sel}{}", words.concat())
    }
    fn w_addr(a: &str) -> String {
        format!("{:0>64}", a.trim_start_matches("0x").to_lowercase())
    }
    fn w_num(n: u128) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn decodes_token_calls() {
        assert_eq!(decode_input("0x"), EthCall::EthTransfer);
        let other: EthAddress = OTHER.parse().expect("a");
        assert_eq!(
            decode_input(&input("a9059cbb", &[w_addr(OTHER), w_num(5)])),
            EthCall::TokenTransfer {
                to: other,
                amount: Some(5)
            }
        );
        assert_eq!(
            decode_input(&input("095ea7b3", &[w_addr(OTHER), "f".repeat(64)])),
            EthCall::Approve {
                spender: other,
                amount: None
            },
            "unlimited approval"
        );
        assert_eq!(
            decode_input(&input("a22cb465", &[w_addr(OTHER), w_num(1)])),
            EthCall::SetApprovalForAll {
                operator: other,
                approved: true
            }
        );
        assert_eq!(
            decode_input("0x12345678"),
            EthCall::Other {
                selector: Some("12345678".into())
            }
        );
        // Truncated approve: not decoded as an approval, but shown as "other".
        assert!(matches!(decode_input("0x095ea7b3"), EthCall::Other { .. }));
    }

    #[test]
    fn parses_transactions() {
        let body = json!({
            "items": [
                {"hash": hash(3), "status": "ok", "timestamp": "2024-01-01T00:00:00Z",
                 "from": {"hash": ME}, "to": {"hash": USDT}, "value": "0",
                 "raw_input": input("095ea7b3", &[w_addr(OTHER), w_num(1_000_000)])},
                {"hash": hash(4), "status": "error", "timestamp": "2024-01-02T00:00:00Z",
                 "from": {"hash": OTHER}, "to": {"hash": ME}, "value": "1000000000000000000", "raw_input": "0x"},
                {"hash": hash(5), "status": null, "from": {"hash": ME}, "to": {"hash": OTHER}},
                {"hash": hash(6), "status": "ok", "from": {"hash": ME}, "to": null, "value": "0", "raw_input": "0x6080"}
            ],
            "next_page_params": null
        });
        let page = parse_transactions(&body).expect("page");
        assert_eq!(page.items.len(), 3, "pending left out");
        assert!(!page.more);
        assert!(matches!(
            page.items[0].call,
            EthCall::Approve {
                amount: Some(1_000_000),
                ..
            }
        ));
        assert!(!page.items[1].success);
        assert_eq!(page.items[1].value_wei, Some(1_000_000_000_000_000_000));
        assert_eq!(page.items[2].call, EthCall::Create);
    }
}
