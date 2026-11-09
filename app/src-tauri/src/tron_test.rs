//! TRON **Nile** test payments (Phase 2 testing): USDT with no value.
//! The UI→core commands are in `commands.rs`; this file holds the logic.
//!
//! The transaction is built **here** (tron-tx), never by a node: the node is
//! only asked for balances, a recent solidified block (reference block and
//! time), and to broadcast the signed result. After the tablet signs, the
//! PC checks that the signature is for exactly the transaction it built and
//! comes from the wallet's own address.

use chain_tron::{api, TronAddress};
use data_sources::{HttpClient, NetworkConfig};
use serde::Serialize;
use serde_json::{json, Value};
use tron_tx::Trc20Transfer;

/// Fee limit put on test transfers (the tablet accepts up to 30 TRX).
pub const FEE_LIMIT_SUN: u64 = 30_000_000;
/// How long a built transaction stays valid (the tablet accepts up to 10 min).
pub const VALIDITY_MS: u64 = 9 * 60 * 1000;

fn first_provider(config: &NetworkConfig) -> Result<&data_sources::config::SignetProvider, String> {
    config
        .nile_providers
        .first()
        .ok_or_else(|| "No TRON Nile node is configured.".to_owned())
}

fn nile_usdt(config: &NetworkConfig) -> Result<TronAddress, String> {
    config
        .usdt_trc20_nile
        .ok_or_else(|| "The Nile test USDT contract isn't configured.".to_owned())
}

#[derive(Debug, Clone, Serialize)]
pub struct NileBalances {
    pub address: String,
    pub trx: String,
    pub usdt: String,
    pub source: String,
    pub explorer_url: String,
}

fn decimal6(v: u128) -> String {
    let (w, f) = (v / 1_000_000, v % 1_000_000);
    if f == 0 {
        w.to_string()
    } else {
        format!("{w}.{}", format!("{f:06}").trim_end_matches('0'))
    }
}

/// Parse a USDT amount like "12.5" into base units (6 decimals).
pub fn parse_usdt(s: &str) -> Result<u128, String> {
    let s = s.trim();
    let bad = || "Enter the amount like 12.5 (at most 6 decimals).".to_owned();
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if w.is_empty() && f.is_empty()
        || f.len() > 6
        || !w.chars().chain(f.chars()).all(|c| c.is_ascii_digit())
    {
        return Err(bad());
    }
    let whole: u128 = if w.is_empty() {
        0
    } else {
        w.parse().map_err(|_| bad())?
    };
    let frac: u128 = format!("{f:0<6}").parse().map_err(|_| bad())?;
    let v = whole
        .checked_mul(1_000_000)
        .and_then(|x| x.checked_add(frac))
        .ok_or_else(bad)?;
    if v == 0 {
        return Err("The amount must be more than 0.".into());
    }
    Ok(v)
}

pub async fn balances<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    addr: &TronAddress,
) -> Result<NileBalances, String> {
    let p = first_provider(config)?;
    let usdt = nile_usdt(config)?;
    let e = |what: &str, x: String| format!("{} ({what}): {x}", p.id);
    let acct = http
        .post_json(
            &format!("{}{}", p.base_url, api::GET_ACCOUNT_PATH),
            &api::get_account(addr),
        )
        .await
        .map_err(|x| e("TRX balance", x.to_string()))?;
    // A never-used account answers {}: balance 0.
    let trx = if acct.as_object().is_some_and(|o| o.is_empty()) {
        0
    } else {
        api::parse_trx_balance(&acct).map_err(|x| e("TRX balance", x.to_string()))?
    };
    let tok = http
        .post_json(
            &format!("{}{}", p.base_url, api::TRIGGER_CONSTANT_PATH),
            &api::trc20_balance_of(&usdt, addr),
        )
        .await
        .map_err(|x| e("USDT balance", x.to_string()))?;
    let usdt_v = api::parse_trc20_balance(&tok).map_err(|x| e("USDT balance", x.to_string()))?;
    Ok(NileBalances {
        address: addr.to_base58(),
        trx: decimal6(trx),
        usdt: decimal6(usdt_v),
        source: p.id.clone(),
        explorer_url: format!("https://nile.tronscan.org/#/address/{}", addr.to_base58()),
    })
}

/// The sender must be an activated TRON account with some TRX: an address
/// that has only ever received tokens (no TRX) doesn't exist on-chain yet,
/// and sending USDT costs TRX (energy/bandwidth). Checked before building,
/// so the problem is explained before anything is signed.
pub async fn require_ready_sender<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    owner: &TronAddress,
) -> Result<(), String> {
    let p = first_provider(config)?;
    let acct = http
        .post_json(
            &format!("{}{}", p.base_url, api::GET_ACCOUNT_PATH),
            &api::get_account(owner),
        )
        .await
        .map_err(|e| format!("{}: couldn't read the sending account: {e}", p.id))?;
    if acct.as_object().is_some_and(|o| o.is_empty()) {
        return Err(format!(
            "This TRON address isn't activated yet: on TRON an address only becomes an account when it first receives TRX (receiving only USDT doesn't activate it), and sending USDT also needs TRX for the network fee. Send some test TRX to {} (Nile faucet), then try again.",
            owner.to_base58()
        ));
    }
    api::check_permissions(&acct, owner).map_err(|why| {
        format!(
            "Refused: {why}. Someone may have added their own key to this TRON account. Don't send from it; follow the incident runbook (move funds from a clean device). Compare on tronscan: Account → Permissions."
        )
    })?;
    let trx = api::parse_trx_balance(&acct).map_err(|e| format!("{}: {e}", p.id))?;
    if trx == 0 {
        return Err(format!(
            "This address has no TRX. Sending USDT on TRON uses TRX for the network fee (up to {} TRX). Send some test TRX to {} first.",
            FEE_LIMIT_SUN / 1_000_000,
            owner.to_base58()
        ));
    }
    Ok(())
}

/// Latest solidified block: (number, block id, timestamp ms).
pub fn parse_block(v: &Value) -> Result<(u64, [u8; 32], u64), String> {
    let bad = || "The node's block answer is malformed.".to_owned();
    let id_hex = v.get("blockID").and_then(Value::as_str).ok_or_else(bad)?;
    let mut id = [0u8; 32];
    hex::decode_to_slice(id_hex, &mut id).map_err(|_| bad())?;
    let raw = v
        .get("block_header")
        .and_then(|h| h.get("raw_data"))
        .ok_or_else(bad)?;
    let number = raw.get("number").and_then(Value::as_u64).ok_or_else(bad)?;
    let ts = raw
        .get("timestamp")
        .and_then(Value::as_u64)
        .ok_or_else(bad)?;
    // The block id starts with the block number (8 bytes, big-endian).
    if id[..8] != number.to_be_bytes() {
        return Err(bad());
    }
    Ok((number, id, ts))
}

/// Build the unsigned transfer from a recent solidified block.
pub async fn build<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    owner: TronAddress,
    recipient: TronAddress,
    amount: u128,
) -> Result<Trc20Transfer, String> {
    let p = first_provider(config)?;
    let block = http
        .post_json(
            &format!("{}/walletsolidity/getnowblock", p.base_url),
            &json!({}),
        )
        .await
        .map_err(|e| format!("{}: couldn't read the latest block: {e}", p.id))?;
    let (number, id, ts) = parse_block(&block)?;
    let (ref_block_bytes, ref_block_hash) = tron_tx::ref_block(number, &id);
    Ok(Trc20Transfer {
        ref_block_bytes,
        ref_block_hash,
        expiration_ms: ts + VALIDITY_MS,
        timestamp_ms: ts,
        fee_limit_sun: FEE_LIMIT_SUN,
        owner,
        token: nile_usdt(config)?,
        recipient,
        amount,
    })
}

/// The tablet's signing-log receipt sent with a signature: the
/// signature's number in its log and the log's head hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub seq: u64,
    pub head: [u8; 32],
}

/// Check the tablet's answer (32-byte txid ‖ 65-byte signature, then from
/// tablets with a signing log: 8-byte log number ‖ 32-byte log head)
/// against the raw transaction built here; returns the signed transaction
/// bytes and the receipt.
pub fn finalize(
    raw: &[u8],
    owner: &TronAddress,
    answer: &[u8],
) -> Result<(Vec<u8>, Option<Receipt>), String> {
    let receipt = match answer.len() {
        97 => None,
        137 => Some(Receipt {
            seq: u64::from_be_bytes(
                answer[97..105]
                    .try_into()
                    .map_err(|_| "Malformed receipt.")?,
            ),
            head: answer[105..].try_into().map_err(|_| "Malformed receipt.")?,
        }),
        _ => return Err("That isn't a TRON signature from the tablet.".into()),
    };
    let answer = &answer[..97];
    if answer[..32] != tron_tx::txid(raw) {
        return Err("The signature is for a different transaction. Build the payment again and scan the new QR on the tablet.".into());
    }
    let sig: [u8; 65] = answer[32..]
        .try_into()
        .map_err(|_| "Malformed signature.".to_owned())?;
    match tron_tx::recover_signer(raw, &sig) {
        Ok(a) if a == *owner => Ok((tron_tx::signed_transaction(raw, &sig), receipt)),
        Ok(_) => Err("The signature isn't from this wallet's TRON key.".into()),
        Err(_) => Err("The signature is invalid.".into()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TronSent {
    pub txid: String,
    pub explorer_url: String,
    /// About the tablet's signing log (a warning if it signed something
    /// this PC didn't see); empty when there's nothing to say.
    pub log_note: String,
}

/// Compare a new receipt with the previous one for the same wallet.
/// Returns a warning when the tablet signed more than this PC saw.
pub fn receipt_note(previous: Option<u64>, now: u64) -> String {
    match previous {
        Some(p) if now == p + 1 => String::new(),
        Some(p) if now > p + 1 => format!(
            "Warning: the tablet's signing log is at #{now}, but the last signature this PC saw was #{p}. \
             The tablet signed {} payment(s) this PC didn't send (for example ones you cancelled, or sent \
             from another PC). If you don't know of any, check the log on the tablet (Signing log) and \
             follow the incident runbook.",
            now - p - 1
        ),
        Some(p) => format!(
            "Warning: the tablet's signing log went back (#{now} after #{p}). Its policy may have been reset \
             or restored from an older copy. Check the tablet."
        ),
        None => String::new(),
    }
}

/// Broadcast with `/wallet/broadcasthex`.
pub async fn broadcast<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    signed: &[u8],
    txid: &[u8; 32],
) -> Result<TronSent, String> {
    let p = first_provider(config)?;
    let resp = http
        .post_json(
            &format!("{}/wallet/broadcasthex", p.base_url),
            &json!({ "transaction": hex::encode(signed) }),
        )
        .await
        .map_err(|e| format!("{}: {e}", p.id))?;
    let txid = hex::encode(txid);
    if resp.get("result").and_then(Value::as_bool) == Some(true) {
        return Ok(TronSent {
            explorer_url: format!("https://nile.tronscan.org/#/transaction/{txid}"),
            txid,
            log_note: String::new(),
        });
    }
    // Errors carry a code and a message that is sometimes hex-encoded text.
    let code = resp.get("code").and_then(Value::as_str).unwrap_or("error");
    let msg = resp.get("message").and_then(Value::as_str).unwrap_or("");
    let msg = hex::decode(msg)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| msg.to_owned());
    Err(format!(
        "The node refused the transaction: {code} {}",
        msg.chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_sources::fetch::mock::MockHttp;

    #[test]
    fn config_and_tablet_agree_on_the_test_usdt() {
        let c = NetworkConfig::embedded().expect("config");
        assert_eq!(
            c.usdt_trc20_nile.map(|a| a.to_base58()).as_deref(),
            Some(tron_tx::NILE_USDT)
        );
    }

    #[test]
    fn receipts_reveal_signatures_the_pc_did_not_see() {
        assert_eq!(receipt_note(None, 5), "");
        assert_eq!(receipt_note(Some(4), 5), "");
        assert!(receipt_note(Some(2), 5).contains("signed 2 payment(s)"));
        assert!(receipt_note(Some(5), 5).contains("went back"));
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_usdt("12.5"), Ok(12_500_000));
        assert_eq!(parse_usdt("0.000001"), Ok(1));
        assert_eq!(parse_usdt("7"), Ok(7_000_000));
        assert!(parse_usdt("0").is_err());
        assert!(parse_usdt("1.0000001").is_err());
        assert!(parse_usdt("-1").is_err());
        assert!(parse_usdt("1e3").is_err());
        assert_eq!(decimal6(12_500_000), "12.5");
    }

    #[tokio::test]
    async fn inactive_or_empty_sender_is_explained_before_signing() {
        let config = NetworkConfig::embedded().expect("config");
        let base = &config.nile_providers[0].base_url;
        let owner: TronAddress = "TXJ7MoQLNCGstqko8jQHEjXwAhhwYLh5aC".parse().expect("a");
        let url = format!("{base}{}", api::GET_ACCOUNT_PATH);
        let mut http = MockHttp::default();
        http.on_post(&url, &api::get_account(&owner), json!({}));
        let e = require_ready_sender(&http, &config, &owner)
            .await
            .expect_err("inactive");
        assert!(e.contains("isn't activated"), "{e}");

        let mut http = MockHttp::default();
        http.on_post(
            &url,
            &api::get_account(&owner),
            json!({"address": "41", "create_time": 1}),
        );
        let e = require_ready_sender(&http, &config, &owner)
            .await
            .expect_err("no trx");
        assert!(e.contains("no TRX"), "{e}");

        let mut http = MockHttp::default();
        http.on_post(
            &url,
            &api::get_account(&owner),
            json!({"address": "41", "balance": 50_000_000}),
        );
        assert!(require_ready_sender(&http, &config, &owner).await.is_ok());
    }

    #[tokio::test]
    async fn build_sign_finalize_broadcast() {
        let config = NetworkConfig::embedded().expect("config");
        let base = &config.nile_providers[0].base_url;
        let sk = secp256k1::SecretKey::from_slice(&[5u8; 32]).expect("sk");
        let owner = tron_tx::address_of(&sk.public_key(&secp256k1::Secp256k1::new()));
        let to: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("to");
        let number: u64 = 60_000_123;
        let mut id = [0xabu8; 32];
        id[..8].copy_from_slice(&number.to_be_bytes());
        let mut http = MockHttp::default();
        http.on_post(
            &format!("{base}/walletsolidity/getnowblock"),
            &json!({}),
            json!({"blockID": hex::encode(id), "block_header": {"raw_data": {"number": number, "timestamp": 1_800_000_000_000u64}}}),
        );
        let t = build(&http, &config, owner, to, 2_000_000)
            .await
            .expect("build");
        assert_eq!(
            t.ref_block_bytes,
            [number.to_be_bytes()[6], number.to_be_bytes()[7]]
        );
        assert_eq!(t.expiration_ms - t.timestamp_ms, VALIDITY_MS);
        let raw = t.encode_raw();

        let sig = tron_tx::sign(&raw, &sk);
        let mut answer = tron_tx::txid(&raw).to_vec();
        answer.extend_from_slice(&sig);
        let (signed, receipt) = finalize(&raw, &owner, &answer).expect("finalize");
        assert_eq!(receipt, None);
        // From a tablet with a signing log: the receipt comes along.
        let mut with_log = answer.clone();
        with_log.extend_from_slice(&7u64.to_be_bytes());
        with_log.extend_from_slice(&[0xab; 32]);
        let (signed2, receipt) = finalize(&raw, &owner, &with_log).expect("finalize");
        assert_eq!(signed2, signed);
        assert_eq!(
            receipt,
            Some(Receipt {
                seq: 7,
                head: [0xab; 32]
            })
        );
        assert!(finalize(&raw, &owner, &with_log[..120]).is_err());

        // Wrong wallet, other transaction, garbage: refused.
        let other_sk = secp256k1::SecretKey::from_slice(&[6u8; 32]).expect("sk2");
        let mut bad = tron_tx::txid(&raw).to_vec();
        bad.extend_from_slice(&tron_tx::sign(&raw, &other_sk));
        assert!(finalize(&raw, &owner, &bad).is_err());
        let mut t2 = t.clone();
        t2.amount += 1;
        assert!(finalize(&t2.encode_raw(), &owner, &answer).is_err());
        assert!(finalize(&raw, &owner, &answer[..90]).is_err());

        let txid = tron_tx::txid(&raw);
        http.on_post(
            &format!("{base}/wallet/broadcasthex"),
            &json!({"transaction": hex::encode(&signed)}),
            json!({"result": true, "txid": hex::encode(txid)}),
        );
        let sent = broadcast(&http, &config, &signed, &txid)
            .await
            .expect("sent");
        assert!(sent.explorer_url.contains("nile.tronscan.org"));

        // A refusal is explained (message is hex-encoded text).
        let mut refuse = MockHttp::default();
        refuse.on_post(
            &format!("{base}/wallet/broadcasthex"),
            &json!({"transaction": hex::encode(&signed)}),
            json!({"code": "TRANSACTION_EXPIRATION_ERROR", "message": hex::encode("Transaction expired")}),
        );
        let err = broadcast(&refuse, &config, &signed, &txid)
            .await
            .expect_err("refused");
        assert!(err.contains("Transaction expired"), "{err}");
    }
}
