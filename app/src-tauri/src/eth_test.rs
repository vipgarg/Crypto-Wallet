//! Ethereum **Sepolia** test payments (Phase 2 testing): USDT with no value.
//! The UI→core commands are in `commands.rs`; this file holds the logic.
//!
//! The transaction is built **here** (eth-tx), never by a node: the nodes
//! are only asked for the nonce, current fees, a gas estimate, balances, and
//! to broadcast the signed result. After the tablet signs, the PC checks the
//! signature recovers to the wallet's own address for exactly the
//! transaction it built.

use chain_eth::rpc;
use chain_eth::EthAddress;
use data_sources::config::SignetProvider;
use data_sources::{HttpClient, NetworkConfig};
use eth_tx::Erc20Transfer;
use serde::Serialize;
use serde_json::{json, Value};

/// Gas limit bounds (the tablet accepts up to 120,000).
pub const MIN_GAS: u64 = 60_000;
pub const MAX_GAS: u64 = 120_000;
/// Worst-case fee allowed (the tablet accepts up to 0.05 ETH).
pub const MAX_FEE_WEI: u128 = 50_000_000_000_000_000;
/// Priority fee when the node doesn't suggest one (1.5 gwei).
const DEFAULT_TIP: u128 = 1_500_000_000;

fn providers(config: &NetworkConfig) -> Result<&[SignetProvider], String> {
    if config.sepolia_providers.is_empty() {
        return Err("No Ethereum Sepolia node is configured.".into());
    }
    Ok(&config.sepolia_providers)
}

fn usdt(config: &NetworkConfig) -> Result<EthAddress, String> {
    config
        .usdt_erc20_sepolia
        .ok_or_else(|| "The Sepolia test USDT contract isn't configured.".to_owned())
}

fn req(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// Ask the providers in order; the first good answer wins.
async fn ask<H: HttpClient, T>(
    http: &H,
    config: &NetworkConfig,
    body: &Value,
    parse: impl Fn(&Value) -> Result<T, String>,
) -> Result<(T, String), String> {
    let mut errors = Vec::new();
    for p in providers(config)? {
        match http.post_json(&p.base_url, body).await {
            Ok(v) => match parse(&v) {
                Ok(t) => return Ok((t, p.id.clone())),
                Err(e) => errors.push(format!("{}: {e}", p.id)),
            },
            Err(e) => errors.push(format!("{}: {e}", p.id)),
        }
    }
    Err(errors.join("; "))
}

fn quantity(v: &Value) -> Result<u128, String> {
    rpc::parse_quantity(v).map_err(|e| e.to_string())
}

pub fn decimal(v: u128, decimals: u32) -> String {
    let d = 10u128.pow(decimals);
    let (w, f) = (v / d, v % d);
    if f == 0 {
        w.to_string()
    } else {
        let f = format!("{f:0w$}", w = decimals as usize);
        format!("{w}.{}", f.trim_end_matches('0'))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SepoliaBalances {
    pub address: String,
    pub eth: String,
    pub usdt: String,
    pub source: String,
    pub explorer_url: String,
}

pub async fn balances<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    addr: &EthAddress,
) -> Result<SepoliaBalances, String> {
    let token = usdt(config)?;
    let (eth, source) = ask(http, config, &rpc::eth_get_balance(addr), quantity).await?;
    let (usdt_v, _) = ask(http, config, &rpc::erc20_balance_of(&token, addr), |v| {
        rpc::parse_uint256_word(v).map_err(|e| e.to_string())
    })
    .await?;
    Ok(SepoliaBalances {
        address: addr.to_checksum(),
        eth: decimal(eth, 18),
        usdt: decimal(usdt_v, 6),
        source,
        explorer_url: format!(
            "https://sepolia.etherscan.io/address/{}",
            addr.to_checksum()
        ),
    })
}

/// A built transaction plus what the page shows about its cost.
#[derive(Debug, Clone)]
pub struct Built {
    pub tx: Erc20Transfer,
    /// Likely fee ((base fee + tip) × gas estimate), in wei.
    pub likely_fee_wei: u128,
    /// Worst case (gas limit × max fee), in wei.
    pub max_fee_wei: u128,
}

fn base_fee(v: &Value) -> Result<u128, String> {
    let s = v
        .get("result")
        .and_then(|r| r.get("baseFeePerGas"))
        .and_then(Value::as_str)
        .ok_or("no base fee in the latest block")?;
    rpc::parse_quantity(&json!({ "result": s })).map_err(|e| e.to_string())
}

/// Build the unsigned USDT transfer.
pub async fn build<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    owner: EthAddress,
    recipient: EthAddress,
    amount: u128,
) -> Result<Built, String> {
    let token = usdt(config)?;
    let (chain, _) = ask(http, config, &req("eth_chainId", json!([])), quantity).await?;
    if chain != u128::from(eth_tx::SEPOLIA_CHAIN_ID) {
        return Err("The configured node isn't on the Sepolia test network.".into());
    }
    let (eth_balance, _) = ask(http, config, &rpc::eth_get_balance(&owner), quantity).await?;
    let (token_balance, _) = ask(http, config, &rpc::erc20_balance_of(&token, &owner), |v| {
        rpc::parse_uint256_word(v).map_err(|e| e.to_string())
    })
    .await?;
    if token_balance < amount {
        return Err(format!(
            "Not enough test USDT: this wallet has {} on Sepolia.",
            decimal(token_balance, 6)
        ));
    }
    let (nonce, _) = ask(
        http,
        config,
        &req(
            "eth_getTransactionCount",
            json!([owner.to_checksum(), "pending"]),
        ),
        quantity,
    )
    .await?;
    let (base, _) = ask(http, config, &rpc::eth_latest_block(), base_fee).await?;
    let tip = ask(
        http,
        config,
        &req("eth_maxPriorityFeePerGas", json!([])),
        quantity,
    )
    .await
    .map(|(t, _)| t)
    .unwrap_or(DEFAULT_TIP)
    .max(1);
    let max_fee = base.saturating_mul(2).saturating_add(tip);
    let data = format!(
        "0x{}",
        hex::encode(eth_tx::transfer_data(&recipient, amount))
    );
    let (estimate, _) = ask(
        http,
        config,
        &req(
            "eth_estimateGas",
            json!([{"from": owner.to_checksum(), "to": token.to_checksum(), "data": data}]),
        ),
        quantity,
    )
    .await
    .map_err(|e| format!("The node couldn't estimate the gas ({e})."))?;
    // 30 % margin, within the tablet's bounds.
    let gas = u64::try_from(estimate.saturating_mul(13) / 10)
        .unwrap_or(MAX_GAS)
        .clamp(MIN_GAS, MAX_GAS);
    let worst = u128::from(gas).saturating_mul(max_fee);
    if worst > MAX_FEE_WEI {
        return Err("Sepolia network fees are unusually high right now (over 0.05 test ETH). Try again later.".into());
    }
    if eth_balance < worst {
        return Err(format!(
            "This wallet needs test ETH for the network fee: up to {} ETH, it has {}. Get some from a Sepolia faucet.",
            decimal(worst, 18),
            decimal(eth_balance, 18)
        ));
    }
    Ok(Built {
        tx: Erc20Transfer {
            chain_id: eth_tx::SEPOLIA_CHAIN_ID,
            nonce: u64::try_from(nonce).map_err(|_| "Unusual nonce.".to_owned())?,
            max_priority_fee_per_gas: tip,
            max_fee_per_gas: max_fee,
            gas_limit: gas,
            token,
            recipient,
            amount,
        },
        likely_fee_wei: estimate.saturating_mul(base.saturating_add(tip)),
        max_fee_wei: worst,
    })
}

/// The tablet's signing-log receipt sent with a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub seq: u64,
    pub head: [u8; 32],
}

/// Check the tablet's answer (65-byte signature, then the 40-byte receipt)
/// against the transaction built here; returns the signed transaction.
pub fn finalize(
    tx: &Erc20Transfer,
    owner: &EthAddress,
    answer: &[u8],
) -> Result<(Vec<u8>, Receipt), String> {
    if answer.len() != 105 {
        return Err("That isn't an Ethereum signature from the tablet.".into());
    }
    let sig: [u8; 65] = answer[..65]
        .try_into()
        .map_err(|_| "Malformed signature.".to_owned())?;
    let receipt = Receipt {
        seq: u64::from_be_bytes(
            answer[65..73]
                .try_into()
                .map_err(|_| "Malformed receipt.")?,
        ),
        head: answer[73..].try_into().map_err(|_| "Malformed receipt.")?,
    };
    let unsigned = tx.encode_unsigned();
    match eth_tx::recover_signer(&unsigned, &sig) {
        Ok(a) if a == *owner => Ok((tx.encode_signed(&sig), receipt)),
        Ok(_) => Err("The signature isn't from this wallet's key, or it's for a different transaction. Build the payment again and scan the new QR on the tablet.".into()),
        Err(_) => Err("The signature is invalid.".into()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EthSent {
    pub txid: String,
    pub explorer_url: String,
    pub accepted_by: Vec<String>,
    pub errors: Vec<String>,
    /// About the tablet's signing log (empty when there's nothing to say).
    pub log_note: String,
}

/// Send to every configured node; success if any accepts it.
pub async fn broadcast<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    signed: &[u8],
) -> Result<EthSent, String> {
    let txid = format!("0x{}", hex::encode(eth_tx::tx_hash(signed)));
    let body = req(
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(signed))]),
    );
    let (mut accepted_by, mut errors) = (Vec::new(), Vec::new());
    for p in providers(config)? {
        match http.post_json(&p.base_url, &body).await {
            Ok(v) => {
                let result = v.get("result").and_then(Value::as_str);
                let err = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if result.is_some_and(|r| r.eq_ignore_ascii_case(&txid))
                    || err.contains("already known")
                {
                    accepted_by.push(p.id.clone());
                } else if let Some(r) = result {
                    errors.push(format!("{}: answered a different hash {r}", p.id));
                } else {
                    let clean: String = err.chars().filter(|c| !c.is_control()).take(200).collect();
                    errors.push(format!("{}: {clean}", p.id));
                }
            }
            Err(e) => errors.push(format!("{}: {e}", p.id)),
        }
    }
    if accepted_by.is_empty() {
        return Err(format!(
            "No node accepted the transaction: {}",
            errors.join("; ")
        ));
    }
    Ok(EthSent {
        explorer_url: format!("https://sepolia.etherscan.io/tx/{txid}"),
        txid,
        accepted_by,
        errors,
        log_note: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_sources::fetch::mock::MockHttp;

    #[test]
    fn config_and_tablet_agree_on_the_test_usdt() {
        let c = NetworkConfig::embedded().expect("config");
        assert_eq!(
            c.usdt_erc20_sepolia.map(|a| a.to_checksum()).as_deref(),
            Some(eth_tx::SEPOLIA_USDT)
        );
        assert!(c.sepolia_providers.len() >= 2);
    }

    #[tokio::test]
    async fn build_sign_finalize_broadcast() {
        let config = NetworkConfig::embedded().expect("config");
        let url = config.sepolia_providers[0].base_url.clone();
        let url2 = config.sepolia_providers[1].base_url.clone();
        let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let owner: EthAddress = "0x4a62316623ad457F02cDC5D997deD67a383EC569"
            .parse()
            .expect("me");
        let to: EthAddress = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
            .parse()
            .expect("to");
        let token = usdt(&config).expect("usdt");
        let mut http = MockHttp::default();
        http.on_post(
            &url,
            &req("eth_chainId", json!([])),
            json!({"result": "0xaa36a7"}),
        );
        http.on_post(
            &url,
            &rpc::eth_get_balance(&owner),
            json!({"result": "0x16345785d8a0000"}),
        ); // 0.1 ETH
        http.on_post(
            &url,
            &rpc::erc20_balance_of(&token, &owner),
            json!({"result": format!("0x{:064x}", 10_000_000u128)}),
        );
        http.on_post(
            &url,
            &req(
                "eth_getTransactionCount",
                json!([owner.to_checksum(), "pending"]),
            ),
            json!({"result": "0x5"}),
        );
        http.on_post(
            &url,
            &rpc::eth_latest_block(),
            json!({"result": {"baseFeePerGas": "0x3b9aca00"}}),
        ); // 1 gwei
        http.on_post(
            &url,
            &req("eth_maxPriorityFeePerGas", json!([])),
            json!({"result": "0x59682f00"}),
        );
        let data = format!("0x{}", hex::encode(eth_tx::transfer_data(&to, 2_500_000)));
        http.on_post(
            &url,
            &req(
                "eth_estimateGas",
                json!([{"from": owner.to_checksum(), "to": token.to_checksum(), "data": data}]),
            ),
            json!({"result": "0xc350"}),
        ); // 50,000
        let b = build(&http, &config, owner, to, 2_500_000)
            .await
            .expect("build");
        assert_eq!(b.tx.nonce, 5);
        assert_eq!(b.tx.gas_limit, 65_000);
        assert_eq!(b.tx.max_fee_per_gas, 2_000_000_000 + 1_500_000_000);

        // Too much: refused before anything is shown.
        assert!(build(&http, &config, owner, to, 20_000_000)
            .await
            .expect_err("balance")
            .contains("Not enough"));

        let unsigned = b.tx.encode_unsigned();
        let mut answer = eth_tx::sign(&unsigned, &sk).to_vec();
        answer.extend_from_slice(&9u64.to_be_bytes());
        answer.extend_from_slice(&[1u8; 32]);
        let (signed, r) = finalize(&b.tx, &owner, &answer).expect("finalize");
        assert_eq!(r.seq, 9);
        // Wrong key, wrong transaction, truncated: refused.
        let other = secp256k1::SecretKey::from_slice(&[8u8; 32]).expect("sk2");
        let mut bad = eth_tx::sign(&unsigned, &other).to_vec();
        bad.extend_from_slice(&answer[65..]);
        assert!(finalize(&b.tx, &owner, &bad).is_err());
        let mut t2 = b.tx.clone();
        t2.amount += 1;
        assert!(finalize(&t2, &owner, &answer).is_err());
        assert!(finalize(&b.tx, &owner, &answer[..65]).is_err());

        let txid = format!("0x{}", hex::encode(eth_tx::tx_hash(&signed)));
        let send = req(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(&signed))]),
        );
        http.on_post(&url, &send, json!({"result": txid}));
        http.on_post(&url2, &send, json!({"error": {"message": "already known"}}));
        let sent = broadcast(&http, &config, &signed).await.expect("sent");
        assert_eq!(sent.accepted_by.len(), 2);
        assert_eq!(sent.txid, txid);
    }
}
