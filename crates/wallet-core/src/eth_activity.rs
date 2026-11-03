//! Ethereum history with address-poisoning detection: the same rules as for
//! TRON (`activity.rs`), applied to Blockscout data.
//!
//! - 0-value USDT transfers, USDT dust (< 1 USDT), incoming ETH dust and
//!   tokens that aren't the pinned USDT contract are hidden.
//! - Counterparties that look like one of your addresses or a real
//!   counterparty (same 3 characters after "0x", or same last 3) are flagged.
//! - Approvals you signed and USDT moved out of your address by someone else
//!   (`transferFrom` with an earlier approval) are always shown.
//!
//! History comes from one indexer, isn't cross-checked, and never feeds a
//! balance or a payment.

use std::collections::{BTreeSet, HashSet};

use chain_eth::history::{Erc20Transfer, EthCall, EthTx};
use chain_eth::EthAddress;
use wallet_types::{format_base_units, Amount, Asset};

use crate::activity::{
    looks_alike, ActivityEntry, Direction, Flag, Known, TxEntry, DUST_BASE_UNITS,
};

/// Incoming ETH below this (0.0001 ETH, in wei) is treated as dust.
pub const DUST_WEI: u128 = 100_000_000_000_000;

/// A watched Ethereum address and its label (for look-alike warnings).
#[derive(Debug, Clone)]
pub struct KnownEth {
    pub address: EthAddress,
    pub label: String,
}

fn dir(from_me: bool, to_me: bool) -> Direction {
    match (from_me, to_me) {
        (true, true) => Direction::SelfTransfer,
        (true, false) => Direction::Out,
        (false, true) => Direction::In,
        (false, false) => Direction::NotInvolved,
    }
}

fn usdt_text(v: Option<u128>) -> String {
    match v {
        Some(v) => Amount::new(Asset::UsdtErc20, v).to_decimal_string(),
        None => "unlimited".to_owned(),
    }
}

fn eth_text(wei: u128) -> String {
    Amount::new(Asset::Eth, wei).to_decimal_string()
}

/// Your own addresses plus counterparties of real transfers (genuine USDT
/// >= 1 USDT, ETH >= 0.0001, USDT you sent yourself).
pub fn known_counterparties_eth(
    me: &EthAddress,
    own: &[KnownEth],
    usdt: &EthAddress,
    transfers: &[Erc20Transfer],
    txs: &[EthTx],
) -> Vec<Known> {
    let mut known: Vec<Known> = own
        .iter()
        .filter(|k| k.address != *me)
        .map(|k| {
            (
                k.address.to_checksum(),
                format!("your wallet \"{}\"", k.label),
            )
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut add = |a: EthAddress, known: &mut Vec<Known>| {
        if a != *me && seen.insert(a) {
            known.push((a.to_checksum(), "someone you transacted with".into()));
        }
    };
    for t in transfers {
        if t.token == *usdt && t.value.is_some_and(|v| v >= DUST_BASE_UNITS) {
            add(if t.from == *me { t.to } else { t.from }, &mut known);
        }
    }
    for tx in txs.iter().filter(|t| t.success) {
        match (&tx.call, tx.to) {
            (EthCall::EthTransfer, Some(to)) if tx.value_wei.is_some_and(|v| v >= DUST_WEI) => {
                add(if tx.from == *me { to } else { tx.from }, &mut known);
            }
            (EthCall::TokenTransfer { to, amount }, Some(c))
                if tx.from == *me && c == *usdt && amount.is_some_and(|a| a >= DUST_BASE_UNITS) =>
            {
                add(*to, &mut known);
            }
            _ => {}
        }
    }
    known
}

/// Look-alike check for Ethereum: hex is case-insensitive, and the fixed
/// "0x" prefix is skipped.
pub fn eth_lookalike(known: &[Known], cp: &EthAddress) -> Option<Flag> {
    let c = cp.to_checksum().to_lowercase();
    known
        .iter()
        .find(|(k, _)| looks_alike(&k.to_lowercase(), &c, 2))
        .map(|(addr, label)| Flag::LookAlike {
            similar_to: addr.clone(),
            similar_to_label: label.clone(),
        })
}

/// Classify ERC-20 transfers ("Transfers" tab).
///
/// `my_txids` = hashes of transactions this address sent, when that list is
/// complete for the period shown; a USDT transfer *out* of this address that
/// isn't one of them was made by someone else using an approval.
pub fn classify_eth_transfers(
    me: &EthAddress,
    usdt: &EthAddress,
    transfers: &[Erc20Transfer],
    known: &[Known],
    my_txids: Option<&HashSet<String>>,
) -> Vec<ActivityEntry> {
    transfers
        .iter()
        .map(|t| {
            let genuine = t.token == *usdt;
            let direction = dir(t.from == *me, t.to == *me);
            let cp = if direction == Direction::Out {
                t.to
            } else {
                t.from
            };
            let mut flags = Vec::new();
            if !genuine {
                flags.push(if t.claimed_symbol.to_ascii_uppercase().contains("USD") {
                    Flag::FakeToken
                } else {
                    Flag::UnknownToken
                });
            }
            let mut never_hide = false;
            if genuine {
                match t.value {
                    Some(0) => flags.push(Flag::ZeroValue),
                    Some(v) if v < DUST_BASE_UNITS => flags.push(Flag::Dust {
                        below: "1 USDT".into(),
                    }),
                    _ => {}
                }
                let spent_by_other = direction == Direction::Out
                    && t.value != Some(0)
                    && my_txids.is_some_and(|ids| !ids.contains(&t.txid.to_lowercase()));
                if spent_by_other {
                    flags.push(Flag::SpentByOther);
                    never_hide = true;
                }
            }
            if cp != *me {
                flags.extend(eth_lookalike(known, &cp));
            }
            let hidden = !genuine
                || flags
                    .iter()
                    .any(|f| matches!(f, Flag::ZeroValue | Flag::Dust { .. }))
                || direction == Direction::NotInvolved;
            ActivityEntry {
                txid: t.txid.clone(),
                time_ms: t.time_ms,
                direction,
                is_approval: false,
                token_label: if genuine {
                    Asset::UsdtErc20.label().to_owned()
                } else {
                    format!("Unknown token calling itself \"{}\"", t.claimed_symbol)
                },
                genuine_usdt: genuine,
                amount: t.value.map(|v| {
                    if genuine {
                        Amount::new(Asset::UsdtErc20, v).to_decimal_string()
                    } else {
                        format_base_units(v, t.claimed_decimals)
                    }
                }),
                counterparty: cp.to_checksum(),
                flags,
                hidden: hidden && !never_hide,
            }
        })
        .collect()
}

/// Classify the address's own transactions ("Transactions" tab).
pub fn classify_eth_transactions(
    me: &EthAddress,
    usdt: &EthAddress,
    txs: &[EthTx],
    known: &[Known],
) -> Vec<TxEntry> {
    txs.iter()
        .map(|tx| {
            let mine = tx.from == *me;
            let to_me = tx.to == Some(*me);
            let mut flags = Vec::new();
            let mut hidden = false;
            let mut never_hide = false;
            let wei = tx.value_wei.unwrap_or(0);
            let contract = tx.to;
            let is_usdt = contract == Some(*usdt);
            let token_label = || {
                if is_usdt {
                    Asset::UsdtErc20.label().to_owned()
                } else {
                    "Other token / contract".to_owned()
                }
            };
            let other_contract = |flags: &mut Vec<Flag>| {
                if let Some(c) = contract.filter(|c| c != usdt) {
                    flags.push(Flag::OtherContract {
                        contract: c.to_checksum(),
                    });
                }
            };
            let (action, direction, amount, asset_label, counterparty): (
                String,
                Direction,
                Option<String>,
                Option<String>,
                Option<EthAddress>,
            ) = match &tx.call {
                EthCall::EthTransfer => {
                    let direction = dir(mine, to_me);
                    if direction == Direction::In {
                        if wei == 0 {
                            flags.push(Flag::ZeroValue);
                            hidden = true;
                        } else if wei < DUST_WEI {
                            flags.push(Flag::Dust {
                                below: "0.0001 ETH".into(),
                            });
                            hidden = true;
                        }
                    }
                    (
                        "ETH transfer".into(),
                        direction,
                        Some(eth_text(wei)),
                        Some(Asset::Eth.label().into()),
                        if mine { tx.to } else { Some(tx.from) },
                    )
                }
                EthCall::TokenTransfer { to, amount } => {
                    other_contract(&mut flags);
                    (
                        if is_usdt {
                            "USDT transfer"
                        } else {
                            "Token transfer"
                        }
                        .into(),
                        dir(mine, *to == *me),
                        is_usdt.then(|| usdt_text(*amount)),
                        Some(token_label()),
                        Some(*to),
                    )
                }
                EthCall::TokenTransferFrom { from, to, amount } => {
                    other_contract(&mut flags);
                    if *from == *me && !mine && is_usdt {
                        if *amount == Some(0) {
                            flags.push(Flag::ZeroValue);
                            hidden = true;
                        } else {
                            flags.push(Flag::SpentByOther);
                            never_hide = true;
                        }
                    }
                    (
                        if is_usdt {
                            "USDT transferFrom"
                        } else {
                            "Token transferFrom"
                        }
                        .into(),
                        dir(*from == *me, *to == *me),
                        is_usdt.then(|| usdt_text(*amount)),
                        Some(token_label()),
                        Some(*to),
                    )
                }
                EthCall::Approve { spender, amount }
                | EthCall::IncreaseAllowance { spender, amount } => {
                    other_contract(&mut flags);
                    if mine {
                        flags.push(Flag::Approval);
                        never_hide = true;
                    }
                    let what = if matches!(tx.call, EthCall::Approve { .. }) {
                        "approval"
                    } else {
                        "allowance increase"
                    };
                    (
                        format!("{} {what}", if is_usdt { "USDT" } else { "Token" }),
                        if mine {
                            Direction::Out
                        } else {
                            Direction::NotInvolved
                        },
                        Some(if is_usdt {
                            usdt_text(*amount)
                        } else {
                            amount.map_or_else(|| "unlimited".to_owned(), |a| a.to_string())
                        }),
                        Some(token_label()),
                        Some(*spender),
                    )
                }
                EthCall::SetApprovalForAll { operator, approved } => {
                    other_contract(&mut flags);
                    if mine && *approved {
                        flags.push(Flag::Approval);
                        never_hide = true;
                    }
                    (
                        if *approved {
                            "Approval for ALL tokens of a contract"
                        } else {
                            "Approval for all revoked"
                        }
                        .into(),
                        if mine {
                            Direction::Out
                        } else {
                            Direction::NotInvolved
                        },
                        None,
                        Some(token_label()),
                        Some(*operator),
                    )
                }
                EthCall::Other { selector } => {
                    other_contract(&mut flags);
                    if is_usdt {
                        flags.push(Flag::OtherContract {
                            contract: format!(
                                "USDT function 0x{}",
                                selector.as_deref().unwrap_or("?")
                            ),
                        });
                    }
                    (
                        "Contract call".into(),
                        if mine {
                            Direction::Out
                        } else if to_me {
                            Direction::In
                        } else {
                            Direction::NotInvolved
                        },
                        (wei > 0).then(|| eth_text(wei)),
                        (wei > 0).then(|| Asset::Eth.label().into()),
                        if mine { contract } else { Some(tx.from) },
                    )
                }
                EthCall::Create => (
                    "Contract creation".into(),
                    if mine {
                        Direction::Out
                    } else {
                        Direction::NotInvolved
                    },
                    (wei > 0).then(|| eth_text(wei)),
                    (wei > 0).then(|| Asset::Eth.label().into()),
                    None,
                ),
            };
            if direction == Direction::NotInvolved {
                hidden = true;
            }
            if !tx.success {
                flags.push(Flag::Failed);
            }
            let cp = counterparty.filter(|c| c != me);
            if let Some(c) = &cp {
                flags.extend(eth_lookalike(known, c));
            }
            TxEntry {
                txid: tx.txid.clone(),
                time_ms: tx.time_ms,
                success: tx.success,
                action,
                direction,
                amount,
                asset_label,
                counterparty: cp.map(|c| c.to_checksum()),
                flags,
                hidden: hidden && !never_hide,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(b: [u8; 20]) -> EthAddress {
        EthAddress::parse_any_case(&format!("0x{}", hex::encode(b))).expect("addr")
    }
    fn addr(seed: u8) -> EthAddress {
        a([seed; 20])
    }
    /// Same first 3 hex characters and last 3 as `of`, different middle.
    fn lookalike_of(of: &EthAddress) -> EthAddress {
        let mut b = *of.as_bytes();
        b[5] ^= 0xff;
        b[10] ^= 0xff;
        a(b)
    }
    fn usdt() -> EthAddress {
        "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .expect("usdt")
    }
    fn tr(
        n: u8,
        from: EthAddress,
        to: EthAddress,
        token: EthAddress,
        value: u128,
        sym: &str,
    ) -> Erc20Transfer {
        Erc20Transfer {
            txid: format!("0x{}", hex::encode([n; 32])),
            time_ms: u64::from(n) * 1000,
            token,
            claimed_symbol: sym.into(),
            claimed_decimals: 6,
            from,
            to,
            value: Some(value),
        }
    }
    fn tx(n: u8, from: EthAddress, to: Option<EthAddress>, wei: u128, call: EthCall) -> EthTx {
        EthTx {
            txid: format!("0x{}", hex::encode([n; 32])),
            time_ms: u64::from(n) * 1000,
            success: true,
            from,
            to,
            value_wei: Some(wei),
            call,
        }
    }

    #[test]
    fn poisoning_pattern_is_hidden_and_flagged() {
        let me = addr(1);
        let friend = addr(2);
        let fake = lookalike_of(&friend);
        let transfers = vec![
            // Real payment to a friend.
            tr(1, me, friend, usdt(), 500_000_000, "USDT"),
            // Attacker: 0-value transferFrom(me → look-alike) of real USDT.
            tr(2, me, fake, usdt(), 0, "USDT"),
            // Attacker: fake "USDT" token from the look-alike.
            tr(3, fake, me, addr(9), 500_000_000, "USDT"),
            // Dust of real USDT from the look-alike.
            tr(4, fake, me, usdt(), 10, "USDT"),
        ];
        let my_tx = vec![tx(
            1,
            me,
            Some(usdt()),
            0,
            EthCall::TokenTransfer {
                to: friend,
                amount: Some(500_000_000),
            },
        )];
        let known = known_counterparties_eth(&me, &[], &usdt(), &transfers, &my_tx);
        let ids: HashSet<String> = my_tx.iter().map(|t| t.txid.to_lowercase()).collect();
        let e = classify_eth_transfers(&me, &usdt(), &transfers, &known, Some(&ids));

        assert!(!e[0].hidden && e[0].flags.is_empty(), "{:?}", e[0].flags);
        assert!(e[1].hidden && e[1].flags.contains(&Flag::ZeroValue));
        assert!(
            !e[1].flags.contains(&Flag::SpentByOther),
            "0-value isn't a theft"
        );
        assert!(e[1]
            .flags
            .iter()
            .any(|f| matches!(f, Flag::LookAlike { .. })));
        assert!(e[2].hidden && e[2].flags.contains(&Flag::FakeToken));
        assert!(e[3].hidden && e[3].flags.iter().any(|f| matches!(f, Flag::Dust { .. })));
    }

    #[test]
    fn approvals_and_spending_by_others_are_never_hidden() {
        let me = addr(1);
        let spender = addr(7);
        let thief_to = addr(8);
        let txs = vec![
            tx(
                1,
                me,
                Some(usdt()),
                0,
                EthCall::Approve {
                    spender,
                    amount: None,
                },
            ),
            tx(
                2,
                spender,
                Some(usdt()),
                0,
                EthCall::TokenTransferFrom {
                    from: me,
                    to: thief_to,
                    amount: Some(9_000_000),
                },
            ),
            tx(3, addr(3), Some(me), 5, EthCall::EthTransfer), // ETH dust in
        ];
        let e = classify_eth_transactions(&me, &usdt(), &txs, &[]);
        assert_eq!(e[0].action, "USDT approval");
        assert_eq!(e[0].amount.as_deref(), Some("unlimited"));
        assert!(!e[0].hidden && e[0].flags.contains(&Flag::Approval));
        assert!(!e[1].hidden && e[1].flags.contains(&Flag::SpentByOther));
        assert!(e[2].hidden && e[2].flags.iter().any(|f| matches!(f, Flag::Dust { .. })));

        // In the transfers list, USDT out of my address that I didn't send.
        let transfers = vec![tr(2, me, thief_to, usdt(), 9_000_000, "USDT")];
        let mine: HashSet<String> = HashSet::new();
        let t = classify_eth_transfers(&me, &usdt(), &transfers, &[], Some(&mine));
        assert!(!t[0].hidden && t[0].flags.contains(&Flag::SpentByOther));
        // Without a complete list of my transactions, don't guess.
        let t = classify_eth_transfers(&me, &usdt(), &transfers, &[], None);
        assert!(!t[0].flags.contains(&Flag::SpentByOther));
    }

    #[test]
    fn lookalike_is_case_insensitive_and_skips_0x() {
        let mine = addr(0xab);
        let fake = lookalike_of(&mine);
        let known = vec![(mine.to_checksum(), "your wallet \"Savings\"".to_owned())];
        assert!(eth_lookalike(&known, &fake).is_some());
        assert!(eth_lookalike(&known, &addr(0x12)).is_none());
        assert!(
            eth_lookalike(&known, &mine).is_none(),
            "an address doesn't look like itself"
        );
    }
}
