//! Transaction history with address-poisoning detection (ARCHITECTURE.md
//! §7 ③, §7.2, threat T3).
//!
//! Address poisoning: an attacker sends a 0-value or tiny transfer from an
//! address that looks like one you use (same first and last characters), so
//! that it appears in your history. If you later copy the "recipient" from
//! your history, you pay the attacker. This module:
//! - hides 0-value transfers, dust and tokens that aren't the pinned USDT;
//! - flags counterparties that look like (but aren't) one of your own
//!   addresses or someone you really transact with;
//! - shows token approvals prominently (an approval lets someone else move
//!   your USDT later).
//!
//! History comes from ONE provider for now (it isn't cross-checked), so it is
//! information only and never feeds a balance or a payment.

use std::collections::BTreeSet;

use chain_tron::history::{CallKind, EventKind, Trc20Event, TronTx, TxAction};
use chain_tron::TronAddress;
use serde::Serialize;
use wallet_types::{format_base_units, Amount, Asset, Network, WalletId};

/// Transfers of genuine USDT below this (1 USDT) are treated as dust.
pub const DUST_BASE_UNITS: u128 = 1_000_000;
/// TRX transfers below this (1 TRX, in sun) are treated as dust.
pub const DUST_SUN: u128 = 1_000_000;
/// Characters compared at the start (after the network's fixed prefix) and at
/// the end of two addresses for the look-alike check.
pub const LOOKALIKE_CHARS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
    /// From and to are both this address.
    SelfTransfer,
    /// This address is neither sender nor receiver (e.g. it is the spender in
    /// someone else's approval).
    NotInvolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Flag {
    /// Moved 0 tokens: the classic poisoning trick.
    ZeroValue,
    /// A tiny amount (below `below`, e.g. "1 USDT"): typical of poisoning
    /// and tracking attempts.
    Dust { below: String },
    /// Bitcoin dust received: may be used to track you; don't spend it
    /// together with your other coins.
    BtcDust { below: String },
    /// Not confirmed in a block yet.
    Unconfirmed,
    /// The counterparty shares the first or last characters with `similar_to`
    /// but is a different address.
    LookAlike {
        similar_to: String,
        similar_to_label: String,
    },
    /// A token that isn't the pinned USDT contract but calls itself USD-something.
    FakeToken,
    /// Any other token that isn't the pinned USDT contract.
    UnknownToken,
    /// This address gave someone permission to spend its tokens.
    Approval,
    /// Someone else moved tokens out of this address using an earlier approval.
    SpentByOther,
    /// The account's owner/active permissions were changed (§8.5).
    PermissionChange,
    /// A call to a contract that isn't the pinned USDT contract.
    OtherContract { contract: String },
    /// A TRC-10 token transfer (almost always spam).
    Trc10,
    /// The transaction failed on-chain.
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub txid: String,
    pub time_ms: u64,
    pub direction: Direction,
    pub is_approval: bool,
    /// "USDT on TRON (TRC-20)" for the pinned contract; otherwise the token's
    /// own (untrusted) symbol, marked as such.
    pub token_label: String,
    pub genuine_usdt: bool,
    /// Exact decimal string. For unknown tokens it uses the token's own claimed
    /// decimals and must not be trusted.
    pub amount: Option<String>,
    pub counterparty: String,
    pub flags: Vec<Flag>,
    /// Hidden from the main list (still viewable, with a warning).
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletActivity {
    pub wallet_id: WalletId,
    pub network: Network,
    /// The address shown (for a Bitcoin account key: a short description).
    pub address: String,
    pub source: String,
    pub entries: Vec<ActivityEntry>,
    pub hidden_count: usize,
    pub approval_count: usize,
    pub lookalike_count: usize,
    pub unreadable: usize,
    pub notes: Vec<String>,
    /// The account's own transactions (Tronscan's "Transactions" tab).
    pub transactions: Option<TransactionsView>,
    pub transactions_error: Option<String>,
    pub permission_changes: usize,
}

/// True if `a` and `b` are different but share the first `LOOKALIKE_CHARS`
/// characters after `skip` (the fixed network prefix, e.g. "T" or "0x") or the
/// last `LOOKALIKE_CHARS` characters.
pub fn looks_alike(a: &str, b: &str, skip: usize) -> bool {
    if a == b {
        return false;
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let n = LOOKALIKE_CHARS;
    if a.len() < skip + n || b.len() < skip + n {
        return false;
    }
    let head = a[skip..skip + n] == b[skip..skip + n];
    let tail = a[a.len() - n..] == b[b.len() - n..];
    head || tail
}

/// Label for a known address in look-alike warnings.
#[derive(Debug, Clone)]
pub struct KnownAddress {
    pub address: TronAddress,
    pub label: String,
}

fn amount_text(e: &Trc20Event, genuine: bool) -> Option<String> {
    let v = e.value?;
    Some(if genuine {
        Amount::new(Asset::UsdtTrc20, v).to_decimal_string()
    } else {
        format_base_units(v, e.claimed_decimals)
    })
}

/// Classify TRC-20 events for `me`.
///
/// `own` are all of the user's own TRON addresses (every wallet in the
/// registry). `pinned_usdt` comes from the compiled-in config, never from the
/// provider.
pub fn classify_tron(
    me: &TronAddress,
    own: &[KnownAddress],
    pinned_usdt: &TronAddress,
    events: &[Trc20Event],
) -> Vec<ActivityEntry> {
    let known = known_counterparties(me, own, pinned_usdt, events, &[]);
    classify_tron_with_known(me, pinned_usdt, events, &known)
}

/// A known address and how to describe it in a look-alike warning.
pub type Known = (String, String);

/// Reference set for the look-alike check: your own addresses, plus the
/// counterparties of real transfers (genuine USDT >= 1 USDT, TRX >= 1 TRX, and
/// USDT you sent by contract call) in either history list.
pub fn known_counterparties(
    me: &TronAddress,
    own: &[KnownAddress],
    pinned_usdt: &TronAddress,
    events: &[Trc20Event],
    txs: &[TronTx],
) -> Vec<Known> {
    let mut known: Vec<Known> = own
        .iter()
        .map(|k| {
            (
                k.address.to_base58(),
                format!("your wallet \"{}\"", k.label),
            )
        })
        .collect();
    let mut seen = BTreeSet::new();
    for e in events {
        let genuine = e.token == *pinned_usdt;
        let real = genuine
            && e.kind == EventKind::Transfer
            && e.value.is_some_and(|v| v >= DUST_BASE_UNITS);
        if real {
            let other = if e.from == *me { e.to } else { e.from };
            let s = other.to_base58();
            if other != *me && seen.insert(s.clone()) {
                known.push((s, "someone you transacted with".into()));
            }
        }
    }
    for tx in txs.iter().filter(|t| t.success) {
        let other = match &tx.action {
            TxAction::TrxTransfer {
                from,
                to,
                amount_sun,
            } if *amount_sun >= DUST_SUN => Some(if from == me { *to } else { *from }),
            TxAction::ContractCall {
                owner,
                contract,
                call:
                    CallKind::Transfer {
                        to,
                        amount: Some(a),
                    },
                ..
            } if owner == me && contract == pinned_usdt && *a >= DUST_BASE_UNITS => Some(*to),
            _ => None,
        };
        if let Some(o) = other.filter(|o| o != me) {
            let s = o.to_base58();
            if seen.insert(s.clone()) {
                known.push((s, "someone you transacted with".into()));
            }
        }
    }
    known
}

fn lookalike_flag(known: &[Known], cp: &str) -> Option<Flag> {
    known
        .iter()
        .find(|(k, _)| looks_alike(k, cp, 1))
        .map(|(addr, label)| Flag::LookAlike {
            similar_to: addr.clone(),
            similar_to_label: label.clone(),
        })
}

/// Classify TRC-20 events against a precomputed look-alike reference set.
pub fn classify_tron_with_known(
    me: &TronAddress,
    pinned_usdt: &TronAddress,
    events: &[Trc20Event],
    known: &[Known],
) -> Vec<ActivityEntry> {
    events
        .iter()
        .map(|e| {
            let genuine = e.token == *pinned_usdt;
            let direction = match (e.from == *me, e.to == *me) {
                (true, true) => Direction::SelfTransfer,
                (true, false) => Direction::Out,
                (false, true) => Direction::In,
                (false, false) => Direction::NotInvolved,
            };
            let is_approval = e.kind == EventKind::Approval;
            // For an approval, the interesting party is the spender (`to`).
            let counterparty = if is_approval || direction == Direction::Out {
                e.to
            } else {
                e.from
            };
            let cp = counterparty.to_base58();
            let mut flags = Vec::new();

            if !genuine {
                let sym = e.claimed_symbol.to_ascii_uppercase();
                flags.push(if sym.contains("USD") {
                    Flag::FakeToken
                } else {
                    Flag::UnknownToken
                });
            }
            if is_approval && genuine && e.from == *me {
                flags.push(Flag::Approval);
            }
            if e.kind == EventKind::Transfer && genuine {
                match e.value {
                    Some(0) => flags.push(Flag::ZeroValue),
                    Some(v) if v < DUST_BASE_UNITS => flags.push(Flag::Dust {
                        below: "1 USDT".into(),
                    }),
                    _ => {}
                }
            }
            if counterparty != *me {
                flags.extend(lookalike_flag(known, &cp));
            }

            let hidden = !genuine
                || flags
                    .iter()
                    .any(|f| matches!(f, Flag::ZeroValue | Flag::Dust { .. }))
                || (direction == Direction::NotInvolved && !is_approval);

            ActivityEntry {
                txid: e.txid.clone(),
                time_ms: e.timestamp_ms,
                direction,
                is_approval,
                token_label: if genuine {
                    Asset::UsdtTrc20.label().to_owned()
                } else {
                    format!("Unknown token calling itself \"{}\"", e.claimed_symbol)
                },
                genuine_usdt: genuine,
                amount: amount_text(e, genuine),
                counterparty: cp,
                flags,
                // Approvals are never hidden.
                hidden: hidden && !(is_approval && genuine),
            }
        })
        .collect()
}

/// One entry of the account's own transactions (Tronscan's "Transactions").
#[derive(Debug, Clone, Serialize)]
pub struct TxEntry {
    pub txid: String,
    pub time_ms: u64,
    pub success: bool,
    /// What happened, in plain words ("TRX transfer", "USDT approval", …).
    pub action: String,
    pub direction: Direction,
    pub amount: Option<String>,
    pub asset_label: Option<String>,
    pub counterparty: Option<String>,
    pub flags: Vec<Flag>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionsView {
    pub source: String,
    pub entries: Vec<TxEntry>,
    pub hidden_count: usize,
    pub unreadable: usize,
}

fn usdt_amount(a: Option<u128>) -> Option<String> {
    Some(match a {
        Some(v) => Amount::new(Asset::UsdtTrc20, v).to_decimal_string(),
        None => "unlimited".to_owned(),
    })
}

fn trx_amount(sun: u128) -> String {
    Amount::new(Asset::Trx, sun).to_decimal_string()
}

fn dir(from_me: bool, to_me: bool) -> Direction {
    match (from_me, to_me) {
        (true, true) => Direction::SelfTransfer,
        (true, false) => Direction::Out,
        (false, true) => Direction::In,
        (false, false) => Direction::NotInvolved,
    }
}

/// What a transaction did, before flags.
struct Described {
    action: String,
    direction: Direction,
    amount: Option<String>,
    asset_label: Option<String>,
    counterparty: Option<TronAddress>,
}

/// Classify the account's own transactions.
///
/// Rules: anything this address signed is shown; dust and 0-value transfers it
/// received, TRC-10 spam and transactions it isn't part of are hidden;
/// approvals, permission changes and tokens spent by someone else are shown
/// prominently and never hidden.
pub fn classify_tron_transactions(
    me: &TronAddress,
    pinned_usdt: &TronAddress,
    txs: &[TronTx],
    known: &[Known],
) -> Vec<TxEntry> {
    txs.iter()
        .map(|tx| {
            let mut flags = Vec::new();
            let mut hidden = false;
            let mut never_hide = false;
            let d = match &tx.action {
                TxAction::TrxTransfer {
                    from,
                    to,
                    amount_sun,
                } => {
                    let direction = dir(from == me, to == me);
                    if *amount_sun == 0 {
                        flags.push(Flag::ZeroValue);
                    } else if *amount_sun < DUST_SUN && direction == Direction::In {
                        flags.push(Flag::Dust {
                            below: "1 TRX".into(),
                        });
                    }
                    hidden = direction == Direction::NotInvolved
                        || (direction == Direction::In && *amount_sun < DUST_SUN);
                    Described {
                        action: "TRX transfer".into(),
                        direction,
                        amount: Some(trx_amount(*amount_sun)),
                        asset_label: Some(Asset::Trx.label().into()),
                        counterparty: Some(if from == me { *to } else { *from }),
                    }
                }
                TxAction::ContractCall {
                    owner,
                    contract,
                    call,
                    call_value_sun,
                } => {
                    let usdt = contract == pinned_usdt;
                    let mine = owner == me;
                    if !usdt {
                        flags.push(Flag::OtherContract {
                            contract: contract.to_base58(),
                        });
                    }
                    let asset_label = Some(if usdt {
                        Asset::UsdtTrc20.label().to_owned()
                    } else {
                        "Unknown token / contract".to_owned()
                    });
                    let mut d = match call {
                        CallKind::Transfer { to, amount } => Described {
                            action: if usdt {
                                "USDT transfer"
                            } else {
                                "Token transfer"
                            }
                            .into(),
                            direction: dir(mine, to == me),
                            amount: if usdt { usdt_amount(*amount) } else { None },
                            asset_label,
                            counterparty: Some(*to),
                        },
                        CallKind::TransferFrom { from, to, amount } => {
                            if from == me && !mine && usdt {
                                if *amount == Some(0) {
                                    flags.push(Flag::ZeroValue);
                                    hidden = true;
                                } else {
                                    flags.push(Flag::SpentByOther);
                                    never_hide = true;
                                }
                            }
                            Described {
                                action: if usdt {
                                    "USDT transferFrom"
                                } else {
                                    "Token transferFrom"
                                }
                                .into(),
                                direction: dir(from == me, to == me),
                                amount: if usdt { usdt_amount(*amount) } else { None },
                                asset_label,
                                counterparty: Some(*to),
                            }
                        }
                        CallKind::Approve { spender, amount } => {
                            if mine {
                                flags.push(Flag::Approval);
                                never_hide = true;
                            }
                            Described {
                                action: if usdt {
                                    "USDT approval"
                                } else {
                                    "Token approval"
                                }
                                .into(),
                                direction: if mine {
                                    Direction::Out
                                } else {
                                    Direction::NotInvolved
                                },
                                amount: if usdt {
                                    usdt_amount(*amount)
                                } else {
                                    Some(
                                        amount.map_or_else(
                                            || "unlimited".to_owned(),
                                            |a| a.to_string(),
                                        ),
                                    )
                                },
                                asset_label,
                                counterparty: Some(*spender),
                            }
                        }
                        CallKind::Unknown { selector } => {
                            if usdt {
                                flags.push(Flag::OtherContract {
                                    contract: format!("USDT function 0x{selector}"),
                                });
                            }
                            Described {
                                action: "Contract call".into(),
                                direction: if mine {
                                    Direction::Out
                                } else {
                                    Direction::NotInvolved
                                },
                                amount: (*call_value_sun > 0).then(|| trx_amount(*call_value_sun)),
                                asset_label: (*call_value_sun > 0)
                                    .then(|| Asset::Trx.label().into()),
                                counterparty: Some(*contract),
                            }
                        }
                    };
                    if !mine && d.direction == Direction::NotInvolved {
                        hidden = true;
                    }
                    if d.amount.is_none() && *call_value_sun > 0 {
                        d.amount = Some(trx_amount(*call_value_sun));
                    }
                    d
                }
                TxAction::PermissionUpdate { owner } => {
                    if owner == me {
                        flags.push(Flag::PermissionChange);
                        never_hide = true;
                    } else {
                        hidden = true;
                    }
                    Described {
                        action: "Account permissions changed".into(),
                        direction: if owner == me {
                            Direction::Out
                        } else {
                            Direction::NotInvolved
                        },
                        amount: None,
                        asset_label: None,
                        counterparty: None,
                    }
                }
                TxAction::Trc10Transfer { from, to, amount } => {
                    flags.push(Flag::Trc10);
                    hidden = true;
                    Described {
                        action: "TRC-10 token transfer".into(),
                        direction: dir(from == me, to == me),
                        amount: Some(amount.to_string()),
                        asset_label: Some("TRC-10 token (not USDT)".into()),
                        counterparty: Some(if from == me { *to } else { *from }),
                    }
                }
                TxAction::Resource { owner, what } => {
                    hidden = owner != me;
                    Described {
                        action: (*what).into(),
                        direction: if owner == me {
                            Direction::Out
                        } else {
                            Direction::NotInvolved
                        },
                        amount: None,
                        asset_label: None,
                        counterparty: None,
                    }
                }
                TxAction::Other {
                    owner,
                    contract_type,
                } => {
                    let mine = owner.as_ref() == Some(me);
                    hidden = !mine;
                    Described {
                        action: format!("Other: {contract_type}"),
                        direction: if mine {
                            Direction::Out
                        } else {
                            Direction::NotInvolved
                        },
                        amount: None,
                        asset_label: None,
                        counterparty: None,
                    }
                }
            };
            if !tx.success {
                flags.push(Flag::Failed);
            }
            let cp = d.counterparty.filter(|c| c != me).map(|c| c.to_base58());
            if let Some(c) = &cp {
                flags.extend(lookalike_flag(known, c));
            }
            TxEntry {
                txid: tx.txid.clone(),
                time_ms: tx.timestamp_ms,
                success: tx.success,
                action: d.action,
                direction: d.direction,
                amount: d.amount,
                asset_label: d.asset_label,
                counterparty: cp,
                flags,
                hidden: hidden && !never_hide,
            }
        })
        .collect()
}

pub fn transactions_view(
    source: String,
    entries: Vec<TxEntry>,
    unreadable: usize,
) -> TransactionsView {
    let hidden_count = entries.iter().filter(|e| e.hidden).count();
    TransactionsView {
        source,
        entries,
        hidden_count,
        unreadable,
    }
}

impl WalletActivity {
    /// Add the account's transactions (or why they couldn't be loaded) and
    /// fold their warnings into the page-level counters.
    pub fn attach_transactions(&mut self, result: Result<TransactionsView, String>) {
        match result {
            Ok(view) => {
                let count = |pred: fn(&Flag) -> bool| {
                    view.entries
                        .iter()
                        .filter(|e| e.flags.iter().any(pred))
                        .count()
                };
                self.approval_count += count(|f| matches!(f, Flag::Approval | Flag::SpentByOther));
                self.lookalike_count += count(|f| matches!(f, Flag::LookAlike { .. }));
                self.permission_changes = count(|f| matches!(f, Flag::PermissionChange));
                if view.unreadable > 0 {
                    self.notes.push(format!(
                        "{} transactions couldn't be read and were left out.",
                        view.unreadable
                    ));
                }
                self.transactions = Some(view);
            }
            Err(e) => self.transactions_error = Some(e),
        }
    }
}

pub fn summarize(
    wallet_id: WalletId,
    address: &TronAddress,
    source: String,
    entries: Vec<ActivityEntry>,
    unreadable: usize,
) -> WalletActivity {
    summarize_for(
        wallet_id,
        Network::Tron,
        address.to_base58(),
        source,
        entries,
        unreadable,
    )
}

/// Page summary for any network.
pub fn summarize_for(
    wallet_id: WalletId,
    network: Network,
    address: String,
    source: String,
    entries: Vec<ActivityEntry>,
    unreadable: usize,
) -> WalletActivity {
    let hidden_count = entries.iter().filter(|e| e.hidden).count();
    let approval_count = entries
        .iter()
        .filter(|e| {
            e.flags
                .iter()
                .any(|f| matches!(f, Flag::Approval | Flag::SpentByOther))
        })
        .count();
    let lookalike_count = entries
        .iter()
        .filter(|e| e.flags.iter().any(|f| matches!(f, Flag::LookAlike { .. })))
        .count();
    let mut notes = vec![format!(
        "History comes from one provider ({source}) and isn't cross-checked. Use it for information only; balances on the Portfolio page are cross-checked."
    )];
    if unreadable > 0 {
        notes.push(format!(
            "{unreadable} entries from the provider couldn't be read and were left out."
        ));
    }
    WalletActivity {
        wallet_id,
        network,
        address,
        source,
        entries,
        hidden_count,
        approval_count,
        lookalike_count,
        unreadable,
        notes,
        transactions: None,
        transactions_error: None,
        permission_changes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_tron::TronAddress;

    fn addr(seed: u8, tail: Option<[u8; 3]>) -> TronAddress {
        let mut b = [seed; 20];
        if let Some(t) = tail {
            b[17..].copy_from_slice(&t);
        }
        TronAddress::from_hash20(b)
    }

    fn usdt() -> TronAddress {
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("usdt")
    }

    fn ev(
        from: TronAddress,
        to: TronAddress,
        value: u128,
        kind: EventKind,
        token: TronAddress,
        sym: &str,
    ) -> Trc20Event {
        Trc20Event {
            txid: "ab".repeat(32),
            token,
            claimed_symbol: sym.into(),
            claimed_decimals: 6,
            timestamp_ms: 1,
            from,
            to,
            kind,
            value: Some(value),
        }
    }

    #[test]
    fn looks_alike_compares_head_after_prefix_and_tail() {
        assert!(looks_alike(
            "TABCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1",
            "TABCyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy2",
            1
        ));
        assert!(looks_alike(
            "TxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxXYZ",
            "TyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyXYZ",
            1
        ));
        assert!(!looks_alike(
            "TABCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1",
            "TABDyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy2",
            1
        ));
        assert!(
            !looks_alike("Tsame", "Tsame", 1),
            "identical is not a look-alike"
        );
        // The fixed "T" prefix alone doesn't count.
        assert!(!looks_alike(
            "TAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1",
            "TByyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy2",
            1
        ));
    }

    /// Builds a pair of different addresses whose Base58 forms share the last
    /// 3 characters, by searching a small space.
    fn lookalike_pair() -> (TronAddress, TronAddress) {
        let target = addr(9, None);
        let tail: String = target.to_base58().chars().rev().take(3).collect();
        for i in 0u32..2_000_000 {
            let mut b = [7u8; 20];
            b[16..].copy_from_slice(&i.to_be_bytes());
            let cand = TronAddress::from_hash20(b);
            let s: String = cand.to_base58().chars().rev().take(3).collect();
            if s == tail && cand != target {
                return (target, cand);
            }
        }
        panic!("no look-alike found");
    }

    #[test]
    fn poisoning_attempts_are_hidden_and_flagged() {
        let me = addr(1, None);
        let (friend, impostor) = lookalike_pair();
        let fake_token = addr(66, None);
        let events = vec![
            // Real payment to a friend: visible, establishes the friend.
            ev(me, friend, 50_000_000, EventKind::Transfer, usdt(), "USDT"),
            // Attacker's 0-value transferFrom(me → impostor): hidden.
            ev(me, impostor, 0, EventKind::Transfer, usdt(), "USDT"),
            // Attacker's dust from the look-alike: hidden + look-alike.
            ev(impostor, me, 1, EventKind::Transfer, usdt(), "USDT"),
            // Fake "USDT" token: hidden.
            ev(
                impostor,
                me,
                50_000_000,
                EventKind::Transfer,
                fake_token,
                "USDT",
            ),
        ];
        let out = classify_tron(&me, &[], &usdt(), &events);
        assert!(!out[0].hidden && out[0].flags.is_empty(), "{:?}", out[0]);
        assert!(out[1].hidden && out[1].flags.contains(&Flag::ZeroValue));
        assert!(out[1]
            .flags
            .iter()
            .any(|f| matches!(f, Flag::LookAlike { .. })));
        assert!(out[2].hidden && out[2].flags.iter().any(|f| matches!(f, Flag::Dust { .. })));
        assert!(out[2].flags.iter().any(
            |f| matches!(f, Flag::LookAlike { similar_to, .. } if *similar_to == friend.to_base58())
        ));
        assert!(out[3].hidden && out[3].flags.contains(&Flag::FakeToken));
        assert!(!out[3].genuine_usdt);
        assert!(out[3].token_label.contains("Unknown token"));
    }

    #[test]
    fn lookalike_of_own_wallet_is_flagged_even_when_large() {
        let me = addr(1, None);
        let (savings, impostor) = lookalike_pair();
        let own = [KnownAddress {
            address: savings,
            label: "Savings".into(),
        }];
        let events = vec![ev(
            impostor,
            me,
            5_000_000,
            EventKind::Transfer,
            usdt(),
            "USDT",
        )];
        let out = classify_tron(&me, &own, &usdt(), &events);
        assert!(!out[0].hidden, "not dust, so visible…");
        assert!(out[0].flags.iter().any(|f| matches!(f, Flag::LookAlike { similar_to_label, .. } if similar_to_label.contains("Savings"))), "…but warned");
    }

    #[test]
    fn approvals_are_shown_never_hidden() {
        let me = addr(1, None);
        let spender = addr(2, None);
        let mut e = ev(me, spender, 0, EventKind::Approval, usdt(), "USDT");
        e.value = None; // "unlimited" approval
        let out = classify_tron(&me, &[], &usdt(), &[e]);
        assert!(!out[0].hidden);
        assert!(out[0].flags.contains(&Flag::Approval));
        assert_eq!(out[0].counterparty, spender.to_base58());
        let s = summarize("w".parse().expect("id"), &me, "trongrid".into(), out, 0);
        assert_eq!(s.approval_count, 1);
    }

    #[test]
    fn directions() {
        let me = addr(1, None);
        let o = addr(2, None);
        let x = addr(3, None);
        let out = classify_tron(
            &me,
            &[],
            &usdt(),
            &[
                ev(o, me, 2_000_000, EventKind::Transfer, usdt(), "USDT"),
                ev(me, o, 2_000_000, EventKind::Transfer, usdt(), "USDT"),
                ev(me, me, 2_000_000, EventKind::Transfer, usdt(), "USDT"),
                ev(o, x, 2_000_000, EventKind::Transfer, usdt(), "USDT"),
            ],
        );
        let d: Vec<_> = out.iter().map(|e| e.direction).collect();
        assert_eq!(
            d,
            vec![
                Direction::In,
                Direction::Out,
                Direction::SelfTransfer,
                Direction::NotInvolved
            ]
        );
        assert_eq!(out[0].amount.as_deref(), Some("2"));
        assert!(out[3].hidden);
    }

    fn tx(action: TxAction, success: bool) -> TronTx {
        TronTx {
            txid: "cd".repeat(32),
            timestamp_ms: 1,
            success,
            action,
        }
    }

    #[test]
    fn transactions_rules() {
        let me = addr(1, None);
        let (friend, impostor) = lookalike_pair();
        let spender = addr(4, None);
        let other_contract = addr(5, None);
        let txs = vec![
            // 0: I sent 10 TRX to a friend (establishes the friend).
            tx(
                TxAction::TrxTransfer {
                    from: me,
                    to: friend,
                    amount_sun: 10_000_000,
                },
                true,
            ),
            // 1: TRX dust from a look-alike: hidden and flagged.
            tx(
                TxAction::TrxTransfer {
                    from: impostor,
                    to: me,
                    amount_sun: 1,
                },
                true,
            ),
            // 2: I approved a spender for unlimited USDT: never hidden.
            tx(
                TxAction::ContractCall {
                    owner: me,
                    contract: usdt(),
                    call: CallKind::Approve {
                        spender,
                        amount: None,
                    },
                    call_value_sun: 0,
                },
                true,
            ),
            // 3: Permission change on my account: never hidden.
            tx(TxAction::PermissionUpdate { owner: me }, true),
            // 4: Someone else moved my USDT with transferFrom.
            tx(
                TxAction::ContractCall {
                    owner: spender,
                    contract: usdt(),
                    call: CallKind::TransferFrom {
                        from: me,
                        to: spender,
                        amount: Some(5_000_000),
                    },
                    call_value_sun: 0,
                },
                true,
            ),
            // 5: 0-value transferFrom poisoning: hidden.
            tx(
                TxAction::ContractCall {
                    owner: impostor,
                    contract: usdt(),
                    call: CallKind::TransferFrom {
                        from: me,
                        to: impostor,
                        amount: Some(0),
                    },
                    call_value_sun: 0,
                },
                true,
            ),
            // 6: I called some other contract.
            tx(
                TxAction::ContractCall {
                    owner: me,
                    contract: other_contract,
                    call: CallKind::Unknown {
                        selector: "12345678".into(),
                    },
                    call_value_sun: 0,
                },
                true,
            ),
            // 7: Staking: shown, no warning.
            tx(
                TxAction::Resource {
                    owner: me,
                    what: "Stake TRX (freeze)",
                },
                true,
            ),
            // 8: A failed TRX transfer I sent.
            tx(
                TxAction::TrxTransfer {
                    from: me,
                    to: friend,
                    amount_sun: 2_000_000,
                },
                false,
            ),
            // 9: TRC-10 spam: hidden.
            tx(
                TxAction::Trc10Transfer {
                    from: impostor,
                    to: me,
                    amount: 1,
                },
                true,
            ),
        ];
        let known = known_counterparties(&me, &[], &usdt(), &[], &txs);
        assert!(known.iter().any(|(a, _)| *a == friend.to_base58()));
        let out = classify_tron_transactions(&me, &usdt(), &txs, &known);

        assert!(!out[0].hidden && out[0].flags.is_empty(), "{:?}", out[0]);
        assert_eq!(out[0].amount.as_deref(), Some("10"));
        assert!(out[1].hidden && out[1].flags.iter().any(|f| matches!(f, Flag::Dust { .. })));
        assert!(out[1]
            .flags
            .iter()
            .any(|f| matches!(f, Flag::LookAlike { .. })));
        assert!(!out[2].hidden && out[2].flags.contains(&Flag::Approval));
        assert_eq!(out[2].amount.as_deref(), Some("unlimited"));
        assert!(!out[3].hidden && out[3].flags.contains(&Flag::PermissionChange));
        assert!(!out[4].hidden && out[4].flags.contains(&Flag::SpentByOther));
        assert!(out[5].hidden && out[5].flags.contains(&Flag::ZeroValue));
        assert!(
            !out[6].hidden
                && out[6]
                    .flags
                    .iter()
                    .any(|f| matches!(f, Flag::OtherContract { .. }))
        );
        assert!(!out[7].hidden && out[7].flags.is_empty());
        assert!(!out[8].hidden && out[8].flags.contains(&Flag::Failed));
        assert!(out[9].hidden && out[9].flags.contains(&Flag::Trc10));

        let mut page = summarize("w".parse().expect("id"), &me, "trongrid".into(), vec![], 0);
        page.attach_transactions(Ok(transactions_view("trongrid".into(), out, 0)));
        assert_eq!(page.approval_count, 2, "own approval + spent by other");
        assert_eq!(page.permission_changes, 1);
        assert!(page.lookalike_count >= 1);
    }
}
