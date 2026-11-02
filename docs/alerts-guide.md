# Free Email Alerts — Setup Guide

**Purpose:** get an email within minutes whenever one of your addresses sends or receives funds, **even when your PC is off**. In the budget variant this replaces the always-on monitor device for now (ARCHITECTURE-MOBILE.md §6). It's a **detection** control: it can't stop a theft, but it tells you fast so you can follow the incident runbook.

**Status:** guide written 2026-11-02. Services, steps and free-plan limits change; the test in step 6 is what proves an alert actually works.

---

## 1. Before you start: a dedicated alert inbox

Use an email account **only for wallet alerts**, not your everyday inbox.

| Setting | Why |
|---|---|
| New email address used for nothing else | Fewer phishing emails reach it; nobody can link it to your social media |
| Strong unique password + **2FA with an authenticator app or security key** (not SMS) | Someone who takes over this inbox could delete alerts before you see them |
| Phone notifications **on** for this inbox | Alerts are only useful if you see them quickly |
| Filter/label "Wallet alerts" (never auto-archive or auto-delete) | So alerts can't get buried |

## 2. Which addresses to register

Register **public addresses only**, exported from the signer tablet (or from the watch-only app's Wallets page). Never enter a seed phrase, private key, `xprv`, or a zpub/xpub (an xpub reveals all your addresses and full history to the service).

| Wallet | Register |
|---|---|
| Vault and Savings | **Every** address you have ever given out or funded |
| Spending | Its addresses (useful mostly for outgoing alerts) |
| Bitcoin | Each receive address you've used, one by one (the app uses a fresh address per deposit) |

**Labels:** use neutral names like `W1-TRON`, `W2-ETH`. **Never** write tier, amount or purpose ("Savings 40L") in a third-party service.

## 3. Ethereum (ERC-20 USDT and ETH): Etherscan Watch List

Etherscan's watch list emails you about incoming and outgoing transactions for addresses you add, including token transfers. It needs a free account. ([Etherscan: Address Watch List](https://support.etherscan.com/support/solutions/articles/69000793842-address-watch-list))

1. Go to **etherscan.io** (type the address yourself; don't follow links in emails or search ads). Sign up with the alert inbox and confirm the email.
2. Turn on 2FA in the account settings.
3. Open **My Account → Watch List → Add**.
4. Paste the Ethereum address (copy it from the app, then check the first and last 6 characters).
5. Description: a neutral label (`W2-ETH`).
6. Notification: **"Notify on Incoming & Outgoing Txns"**, and enable **token transfers (ERC-20)** so USDT movements are included.
7. Save. Repeat for each Ethereum address.

## 4. TRON (TRC-20 USDT and TRX): Cryptocurrency Alerting "Wallet Watch"

Tronscan's own notifications have been reported as unreliable by at least one user ([tron-watcher project](https://awesome.ecosyste.ms/projects/github.com%2Fcarlosmiei%2Ftron-watcher)), so this guide uses an independent service that supports TRON wallet monitoring with email alerts ([Cryptocurrency Alerting: Tron Wallet Monitoring](https://CryptoCurrencyAlerting.com/guide/tron-monitoring.html)).

1. Go to **cryptocurrencyalerting.com** and sign up with the alert inbox (an email address is all it needs).
2. Create a **Wallet Watch** alert ([Wallet Watch](https://cryptocurrencyalerting.com/wallet-watch.html)): choose **TRON**, paste the TRON address, choose **email** as the channel.
3. If it lets you pick tokens, include **USDT (TRC-20)** as well as TRX.
4. Repeat for each TRON address.

**Free-plan limits:** the free plan caps the number of notifications ([FAQ](https://cryptocurrencyalerting.com/faq.html)). If you hit the cap, alerts stop, so check the plan page and decide whether the small paid plan is worth it for your Vault/Savings addresses. **Optional extra:** also try Tronscan's own watch list with the same inbox, and keep it only if the step 6 test shows it works.

## 5. Bitcoin: Blockonomics Wallet Watcher

Blockonomics' Wallet Watcher tracks Bitcoin addresses and emails you when they change, for up to 20 addresses ([Blockonomics: Wallet Watcher FAQ](https://blockonomics.freshdesk.com/support/solutions/articles/33000248601-wallet-watcher-faq)).

1. Go to **blockonomics.co**, open **Wallet Watcher**, and sign in with the alert inbox (needed for email alerts).
2. Add each Bitcoin **address** (not the zpub), with a neutral label.
3. Turn on email notifications.

Alternative if Blockonomics doesn't suit: Cryptocurrency Alerting's Wallet Watch also covers Bitcoin ([guide](https://cryptocurrencyalerting.com/guide/tracking-bitcoin-transactions.html)).

## 6. Test every alert (required; repeat monthly)

An alert you haven't seen arrive doesn't count.

| Test | How | Pass |
|---|---|---|
| Incoming | Send a small amount to one registered address of each network (e.g. 1 USDT on TRON, a small ETH or USDT amount, a small BTC amount) | Email arrives within **5 minutes** |
| **With the PC switched off** | Do the incoming test while your PC is off (send from an exchange or phone) | Email still arrives (Phase 1 exit gate) |
| Outgoing | When you first send from the Spending wallet | Email arrives within 5 minutes |
| Monthly | Repeat one incoming test on a rotating address | Email arrives |

Record each test in `docs/release-gate.md` (date, network, service, minutes until the email arrived).

## 7. When an alert arrives

1. **Don't click anything in the email.** Alert emails can be faked to lure you to a phishing site. Open the watch-only app or type the explorer address yourself and look the transaction up.
2. **Expected** (you just sent or received it)? Nothing to do.
3. **Unexpected outgoing transaction, token approval, or TRON permission change?** Follow the incident runbook: assume that wallet's seed is compromised and move the remaining funds from the signer tablet to a **new** wallet with a **new** seed. Don't wait to investigate first.
4. **Unexpected incoming dust or 0-value transfer?** That's address poisoning. Ignore it; never copy that address. The app's Activity page hides these.

## 8. Limits of this setup (be aware)

| Limit | Mitigation |
|---|---|
| No "I'm still alive" heartbeat: a service can stop silently (plan change, outage, free cap reached) | Monthly test (step 6); use two services for Vault/Savings addresses where possible |
| Third parties learn which addresses belong to your email | Dedicated inbox, neutral labels, never an xpub |
| Phishing using fake alert emails | Never click links in alerts (step 7) |
| Alerts tell you after the fact | Caps, the signer tablet and the incident runbook limit the damage; act fast |
| Inbox takeover can hide alerts | 2FA with an authenticator app or security key |

**Upgrade path:** the independent monitor device (ARCHITECTURE.md §10.0) adds a daily heartbeat, two channels and checks the explorers don't do (TRON permission objects, token approvals, unknown nonces). Keep these email alerts as an extra layer after that.
