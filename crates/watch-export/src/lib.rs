//! Watch-only export: what the signer tablet shows as a QR code so the PC app
//! can add the wallet. Public data only (fingerprint, zpub, addresses).
//!
//! Shared by the tablet (`signer-core`, which encodes) and the PC app
//! (`wallet-core`, which decodes). This crate has no seed or key code.
//!
//! Format: `WWX1:` + compact JSON + `#` + first 8 hex characters of
//! SHA-256(JSON). The checksum catches scanning errors; it is **not** a
//! signature. The PC re-validates every field, and the user confirms the
//! receive addresses on the tablet screen (§7.2) before using them.

use chain_btc::AccountXpub;
use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wallet_types::{Tier, WalletId};

pub const PREFIX: &str = "WWX1:";

/// Longest export accepted (a real one is under 500 characters).
pub const MAX_LEN: usize = 2000;

/// Everything the PC needs to watch a wallet. Public data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPublic {
    /// Master fingerprint (seed + passphrase), 8 hex characters.
    pub fingerprint: String,
    pub btc_zpub: String,
    pub eth: String,
    pub tron: String,
}

/// Re-validate the public data (catches a corrupted or forged record).
pub fn validate(public: &WalletPublic) -> bool {
    public.btc_zpub.starts_with("zpub")
        && public.btc_zpub.parse::<AccountXpub>().is_ok()
        && public.eth.parse::<EthAddress>().is_ok()
        && public.tron.parse::<TronAddress>().is_ok()
        && public.fingerprint.len() == 8
        && public
            .fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchOnlyExport {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    #[serde(flatten)]
    pub public: WalletPublic,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("this isn't a wallet export from the signer")]
    NotAnExport,
    #[error("the export was scanned wrongly (checksum mismatch); scan it again")]
    Checksum,
    #[error("the export contains invalid data")]
    Invalid,
}

fn checksum(json: &str) -> String {
    hex::encode(&Sha256::digest(json.as_bytes())[..4])
}

pub fn encode(e: &WatchOnlyExport) -> Result<String, ExportError> {
    let json = serde_json::to_string(e).map_err(|_| ExportError::Invalid)?;
    Ok(format!("{PREFIX}{json}#{}", checksum(&json)))
}

pub fn decode(s: &str) -> Result<WatchOnlyExport, ExportError> {
    let s = s.trim();
    if s.len() > MAX_LEN {
        return Err(ExportError::NotAnExport);
    }
    let body = s.strip_prefix(PREFIX).ok_or(ExportError::NotAnExport)?;
    let (json, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    if sum != checksum(json) {
        return Err(ExportError::Checksum);
    }
    let e: WatchOnlyExport = serde_json::from_str(json).map_err(|_| ExportError::Invalid)?;
    let label_ok = !e.label.trim().is_empty()
        && e.label.chars().count() <= 40
        && !e.label.chars().any(char::is_control);
    if !label_ok || !validate(&e.public) {
        return Err(ExportError::Invalid);
    }
    Ok(e)
}

/// Test-network export (Phase 2 testing): `WWT1:` + JSON + `#` + checksum.
/// Carries the `m/84'/1'/0'` public key (tpub) used on Bitcoin signet. Kept
/// separate from the mainnet export so a test wallet can never be mistaken
/// for a real one.
pub const TEST_PREFIX: &str = "WWT1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestExport {
    pub id: WalletId,
    pub label: String,
    /// Master fingerprint, 8 lowercase hex characters.
    pub fingerprint: String,
    /// BIP-84 test account public key `m/84'/1'/0'` (tpub).
    pub tpub: String,
}

fn valid_test(e: &TestExport) -> bool {
    let label_ok = !e.label.trim().is_empty()
        && e.label.chars().count() <= 40
        && !e.label.chars().any(char::is_control);
    let fp_ok = e.fingerprint.len() == 8
        && e.fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let key_ok = e
        .tpub
        .parse::<bitcoin::bip32::Xpub>()
        .is_ok_and(|x| x.network == bitcoin::NetworkKind::Test && x.depth == 3);
    label_ok && fp_ok && key_ok
}

pub fn encode_test(e: &TestExport) -> Result<String, ExportError> {
    if !valid_test(e) {
        return Err(ExportError::Invalid);
    }
    let json = serde_json::to_string(e).map_err(|_| ExportError::Invalid)?;
    Ok(format!("{TEST_PREFIX}{json}#{}", checksum(&json)))
}

pub fn decode_test(s: &str) -> Result<TestExport, ExportError> {
    let s = s.trim();
    if s.len() > MAX_LEN {
        return Err(ExportError::NotAnExport);
    }
    let body = s
        .strip_prefix(TEST_PREFIX)
        .ok_or(ExportError::NotAnExport)?;
    let (json, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    if sum != checksum(json) {
        return Err(ExportError::Checksum);
    }
    let e: TestExport = serde_json::from_str(json).map_err(|_| ExportError::Invalid)?;
    if !valid_test(&e) {
        return Err(ExportError::Invalid);
    }
    Ok(e)
}

/// QR envelope for a PSBT going between the PC and the tablet:
/// `WPS1:` + base64(PSBT) + `#` + first 8 hex of SHA-256(PSBT). The
/// checksum catches scanning errors; it is not a signature (the tablet
/// checks the transaction itself, and the PC verifies the signatures).
pub const PSBT_PREFIX: &str = "WPS1:";
/// Largest PSBT carried in one QR code (QR version 40, error correction L,
/// byte mode holds 2,953 bytes; base64 adds a third).
pub const MAX_PSBT_BYTES: usize = 2_100;

pub fn psbt_to_qr(psbt: &[u8]) -> Result<String, ExportError> {
    use base64::Engine;
    if psbt.is_empty() || psbt.len() > MAX_PSBT_BYTES {
        return Err(ExportError::Invalid);
    }
    let sum = hex::encode(&Sha256::digest(psbt)[..4]);
    Ok(format!(
        "{PSBT_PREFIX}{}#{sum}",
        base64::engine::general_purpose::STANDARD.encode(psbt)
    ))
}

pub fn psbt_from_qr(s: &str) -> Result<Vec<u8>, ExportError> {
    use base64::Engine;
    let s = s.trim();
    if s.len() > MAX_LEN * 2 {
        return Err(ExportError::NotAnExport);
    }
    let body = s
        .strip_prefix(PSBT_PREFIX)
        .ok_or(ExportError::NotAnExport)?;
    let (b64, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| ExportError::Checksum)?;
    if bytes.len() > MAX_PSBT_BYTES || hex::encode(&Sha256::digest(&bytes)[..4]) != sum {
        return Err(ExportError::Checksum);
    }
    Ok(bytes)
}

/// TRON payment request from the PC (unsigned `Transaction.raw`).
pub const TRON_REQUEST_PREFIX: &str = "WTR1:";
/// TRON signature from the tablet: 32-byte txid followed by the 65-byte
/// signature.
pub const TRON_SIGNATURE_PREFIX: &str = "WTS1:";
/// Ethereum payment request from the PC (unsigned EIP-1559 transaction).
pub const ETH_REQUEST_PREFIX: &str = "WER1:";
/// Ethereum signature from the tablet: r ‖ s ‖ y_parity (65 bytes), then
/// the signing-log receipt (8-byte number ‖ 32-byte head).
pub const ETH_SIGNATURE_PREFIX: &str = "WES1:";

/// Generic QR envelope: `prefix` + base64(bytes) + `#` + first 8 hex of
/// SHA-256(bytes). The checksum catches scanning errors only.
pub fn bytes_to_qr(prefix: &str, data: &[u8]) -> Result<String, ExportError> {
    use base64::Engine;
    if data.is_empty() || data.len() > MAX_PSBT_BYTES {
        return Err(ExportError::Invalid);
    }
    let sum = hex::encode(&Sha256::digest(data)[..4]);
    Ok(format!(
        "{prefix}{}#{sum}",
        base64::engine::general_purpose::STANDARD.encode(data)
    ))
}

pub fn bytes_from_qr(prefix: &str, s: &str) -> Result<Vec<u8>, ExportError> {
    use base64::Engine;
    let s = s.trim();
    if s.len() > MAX_LEN * 2 {
        return Err(ExportError::NotAnExport);
    }
    let body = s.strip_prefix(prefix).ok_or(ExportError::NotAnExport)?;
    let (b64, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| ExportError::Checksum)?;
    if bytes.len() > MAX_PSBT_BYTES || hex::encode(&Sha256::digest(&bytes)[..4]) != sum {
        return Err(ExportError::Checksum);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made by the tablet code from the public BIP-39 test phrase
    /// "abandon … about" (no passphrase). Test data only.
    const SAMPLE: &str = r#"WWX1:{"id":"test-01","label":"Test spending","tier":"spending","fingerprint":"73c5da0a","btc_zpub":"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs","eth":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","tron":"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"}#55971832"#;

    fn resign(json: &str) -> String {
        format!("{PREFIX}{json}#{}", checksum(json))
    }

    fn json_of(s: &str) -> &str {
        s.strip_prefix(PREFIX)
            .and_then(|b| b.rsplit_once('#'))
            .map(|(j, _)| j)
            .unwrap_or_default()
    }

    #[test]
    fn test_export_round_trip_and_separation() {
        let master = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Test, &[3u8; 64])
            .expect("master");
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let path: bitcoin::bip32::DerivationPath = "m/84'/1'/0'".parse().expect("path");
        let acct = master.derive_priv(&secp, &path).expect("acct");
        let tpub = bitcoin::bip32::Xpub::from_priv(&secp, &acct).to_string();
        let e = TestExport {
            id: "test-01".parse().expect("id"),
            label: "Test".into(),
            fingerprint: master.fingerprint(&secp).to_string(),
            tpub,
        };
        let s = encode_test(&e).expect("encode");
        assert!(s.starts_with(TEST_PREFIX));
        assert_eq!(decode_test(&s), Ok(e.clone()));
        // A test export is never accepted as a mainnet export, and vice versa.
        assert_eq!(decode(&s), Err(ExportError::NotAnExport));
        assert_eq!(decode_test(SAMPLE), Err(ExportError::NotAnExport));
        // A mainnet key in a test export is refused.
        let mut bad = e.clone();
        bad.tpub = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V".into();
        assert_eq!(encode_test(&bad), Err(ExportError::Invalid));
    }

    #[test]
    fn generic_envelope_keeps_prefixes_apart() {
        let qr = bytes_to_qr(TRON_REQUEST_PREFIX, &[1, 2, 3]).expect("qr");
        assert_eq!(bytes_from_qr(TRON_REQUEST_PREFIX, &qr), Ok(vec![1, 2, 3]));
        assert_eq!(
            bytes_from_qr(TRON_SIGNATURE_PREFIX, &qr),
            Err(ExportError::NotAnExport)
        );
        assert_eq!(psbt_from_qr(&qr), Err(ExportError::NotAnExport));
    }

    #[test]
    fn psbt_envelope() {
        let data = vec![0x70, 0x73, 0x62, 0x74, 0xff, 1, 2, 3];
        let qr = psbt_to_qr(&data).expect("qr");
        assert!(qr.starts_with(PSBT_PREFIX));
        assert_eq!(psbt_from_qr(&qr), Ok(data.clone()));
        let damaged = qr.replacen('c', "d", 1);
        assert!(psbt_from_qr(&damaged).is_err());
        assert_eq!(psbt_from_qr(SAMPLE), Err(ExportError::NotAnExport));
        assert!(psbt_to_qr(&vec![0u8; MAX_PSBT_BYTES + 1]).is_err());
    }

    #[test]
    fn decodes_a_tablet_export() {
        let e = decode(&format!("  {SAMPLE}\n")).expect("decode");
        assert_eq!(e.id.as_str(), "test-01");
        assert_eq!(e.tier, Tier::Spending);
        assert_eq!(e.public.fingerprint, "73c5da0a");
        assert_eq!(e.public.eth, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(encode(&e).as_deref(), Ok(SAMPLE), "round trip");
    }

    #[test]
    fn rejects_damage_forgery_and_extras() {
        assert_eq!(decode("hello"), Err(ExportError::NotAnExport));
        assert_eq!(decode(""), Err(ExportError::NotAnExport));
        assert_eq!(
            decode(&format!("{SAMPLE}{}", " ".repeat(MAX_LEN))),
            Ok(decode(SAMPLE).expect("ok")),
            "trailing spaces are trimmed first"
        );
        assert_eq!(
            decode(&format!("{PREFIX}{}", "x".repeat(MAX_LEN))),
            Err(ExportError::NotAnExport)
        );
        assert_eq!(
            decode(&SAMPLE.replacen("spending", "savings", 1)),
            Err(ExportError::Checksum)
        );
        let json = json_of(SAMPLE);
        // Valid checksum, but data that isn't valid public data.
        for bad in [
            json.replacen("0x9858EfFD", "0x9858effd", 1), // checksum case broken
            json.replacen("TUEZ", "TUEz", 1),             // TRON checksum broken
            json.replacen("zpub6rFR", "xpub6rFR", 1),     // not a zpub
            json.replacen("73c5da0a", "73C5DA0A", 1),     // fingerprint must be lowercase hex
            json.replacen("Test spending", "", 1),        // empty label
            json.replacen("Test spending", "a\\u0007b", 1),
            json.replacen("test-01", "Test 01", 1), // invalid id
            json.replacen("\"tier\":\"spending\"", "\"tier\":\"admin\"", 1),
            json.replacen('{', "{\"xprv\":\"x\",", 1), // smuggled field
        ] {
            assert_eq!(decode(&resign(&bad)), Err(ExportError::Invalid), "{bad}");
        }
    }
}
