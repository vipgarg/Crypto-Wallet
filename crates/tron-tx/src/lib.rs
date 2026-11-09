//! TRON TRC-20 USDT transfers (ARCHITECTURE.md §8.3), built **locally**.
//!
//! Node endpoints that build transactions are never used for anything that
//! gets signed. This crate encodes `Transaction.raw` by hand (protobuf
//! wire format, the fields used by a `TriggerSmartContract` call) and
//! decodes it **strictly**: unknown fields, unknown contract types, more than
//! one contract, a memo, or a non-owner permission are rejected.
//!
//! Field numbers follow TRON's `core/Tron.proto` and
//! `core/contract/smart_contract.proto`:
//! - `Transaction.raw`: ref_block_bytes = 1, ref_block_hash = 4,
//!   expiration = 8, data (memo) = 10, contract = 11, timestamp = 14,
//!   fee_limit = 18.
//! - `Transaction.Contract`: type = 1 (TriggerSmartContract = 31),
//!   parameter = 2 (google.protobuf.Any: type_url = 1, value = 2),
//!   Permission_id = 5.
//! - `TriggerSmartContract`: owner_address = 1, contract_address = 2,
//!   call_value = 3, data = 4, call_token_value = 5, token_id = 6.
//! - `Transaction`: raw_data = 1, signature = 2.

use chain_tron::TronAddress;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// TRON Nile **test** USDT contract (TRON wallet-cli token list, "official",
/// 6 decimals). The tablet's test build signs only this contract; the PC's
/// config pins the same value (a test checks they agree).
pub const NILE_USDT: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";

/// `TriggerSmartContract` in TRON's `ContractType` enum.
pub const TRIGGER_SMART_CONTRACT: u64 = 31;
pub const TRIGGER_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";
/// ERC-20/TRC-20 `transfer(address,uint256)` selector.
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxError {
    #[error("malformed transaction data")]
    Malformed,
    #[error("refused: {0}")]
    Refused(String),
}

fn refuse<T>(why: impl Into<String>) -> Result<T, TxError> {
    Err(TxError::Refused(why.into()))
}

/// A TRC-20 `transfer` call, as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trc20Transfer {
    pub ref_block_bytes: [u8; 2],
    pub ref_block_hash: [u8; 8],
    pub expiration_ms: u64,
    pub timestamp_ms: u64,
    /// Maximum TRX (in sun) the transaction may burn for energy.
    pub fee_limit_sun: u64,
    pub owner: TronAddress,
    pub token: TronAddress,
    pub recipient: TronAddress,
    /// Token base units (USDT: 6 decimals).
    pub amount: u128,
}

// ---------------------------------------------------------------------------
// Protobuf wire format (just what's needed)
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_key(out: &mut Vec<u8>, field: u64, wire: u64) {
    put_varint(out, (field << 3) | wire);
}

fn put_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    put_key(out, field, 0);
    put_varint(out, v);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    put_key(out, field, 2);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64, TxError> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos).ok_or(TxError::Malformed)?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(TxError::Malformed)
    }

    /// Next field, or `None` at the end. Only varint and length-delimited
    /// wire types are accepted.
    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, TxError> {
        if self.pos == self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let (field, wire) = (key >> 3, key & 7);
        let value = match wire {
            0 => Value::Varint(self.varint()?),
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| TxError::Malformed)?;
                let end = self.pos.checked_add(len).ok_or(TxError::Malformed)?;
                let b = self.buf.get(self.pos..end).ok_or(TxError::Malformed)?;
                self.pos = end;
                Value::Bytes(b)
            }
            _ => return Err(TxError::Malformed),
        };
        Ok(Some((field, value)))
    }
}

fn bytes(v: Value<'_>) -> Result<&[u8], TxError> {
    match v {
        Value::Bytes(b) => Ok(b),
        Value::Varint(_) => Err(TxError::Malformed),
    }
}

fn uint(v: Value<'_>) -> Result<u64, TxError> {
    match v {
        Value::Varint(n) => Ok(n),
        Value::Bytes(_) => Err(TxError::Malformed),
    }
}

fn address21(b: &[u8]) -> Result<TronAddress, TxError> {
    if b.len() != 21 || b[0] != chain_tron::MAINNET_PREFIX {
        return Err(TxError::Malformed);
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&b[1..]);
    Ok(TronAddress::from_hash20(h))
}

/// `transfer(recipient, amount)` call data: 4 + 32 + 32 = 68 bytes.
pub fn transfer_data(recipient: &TronAddress, amount: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&TRANSFER_SELECTOR);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(recipient.hash20());
    d.extend_from_slice(&[0u8; 16]);
    d.extend_from_slice(&amount.to_be_bytes());
    d
}

/// Read `transfer` call data; exactly 68 bytes, standard address word.
pub fn parse_transfer_data(d: &[u8]) -> Result<(TronAddress, u128), TxError> {
    if d.len() != 68 || d[..4] != TRANSFER_SELECTOR {
        return refuse("the contract call isn't a plain USDT transfer");
    }
    if d[4..16].iter().any(|b| *b != 0) || d[36..52].iter().any(|b| *b != 0) {
        return refuse("the transfer data is malformed");
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&d[16..36]);
    let mut a = [0u8; 16];
    a.copy_from_slice(&d[52..68]);
    Ok((TronAddress::from_hash20(h), u128::from_be_bytes(a)))
}

impl Trc20Transfer {
    /// Encode `Transaction.raw` (the bytes whose SHA-256 is the txID).
    pub fn encode_raw(&self) -> Vec<u8> {
        let mut call = Vec::new();
        put_bytes(&mut call, 1, &self.owner.to_bytes21());
        put_bytes(&mut call, 2, &self.token.to_bytes21());
        put_bytes(&mut call, 4, &transfer_data(&self.recipient, self.amount));
        let mut any = Vec::new();
        put_bytes(&mut any, 1, TRIGGER_TYPE_URL.as_bytes());
        put_bytes(&mut any, 2, &call);
        let mut contract = Vec::new();
        put_uint(&mut contract, 1, TRIGGER_SMART_CONTRACT);
        put_bytes(&mut contract, 2, &any);
        let mut raw = Vec::new();
        put_bytes(&mut raw, 1, &self.ref_block_bytes);
        put_bytes(&mut raw, 4, &self.ref_block_hash);
        put_uint(&mut raw, 8, self.expiration_ms);
        put_bytes(&mut raw, 11, &contract);
        put_uint(&mut raw, 14, self.timestamp_ms);
        put_uint(&mut raw, 18, self.fee_limit_sun);
        raw
    }

    /// Decode `Transaction.raw` strictly (see the module notes).
    pub fn decode_raw(raw: &[u8]) -> Result<Self, TxError> {
        let mut r = Reader::new(raw);
        let (mut rbb, mut rbh, mut exp, mut ts, mut fee, mut contract) =
            (None, None, None, None, None, None);
        while let Some((f, v)) = r.next()? {
            match f {
                1 => rbb = Some(bytes(v)?),
                4 => rbh = Some(bytes(v)?),
                8 => exp = Some(uint(v)?),
                11 => {
                    if contract.is_some() {
                        return refuse("more than one contract call");
                    }
                    contract = Some(bytes(v)?);
                }
                14 => ts = Some(uint(v)?),
                18 => fee = Some(uint(v)?),
                10 => return refuse("the transaction carries a memo"),
                _ => return refuse(format!("unexpected transaction field {f}")),
            }
        }
        let ref_block_bytes: [u8; 2] = rbb
            .and_then(|b| b.try_into().ok())
            .ok_or(TxError::Malformed)?;
        let ref_block_hash: [u8; 8] = rbh
            .and_then(|b| b.try_into().ok())
            .ok_or(TxError::Malformed)?;
        let contract = contract.ok_or_else(|| TxError::Refused("no contract call".into()))?;

        // Transaction.Contract
        let (mut ctype, mut param) = (None, None);
        let mut r = Reader::new(contract);
        while let Some((f, v)) = r.next()? {
            match f {
                1 => ctype = Some(uint(v)?),
                2 => param = Some(bytes(v)?),
                5 => {
                    if uint(v)? != 0 {
                        return refuse("the transaction uses a non-owner permission");
                    }
                }
                _ => return refuse(format!("unexpected contract field {f}")),
            }
        }
        if ctype != Some(TRIGGER_SMART_CONTRACT) {
            return refuse("only a token transfer (TriggerSmartContract) can be signed");
        }
        // google.protobuf.Any
        let (mut url, mut value) = (None, None);
        let mut r = Reader::new(param.ok_or(TxError::Malformed)?);
        while let Some((f, v)) = r.next()? {
            match f {
                1 => url = Some(bytes(v)?),
                2 => value = Some(bytes(v)?),
                _ => return Err(TxError::Malformed),
            }
        }
        if url != Some(TRIGGER_TYPE_URL.as_bytes()) {
            return refuse("unexpected contract type");
        }
        // TriggerSmartContract
        let (mut owner, mut token, mut data) = (None, None, None);
        let mut r = Reader::new(value.ok_or(TxError::Malformed)?);
        while let Some((f, v)) = r.next()? {
            match f {
                1 => owner = Some(address21(bytes(v)?)?),
                2 => token = Some(address21(bytes(v)?)?),
                4 => data = Some(bytes(v)?),
                3 | 5 | 6 => {
                    if uint(v)? != 0 {
                        return refuse("the call also sends TRX or another token");
                    }
                }
                _ => return refuse(format!("unexpected call field {f}")),
            }
        }
        let (recipient, amount) = parse_transfer_data(data.ok_or(TxError::Malformed)?)?;
        Ok(Self {
            ref_block_bytes,
            ref_block_hash,
            expiration_ms: exp.ok_or(TxError::Malformed)?,
            timestamp_ms: ts.ok_or(TxError::Malformed)?,
            fee_limit_sun: fee.ok_or(TxError::Malformed)?,
            owner: owner.ok_or(TxError::Malformed)?,
            token: token.ok_or(TxError::Malformed)?,
            recipient,
            amount,
        })
    }
}

/// Transaction id: SHA-256 of the raw bytes.
pub fn txid(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

/// Sign `raw` with a secp256k1 key: 65 bytes r ‖ s ‖ v (v = 27 + recovery id).
pub fn sign(raw: &[u8], secret: &secp256k1::SecretKey) -> [u8; 65] {
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(txid(raw));
    let (rid, compact) = secp
        .sign_ecdsa_recoverable(&msg, secret)
        .serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&compact);
    out[64] = 27 + rid.to_i32() as u8;
    out
}

/// The address that produced `sig` over `raw`, or an error.
pub fn recover_signer(raw: &[u8], sig: &[u8; 65]) -> Result<TronAddress, TxError> {
    let v = sig[64];
    let rid = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => return Err(TxError::Malformed),
    };
    let rid = RecoveryId::from_i32(i32::from(rid)).map_err(|_| TxError::Malformed)?;
    let rs = RecoverableSignature::from_compact(&sig[..64], rid).map_err(|_| TxError::Malformed)?;
    let secp = Secp256k1::verification_only();
    let pk = secp
        .recover_ecdsa(&Message::from_digest(txid(raw)), &rs)
        .map_err(|_| TxError::Malformed)?;
    Ok(address_of(&pk))
}

/// TRON address of a public key.
pub fn address_of(pk: &secp256k1::PublicKey) -> TronAddress {
    let eth = chain_eth::EthAddress::from_public_key(pk);
    TronAddress::from_eth_address(&eth)
}

/// Full signed `Transaction` protobuf (for `/wallet/broadcasthex`).
pub fn signed_transaction(raw: &[u8], sig: &[u8; 65]) -> Vec<u8> {
    let mut tx = Vec::new();
    put_bytes(&mut tx, 1, raw);
    put_bytes(&mut tx, 2, sig);
    tx
}

/// Reference block fields from a block number and block id (hex, 64 chars):
/// bytes 6..8 of the big-endian number and bytes 8..16 of the id.
pub fn ref_block(number: u64, block_id: &[u8; 32]) -> ([u8; 2], [u8; 8]) {
    let n = number.to_be_bytes();
    let mut h = [0u8; 8];
    h.copy_from_slice(&block_id[8..16]);
    ([n[6], n[7]], h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> TronAddress {
        s.parse().expect("addr")
    }

    fn sample(owner: TronAddress) -> Trc20Transfer {
        Trc20Transfer {
            ref_block_bytes: [0x12, 0x34],
            ref_block_hash: [1, 2, 3, 4, 5, 6, 7, 8],
            expiration_ms: 1_700_000_060_000,
            timestamp_ms: 1_700_000_000_000,
            fee_limit_sun: 30_000_000,
            owner,
            token: addr("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"),
            recipient: addr("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            amount: 1_500_000,
        }
    }

    #[test]
    fn transfer_data_matches_wallet_cli_layout() {
        // From TRON's wallet-cli docs (Nile TransferUSDT example): amount 1
        // to TQwh1ZDBdmMhxRWJzPA7cXuMkFvXjmWXSr (hex 41a5418b8d…21fc).
        let to = TronAddress::from_hex("41a5418b8da12e73075abb46375e7a15c758ea21fc").expect("to");
        let d = transfer_data(&to, 1);
        // wallet-cli writes the 0x41 byte inside the word; we use the
        // standard zero-padded word. Both carry the same last 20 bytes.
        assert_eq!(
            &hex::encode(&d[16..36]),
            "a5418b8da12e73075abb46375e7a15c758ea21fc"
        );
        assert_eq!(parse_transfer_data(&d), Ok((to, 1)));
    }

    #[test]
    fn encode_decode_round_trip_and_sign() {
        let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let pk = sk.public_key(&Secp256k1::new());
        let owner = address_of(&pk);
        let t = sample(owner);
        let raw = t.encode_raw();
        assert_eq!(Trc20Transfer::decode_raw(&raw), Ok(t));
        let sig = sign(&raw, &sk);
        assert_eq!(recover_signer(&raw, &sig), Ok(owner));
        // A different transaction doesn't verify with that signature.
        let mut other = sample(owner);
        other.amount += 1;
        assert_ne!(recover_signer(&other.encode_raw(), &sig), Ok(owner));
        let full = signed_transaction(&raw, &sig);
        assert!(full.len() > raw.len() + 65);
    }

    #[test]
    fn strict_decoding_refuses_extras() {
        let t = sample(addr("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"));
        let raw = t.encode_raw();
        // Memo (field 10).
        let mut m = raw.clone();
        put_bytes(&mut m, 10, b"hi");
        assert!(matches!(
            Trc20Transfer::decode_raw(&m),
            Err(TxError::Refused(_))
        ));
        // A second contract.
        let mut two = raw.clone();
        let mut c = Vec::new();
        put_uint(&mut c, 1, TRIGGER_SMART_CONTRACT);
        put_bytes(&mut two, 11, &c);
        assert!(matches!(
            Trc20Transfer::decode_raw(&two),
            Err(TxError::Refused(_))
        ));
        // Unknown field.
        let mut u = raw.clone();
        put_uint(&mut u, 99, 1);
        assert!(matches!(
            Trc20Transfer::decode_raw(&u),
            Err(TxError::Refused(_))
        ));
        // Truncated.
        assert!(Trc20Transfer::decode_raw(&raw[..raw.len() - 3]).is_err());
        // Non-transfer call data.
        assert!(parse_transfer_data(&[0u8; 68]).is_err());
        assert!(parse_transfer_data(&transfer_data(&t.recipient, 1)[..67]).is_err());
    }

    /// A real Nile USDT transfer from TRON's wallet-cli documentation
    /// (java/docs/commands/usdt.md): signed transaction hex and its TxId.
    const DOC_SIGNED: &str = "0ad4010a0208c72208c02252c2ae3b92e1409fb0b9d9a2335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541caf9798d70a3c609b600f163e53cfe8f586e1b9f121541eca9bc828a3005b9a3b909f2cc5c2a54794de05f2244a9059cbb000000000000000000000041a5418b8da12e73075abb46375e7a15c758ea21fc000000000000000000000000000000000000000000000000000000000000000170938293cfa23390018094ebdc031241a776830e5cd054c6a94631b6d62704e249e7587ab3f036e5e4fac15cbf49e671262532e094e1a32ad858272da3e101958102df61b0f72f26756a94b608883a6f01";
    const DOC_TXID: &str = "9c8d4b84e9a71ccaad86b0a96f790067d3fc7ea85c26b425e5d748b81d31a8b8";

    #[test]
    fn matches_a_real_nile_transaction() {
        let full = hex::decode(DOC_SIGNED).expect("hex");
        // Split the documented Transaction into raw_data (1) and signature (2).
        let mut r = Reader::new(&full);
        let (mut raw, mut sig) = (None, None);
        while let Some((f, v)) = r.next().expect("read") {
            match f {
                1 => raw = Some(bytes(v).expect("raw").to_vec()),
                2 => sig = Some(bytes(v).expect("sig").to_vec()),
                _ => panic!("unexpected field"),
            }
        }
        let (raw, sig) = (raw.expect("raw"), sig.expect("sig"));
        // Our id computation gives TRON's TxId.
        assert_eq!(hex::encode(txid(&raw)), DOC_TXID);
        // Signature recovery gives the documented owner (v = 1 form).
        let sig: [u8; 65] = sig.try_into().expect("65");
        assert_eq!(
            recover_signer(&raw, &sig).map(|a| a.to_base58()),
            Ok("TUUSMd58eC3fKx3fn7whxJyr1FR56tgaP8".to_owned())
        );
        // Our encoder produces the same bytes. (wallet-cli writes the 0x41
        // prefix inside the address word; ours is the standard zero-padded
        // word, so patch that one byte for the comparison.)
        let t = Trc20Transfer {
            ref_block_bytes: [0x08, 0xc7],
            ref_block_hash: [0xc0, 0x22, 0x52, 0xc2, 0xae, 0x3b, 0x92, 0xe1],
            expiration_ms: 1_761_661_048_863,
            timestamp_ms: 1_761_639_448_851,
            fee_limit_sun: 1_000_000_000,
            owner: addr("TUUSMd58eC3fKx3fn7whxJyr1FR56tgaP8"),
            token: addr("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"),
            recipient: TronAddress::from_hex("41a5418b8da12e73075abb46375e7a15c758ea21fc")
                .expect("to"),
            amount: 1,
        };
        let mut ours = t.encode_raw();
        let at = ours
            .windows(4)
            .position(|w| w == TRANSFER_SELECTOR)
            .expect("selector");
        ours[at + 4 + 11] = 0x41;
        assert_eq!(hex::encode(&ours), hex::encode(&raw));
        // And our strict decoder refuses wallet-cli's non-standard word.
        assert!(Trc20Transfer::decode_raw(&raw).is_err());
    }

    #[test]
    fn ref_block_bytes_and_hash() {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (b, h) = ref_block(0x0123_4567, &id);
        assert_eq!(b, [0x45, 0x67]);
        assert_eq!(h, [8, 9, 10, 11, 12, 13, 14, 15]);
    }
}
