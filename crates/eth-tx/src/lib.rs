//! Ethereum ERC-20 USDT transfers (ARCHITECTURE.md §8.3), built **locally**
//! as EIP-1559 (type 2) transactions and decoded **strictly**.
//!
//! Unsigned form (what the PC sends to the tablet):
//! `0x02 ‖ rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//! gas_limit, to, value, data, access_list])`; its Keccak-256 is the signing
//! hash. Signed form: the same list with `y_parity, r, s` appended; its
//! Keccak-256 is the transaction hash.
//!
//! Decoding refuses anything but canonical RLP: non-minimal integers or
//! lengths, trailing bytes, a non-empty access list, a contract creation,
//! and (for USDT) ETH sent along or call data other than a plain 68-byte
//! `transfer(address,uint256)`.

use chain_eth::{keccak256, EthAddress};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use thiserror::Error;

/// Ethereum Sepolia (test network).
pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
/// Test USDT on Sepolia (Aave V3 Sepolia market, `USDT_UNDERLYING`, 6
/// decimals, from bgd-labs/aave-address-book `AaveV3Sepolia.sol`). The
/// tablet's test build signs only this contract; the PC's config pins the
/// same value (a test checks they agree).
pub const SEPOLIA_USDT: &str = "0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0";
/// ERC-20 `transfer(address,uint256)`.
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TYPE_EIP1559: u8 = 0x02;

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

/// An ERC-20 `transfer` call in an EIP-1559 transaction, as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20Transfer {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub token: EthAddress,
    pub recipient: EthAddress,
    /// Token base units (USDT: 6 decimals).
    pub amount: u128,
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

fn be_trimmed(v: u128) -> Vec<u8> {
    let b = v.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

fn rlp_len_prefix(out: &mut Vec<u8>, len: usize, short: u8, long: u8) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let l = be_trimmed(len as u128);
        out.push(long + l.len() as u8);
        out.extend_from_slice(&l);
    }
}

fn rlp_bytes(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_len_prefix(out, b.len(), 0x80, 0xb7);
        out.extend_from_slice(b);
    }
}

fn rlp_uint(out: &mut Vec<u8>, v: u128) {
    rlp_bytes(out, &be_trimmed(v));
}

fn rlp_list(items: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() + 4);
    rlp_len_prefix(&mut out, items.len(), 0xc0, 0xf7);
    out.extend_from_slice(items);
    out
}

#[derive(Debug, PartialEq, Eq)]
enum Item<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

/// Read one canonical RLP item; returns it and the rest.
fn rlp_item(b: &[u8]) -> Result<(Item<'_>, &[u8]), TxError> {
    let first = *b.first().ok_or(TxError::Malformed)?;
    let long_len = |n: usize| -> Result<(usize, usize), TxError> {
        let lb = b.get(1..1 + n).ok_or(TxError::Malformed)?;
        if lb.first() == Some(&0) || n > 4 {
            return Err(TxError::Malformed);
        }
        let len = lb.iter().fold(0usize, |a, x| (a << 8) | usize::from(*x));
        if len < 56 {
            return Err(TxError::Malformed);
        }
        Ok((1 + n, len))
    };
    let (is_list, start, len) = match first {
        0x00..=0x7f => return Ok((Item::Bytes(&b[..1]), &b[1..])),
        0x80..=0xb7 => (false, 1, usize::from(first - 0x80)),
        0xb8..=0xbf => {
            let (s, l) = long_len(usize::from(first - 0xb7))?;
            (false, s, l)
        }
        0xc0..=0xf7 => (true, 1, usize::from(first - 0xc0)),
        _ => {
            let (s, l) = long_len(usize::from(first - 0xf7))?;
            (true, s, l)
        }
    };
    let end = start.checked_add(len).ok_or(TxError::Malformed)?;
    let body = b.get(start..end).ok_or(TxError::Malformed)?;
    if !is_list && len == 1 && body[0] < 0x80 {
        return Err(TxError::Malformed); // should have been a single byte
    }
    let item = if is_list {
        Item::List(body)
    } else {
        Item::Bytes(body)
    };
    Ok((item, &b[end..]))
}

fn rlp_list_items(body: &[u8]) -> Result<Vec<Item<'_>>, TxError> {
    let mut items = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (i, r) = rlp_item(rest)?;
        items.push(i);
        rest = r;
    }
    Ok(items)
}

fn as_bytes<'a>(i: &Item<'a>) -> Result<&'a [u8], TxError> {
    match i {
        Item::Bytes(b) => Ok(b),
        Item::List(_) => Err(TxError::Malformed),
    }
}

fn as_uint(i: &Item<'_>, max_bytes: usize) -> Result<u128, TxError> {
    let b = as_bytes(i)?;
    if b.len() > max_bytes || b.first() == Some(&0) {
        return Err(TxError::Malformed);
    }
    Ok(b.iter().fold(0u128, |a, x| (a << 8) | u128::from(*x)))
}

fn as_u64(i: &Item<'_>) -> Result<u64, TxError> {
    u64::try_from(as_uint(i, 8)?).map_err(|_| TxError::Malformed)
}

/// `transfer(recipient, amount)` call data: 4 + 32 + 32 = 68 bytes.
pub fn transfer_data(recipient: &EthAddress, amount: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&TRANSFER_SELECTOR);
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(recipient.as_bytes());
    d.extend_from_slice(&[0u8; 16]);
    d.extend_from_slice(&amount.to_be_bytes());
    d
}

/// Read `transfer` call data; exactly 68 bytes, standard words.
pub fn parse_transfer_data(d: &[u8]) -> Result<(EthAddress, u128), TxError> {
    if d.len() != 68 || d[..4] != TRANSFER_SELECTOR {
        return refuse("the contract call isn't a plain USDT transfer");
    }
    if d[4..16].iter().any(|b| *b != 0) || d[36..52].iter().any(|b| *b != 0) {
        return refuse("the transfer data is malformed");
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&d[16..36]);
    let mut v = [0u8; 16];
    v.copy_from_slice(&d[52..68]);
    let to = EthAddress::from_bytes(a).map_err(|_| TxError::Malformed)?;
    Ok((to, u128::from_be_bytes(v)))
}

impl Erc20Transfer {
    fn fields(&self) -> Vec<u8> {
        let mut f = Vec::new();
        rlp_uint(&mut f, u128::from(self.chain_id));
        rlp_uint(&mut f, u128::from(self.nonce));
        rlp_uint(&mut f, self.max_priority_fee_per_gas);
        rlp_uint(&mut f, self.max_fee_per_gas);
        rlp_uint(&mut f, u128::from(self.gas_limit));
        rlp_bytes(&mut f, self.token.as_bytes());
        rlp_uint(&mut f, 0); // value: no ETH sent along
        rlp_bytes(&mut f, &transfer_data(&self.recipient, self.amount));
        f.extend_from_slice(&rlp_list(&[])); // empty access list
        f
    }

    /// The unsigned transaction (`0x02 ‖ rlp(fields)`).
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = vec![TYPE_EIP1559];
        out.extend_from_slice(&rlp_list(&self.fields()));
        out
    }

    /// Decode an unsigned transaction strictly.
    pub fn decode_unsigned(raw: &[u8]) -> Result<Self, TxError> {
        let (&ty, body) = raw.split_first().ok_or(TxError::Malformed)?;
        if ty != TYPE_EIP1559 {
            return refuse("only EIP-1559 (type 2) transactions are signed");
        }
        let (item, rest) = rlp_item(body)?;
        if !rest.is_empty() {
            return Err(TxError::Malformed);
        }
        let Item::List(list) = item else {
            return Err(TxError::Malformed);
        };
        let f = rlp_list_items(list)?;
        if f.len() != 9 {
            return refuse("unexpected transaction fields (a signed transaction, or extra data)");
        }
        let to = as_bytes(&f[5])?;
        if to.is_empty() {
            return refuse("contract creation can't be signed");
        }
        let to: [u8; 20] = to.try_into().map_err(|_| TxError::Malformed)?;
        if as_uint(&f[6], 32)? != 0 {
            return refuse("the transaction also sends ETH");
        }
        match &f[8] {
            Item::List([]) => {}
            _ => return refuse("the transaction carries an access list"),
        }
        let (recipient, amount) = parse_transfer_data(as_bytes(&f[7])?)?;
        Ok(Self {
            chain_id: as_u64(&f[0])?,
            nonce: as_u64(&f[1])?,
            max_priority_fee_per_gas: as_uint(&f[2], 16)?,
            max_fee_per_gas: as_uint(&f[3], 16)?,
            gas_limit: as_u64(&f[4])?,
            token: EthAddress::from_bytes(to).map_err(|_| TxError::Malformed)?,
            recipient,
            amount,
        })
    }

    /// The signed transaction (`0x02 ‖ rlp(fields ‖ y_parity, r, s)`), for
    /// `eth_sendRawTransaction`.
    pub fn encode_signed(&self, sig: &[u8; 65]) -> Vec<u8> {
        let mut f = self.fields();
        rlp_uint(&mut f, u128::from(sig[64]));
        let trim = |b: &[u8]| {
            let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
            b[i..].to_vec()
        };
        rlp_bytes(&mut f, &trim(&sig[..32]));
        rlp_bytes(&mut f, &trim(&sig[32..64]));
        let mut out = vec![TYPE_EIP1559];
        out.extend_from_slice(&rlp_list(&f));
        out
    }
}

/// Signing hash of an unsigned transaction.
pub fn signing_hash(unsigned: &[u8]) -> [u8; 32] {
    keccak256(unsigned)
}

/// Transaction hash of a signed transaction.
pub fn tx_hash(signed: &[u8]) -> [u8; 32] {
    keccak256(signed)
}

/// Sign: 65 bytes r ‖ s ‖ y_parity (0 or 1).
pub fn sign(unsigned: &[u8], secret: &secp256k1::SecretKey) -> [u8; 65] {
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(signing_hash(unsigned));
    let (rid, compact) = secp
        .sign_ecdsa_recoverable(&msg, secret)
        .serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&compact);
    out[64] = rid.to_i32() as u8;
    out
}

/// The address that produced `sig` over `unsigned`.
pub fn recover_signer(unsigned: &[u8], sig: &[u8; 65]) -> Result<EthAddress, TxError> {
    if sig[64] > 1 {
        return Err(TxError::Malformed);
    }
    let rid = RecoveryId::from_i32(i32::from(sig[64])).map_err(|_| TxError::Malformed)?;
    let rs = RecoverableSignature::from_compact(&sig[..64], rid).map_err(|_| TxError::Malformed)?;
    let pk = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(signing_hash(unsigned)), &rs)
        .map_err(|_| TxError::Malformed)?;
    Ok(EthAddress::from_public_key(&pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Erc20Transfer {
        Erc20Transfer {
            chain_id: SEPOLIA_CHAIN_ID,
            nonce: 5,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 65_000,
            token: SEPOLIA_USDT.parse().expect("usdt"),
            recipient: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
                .parse()
                .expect("to"),
            amount: 2_500_000,
        }
    }

    /// Independent vector from the eth-account Python library (0.14):
    /// same transaction, key 0x0707…07 → signing hash, raw signed
    /// transaction and hash.
    #[test]
    fn matches_eth_account_byte_for_byte() {
        let t = sample();
        let unsigned = t.encode_unsigned();
        assert_eq!(
            hex::encode(signing_hash(&unsigned)),
            "8f543c3d0624c2eb353abc54273b77aab3a6ff8bbcb3bcd1fa2731fdb2058838"
        );
        let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let sig = sign(&unsigned, &sk);
        let me = recover_signer(&unsigned, &sig).expect("recover");
        assert_eq!(
            me.to_checksum(),
            "0x4a62316623ad457F02cDC5D997deD67a383EC569"
        );
        let signed = t.encode_signed(&sig);
        assert_eq!(
            hex::encode(&signed),
            "02f8b383aa36a7058459682f008506fc23ac0082fde894aa8e23fb1079ea71e0a56f48a2aa51851d8433d080b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda9400000000000000000000000000000000000000000000000000000000002625a0c001a0fd46627ae89f8e27b4c332bc1a9cde05ba646a946b8f06a09324f268ef5c3ab7a05054845e377a4d26fdea6813d612f92b4512a40b8058c62f08fd94c1c8bf4025"
        );
        assert_eq!(
            hex::encode(tx_hash(&signed)),
            "4d6785ee50ec65bc343ee7f2c8b075761ec09dea5b814a62f22acef7aec3198a"
        );
        assert_eq!(Erc20Transfer::decode_unsigned(&unsigned), Ok(t));
    }

    #[test]
    fn strict_decoding() {
        let t = sample();
        let u = t.encode_unsigned();
        // Trailing byte, truncated, wrong type, signed form given as unsigned.
        let mut x = u.clone();
        x.push(0);
        assert!(Erc20Transfer::decode_unsigned(&x).is_err());
        assert!(Erc20Transfer::decode_unsigned(&u[..u.len() - 1]).is_err());
        let mut y = u.clone();
        y[0] = 0x01;
        assert!(Erc20Transfer::decode_unsigned(&y).is_err());
        let signed = t.encode_signed(&[1u8; 65]);
        assert!(Erc20Transfer::decode_unsigned(&signed).is_err());
        // Non-minimal integer (nonce 5 written as 0x8105).
        let mut f = Vec::new();
        rlp_uint(&mut f, u128::from(t.chain_id));
        f.extend_from_slice(&[0x81, 0x05]);
        let rest = &t.fields()[f.len() - 1..];
        f.extend_from_slice(rest);
        let mut bad = vec![2u8];
        bad.extend_from_slice(&rlp_list(&f));
        assert!(Erc20Transfer::decode_unsigned(&bad).is_err());
        // ETH sent along, an access list, other call data.
        let build = |value: u128, data: &[u8], access: &[u8]| {
            let mut f = Vec::new();
            for v in [u128::from(t.chain_id), 5, 1, 2, 65_000] {
                rlp_uint(&mut f, v);
            }
            rlp_bytes(&mut f, t.token.as_bytes());
            rlp_uint(&mut f, value);
            rlp_bytes(&mut f, data);
            f.extend_from_slice(&rlp_list(access));
            let mut out = vec![2u8];
            out.extend_from_slice(&rlp_list(&f));
            out
        };
        let good = transfer_data(&t.recipient, 1);
        assert!(Erc20Transfer::decode_unsigned(&build(0, &good, &[])).is_ok());
        assert!(Erc20Transfer::decode_unsigned(&build(1, &good, &[])).is_err());
        assert!(Erc20Transfer::decode_unsigned(&build(0, &good, &[0xc0])).is_err());
        let mut approve = good.clone();
        approve[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
        assert!(Erc20Transfer::decode_unsigned(&build(0, &approve, &[])).is_err());
    }
}
