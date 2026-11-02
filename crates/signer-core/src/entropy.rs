//! Seed entropy = SHA-256(domain ‖ 32 bytes from the OS ‖ dice rolls).
//!
//! A weak OS random generator alone, or a biased/predictable set of dice
//! alone, can't weaken the result: each input on its own already carries
//! enough unpredictability (32 random bytes; 99 rolls of a fair die ≈ 256
//! bits). The dice also let you know the seed doesn't come only from the
//! device.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// 99 rolls of a six-sided die ≈ 256 bits.
pub const MIN_DICE_ROLLS: usize = 99;
const DOMAIN: &[u8] = b"crypto-wallet/signer/seed-entropy/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiceError {
    #[error("enter at least {MIN_DICE_ROLLS} dice rolls (you entered {0})")]
    TooFew(usize),
    #[error("dice rolls must be the digits 1 to 6 only")]
    BadDigit,
    #[error("those rolls don't look random (one number is more than half of all rolls)")]
    NotRandom,
}

/// Parse dice rolls typed as digits 1-6 (spaces and line breaks allowed).
pub fn parse_dice(input: &str) -> Result<Zeroizing<Vec<u8>>, DiceError> {
    let mut rolls = Zeroizing::new(Vec::with_capacity(input.len()));
    for c in input.chars().filter(|c| !c.is_whitespace()) {
        match c {
            '1'..='6' => rolls.push(c as u8 - b'0'),
            _ => return Err(DiceError::BadDigit),
        }
    }
    if rolls.len() < MIN_DICE_ROLLS {
        return Err(DiceError::TooFew(rolls.len()));
    }
    // Catch obvious mistakes like "111111…" (not a proof of randomness).
    let mut counts = [0usize; 7];
    for r in rolls.iter() {
        counts[usize::from(*r)] += 1;
    }
    if counts.iter().any(|c| *c * 2 > rolls.len()) {
        return Err(DiceError::NotRandom);
    }
    Ok(rolls)
}

/// Mix 32 bytes of OS randomness with the dice rolls into 32 bytes of entropy.
pub fn mix(os_random: &[u8; 32], dice: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(os_random);
    h.update((dice.len() as u64).to_be_bytes());
    h.update(dice);
    Zeroizing::new(h.finalize().into())
}

/// Fresh entropy from the OS generator mixed with the dice.
pub fn new_entropy(dice: &[u8]) -> Result<Zeroizing<[u8; 32]>, getrandom::Error> {
    let mut os = Zeroizing::new([0u8; 32]);
    auth::random_bytes(os.as_mut())?;
    Ok(mix(&os, dice))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rolls(n: usize) -> String {
        (0..n)
            .map(|i| char::from(b'1' + (i * 7 % 6) as u8))
            .collect()
    }

    #[test]
    fn dice_parsing() {
        assert!(parse_dice(&rolls(99)).is_ok());
        assert_eq!(
            parse_dice(&rolls(98)).map(|_| ()),
            Err(DiceError::TooFew(98))
        );
        assert_eq!(
            parse_dice(&format!("{}7", rolls(99))).map(|_| ()),
            Err(DiceError::BadDigit)
        );
        assert_eq!(
            parse_dice(&"1".repeat(120)).map(|_| ()),
            Err(DiceError::NotRandom)
        );
        let spaced = rolls(99)
            .chars()
            .map(|c| format!("{c} "))
            .collect::<String>();
        assert!(parse_dice(&spaced).is_ok());
    }

    #[test]
    fn mixing_depends_on_both_inputs() {
        let d1 = parse_dice(&rolls(99)).expect("d1");
        let mut d2 = d1.clone();
        d2[0] = if d2[0] == 1 { 2 } else { 1 };
        let a = mix(&[0u8; 32], &d1);
        assert_eq!(*a, *mix(&[0u8; 32], &d1), "deterministic");
        assert_ne!(*a, *mix(&[1u8; 32], &d1), "OS randomness matters");
        assert_ne!(*a, *mix(&[0u8; 32], &d2), "every roll matters");
        assert_ne!(
            *new_entropy(&d1).expect("e1"),
            *new_entropy(&d1).expect("e2")
        );
    }
}
