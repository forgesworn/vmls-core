//! Signed slot receipts and witness receipts (contract §4.2, §5.1).
//!
//! Both are fixed binary layouts signed with plain Ed25519 (RFC 8032, not
//! Ed25519ph) over a 32-byte SHA-256 digest. Verification is strict and only
//! against a key the caller pinned earlier: a receipt never introduces a key.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ErrorCode, MAX_SAFE_INTEGER};

/// The only receipt layout version.
pub const RECEIPT_VERSION: u8 = 1;
/// Bytes in a slot receipt.
pub const SLOT_RECEIPT_BYTES: usize = 165;
/// Bytes in a witness receipt.
pub const WITNESS_RECEIPT_BYTES: usize = 170;
/// Domain tag for the slot receipt digest.
pub const SLOT_RECEIPT_TAG: &[u8] = b"VMLS/1 slot receipt";
/// Domain tag for the witness receipt digest.
pub const WITNESS_RECEIPT_TAG: &[u8] = b"VMLS/1 witness receipt";

/// SHA-256 of the exact deposited envelope bytes.
pub fn envelope_hash(envelope: &[u8]) -> [u8; 32] {
    Sha256::digest(envelope).into()
}

/// The digest the home box signs for one slot attempt.
pub fn slot_digest(slot: &[u8; 32], attempt: u32, envelope_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(SLOT_RECEIPT_TAG)
        .chain_update(slot)
        .chain_update(attempt.to_be_bytes())
        .chain_update(envelope_hash)
        .finalize()
        .into()
}

fn verify(key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> Result<(), ErrorCode> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| ErrorCode::ReceiptSignatureInvalid)?;
    key.verify_strict(digest, &Signature::from_bytes(signature))
        .map_err(|_| ErrorCode::ReceiptSignatureInvalid)
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N]
        .try_into()
        .expect("caller checked the length")
}

/// A home box's signed statement that `envelope_hash` won `slot` at `attempt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotReceipt {
    pub node: [u8; 32],
    pub slot: [u8; 32],
    pub attempt: u32,
    pub envelope_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl SlotReceipt {
    /// Reads the fixed layout. Does not verify the signature.
    pub fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.len() != SLOT_RECEIPT_BYTES {
            return Err(ErrorCode::Malformed);
        }
        if bytes[0] != RECEIPT_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        Ok(Self {
            node: array(bytes, 1),
            slot: array(bytes, 33),
            attempt: u32::from_be_bytes(array(bytes, 65)),
            envelope_hash: array(bytes, 69),
            signature: array(bytes, 101),
        })
    }

    pub fn encode(&self) -> [u8; SLOT_RECEIPT_BYTES] {
        let mut out = [0; SLOT_RECEIPT_BYTES];
        out[0] = RECEIPT_VERSION;
        out[1..33].copy_from_slice(&self.node);
        out[33..65].copy_from_slice(&self.slot);
        out[65..69].copy_from_slice(&self.attempt.to_be_bytes());
        out[69..101].copy_from_slice(&self.envelope_hash);
        out[101..].copy_from_slice(&self.signature);
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        slot_digest(&self.slot, self.attempt, &self.envelope_hash)
    }

    /// Checks the receipt names `pinned_node` and is strictly signed by it.
    pub fn verify(&self, pinned_node: &[u8; 32]) -> Result<(), ErrorCode> {
        if &self.node != pinned_node {
            return Err(ErrorCode::ReceiptWrongNode);
        }
        verify(pinned_node, &self.digest(), &self.signature)
    }

    /// Parses and verifies in one step.
    pub fn verified(bytes: &[u8], pinned_node: &[u8; 32]) -> Result<Self, ErrorCode> {
        let receipt = Self::parse(bytes)?;
        receipt.verify(pinned_node)?;
        Ok(receipt)
    }

    /// True when both receipts describe the same node, slot and attempt.
    pub fn same_position(&self, other: &Self) -> bool {
        self.node == other.node && self.slot == other.slot && self.attempt == other.attempt
    }
}

/// The witness's view of a subject after a read or advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessStatus {
    /// The read succeeded, or the advance committed (HTTP 200).
    Current,
    /// The advance's expectation did not match; this is the current state (409).
    Conflict,
    /// The subject is retired (410).
    Retired,
}

impl WitnessStatus {
    pub const fn value(self) -> u8 {
        match self {
            Self::Current => 0,
            Self::Conflict => 1,
            Self::Retired => 2,
        }
    }

    pub const fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Current),
            1 => Some(Self::Conflict),
            2 => Some(Self::Retired),
            _ => None,
        }
    }
}

/// A witness's signed statement of a subject's sequence and digest,
/// bound to the caller's fresh challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessReceipt {
    pub status: WitnessStatus,
    pub subject: [u8; 32],
    pub seq: u64,
    pub digest: [u8; 32],
    pub challenge: [u8; 32],
    pub signature: [u8; 64],
}

impl WitnessReceipt {
    /// Reads the fixed layout. Does not verify the signature or challenge.
    pub fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.len() != WITNESS_RECEIPT_BYTES {
            return Err(ErrorCode::Malformed);
        }
        if bytes[0] != RECEIPT_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let status = WitnessStatus::from_value(bytes[1]).ok_or(ErrorCode::Malformed)?;
        let seq = u64::from_be_bytes(array(bytes, 34));
        if seq > MAX_SAFE_INTEGER {
            return Err(ErrorCode::Malformed);
        }
        Ok(Self {
            status,
            subject: array(bytes, 2),
            seq,
            digest: array(bytes, 42),
            challenge: array(bytes, 74),
            signature: array(bytes, 106),
        })
    }

    pub fn encode(&self) -> [u8; WITNESS_RECEIPT_BYTES] {
        let mut out = [0; WITNESS_RECEIPT_BYTES];
        out[..106].copy_from_slice(&self.signed_bytes());
        out[106..].copy_from_slice(&self.signature);
        out
    }

    fn signed_bytes(&self) -> [u8; 106] {
        let mut out = [0; 106];
        out[0] = RECEIPT_VERSION;
        out[1] = self.status.value();
        out[2..34].copy_from_slice(&self.subject);
        out[34..42].copy_from_slice(&self.seq.to_be_bytes());
        out[42..74].copy_from_slice(&self.digest);
        out[74..106].copy_from_slice(&self.challenge);
        out
    }

    /// The digest the witness signs.
    pub fn digest_to_sign(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(WITNESS_RECEIPT_TAG)
            .chain_update(self.signed_bytes())
            .finalize()
            .into()
    }

    /// Checks the receipt answers `challenge` and is strictly signed by the
    /// witness key pinned at enrolment. The caller still checks subject and
    /// status against what it asked for.
    pub fn verify(&self, pinned_witness: &[u8; 32], challenge: &[u8; 32]) -> Result<(), ErrorCode> {
        if &self.challenge != challenge {
            return Err(ErrorCode::WitnessChallengeMismatch);
        }
        verify(pinned_witness, &self.digest_to_sign(), &self.signature)
    }

    /// Parses and verifies in one step.
    pub fn verified(
        bytes: &[u8],
        pinned_witness: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Result<Self, ErrorCode> {
        let receipt = Self::parse(bytes)?;
        receipt.verify(pinned_witness, challenge)?;
        Ok(receipt)
    }
}
