//! The fork-evidence payload carried by record type 5 (contract §5.2, §5.3).
//!
//! ```text
//! 01 || pre_epoch:u64be || count:u8 || receipt[165] * count
//! ```
//!
//! One receipt reports an observation; two are a candidate equivocation
//! proof. The epoch label is unsigned: it never associates an unrelated slot
//! with a session, which is the engine's job.

use crate::ErrorCode;
use crate::receipt::{SLOT_RECEIPT_BYTES, SlotReceipt};

/// The only evidence payload version.
pub const EVIDENCE_VERSION: u8 = 1;
const HEADER_BYTES: usize = 10;
/// Payload length with one receipt.
pub const ONE_RECEIPT_BYTES: usize = HEADER_BYTES + SLOT_RECEIPT_BYTES;
/// Payload length with two receipts.
pub const TWO_RECEIPT_BYTES: usize = HEADER_BYTES + 2 * SLOT_RECEIPT_BYTES;

/// A decoded evidence payload. A pair is always the same node, slot and
/// attempt with distinct envelope hashes in ascending order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkEvidence {
    Observation {
        pre_epoch: u64,
        receipt: SlotReceipt,
    },
    Equivocation {
        pre_epoch: u64,
        first: SlotReceipt,
        second: SlotReceipt,
    },
}

impl ForkEvidence {
    /// Builds a pair in canonical order, refusing anything that is not one
    /// node's two different winners for the same slot and attempt.
    pub fn equivocation(pre_epoch: u64, a: SlotReceipt, b: SlotReceipt) -> Result<Self, ErrorCode> {
        let (first, second) = if a.envelope_hash <= b.envelope_hash {
            (a, b)
        } else {
            (b, a)
        };
        check_pair(&first, &second)?;
        Ok(Self::Equivocation {
            pre_epoch,
            first,
            second,
        })
    }

    /// Reads the fixed layout and the pair rules. Does not verify signatures.
    pub fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.len() < HEADER_BYTES {
            return Err(ErrorCode::Malformed);
        }
        if bytes[0] != EVIDENCE_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let pre_epoch = u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes"));
        match (bytes[9], bytes.len()) {
            (1, ONE_RECEIPT_BYTES) => Ok(Self::Observation {
                pre_epoch,
                receipt: SlotReceipt::parse(&bytes[HEADER_BYTES..])?,
            }),
            (2, TWO_RECEIPT_BYTES) => {
                let first = SlotReceipt::parse(&bytes[HEADER_BYTES..ONE_RECEIPT_BYTES])?;
                let second = SlotReceipt::parse(&bytes[ONE_RECEIPT_BYTES..])?;
                check_pair(&first, &second)?;
                Ok(Self::Equivocation {
                    pre_epoch,
                    first,
                    second,
                })
            }
            _ => Err(ErrorCode::Malformed),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TWO_RECEIPT_BYTES);
        out.push(EVIDENCE_VERSION);
        out.extend_from_slice(&self.pre_epoch().to_be_bytes());
        match self {
            Self::Observation { receipt, .. } => {
                out.push(1);
                out.extend_from_slice(&receipt.encode());
            }
            Self::Equivocation { first, second, .. } => {
                out.push(2);
                out.extend_from_slice(&first.encode());
                out.extend_from_slice(&second.encode());
            }
        }
        out
    }

    pub fn pre_epoch(&self) -> u64 {
        match self {
            Self::Observation { pre_epoch, .. } | Self::Equivocation { pre_epoch, .. } => {
                *pre_epoch
            }
        }
    }

    /// Verifies every receipt strictly against the pinned home box. A
    /// verified `Equivocation` is portable proof; whether it concerns this
    /// session is decided by the engine's own receipt-to-epoch association.
    pub fn verify(&self, pinned_node: &[u8; 32]) -> Result<(), ErrorCode> {
        match self {
            Self::Observation { receipt, .. } => receipt.verify(pinned_node),
            Self::Equivocation { first, second, .. } => {
                first.verify(pinned_node)?;
                second.verify(pinned_node)
            }
        }
    }
}

fn check_pair(first: &SlotReceipt, second: &SlotReceipt) -> Result<(), ErrorCode> {
    if !first.same_position(second) || first.envelope_hash >= second.envelope_hash {
        return Err(ErrorCode::EvidenceNotEquivocation);
    }
    Ok(())
}
