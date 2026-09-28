//! Mailbox, record-secret, commit-slot and introduction derivations.
//!
//! The MLS engine makes exactly one exporter call per epoch:
//!
//! ```text
//! epoch_secret = MLS-Exporter(EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH)
//! ```
//!
//! Every per-epoch value is then HKDF-Expand-SHA256 of that secret with a
//! fixed info string, so web and Android derive identical values from one
//! implementation and the vectors need no MLS engine. The info strings end in
//! fixed-length fields only, so no two derivations can share an input.
//!
//! The introduction derivation is the one value that exists before a group:
//! it keys the capability record a joining device seals to the adding
//! person's rendezvous key `rz`. The ECDH itself happens behind the
//! platform's rendezvous callback; this crate receives only its x coordinate.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// The single MLS exporter label VMLS/1 uses.
pub const EXPORTER_LABEL: &str = "VMLS/1 epoch";
/// The exporter context: empty.
pub const EXPORTER_CONTEXT: &[u8] = b"";
/// The exporter output length in bytes.
pub const EXPORTER_LENGTH: usize = 32;

/// HKDF info prefix for a leaf's mailbox; followed by the 32-byte leaf id.
pub const INFO_MAILBOX: &[u8] = b"VMLS/1 mailbox";
/// HKDF info prefix for a leaf's outer-record secret; followed by the leaf id
/// and that leaf's mailbox.
pub const INFO_RECORD: &[u8] = b"VMLS/1 record";
/// HKDF info prefix for one of the epoch's commit slots at the home box;
/// followed by the 4-byte big-endian attempt number.
pub const INFO_COMMIT_SLOT: &[u8] = b"VMLS/1 commit-slot";
/// HKDF info prefix for the outer-record secret of the record deposited at a
/// commit slot; followed by the 32-byte slot.
pub const INFO_SLOT_RECORD: &[u8] = b"VMLS/1 slot record";
/// HKDF info for a record's AEAD key and nonce (salt is the record id).
pub const INFO_RECORD_AEAD: &[u8] = b"VMLS/1 record aead";
/// HKDF-Extract salt for the pairwise introduction secret.
pub const INTRODUCTION_SALT: &[u8] = b"VMLS/1 introduction";
/// HKDF info prefix for an introduction mailbox; followed by the recipient's
/// 32-byte x-only `rz` and an 8-byte big-endian counter.
pub const INFO_INTRODUCTION_MAILBOX: &[u8] = b"VMLS/1 introduction mailbox";
/// HKDF info prefix for an introduction record secret; same suffix.
pub const INFO_INTRODUCTION_RECORD: &[u8] = b"VMLS/1 introduction record";
/// Domain tag for the commit hash a commit slot records.
pub const COMMIT_HASH_TAG: &[u8] = b"VMLS/1 commit";

/// Decision D6: previous epochs whose mailboxes and record secrets are kept.
pub const RETAINED_PAST_EPOCHS: u32 = 2;
/// Decision D6: a retained epoch is deleted when drained or after this long.
pub const RETENTION_SECONDS: u64 = 72 * 3600;

/// AES-128-GCM key bytes for suite 0x0001.
pub const AEAD_KEY_BYTES: usize = 16;
/// AES-128-GCM nonce bytes.
pub const AEAD_NONCE_BYTES: usize = 12;

fn expand(prk: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand_into(prk, parts, &mut out);
    out
}

fn expand_into(prk: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
    // A 32-byte PRK is always long enough and every output here is at most
    // 32 bytes, far below HKDF's 255 * 32 limit, so neither call can fail.
    let hkdf = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK is valid for SHA-256");
    hkdf.expand_multi_info(parts, out)
        .expect("output length is within the HKDF limit");
}

/// The mailbox where `leaf_id` receives records in this epoch.
pub fn mailbox(epoch_secret: &[u8; 32], leaf_id: &[u8; 32]) -> [u8; 32] {
    expand(epoch_secret, &[INFO_MAILBOX, leaf_id])
}

/// The outer-record secret for records to `leaf_id` at `mailbox`.
pub fn record_secret(epoch_secret: &[u8; 32], leaf_id: &[u8; 32], mailbox: &[u8; 32]) -> [u8; 32] {
    expand(epoch_secret, &[INFO_RECORD, leaf_id, mailbox])
}

/// Commit slot number `attempt` of this epoch at the group's home box
/// (decision D4). Attempts are read in order from 0; a void attempt passes
/// the epoch's Commit to the next.
pub fn commit_slot(epoch_secret: &[u8; 32], attempt: u32) -> [u8; 32] {
    expand(epoch_secret, &[INFO_COMMIT_SLOT, &attempt.to_be_bytes()])
}

/// The outer-record secret for the one record deposited at `slot`.
pub fn slot_record_secret(epoch_secret: &[u8; 32], slot: &[u8; 32]) -> [u8; 32] {
    expand(epoch_secret, &[INFO_SLOT_RECORD, slot])
}

/// SHA-256 over the tag and the exact MLS message bytes of a Commit. The
/// box's slot receipt names the hash of the deposited sealed record instead;
/// this one identifies the Commit inside it, for replay state.
pub fn commit_hash(commit_message: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMIT_HASH_TAG)
        .chain_update(commit_message)
        .finalize()
        .into()
}

/// The AES-128-GCM key and nonce for one record.
pub fn record_key_nonce(
    record_secret: &[u8; 32],
    record_id: &[u8; 32],
) -> ([u8; AEAD_KEY_BYTES], [u8; AEAD_NONCE_BYTES]) {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(record_id), record_secret);
    let prk: [u8; 32] = prk.into();
    let mut okm = [0u8; AEAD_KEY_BYTES + AEAD_NONCE_BYTES];
    expand_into(&prk, &[INFO_RECORD_AEAD], &mut okm);
    let mut key = [0u8; AEAD_KEY_BYTES];
    let mut nonce = [0u8; AEAD_NONCE_BYTES];
    key.copy_from_slice(&okm[..AEAD_KEY_BYTES]);
    nonce.copy_from_slice(&okm[AEAD_KEY_BYTES..]);
    (key, nonce)
}

/// One direction and counter of a pairwise introduction.
#[derive(Clone, PartialEq, Eq)]
pub struct Introduction {
    pub mailbox: [u8; 32],
    pub record_secret: [u8; 32],
}

/// The introduction mailbox and record secret for capability record number
/// `counter` sent to the holder of `recipient_rz`. `ecdh_x` is the 32-byte x
/// coordinate of the secp256k1 ECDH between the two people's rendezvous
/// keys, the same value from either side; `recipient_rz` fixes the direction
/// and `counter` makes each capability record's mailbox single-use.
pub fn introduction(ecdh_x: &[u8; 32], recipient_rz: &[u8; 32], counter: u64) -> Introduction {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(INTRODUCTION_SALT), ecdh_x);
    let prk: [u8; 32] = prk.into();
    let counter = counter.to_be_bytes();
    Introduction {
        mailbox: expand(&prk, &[INFO_INTRODUCTION_MAILBOX, recipient_rz, &counter]),
        record_secret: expand(&prk, &[INFO_INTRODUCTION_RECORD, recipient_rz, &counter]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_are_separated_by_input() {
        let secret = [7u8; 32];
        let leaf_a = [1u8; 32];
        let leaf_b = [2u8; 32];
        let mailbox_a = mailbox(&secret, &leaf_a);
        assert_ne!(mailbox_a, mailbox(&secret, &leaf_b));
        assert_ne!(mailbox_a, mailbox(&[8u8; 32], &leaf_a));
        assert_ne!(record_secret(&secret, &leaf_a, &mailbox_a), mailbox_a);
        assert_ne!(commit_slot(&secret, 0), commit_slot(&[8u8; 32], 0));
        assert_ne!(commit_slot(&secret, 0), commit_slot(&secret, 1));
        let slot = commit_slot(&secret, 0);
        assert_ne!(slot_record_secret(&secret, &slot), slot);
        let first = introduction(&[3u8; 32], &[4u8; 32], 0);
        let next = introduction(&[3u8; 32], &[4u8; 32], 1);
        let reverse = introduction(&[3u8; 32], &[5u8; 32], 0);
        assert!(first.mailbox != next.mailbox && first.mailbox != reverse.mailbox);
        assert_ne!(first.mailbox, first.record_secret);
        let (key, nonce) = record_key_nonce(&[9u8; 32], &[0u8; 32]);
        assert_ne!(
            (key, nonce),
            record_key_nonce(&[9u8; 32], &[1u8; 32]),
            "the record id must change the key and nonce"
        );
    }
}
