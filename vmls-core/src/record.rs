//! The inner record carried as the envelope's opaque ciphertext (key `3`).
//!
//! ```text
//! sealed    = record_id[32] || AES-128-GCM(key, nonce, aad, padded)
//! key,nonce = HKDF-SHA256(salt = record_id, ikm = record_secret,
//!                         info = "VMLS/1 record aead", L = 28)
//! aad       = "VMLS/1 record" || mailbox[32] || record_id[32]
//! padded    = canonical CBOR {1: type, 2: payload} || zero bytes
//! ```
//!
//! `len(sealed)` is exactly one of `BUCKETS`, the smallest that fits, so a
//! box sees one of five lengths and cannot tell a Commit from chat. The
//! record type, and everything MLS, is inside the AEAD.
//!
//! Every failure to open a record is a [`SilentDrop`]: it is not shown, not
//! counted and never escalates to needs-recovery, because anyone who holds a
//! mailbox value can produce one.

use crate::cbor::{self, Reader};
use crate::derive::{self, AEAD_KEY_BYTES, AEAD_NONCE_BYTES};
use crate::{ErrorCode, MAILBOX_CAPABILITY_BYTES};

/// Bytes in a record id. The sender draws it from the platform CSPRNG.
pub const RECORD_ID_BYTES: usize = 32;
/// AES-128-GCM tag bytes.
pub const AEAD_TAG_BYTES: usize = 16;
/// Sealed-record lengths a box can see: 1 KiB, 4 KiB, 16 KiB, 64 KiB, 1 MiB.
/// The largest equals the envelope's ciphertext ceiling.
pub const BUCKETS: [usize; 5] = [1024, 4096, 16_384, 65_536, 1_048_576];
/// Sealed bytes that are not padded plaintext.
pub const RECORD_OVERHEAD: usize = RECORD_ID_BYTES + AEAD_TAG_BYTES;
/// The associated-data prefix. The mailbox and record id follow it.
pub const AAD_TAG: &[u8] = b"VMLS/1 record";

const PLAINTEXT_KEYS: u64 = 2;
const KEY_TYPE: u64 = 1;
const KEY_PAYLOAD: u64 = 2;
/// `a2 01 <type> 02` before the payload's byte-string head.
const PLAINTEXT_PREFIX: usize = 4;

/// The largest payload the largest bucket can carry.
pub const MAX_PAYLOAD_BYTES: usize =
    BUCKETS[BUCKETS.len() - 1] - RECORD_OVERHEAD - PLAINTEXT_PREFIX - 5;

/// What the record carries, inside the AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// An MLS `PrivateMessage` that is not a Commit: an application message
    /// or a proposal, sent to a leaf mailbox.
    MlsMessage,
    /// A Welcome, sealed a second time to the capability's welcome transport.
    Welcome,
    /// A `capability/1` record, sent to an introduction mailbox.
    Capability,
    /// An MLS `PrivateMessage` carrying a Commit, deposited at a commit slot.
    Commit,
}

/// Where a record was fetched from. Each kind of mailbox carries exactly one
/// record type; any other type found there is a silent drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxKind {
    /// A leaf's mailbox in the current or a retained past epoch.
    Leaf,
    /// One attempt of an epoch's commit slot at the home box.
    CommitSlot,
    /// A capability's single-use `welcome_mailbox`.
    Welcome,
    /// A pairwise introduction mailbox.
    Introduction,
}

impl MailboxKind {
    /// The one record type this kind of mailbox carries.
    pub const fn record_type(self) -> RecordType {
        match self {
            Self::Leaf => RecordType::MlsMessage,
            Self::CommitSlot => RecordType::Commit,
            Self::Welcome => RecordType::Welcome,
            Self::Introduction => RecordType::Capability,
        }
    }
}

impl RecordType {
    pub const fn value(self) -> u8 {
        match self {
            Self::MlsMessage => 1,
            Self::Welcome => 2,
            Self::Capability => 3,
            Self::Commit => 4,
        }
    }

    pub const fn from_value(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::MlsMessage),
            2 => Some(Self::Welcome),
            3 => Some(Self::Capability),
            4 => Some(Self::Commit),
            _ => None,
        }
    }
}

/// The plaintext content of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerRecord {
    pub record_type: RecordType,
    pub payload: Vec<u8>,
}

/// An opened record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub record_id: [u8; RECORD_ID_BYTES],
    pub record: InnerRecord,
}

/// A record that did not open. The only permitted response is to discard it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SilentDrop(pub ErrorCode);

/// The MLS suite's AEAD, supplied by the caller (AES-128-GCM for 0x0001).
///
/// `seal` returns ciphertext followed by the 16-byte tag; `open` takes the
/// same and returns the plaintext, or `None` on any authentication failure.
pub trait RecordAead {
    fn seal(
        &self,
        key: &[u8; AEAD_KEY_BYTES],
        nonce: &[u8; AEAD_NONCE_BYTES],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>>;

    fn open(
        &self,
        key: &[u8; AEAD_KEY_BYTES],
        nonce: &[u8; AEAD_NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>>;
}

/// The smallest bucket whose plaintext capacity holds `content_len` bytes.
pub fn bucket_for(content_len: usize) -> Option<usize> {
    BUCKETS
        .into_iter()
        .find(|bucket| content_len <= bucket - RECORD_OVERHEAD)
}

/// The associated data for a record.
pub fn aad(mailbox: &[u8; MAILBOX_CAPABILITY_BYTES], record_id: &[u8; RECORD_ID_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_TAG.len() + MAILBOX_CAPABILITY_BYTES + RECORD_ID_BYTES);
    out.extend_from_slice(AAD_TAG);
    out.extend_from_slice(mailbox);
    out.extend_from_slice(record_id);
    out
}

/// Writes the padded plaintext: canonical CBOR, then zeros to the bucket.
pub fn encode_plaintext(record: &InnerRecord) -> Result<Vec<u8>, ErrorCode> {
    if record.payload.is_empty() {
        return Err(ErrorCode::Empty);
    }
    if record.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ErrorCode::TooLarge);
    }
    let content_len =
        PLAINTEXT_PREFIX + cbor::bytes_head_len(record.payload.len()) + record.payload.len();
    let bucket = bucket_for(content_len).ok_or(ErrorCode::TooLarge)?;
    let mut out = Vec::with_capacity(bucket - RECORD_OVERHEAD);
    cbor::write_map(&mut out, PLAINTEXT_KEYS);
    cbor::write_uint(&mut out, KEY_TYPE);
    cbor::write_uint(&mut out, u64::from(record.record_type.value()));
    cbor::write_uint(&mut out, KEY_PAYLOAD);
    cbor::write_bytes(&mut out, &record.payload);
    debug_assert_eq!(out.len(), content_len);
    out.resize(bucket - RECORD_OVERHEAD, 0);
    Ok(out)
}

/// Reads a padded plaintext and refuses any other padding or bucket choice.
pub fn decode_plaintext(padded: &[u8]) -> Result<InnerRecord, ErrorCode> {
    if !BUCKETS
        .into_iter()
        .any(|bucket| padded.len() == bucket - RECORD_OVERHEAD)
    {
        return Err(ErrorCode::BadRecordLength);
    }
    let mut reader = Reader::new(padded);
    reader.map(PLAINTEXT_KEYS)?;
    reader.key(KEY_TYPE)?;
    let record_type = reader.uint()?;
    reader.key(KEY_PAYLOAD)?;
    let payload = reader.bytes(MAX_PAYLOAD_BYTES)?;
    let content_len = reader.position();
    let record_type =
        RecordType::from_value(record_type).ok_or(ErrorCode::UnsupportedRecordType)?;
    if payload.is_empty() {
        return Err(ErrorCode::Empty);
    }
    if bucket_for(content_len) != Some(padded.len() + RECORD_OVERHEAD)
        || padded[content_len..].iter().any(|byte| *byte != 0)
    {
        return Err(ErrorCode::BadPadding);
    }
    Ok(InnerRecord {
        record_type,
        payload: payload.to_vec(),
    })
}

/// Seals `record` for the holder of `record_secret` at `mailbox`.
pub fn seal(
    aead: &impl RecordAead,
    record_secret: &[u8; 32],
    mailbox: &[u8; MAILBOX_CAPABILITY_BYTES],
    record_id: &[u8; RECORD_ID_BYTES],
    record: &InnerRecord,
) -> Result<Vec<u8>, ErrorCode> {
    let padded = encode_plaintext(record)?;
    let (key, nonce) = derive::record_key_nonce(record_secret, record_id);
    let ciphertext = aead
        .seal(&key, &nonce, &aad(mailbox, record_id), &padded)
        .ok_or(ErrorCode::AeadUnavailable)?;
    if ciphertext.len() != padded.len() + AEAD_TAG_BYTES {
        return Err(ErrorCode::AeadUnavailable);
    }
    let mut out = Vec::with_capacity(RECORD_ID_BYTES + ciphertext.len());
    out.extend_from_slice(record_id);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a sealed record fetched from a mailbox of `kind`. Every failure,
/// including a record type that does not belong on that kind of mailbox, is
/// a [`SilentDrop`].
///
/// A record id is bound to one sealed byte string: a sender that retries
/// resends the bytes it stored, never a fresh seal under the same id, and a
/// receiver adds an id to its replay state only after this returns `Ok`.
pub fn open(
    aead: &impl RecordAead,
    record_secret: &[u8; 32],
    mailbox: &[u8; MAILBOX_CAPABILITY_BYTES],
    sealed: &[u8],
    kind: MailboxKind,
) -> Result<Opened, SilentDrop> {
    if !BUCKETS.contains(&sealed.len()) {
        return Err(SilentDrop(ErrorCode::BadRecordLength));
    }
    let (record_id, ciphertext) = sealed.split_at(RECORD_ID_BYTES);
    let record_id: [u8; RECORD_ID_BYTES] = record_id
        .try_into()
        .map_err(|_| SilentDrop(ErrorCode::Malformed))?;
    let (key, nonce) = derive::record_key_nonce(record_secret, &record_id);
    let padded = aead
        .open(&key, &nonce, &aad(mailbox, &record_id), ciphertext)
        .ok_or(SilentDrop(ErrorCode::OuterSealFailed))?;
    if padded.len() + RECORD_OVERHEAD != sealed.len() {
        return Err(SilentDrop(ErrorCode::OuterSealFailed));
    }
    let record = decode_plaintext(&padded).map_err(SilentDrop)?;
    if record.record_type != kind.record_type() {
        return Err(SilentDrop(ErrorCode::UnexpectedRecordType));
    }
    Ok(Opened { record_id, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Nonce};

    pub(crate) struct TestAead;

    impl RecordAead for TestAead {
        fn seal(
            &self,
            key: &[u8; 16],
            nonce: &[u8; 12],
            aad: &[u8],
            msg: &[u8],
        ) -> Option<Vec<u8>> {
            Aes128Gcm::new(key.into())
                .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
                .ok()
        }

        fn open(
            &self,
            key: &[u8; 16],
            nonce: &[u8; 12],
            aad: &[u8],
            msg: &[u8],
        ) -> Option<Vec<u8>> {
            Aes128Gcm::new(key.into())
                .decrypt(Nonce::from_slice(nonce), Payload { msg, aad })
                .ok()
        }
    }

    const SECRET: [u8; 32] = [0x11; 32];
    const MAILBOX: [u8; 32] = [0x22; 32];
    const RECORD_ID: [u8; 32] = [0x33; 32];

    fn record(len: usize) -> InnerRecord {
        InnerRecord {
            record_type: RecordType::MlsMessage,
            payload: vec![0xa5; len],
        }
    }

    fn lcg(state: &mut u32) -> u8 {
        *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (*state >> 24) as u8
    }

    #[test]
    fn every_bucket_boundary_round_trips_at_its_own_size() {
        for bucket in BUCKETS {
            let capacity = bucket - RECORD_OVERHEAD - PLAINTEXT_PREFIX;
            let largest = capacity - cbor::bytes_head_len(capacity);
            // Walk down to the first payload whose head fits.
            let largest = (1..=largest)
                .rev()
                .find(|len| {
                    PLAINTEXT_PREFIX + cbor::bytes_head_len(*len) + len <= bucket - RECORD_OVERHEAD
                })
                .unwrap();
            for len in [largest, largest.saturating_sub(1).max(1)] {
                let sealed = seal(&TestAead, &SECRET, &MAILBOX, &RECORD_ID, &record(len)).unwrap();
                assert_eq!(sealed.len(), bucket);
                let opened =
                    open(&TestAead, &SECRET, &MAILBOX, &sealed, MailboxKind::Leaf).unwrap();
                assert_eq!(opened.record, record(len));
                assert_eq!(opened.record_id, RECORD_ID);
            }
            if bucket != BUCKETS[BUCKETS.len() - 1] {
                let sealed = seal(
                    &TestAead,
                    &SECRET,
                    &MAILBOX,
                    &RECORD_ID,
                    &record(largest + 1),
                )
                .unwrap();
                assert!(
                    sealed.len() > bucket,
                    "one byte more moves to the next bucket"
                );
            }
        }
        assert_eq!(
            encode_plaintext(&record(MAX_PAYLOAD_BYTES + 1)),
            Err(ErrorCode::TooLarge)
        );
        assert_eq!(encode_plaintext(&record(0)), Err(ErrorCode::Empty));
    }

    #[test]
    fn wrong_secret_mailbox_or_any_bit_flip_is_a_silent_drop() {
        let sealed = seal(&TestAead, &SECRET, &MAILBOX, &RECORD_ID, &record(40)).unwrap();
        assert_eq!(
            open(&TestAead, &[0x12; 32], &MAILBOX, &sealed, MailboxKind::Leaf),
            Err(SilentDrop(ErrorCode::OuterSealFailed))
        );
        assert_eq!(
            open(&TestAead, &SECRET, &[0x23; 32], &sealed, MailboxKind::Leaf),
            Err(SilentDrop(ErrorCode::OuterSealFailed))
        );
        for bit in 0..sealed.len() * 8 {
            let mut flipped = sealed.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                open(&TestAead, &SECRET, &MAILBOX, &flipped, MailboxKind::Leaf),
                Err(SilentDrop(ErrorCode::OuterSealFailed))
            );
        }
        for len in 0..sealed.len() {
            assert!(
                open(
                    &TestAead,
                    &SECRET,
                    &MAILBOX,
                    &sealed[..len],
                    MailboxKind::Leaf
                )
                .is_err()
            );
        }
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(
            open(&TestAead, &SECRET, &MAILBOX, &long, MailboxKind::Leaf),
            Err(SilentDrop(ErrorCode::BadRecordLength))
        );
    }

    #[test]
    fn each_mailbox_kind_accepts_only_its_own_record_type() {
        let kinds = [
            MailboxKind::Leaf,
            MailboxKind::CommitSlot,
            MailboxKind::Welcome,
            MailboxKind::Introduction,
        ];
        for sent in kinds {
            let record = InnerRecord {
                record_type: sent.record_type(),
                payload: vec![1, 2, 3],
            };
            let sealed = seal(&TestAead, &SECRET, &MAILBOX, &RECORD_ID, &record).unwrap();
            for fetched in kinds {
                let result = open(&TestAead, &SECRET, &MAILBOX, &sealed, fetched);
                if sent == fetched {
                    assert_eq!(result.unwrap().record, record);
                } else {
                    assert_eq!(result, Err(SilentDrop(ErrorCode::UnexpectedRecordType)));
                }
            }
        }
    }

    #[test]
    fn padding_and_type_are_canonical_inside_the_seal() {
        let good = encode_plaintext(&record(3)).unwrap();
        assert_eq!(&good[..7], &[0xa2, 0x01, 0x01, 0x02, 0x43, 0xa5, 0xa5]);
        let mut dirty = good.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(decode_plaintext(&dirty), Err(ErrorCode::BadPadding));
        let mut roomy = good[..8].to_vec();
        roomy.resize(BUCKETS[1] - RECORD_OVERHEAD, 0);
        assert_eq!(decode_plaintext(&roomy), Err(ErrorCode::BadPadding));
        let mut unknown = good.clone();
        unknown[2] = 5;
        assert_eq!(
            decode_plaintext(&unknown),
            Err(ErrorCode::UnsupportedRecordType)
        );
        let mut wide_type = good.clone();
        wide_type.splice(2..3, [0x18, 0x01]);
        wide_type.pop();
        assert_eq!(decode_plaintext(&wide_type), Err(ErrorCode::NonCanonical));
        let mut empty = vec![0xa2, 0x01, 0x01, 0x02, 0x40];
        empty.resize(good.len(), 0);
        assert_eq!(decode_plaintext(&empty), Err(ErrorCode::Empty));
        assert_eq!(
            decode_plaintext(&good[1..]),
            Err(ErrorCode::BadRecordLength)
        );
    }

    #[test]
    fn hostile_plaintexts_never_panic_and_accepted_ones_are_canonical() {
        let mut state = 0x5eed_1234u32;
        let len = BUCKETS[0] - RECORD_OVERHEAD;
        for round in 0..4096 {
            let mut bytes = vec![0u8; len];
            // Mostly structured prefixes so the parser gets past the head.
            let prefix = (round % 16) + 1;
            for byte in bytes.iter_mut().take(prefix) {
                *byte = lcg(&mut state);
            }
            if round % 3 == 0 {
                bytes[0] = 0xa2;
                bytes[1] = 0x01;
            }
            if let Ok(record) = decode_plaintext(&bytes) {
                assert_eq!(encode_plaintext(&record).unwrap(), bytes);
            }
        }
        let good = encode_plaintext(&record(100)).unwrap();
        for bit in 0..200 * 8 {
            let mut flipped = good.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            if let Ok(record) = decode_plaintext(&flipped) {
                assert_eq!(encode_plaintext(&record).unwrap(), flipped);
            }
        }
        for sealed_len in [0, 1, 31, 32, 48, 1023, 1025, 4096] {
            let bytes: Vec<u8> = (0..sealed_len).map(|_| lcg(&mut state)).collect();
            assert!(open(&TestAead, &SECRET, &MAILBOX, &bytes, MailboxKind::Leaf).is_err());
        }
    }

    #[test]
    fn a_misbehaving_aead_is_refused_not_trusted() {
        struct Short;
        impl RecordAead for Short {
            fn seal(&self, _: &[u8; 16], _: &[u8; 12], _: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
                Some(msg.to_vec())
            }
            fn open(&self, _: &[u8; 16], _: &[u8; 12], _: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
                Some(msg.to_vec())
            }
        }
        assert_eq!(
            seal(&Short, &SECRET, &MAILBOX, &RECORD_ID, &record(4)),
            Err(ErrorCode::AeadUnavailable)
        );
        assert_eq!(
            open(&Short, &SECRET, &MAILBOX, &[0u8; 1024], MailboxKind::Leaf),
            Err(SilentDrop(ErrorCode::OuterSealFailed))
        );
    }
}
