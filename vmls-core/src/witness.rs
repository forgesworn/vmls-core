//! Restore-witness request bodies (contract §4.2).
//!
//! Both are canonical CBOR maps with ascending integer keys, definite
//! lengths, shortest integers and nothing else, bounded to
//! [`MAX_REQUEST_BYTES`] before parsing. The witness answers with a
//! [`crate::receipt::WitnessReceipt`].

use crate::cbor::{self, Reader};
use crate::{ErrorCode, MAX_SAFE_INTEGER};

/// The only request version.
pub const WITNESS_REQUEST_VERSION: u64 = 1;
/// Requests larger than this are refused before any parsing.
pub const MAX_REQUEST_BYTES: usize = 256;

/// `read(subject, challenge)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub subject: [u8; 32],
    pub challenge: [u8; 32],
}

/// `advance(subject, expected_seq, expected_digest, next_digest, challenge)`.
/// `expected_seq` is below `MAX_SAFE_INTEGER`, so the next sequence number
/// still fits; a subject at the limit needs a new installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvanceRequest {
    pub subject: [u8; 32],
    pub expected_seq: u64,
    pub expected_digest: [u8; 32],
    pub next_digest: [u8; 32],
    pub challenge: [u8; 32],
}

fn start(bytes: &[u8], entries: u64) -> Result<Reader<'_>, ErrorCode> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ErrorCode::TooLarge);
    }
    let mut reader = Reader::new(bytes);
    reader.map(entries)?;
    reader.key(1)?;
    if reader.uint()? != WITNESS_REQUEST_VERSION {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(reader)
}

impl ReadRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        cbor::write_map(&mut out, 3);
        cbor::write_uint(&mut out, 1);
        cbor::write_uint(&mut out, WITNESS_REQUEST_VERSION);
        cbor::write_uint(&mut out, 2);
        cbor::write_bytes(&mut out, &self.subject);
        cbor::write_uint(&mut out, 3);
        cbor::write_bytes(&mut out, &self.challenge);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        let mut reader = start(bytes, 3)?;
        reader.key(2)?;
        let subject = reader.fixed()?;
        reader.key(3)?;
        let challenge = reader.fixed()?;
        reader.finish()?;
        Ok(Self { subject, challenge })
    }
}

impl AdvanceRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(150);
        cbor::write_map(&mut out, 6);
        cbor::write_uint(&mut out, 1);
        cbor::write_uint(&mut out, WITNESS_REQUEST_VERSION);
        cbor::write_uint(&mut out, 2);
        cbor::write_bytes(&mut out, &self.subject);
        cbor::write_uint(&mut out, 3);
        cbor::write_uint(&mut out, self.expected_seq);
        cbor::write_uint(&mut out, 4);
        cbor::write_bytes(&mut out, &self.expected_digest);
        cbor::write_uint(&mut out, 5);
        cbor::write_bytes(&mut out, &self.next_digest);
        cbor::write_uint(&mut out, 6);
        cbor::write_bytes(&mut out, &self.challenge);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        let mut reader = start(bytes, 6)?;
        reader.key(2)?;
        let subject = reader.fixed()?;
        reader.key(3)?;
        let expected_seq = reader.uint()?;
        if expected_seq >= MAX_SAFE_INTEGER {
            return Err(ErrorCode::Malformed);
        }
        reader.key(4)?;
        let expected_digest = reader.fixed()?;
        reader.key(5)?;
        let next_digest = reader.fixed()?;
        reader.key(6)?;
        let challenge = reader.fixed()?;
        reader.finish()?;
        Ok(Self {
            subject,
            expected_seq,
            expected_digest,
            next_digest,
            challenge,
        })
    }
}
