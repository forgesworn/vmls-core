//! Canonical VMLS/1 wire codecs.
//!
//! This package deliberately does not implement MLS. It owns every byte
//! layout VMLS/1 defines around MLS, so web, Android and the box share one
//! codec:
//!
//! - [`Envelope`]: the outer record a box sees (profile, mailbox, opaque bytes);
//! - [`record`]: the bucket-padded inner record inside the envelope, sealed
//!   with the MLS suite's AEAD supplied by the caller;
//! - [`derive`]: the exporter label and the mailbox, record-secret, commit-slot
//!   and introduction derivations;
//! - [`binding`]: `leaf-binding/1` and the kind-20460 person-credential rules;
//! - [`capability`]: the one-time KeyPackage capability record;
//! - [`lane`]: the composer's send-lane decision table;
//! - [`receipt`]: signed slot receipts and restore-witness receipts;
//! - [`evidence`]: the fork-evidence payload (record type 5);
//! - [`witness`]: restore-witness read and advance requests;
//! - [`manifest`]: the canonical state manifest and its digest;
//! - [`ErrorCode`]: stable, byte-free failure codes.
//!
//! The VMLS/1 transport contract is not yet published; the vectors in
//! `vectors/` are the reference for every byte layout here.

use core::fmt;

pub mod binding;
pub mod capability;
mod cbor;
pub mod derive;
mod error;
pub mod evidence;
pub mod lane;
pub mod manifest;
pub mod receipt;
pub mod record;
pub mod witness;

pub use cbor::MAX_SAFE_INTEGER;
pub use error::ErrorCode;

/// The only VMLS envelope profile accepted by this package.
pub const PROFILE_VERSION: u8 = 1;
/// Bytes in a rotating per-leaf mailbox capability.
pub const MAILBOX_CAPABILITY_BYTES: usize = 32;
/// A single record is bounded before allocating or decrypting it.
pub const MAX_CIPHERTEXT_BYTES: usize = 1_048_576;

const MAP_THREE: u8 = 0xa3;
const KEY_PROFILE: u8 = 0x01;
const KEY_MAILBOX: u8 = 0x02;
const KEY_CIPHERTEXT: u8 = 0x03;
const BYTES_32: [u8; 2] = [0x58, MAILBOX_CAPABILITY_BYTES as u8];

/// The public outer record. `ciphertext` includes every MLS-sensitive field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub mailbox: [u8; MAILBOX_CAPABILITY_BYTES],
    pub ciphertext: Vec<u8>,
}

/// A bounded decoder failure. Variants deliberately contain no input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    NonCanonical,
    UnsupportedVersion,
    WrongMailbox,
    EmptyCiphertext,
    CiphertextTooLarge,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed VMLS envelope",
            Self::NonCanonical => "non-canonical VMLS envelope",
            Self::UnsupportedVersion => "unsupported VMLS envelope version",
            Self::WrongMailbox => "VMLS envelope is not for this mailbox",
            Self::EmptyCiphertext => "VMLS envelope ciphertext is empty",
            Self::CiphertextTooLarge => "VMLS envelope ciphertext is too large",
        })
    }
}

impl std::error::Error for EnvelopeError {}

impl Envelope {
    /// Writes the sole accepted VMLS/1 outer shape.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        validate_ciphertext_len(self.ciphertext.len())?;
        let mut out = Vec::with_capacity(
            1 + 2 + 2 + MAILBOX_CAPABILITY_BYTES + 1 + 5 + self.ciphertext.len(),
        );
        out.extend_from_slice(&[MAP_THREE, KEY_PROFILE, PROFILE_VERSION, KEY_MAILBOX]);
        out.extend_from_slice(&BYTES_32);
        out.extend_from_slice(&self.mailbox);
        out.push(KEY_CIPHERTEXT);
        write_canonical_bytes_len(&mut out, self.ciphertext.len());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Decodes a VMLS/1 envelope and refuses any non-canonical variation.
    pub fn decode(
        input: &[u8],
        active_mailbox: &[u8; MAILBOX_CAPABILITY_BYTES],
    ) -> Result<Self, EnvelopeError> {
        let mut cursor = Cursor::new(input);
        if cursor.byte()? != MAP_THREE {
            return Err(EnvelopeError::NonCanonical);
        }
        expect(&mut cursor, KEY_PROFILE)?;
        let version = cursor.byte()?;
        if version != PROFILE_VERSION {
            return Err(if version <= 23 {
                EnvelopeError::UnsupportedVersion
            } else {
                EnvelopeError::NonCanonical
            });
        }
        expect(&mut cursor, KEY_MAILBOX)?;
        if cursor.take(2)? != BYTES_32 {
            return Err(EnvelopeError::NonCanonical);
        }
        let mut mailbox = [0u8; MAILBOX_CAPABILITY_BYTES];
        mailbox.copy_from_slice(cursor.take(MAILBOX_CAPABILITY_BYTES)?);
        if &mailbox != active_mailbox {
            return Err(EnvelopeError::WrongMailbox);
        }
        expect(&mut cursor, KEY_CIPHERTEXT)?;
        let ciphertext_len = cursor.canonical_bytes_len()?;
        validate_ciphertext_len(ciphertext_len)?;
        let ciphertext = cursor.take(ciphertext_len)?.to_vec();
        if !cursor.done() {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(Self {
            mailbox,
            ciphertext,
        })
    }
}

fn validate_ciphertext_len(len: usize) -> Result<(), EnvelopeError> {
    if len == 0 {
        Err(EnvelopeError::EmptyCiphertext)
    } else if len > MAX_CIPHERTEXT_BYTES {
        Err(EnvelopeError::CiphertextTooLarge)
    } else {
        Ok(())
    }
}

fn write_canonical_bytes_len(out: &mut Vec<u8>, len: usize) {
    if len <= 23 {
        out.push(0x40 | len as u8);
    } else if len <= u8::MAX as usize {
        out.extend_from_slice(&[0x58, len as u8]);
    } else if len <= u16::MAX as usize {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x5a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn expect(cursor: &mut Cursor<'_>, expected: u8) -> Result<(), EnvelopeError> {
    if cursor.byte()? == expected {
        Ok(())
    } else {
        Err(EnvelopeError::NonCanonical)
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self.at.checked_add(len).ok_or(EnvelopeError::Malformed)?;
        let bytes = self
            .input
            .get(self.at..end)
            .ok_or(EnvelopeError::Malformed)?;
        self.at = end;
        Ok(bytes)
    }

    fn canonical_bytes_len(&mut self) -> Result<usize, EnvelopeError> {
        let first = self.byte()?;
        let len = match first {
            0x40..=0x57 => (first & 0x1f) as usize,
            0x58 => self.byte()? as usize,
            0x59 => u16::from_be_bytes(
                self.take(2)?
                    .try_into()
                    .map_err(|_| EnvelopeError::Malformed)?,
            ) as usize,
            0x5a => u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| EnvelopeError::Malformed)?,
            ) as usize,
            _ => return Err(EnvelopeError::NonCanonical),
        };
        if (len <= 23 && first != 0x40 | len as u8)
            || (len <= u8::MAX as usize && len > 23 && first != 0x58)
            || (len <= u16::MAX as usize && len > u8::MAX as usize && first != 0x59)
            || (len > u16::MAX as usize && first != 0x5a)
        {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(len)
    }

    fn done(&self) -> bool {
        self.at == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const MAILBOX: [u8; MAILBOX_CAPABILITY_BYTES] = [0x61; MAILBOX_CAPABILITY_BYTES];

    fn envelope(ciphertext: &[u8]) -> Envelope {
        Envelope {
            mailbox: MAILBOX,
            ciphertext: ciphertext.to_vec(),
        }
    }

    #[test]
    fn round_trip_is_the_one_canonical_shape() {
        let encoded = envelope(b"opaque").encode().unwrap();
        assert_eq!(&encoded[..7], &[0xa3, 0x01, 0x01, 0x02, 0x58, 0x20, 0x61]);
        assert_eq!(
            Envelope::decode(&encoded, &MAILBOX).unwrap(),
            envelope(b"opaque")
        );
    }

    #[test]
    fn rejects_wrong_profile_or_mailbox() {
        let mut version = envelope(b"x").encode().unwrap();
        version[2] = 2;
        assert_eq!(
            Envelope::decode(&version, &MAILBOX),
            Err(EnvelopeError::UnsupportedVersion)
        );
        let mut noncanonical_version = envelope(b"x").encode().unwrap();
        noncanonical_version.splice(2..=2, [0x18, 0x01]);
        assert_eq!(
            Envelope::decode(&noncanonical_version, &MAILBOX),
            Err(EnvelopeError::NonCanonical)
        );
        let mut other = MAILBOX;
        other[0] ^= 1;
        assert_eq!(
            Envelope::decode(&envelope(b"x").encode().unwrap(), &other),
            Err(EnvelopeError::WrongMailbox)
        );
    }

    #[test]
    fn rejects_duplicate_reordered_and_trailing_map_content() {
        let mut duplicate = envelope(b"x").encode().unwrap();
        duplicate[0] = 0xa4;
        duplicate.extend_from_slice(&[0x02, 0x40]);
        assert_eq!(
            Envelope::decode(&duplicate, &MAILBOX),
            Err(EnvelopeError::NonCanonical)
        );
        let mut reordered = envelope(b"x").encode().unwrap();
        reordered.swap(1, 3);
        assert_eq!(
            Envelope::decode(&reordered, &MAILBOX),
            Err(EnvelopeError::NonCanonical)
        );
        let mut trailing = envelope(b"x").encode().unwrap();
        trailing.push(0);
        assert_eq!(
            Envelope::decode(&trailing, &MAILBOX),
            Err(EnvelopeError::NonCanonical)
        );
    }

    #[test]
    fn rejects_noncanonical_lengths_and_empty_or_large_ciphertext() {
        let mut noncanonical = envelope(b"x").encode().unwrap();
        let index = noncanonical.len() - 2;
        noncanonical.splice(index..=index, [0x58, 0x01]);
        assert_eq!(
            Envelope::decode(&noncanonical, &MAILBOX),
            Err(EnvelopeError::NonCanonical)
        );
        assert_eq!(envelope(&[]).encode(), Err(EnvelopeError::EmptyCiphertext));
        assert_eq!(
            envelope(&vec![0; MAX_CIPHERTEXT_BYTES + 1]).encode(),
            Err(EnvelopeError::CiphertextTooLarge)
        );
    }

    #[test]
    fn hostile_input_never_panics_or_allocates_unboundedly() {
        let mut state = 0x9e37_79b9u32;
        for len in 0..512 {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            let _ = Envelope::decode(&bytes, &MAILBOX);
        }
    }

    #[test]
    fn published_known_answer_suite_matches_the_rust_decoder() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Suite {
            mailbox_hex: String,
            cases: Vec<Case>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Case {
            active_mailbox_hex: Option<String>,
            encoded_hex: String,
            expect: Expected,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Expected {
            ok: bool,
            ciphertext_hex: Option<String>,
            error: Option<String>,
        }

        fn hex(value: &str) -> Vec<u8> {
            assert!(value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()));
            (0..value.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
                .collect()
        }
        fn error(name: &str) -> EnvelopeError {
            match name {
                "Malformed" => EnvelopeError::Malformed,
                "NonCanonical" => EnvelopeError::NonCanonical,
                "UnsupportedVersion" => EnvelopeError::UnsupportedVersion,
                "WrongMailbox" => EnvelopeError::WrongMailbox,
                "EmptyCiphertext" => EnvelopeError::EmptyCiphertext,
                "CiphertextTooLarge" => EnvelopeError::CiphertextTooLarge,
                _ => panic!("unknown vector error"),
            }
        }

        let suite: Suite = serde_json::from_str(include_str!("../vectors/vmls-envelope-v1.json"))
            .expect("known-answer suite must be JSON");
        let default_mailbox: [u8; MAILBOX_CAPABILITY_BYTES] = hex(&suite.mailbox_hex)
            .try_into()
            .expect("known-answer mailbox must be 32 bytes");
        for case in suite.cases {
            let mailbox: [u8; MAILBOX_CAPABILITY_BYTES] = case
                .active_mailbox_hex
                .as_deref()
                .map(hex)
                .unwrap_or_else(|| default_mailbox.to_vec())
                .try_into()
                .expect("active mailbox must be 32 bytes");
            let actual = Envelope::decode(&hex(&case.encoded_hex), &mailbox);
            if case.expect.ok {
                assert_eq!(
                    actual.unwrap().ciphertext,
                    hex(case.expect.ciphertext_hex.as_deref().unwrap())
                );
            } else {
                assert_eq!(
                    actual.unwrap_err(),
                    error(case.expect.error.as_deref().unwrap())
                );
            }
        }
    }
}
