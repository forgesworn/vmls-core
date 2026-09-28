//! Stable VMLS/1 error codes.
//!
//! Every parser and verifier in this crate reports one of these codes and
//! nothing else: no input bytes, no key material, no free text. The string
//! form and the number are both stable wire-adjacent identifiers. Vectors use
//! the string form; FFI and wasm adapters may use either. A code is never
//! renumbered or reused; a retired code keeps its number.

use core::fmt;

use crate::EnvelopeError;

/// A stable, byte-free failure code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Truncated input, a field of the wrong fixed length, text that is not
    /// UTF-8, or a value outside its permitted range.
    Malformed,
    /// Anything other than the one accepted canonical encoding: non-shortest
    /// lengths, indefinite lengths, reordered, duplicate, missing or unknown
    /// keys, unexpected major types or trailing bytes.
    NonCanonical,
    UnsupportedVersion,
    WrongMailbox,
    Empty,
    TooLarge,
    /// A sealed record whose length is not exactly one padding bucket.
    BadRecordLength,
    /// The outer AEAD did not open. Always a silent drop.
    OuterSealFailed,
    /// Non-zero padding, or a larger bucket than the content needs.
    BadPadding,
    UnsupportedRecordType,
    /// A known record type that does not belong on this kind of mailbox.
    /// Always a silent drop.
    UnexpectedRecordType,
    /// The MLS credential identity is not `"vmls1" || leaf_id`.
    BadLeafIdentity,
    /// The binding's device key is not a valid BIP-340 x-only key.
    BadDeviceKey,
    BindingSignatureInvalid,
    BindingExpired,
    BindingOutlivesCredential,
    /// A credential tag the verifier needs is duplicated or unparseable.
    CredentialMalformed,
    CredentialSignatureInvalid,
    /// A room-form credential, or `d`/`scope` not the person form.
    CredentialNotPersonScoped,
    CredentialWrongIdentity,
    CredentialWrongDevice,
    CredentialExpired,
    CredentialLifetimeTooLong,
    CredentialRevoked,
    /// `created_at` is more than the permitted skew ahead of now.
    CredentialNotYetValid,
    /// Key 2 or 3 differs from the carrying leaf's credential identity or
    /// signature key.
    BindingLeafMismatch,
    CapabilityExpired,
    CapabilityLifetimeTooLong,
    CapabilityOutlivesBinding,
    /// The caller's AEAD refused to seal or returned the wrong length.
    AeadUnavailable,
}

impl ErrorCode {
    /// Every code, in number order.
    pub const ALL: [Self; 30] = [
        Self::Malformed,
        Self::NonCanonical,
        Self::UnsupportedVersion,
        Self::WrongMailbox,
        Self::Empty,
        Self::TooLarge,
        Self::BadRecordLength,
        Self::OuterSealFailed,
        Self::BadPadding,
        Self::UnsupportedRecordType,
        Self::UnexpectedRecordType,
        Self::BadLeafIdentity,
        Self::BadDeviceKey,
        Self::BindingSignatureInvalid,
        Self::BindingExpired,
        Self::BindingOutlivesCredential,
        Self::CredentialMalformed,
        Self::CredentialSignatureInvalid,
        Self::CredentialNotPersonScoped,
        Self::CredentialWrongIdentity,
        Self::CredentialWrongDevice,
        Self::CredentialExpired,
        Self::CredentialLifetimeTooLong,
        Self::CredentialRevoked,
        Self::CredentialNotYetValid,
        Self::BindingLeafMismatch,
        Self::CapabilityExpired,
        Self::CapabilityLifetimeTooLong,
        Self::CapabilityOutlivesBinding,
        Self::AeadUnavailable,
    ];

    /// The stable string form, as used in the published vectors.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::NonCanonical => "NonCanonical",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::WrongMailbox => "WrongMailbox",
            Self::Empty => "Empty",
            Self::TooLarge => "TooLarge",
            Self::BadRecordLength => "BadRecordLength",
            Self::OuterSealFailed => "OuterSealFailed",
            Self::BadPadding => "BadPadding",
            Self::UnsupportedRecordType => "UnsupportedRecordType",
            Self::UnexpectedRecordType => "UnexpectedRecordType",
            Self::BadLeafIdentity => "BadLeafIdentity",
            Self::BadDeviceKey => "BadDeviceKey",
            Self::BindingSignatureInvalid => "BindingSignatureInvalid",
            Self::BindingExpired => "BindingExpired",
            Self::BindingOutlivesCredential => "BindingOutlivesCredential",
            Self::CredentialMalformed => "CredentialMalformed",
            Self::CredentialSignatureInvalid => "CredentialSignatureInvalid",
            Self::CredentialNotPersonScoped => "CredentialNotPersonScoped",
            Self::CredentialWrongIdentity => "CredentialWrongIdentity",
            Self::CredentialWrongDevice => "CredentialWrongDevice",
            Self::CredentialExpired => "CredentialExpired",
            Self::CredentialLifetimeTooLong => "CredentialLifetimeTooLong",
            Self::CredentialRevoked => "CredentialRevoked",
            Self::CredentialNotYetValid => "CredentialNotYetValid",
            Self::BindingLeafMismatch => "BindingLeafMismatch",
            Self::CapabilityExpired => "CapabilityExpired",
            Self::CapabilityLifetimeTooLong => "CapabilityLifetimeTooLong",
            Self::CapabilityOutlivesBinding => "CapabilityOutlivesBinding",
            Self::AeadUnavailable => "AeadUnavailable",
        }
    }

    /// The stable number. Ranges: 1-9 codec, 10-19 record, 20-39 binding and
    /// credential, 40-49 capability, 50-59 caller-supplied primitives.
    pub const fn number(self) -> u16 {
        match self {
            Self::Malformed => 1,
            Self::NonCanonical => 2,
            Self::UnsupportedVersion => 3,
            Self::WrongMailbox => 4,
            Self::Empty => 5,
            Self::TooLarge => 6,
            Self::BadRecordLength => 10,
            Self::OuterSealFailed => 11,
            Self::BadPadding => 12,
            Self::UnsupportedRecordType => 13,
            Self::UnexpectedRecordType => 14,
            Self::BadLeafIdentity => 20,
            Self::BadDeviceKey => 21,
            Self::BindingSignatureInvalid => 22,
            Self::BindingExpired => 23,
            Self::BindingOutlivesCredential => 24,
            Self::CredentialMalformed => 25,
            Self::CredentialSignatureInvalid => 26,
            Self::CredentialNotPersonScoped => 27,
            Self::CredentialWrongIdentity => 28,
            Self::CredentialWrongDevice => 29,
            Self::CredentialExpired => 30,
            Self::CredentialLifetimeTooLong => 31,
            Self::CredentialRevoked => 32,
            Self::CredentialNotYetValid => 33,
            Self::BindingLeafMismatch => 34,
            Self::CapabilityExpired => 40,
            Self::CapabilityLifetimeTooLong => 41,
            Self::CapabilityOutlivesBinding => 42,
            Self::AeadUnavailable => 50,
        }
    }

    /// Looks a code up by its stable number.
    pub fn from_number(number: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.number() == number)
    }

    /// Parses the stable string form.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.code() == code)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ErrorCode {}

impl From<EnvelopeError> for ErrorCode {
    fn from(error: EnvelopeError) -> Self {
        match error {
            EnvelopeError::Malformed => Self::Malformed,
            EnvelopeError::NonCanonical => Self::NonCanonical,
            EnvelopeError::UnsupportedVersion => Self::UnsupportedVersion,
            EnvelopeError::WrongMailbox => Self::WrongMailbox,
            EnvelopeError::EmptyCiphertext => Self::Empty,
            EnvelopeError::CiphertextTooLarge => Self::TooLarge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_numbers_are_unique_and_round_trip() {
        for (index, code) in ErrorCode::ALL.iter().enumerate() {
            assert_eq!(ErrorCode::from_code(code.code()), Some(*code));
            assert_eq!(ErrorCode::from_number(code.number()), Some(*code));
            assert_ne!(code.number(), 0, "0 means success in the vectors");
            for other in &ErrorCode::ALL[index + 1..] {
                assert_ne!(code.number(), other.number());
                assert_ne!(code.code(), other.code());
            }
        }
        assert_eq!(ErrorCode::from_code("vmls"), None);
    }
}
