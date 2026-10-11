//! Firmware-writer authentication through an untrusted witness courier.
//!
//! This codec verifies exact request bytes, not current witness authority or
//! token lifetime. A service must atomically consume the one-use courier token
//! for its verified Link peer before touching its witness store. It must never
//! treat signature verification alone as token authorisation or writer enrolment.

use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::witness::{AdvanceRequest, MAX_REQUEST_BYTES, ReadRequest};

pub const VERSION: u8 = 1;
pub const HEADER_BYTES: usize = 68;
pub const OVERHEAD_BYTES: usize = HEADER_BYTES + 64;
pub const MAX_ENVELOPE_BYTES: usize = OVERHEAD_BYTES + MAX_REQUEST_BYTES;
pub const REQUEST_TAG: &[u8] = b"VMLS/1 allocation witness request\0";

/// Separate, byte-free errors; existing VMLS failure numbers are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardingError {
    Malformed,
    TooLarge,
    UnsupportedVersion,
    WrongMethod,
    InvalidRequest,
    SignatureInvalid,
}

impl fmt::Display for ForwardingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed allocation witness envelope",
            Self::TooLarge => "allocation witness envelope is too large",
            Self::UnsupportedVersion => "unsupported allocation witness version",
            Self::WrongMethod => "wrong allocation witness method",
            Self::InvalidRequest => "invalid canonical allocation witness request",
            Self::SignatureInvalid => "invalid allocation writer signature",
        })
    }
}
impl std::error::Error for ForwardingError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Method {
    Read = 1,
    Advance = 2,
}

/// Fixed-size decoded canonical request, with no caller-supplied raw body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Read(ReadRequest),
    Advance(AdvanceRequest),
}

impl Request {
    pub fn method(&self) -> Method {
        match self {
            Self::Read(_) => Method::Read,
            Self::Advance(_) => Method::Advance,
        }
    }

    fn encode_checked(&self) -> Result<Vec<u8>, ForwardingError> {
        let body = match self {
            Self::Read(r) => r.encode(),
            Self::Advance(r) => r.encode(),
        };
        // Typed requests still need the canonical decoder's sequence bounds.
        Self::parse(self.method(), &body)?;
        Ok(body)
    }

    fn parse(method: Method, bytes: &[u8]) -> Result<Self, ForwardingError> {
        match method {
            Method::Read => ReadRequest::parse(bytes).map(Self::Read),
            Method::Advance => AdvanceRequest::parse(bytes).map(Self::Advance),
        }
        .map_err(|_| ForwardingError::InvalidRequest)
    }
}

/// Parsed or assembled envelope. Its writer is untrusted until `verify`.
/// Private fields prevent modifying bytes after signature verification.
#[derive(Clone, PartialEq, Eq)]
pub struct ForwardedRequest {
    writer: [u8; 32],
    courier_token: [u8; 32],
    request: Request,
    signature: [u8; 64],
}

// Do not accidentally log linkable writer, token, subject, digests or nonce.
impl fmt::Debug for ForwardedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardedRequest")
            .field("method", &self.request.method())
            .finish_non_exhaustive()
    }
}

impl ForwardedRequest {
    /// Pure framing, not a signing oracle or allocation authority.
    pub fn new(
        writer: [u8; 32],
        courier_token: [u8; 32],
        request: Request,
        signature: [u8; 64],
    ) -> Result<Self, ForwardingError> {
        request.encode_checked()?;
        Ok(Self {
            writer,
            courier_token,
            request,
            signature,
        })
    }

    pub fn parse(bytes: &[u8], expected_method: Method) -> Result<Self, ForwardingError> {
        // Bound first, before slicing or inner parsing/allocation.
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ForwardingError::TooLarge);
        }
        if bytes.len() <= OVERHEAD_BYTES {
            return Err(ForwardingError::Malformed);
        }
        if bytes[0] != VERSION {
            return Err(ForwardingError::UnsupportedVersion);
        }
        if bytes[1] != expected_method as u8 {
            return Err(ForwardingError::WrongMethod);
        }
        let length = u16::from_be_bytes([bytes[66], bytes[67]]) as usize;
        if length == 0 || length > MAX_REQUEST_BYTES || bytes.len() != OVERHEAD_BYTES + length {
            return Err(ForwardingError::Malformed);
        }
        let request = Request::parse(expected_method, &bytes[HEADER_BYTES..HEADER_BYTES + length])?;
        Ok(Self {
            writer: bytes[2..34].try_into().expect("fixed header checked"),
            courier_token: bytes[34..66].try_into().expect("fixed header checked"),
            request,
            signature: bytes[HEADER_BYTES + length..]
                .try_into()
                .expect("exact length checked"),
        })
    }

    fn unsigned(&self) -> Vec<u8> {
        // Construction and parsing both validate the immutable typed body.
        let body = self.request.encode_checked().expect("validated request");
        let mut out = Vec::with_capacity(HEADER_BYTES + body.len());
        out.extend_from_slice(&[VERSION, self.request.method() as u8]);
        out.extend_from_slice(&self.writer);
        out.extend_from_slice(&self.courier_token);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.unsigned();
        out.extend_from_slice(&self.signature);
        out
    }

    /// The caller supplies its independently pinned witness node key.
    pub fn digest_to_sign(&self, pinned_witness: &[u8; 32]) -> [u8; 32] {
        Sha256::new()
            .chain_update(REQUEST_TAG)
            .chain_update(pinned_witness)
            .chain_update(self.unsigned())
            .finalize()
            .into()
    }

    pub fn verify(
        self,
        pinned_witness: &[u8; 32],
    ) -> Result<SignatureVerifiedRequest, ForwardingError> {
        let key = VerifyingKey::from_bytes(&self.writer)
            .map_err(|_| ForwardingError::SignatureInvalid)?;
        key.verify_strict(
            &self.digest_to_sign(pinned_witness),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ForwardingError::SignatureInvalid)?;
        Ok(SignatureVerifiedRequest(self))
    }

    pub fn verified(
        bytes: &[u8],
        method: Method,
        pinned_witness: &[u8; 32],
    ) -> Result<SignatureVerifiedRequest, ForwardingError> {
        Self::parse(bytes, method)?.verify(pinned_witness)
    }
}

/// Only proves the writer signed this request for this witness. It does not
/// prove token liveness, store membership, freshness or allocation semantics.
/// Services must consume `courier_token()` before performing `request()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerifiedRequest(ForwardedRequest);

impl SignatureVerifiedRequest {
    pub fn writer(&self) -> &[u8; 32] {
        &self.0.writer
    }
    pub fn courier_token(&self) -> &[u8; 32] {
        &self.0.courier_token
    }
    pub fn request(&self) -> &Request {
        &self.0.request
    }
}
