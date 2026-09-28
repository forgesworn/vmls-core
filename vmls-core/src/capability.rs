//! `capability/1`: a one-time KeyPackage offered privately to an adder.
//!
//! ```text
//! capability/1 = {                   ; canonical CBOR, keys in this order
//!   1: 1,                            ; version
//!   2: bstr .size 32,                ; package_id
//!   3: bstr .size (1..16384),        ; the MLS KeyPackage, opaque here
//!   4: bstr .size (1..8192),         ; leaf-binding/1, byte-identical to the
//!                                    ; KeyPackage leaf's binding extension
//!   5: bstr .size 32,                ; welcome_mailbox, single use
//!   6: bstr .size 32,                ; welcome_transport X25519 public key
//!   7: bstr .size 32,                ; welcome_secret: outer-record secret
//!                                    ; for the one Welcome record
//!   8: uint,                         ; expires_at, at most 7 days ahead
//! }
//! ```
//!
//! The record is carried as a `Capability` inner record to an introduction
//! mailbox (see `derive::introduction`). Receiving a valid one is the only
//! signal that a person's device speaks VMLS/1; nothing is advertised.

use crate::ErrorCode;
use crate::binding::{
    BindingPolicy, CarryingLeaf, LeafBinding, MAX_BINDING_BYTES, VerifiedBinding,
};
use crate::cbor::{self, Reader};

pub const CAPABILITY_VERSION: u64 = 1;
pub const MAX_KEY_PACKAGE_BYTES: usize = 16_384;
/// A KeyPackage capability expires at most seven days ahead.
pub const MAX_CAPABILITY_SECONDS: u64 = 7 * 86_400;
/// Upper bound on an encoded capability record, checked before parsing.
pub const MAX_CAPABILITY_BYTES: usize = 32_768;

const KEYS: u64 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub package_id: [u8; 32],
    pub key_package: Vec<u8>,
    pub binding: LeafBinding,
    pub welcome_mailbox: [u8; 32],
    pub welcome_transport: [u8; 32],
    pub welcome_secret: [u8; 32],
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCapability {
    pub package_id: [u8; 32],
    pub binding: VerifiedBinding,
    pub expires_at: u64,
}

impl CapabilityRecord {
    pub fn encode(&self) -> Result<Vec<u8>, ErrorCode> {
        if self.key_package.is_empty() {
            return Err(ErrorCode::Empty);
        }
        if self.key_package.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let binding = self.binding.encode();
        if binding.len() > MAX_BINDING_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let mut out = Vec::with_capacity(self.key_package.len() + binding.len() + 160);
        cbor::write_map(&mut out, KEYS);
        cbor::write_uint(&mut out, 1);
        cbor::write_uint(&mut out, CAPABILITY_VERSION);
        cbor::write_uint(&mut out, 2);
        cbor::write_bytes(&mut out, &self.package_id);
        cbor::write_uint(&mut out, 3);
        cbor::write_bytes(&mut out, &self.key_package);
        cbor::write_uint(&mut out, 4);
        cbor::write_bytes(&mut out, &binding);
        cbor::write_uint(&mut out, 5);
        cbor::write_bytes(&mut out, &self.welcome_mailbox);
        cbor::write_uint(&mut out, 6);
        cbor::write_bytes(&mut out, &self.welcome_transport);
        cbor::write_uint(&mut out, 7);
        cbor::write_bytes(&mut out, &self.welcome_secret);
        cbor::write_uint(&mut out, 8);
        cbor::write_uint(&mut out, self.expires_at);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ErrorCode> {
        if input.len() > MAX_CAPABILITY_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let mut reader = Reader::new(input);
        reader.map(KEYS)?;
        reader.key(1)?;
        if reader.uint()? != CAPABILITY_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        reader.key(2)?;
        let package_id = reader.fixed()?;
        reader.key(3)?;
        let key_package = reader.bytes(MAX_KEY_PACKAGE_BYTES)?;
        if key_package.is_empty() {
            return Err(ErrorCode::Empty);
        }
        reader.key(4)?;
        let binding = LeafBinding::decode(reader.bytes(MAX_BINDING_BYTES)?)?;
        reader.key(5)?;
        let welcome_mailbox = reader.fixed()?;
        reader.key(6)?;
        let welcome_transport = reader.fixed()?;
        reader.key(7)?;
        let welcome_secret = reader.fixed()?;
        reader.key(8)?;
        let expires_at = reader.timestamp()?;
        reader.finish()?;
        Ok(Self {
            package_id,
            key_package: key_package.to_vec(),
            binding,
            welcome_mailbox,
            welcome_transport,
            welcome_secret,
            expires_at,
        })
    }

    /// Checks the capability's own lifetime, then the binding, then that the
    /// capability does not outlive the binding. The first failure is returned.
    ///
    /// `leaf` is the leaf of the KeyPackage in key 3, as the MLS engine
    /// parsed it; the binding must name exactly that leaf.
    pub fn verify(
        &self,
        now: u64,
        leaf: &CarryingLeaf<'_>,
        policy: &BindingPolicy<'_>,
    ) -> Result<VerifiedCapability, ErrorCode> {
        if self.expires_at <= now {
            return Err(ErrorCode::CapabilityExpired);
        }
        if self.expires_at - now > MAX_CAPABILITY_SECONDS {
            return Err(ErrorCode::CapabilityLifetimeTooLong);
        }
        let binding = self.binding.verify(now, leaf, policy)?;
        if self.expires_at > binding.expires_at {
            return Err(ErrorCode::CapabilityOutlivesBinding);
        }
        Ok(VerifiedCapability {
            package_id: self.package_id,
            binding,
            expires_at: self.expires_at,
        })
    }
}
