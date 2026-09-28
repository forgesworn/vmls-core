//! `leaf-binding/1`: which person's device an MLS leaf belongs to.
//!
//! ```text
//! leaf-binding/1 = {                 ; canonical CBOR, keys in this order
//!   1: 1,                            ; version
//!   2: bstr .size 37,                ; MLS credential identity "vmls1" || leaf_id
//!   3: bstr .size 32,                ; MLS Ed25519 signature public key
//!   4: credential,                   ; the kind-20460 person credential
//!   5: bstr .size 32,                ; device x-only public key (BIP-340)
//!   6: uint,                         ; expires_at, unix seconds
//!   7: bstr .size 32,                ; home box: Link node id holding this leaf's mailbox
//!   8: bstr .size 64,                ; BIP-340 signature by key 5
//! }
//! credential = {
//!   1: bstr .size 32,                ; identity pubkey (x-only)
//!   2: uint,                         ; created_at
//!   3: [* [+ tstr]],                 ; tags, exactly as signed
//!   4: tstr,                         ; content, exactly as signed
//!   5: bstr .size 64,                ; the event's BIP-340 signature
//! }
//! digest = SHA-256("VMLS/1 leaf-binding" || canonical map of keys 1..7)
//! ```
//!
//! The credential carries every signed field of the kind-20460 event, so the
//! event id is recomputed with the NIP-01 serialisation and no JSON parser is
//! needed. The kind is fixed at 20460 and is not carried.
//!
//! The binding travels as the private-use LeafNode extension
//! [`LEAF_BINDING_EXTENSION_TYPE`], required through the group's
//! required-capabilities, so every member verifies every leaf (decision D2).

use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ErrorCode;
use crate::cbor::{self, Reader};

pub const LEAF_BINDING_VERSION: u64 = 1;
/// RFC 9420 private-use extension type (0xF000-0xFFFF) for the binding.
pub const LEAF_BINDING_EXTENSION_TYPE: u16 = 0xF0B1;
/// The MLS BasicCredential identity is this prefix followed by the leaf id.
pub const CREDENTIAL_IDENTITY_PREFIX: &[u8; 5] = b"vmls1";
pub const CREDENTIAL_IDENTITY_BYTES: usize = 5 + 32;
/// The domain tag hashed before the binding body.
pub const BINDING_SIGNATURE_TAG: &[u8] = b"VMLS/1 leaf-binding";
/// Upper bound on an encoded binding, checked before parsing.
pub const MAX_BINDING_BYTES: usize = 8192;
/// The device credential's Nostr kind.
pub const DEVICE_CREDENTIAL_KIND: u16 = 20460;
/// A person credential lives at most 30 days after `created_at`, and its
/// expiry is at most 30 days after now.
pub const MAX_PERSON_CREDENTIAL_SECONDS: u64 = 30 * 86_400;
/// How far `created_at` may be ahead of the verifier's clock.
pub const MAX_CREATED_AT_SKEW_SECONDS: u64 = 600;
pub const MAX_CREDENTIAL_TAGS: usize = 16;
pub const MAX_TAG_VALUES: usize = 8;
pub const MAX_TAG_VALUE_BYTES: usize = 512;
pub const MAX_CONTENT_BYTES: usize = 1024;

const BODY_KEYS: u64 = 7;
const BINDING_KEYS: u64 = 8;
const CREDENTIAL_KEYS: u64 = 5;

/// The signed fields of a kind-20460 device credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCredential {
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
}

/// A decoded, not yet verified, `leaf-binding/1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafBinding {
    pub leaf_id: [u8; 32],
    pub signature_key: [u8; 32],
    pub credential: DeviceCredential,
    pub device: [u8; 32],
    pub expires_at: u64,
    pub home_box: [u8; 32],
    pub signature: [u8; 64],
}

/// The MLS leaf that carries a binding, as the MLS engine parsed it: the
/// BasicCredential identity and the leaf's signature public key. A binding
/// verifies only for the leaf it names.
#[derive(Clone, Copy, Debug)]
pub struct CarryingLeaf<'a> {
    pub credential_identity: &'a [u8],
    pub signature_key: &'a [u8],
}

/// What the caller already knows when verifying.
#[derive(Clone, Copy, Debug, Default)]
pub struct BindingPolicy<'a> {
    /// The person this leaf must belong to, when the caller knows it.
    pub expected_identity: Option<&'a [u8; 32]>,
    /// Ids of credentials named by a verified kind-5 tombstone.
    pub revoked_credentials: &'a [[u8; 32]],
}

/// A binding whose signature and person credential both verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBinding {
    pub identity: [u8; 32],
    pub device: [u8; 32],
    pub leaf_id: [u8; 32],
    pub signature_key: [u8; 32],
    pub expires_at: u64,
    pub home_box: [u8; 32],
    pub credential_id: [u8; 32],
    pub credential_expires_at: u64,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    // Only ASCII hex digits were written.
    String::from_utf8(out).unwrap_or_default()
}

fn parse_lower_hex_32(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (index, pair) in text.chunks_exact(2).enumerate() {
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// A decimal timestamp: ASCII digits, no sign, no leading zero, safe range.
fn parse_decimal(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 16
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= cbor::MAX_SAFE_INTEGER)
}

/// Writes a JSON string exactly as `JSON.stringify` does, which is what the
/// NIP-01 event id is computed over by the reference implementations.
fn push_json_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                out.extend_from_slice(b"\\u00");
                push_hex(out, &[byte]);
            }
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

fn schnorr_verify(pubkey: &[u8; 32], message: &[u8; 32], sig: &[u8; 64]) -> Option<bool> {
    let key = VerifyingKey::from_bytes(pubkey).ok()?;
    Some(
        Signature::try_from(sig.as_slice())
            .map(|sig| key.verify_raw(message, &sig).is_ok())
            .unwrap_or(false),
    )
}

impl DeviceCredential {
    /// The NIP-01 serialisation `[0,pubkey,created_at,20460,tags,content]`.
    pub fn serialize_nip01(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"[0,\"");
        push_hex(&mut out, &self.pubkey);
        out.extend_from_slice(b"\",");
        out.extend_from_slice(self.created_at.to_string().as_bytes());
        out.push(b',');
        out.extend_from_slice(DEVICE_CREDENTIAL_KIND.to_string().as_bytes());
        out.extend_from_slice(b",[");
        for (index, tag) in self.tags.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'[');
            for (value_index, value) in tag.iter().enumerate() {
                if value_index > 0 {
                    out.push(b',');
                }
                push_json_string(&mut out, value);
            }
            out.push(b']');
        }
        out.extend_from_slice(b"],");
        push_json_string(&mut out, &self.content);
        out.push(b']');
        out
    }

    /// The Nostr event id.
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.serialize_nip01()).into()
    }

    fn single_tag(&self, name: &str) -> Result<Option<&str>, ErrorCode> {
        let mut found = None;
        for tag in &self.tags {
            if tag.first().map(String::as_str) == Some(name) {
                if found.is_some() {
                    return Err(ErrorCode::CredentialMalformed);
                }
                found = Some(tag.get(1).map(String::as_str).unwrap_or(""));
            }
        }
        Ok(found)
    }

    /// The device credential draft (NIP-DEVICE-CREDENTIAL in
    /// forgesworn/nip-drafts), person form, in its order.
    /// Returns the credential id, the named device key and the expiry.
    pub fn verify_person(
        &self,
        now: u64,
        policy: &BindingPolicy<'_>,
    ) -> Result<([u8; 32], [u8; 32], u64), ErrorCode> {
        let id = self.id();
        if schnorr_verify(&self.pubkey, &id, &self.sig) != Some(true) {
            return Err(ErrorCode::CredentialSignatureInvalid);
        }
        let d = self.single_tag("d")?;
        let scope = self.single_tag("scope")?;
        if d != Some(lower_hex(&self.pubkey).as_str()) || scope != Some("person") {
            return Err(ErrorCode::CredentialNotPersonScoped);
        }
        if policy
            .expected_identity
            .is_some_and(|expected| *expected != self.pubkey)
        {
            return Err(ErrorCode::CredentialWrongIdentity);
        }
        let device = self
            .single_tag("device")?
            .and_then(parse_lower_hex_32)
            .ok_or(ErrorCode::CredentialMalformed)?;
        let expiration = self
            .single_tag("expiration")?
            .and_then(parse_decimal)
            .ok_or(ErrorCode::CredentialMalformed)?;
        if expiration <= now {
            return Err(ErrorCode::CredentialExpired);
        }
        if self.created_at > now.saturating_add(MAX_CREATED_AT_SKEW_SECONDS) {
            return Err(ErrorCode::CredentialNotYetValid);
        }
        // Both bounds: a future-dated `created_at` must not stretch the
        // ceiling, so the expiry is also at most 30 days after now.
        if expiration.saturating_sub(self.created_at) > MAX_PERSON_CREDENTIAL_SECONDS
            || expiration - now > MAX_PERSON_CREDENTIAL_SECONDS
        {
            return Err(ErrorCode::CredentialLifetimeTooLong);
        }
        if policy.revoked_credentials.contains(&id) {
            return Err(ErrorCode::CredentialRevoked);
        }
        Ok((id, device, expiration))
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        cbor::write_map(out, CREDENTIAL_KEYS);
        cbor::write_uint(out, 1);
        cbor::write_bytes(out, &self.pubkey);
        cbor::write_uint(out, 2);
        cbor::write_uint(out, self.created_at);
        cbor::write_uint(out, 3);
        cbor::write_array(out, self.tags.len());
        for tag in &self.tags {
            cbor::write_array(out, tag.len());
            for value in tag {
                cbor::write_text(out, value);
            }
        }
        cbor::write_uint(out, 4);
        cbor::write_text(out, &self.content);
        cbor::write_uint(out, 5);
        cbor::write_bytes(out, &self.sig);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, ErrorCode> {
        reader.map(CREDENTIAL_KEYS)?;
        reader.key(1)?;
        let pubkey = reader.fixed()?;
        reader.key(2)?;
        let created_at = reader.timestamp()?;
        reader.key(3)?;
        let tag_count = reader.array_len(MAX_CREDENTIAL_TAGS)?;
        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            let value_count = reader.array_len(MAX_TAG_VALUES)?;
            if value_count == 0 {
                return Err(ErrorCode::Malformed);
            }
            let mut tag = Vec::with_capacity(value_count);
            for _ in 0..value_count {
                tag.push(reader.text(MAX_TAG_VALUE_BYTES)?.to_owned());
            }
            tags.push(tag);
        }
        reader.key(4)?;
        let content = reader.text(MAX_CONTENT_BYTES)?.to_owned();
        reader.key(5)?;
        let sig = reader.fixed()?;
        Ok(Self {
            pubkey,
            created_at,
            tags,
            content,
            sig,
        })
    }
}

impl LeafBinding {
    /// The MLS BasicCredential identity, `"vmls1" || leaf_id`.
    pub fn credential_identity(&self) -> [u8; CREDENTIAL_IDENTITY_BYTES] {
        let mut out = [0u8; CREDENTIAL_IDENTITY_BYTES];
        out[..5].copy_from_slice(CREDENTIAL_IDENTITY_PREFIX);
        out[5..].copy_from_slice(&self.leaf_id);
        out
    }

    fn write_body(&self, out: &mut Vec<u8>, entries: u64) {
        cbor::write_map(out, entries);
        cbor::write_uint(out, 1);
        cbor::write_uint(out, LEAF_BINDING_VERSION);
        cbor::write_uint(out, 2);
        cbor::write_bytes(out, &self.credential_identity());
        cbor::write_uint(out, 3);
        cbor::write_bytes(out, &self.signature_key);
        cbor::write_uint(out, 4);
        self.credential.encode_into(out);
        cbor::write_uint(out, 5);
        cbor::write_bytes(out, &self.device);
        cbor::write_uint(out, 6);
        cbor::write_uint(out, self.expires_at);
        cbor::write_uint(out, 7);
        cbor::write_bytes(out, &self.home_box);
    }

    /// The signed body: the canonical map of keys 1 to 7.
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        self.write_body(&mut out, BODY_KEYS);
        out
    }

    /// The 32-byte message the device key signs with BIP-340.
    pub fn signing_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(BINDING_SIGNATURE_TAG)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    /// The one canonical encoding, also the LeafNode extension data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1100);
        self.write_body(&mut out, BINDING_KEYS);
        cbor::write_uint(&mut out, 8);
        cbor::write_bytes(&mut out, &self.signature);
        out
    }

    /// Strictly decodes a binding. Nothing here checks a signature.
    pub fn decode(input: &[u8]) -> Result<Self, ErrorCode> {
        if input.len() > MAX_BINDING_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let mut reader = Reader::new(input);
        let binding = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(binding)
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, ErrorCode> {
        reader.map(BINDING_KEYS)?;
        reader.key(1)?;
        let version = reader.uint()?;
        if version != LEAF_BINDING_VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        reader.key(2)?;
        let identity: [u8; CREDENTIAL_IDENTITY_BYTES] = reader.fixed()?;
        if &identity[..5] != CREDENTIAL_IDENTITY_PREFIX {
            return Err(ErrorCode::BadLeafIdentity);
        }
        let mut leaf_id = [0u8; 32];
        leaf_id.copy_from_slice(&identity[5..]);
        reader.key(3)?;
        let signature_key = reader.fixed()?;
        reader.key(4)?;
        let credential = DeviceCredential::decode_from(reader)?;
        reader.key(5)?;
        let device = reader.fixed()?;
        reader.key(6)?;
        let expires_at = reader.timestamp()?;
        reader.key(7)?;
        let home_box = reader.fixed()?;
        reader.key(8)?;
        let signature = reader.fixed()?;
        Ok(Self {
            leaf_id,
            signature_key,
            credential,
            device,
            expires_at,
            home_box,
            signature,
        })
    }

    /// Verifies the carrying leaf, the device signature, the person
    /// credential, then the binding's own lifetime. The first failure is
    /// returned.
    ///
    /// `leaf` is the leaf carrying this binding: key 2 must equal its
    /// credential identity and key 3 its signature key, so a valid binding
    /// cannot be moved onto another leaf. Uniqueness of `leaf_id` within a
    /// group is the MLS engine's check.
    pub fn verify(
        &self,
        now: u64,
        leaf: &CarryingLeaf<'_>,
        policy: &BindingPolicy<'_>,
    ) -> Result<VerifiedBinding, ErrorCode> {
        if leaf.credential_identity != self.credential_identity().as_slice()
            || leaf.signature_key != self.signature_key.as_slice()
        {
            return Err(ErrorCode::BindingLeafMismatch);
        }
        match schnorr_verify(&self.device, &self.signing_digest(), &self.signature) {
            None => return Err(ErrorCode::BadDeviceKey),
            Some(false) => return Err(ErrorCode::BindingSignatureInvalid),
            Some(true) => {}
        }
        let (credential_id, device, credential_expires_at) =
            self.credential.verify_person(now, policy)?;
        if device != self.device {
            return Err(ErrorCode::CredentialWrongDevice);
        }
        if self.expires_at <= now {
            return Err(ErrorCode::BindingExpired);
        }
        if self.expires_at > credential_expires_at {
            return Err(ErrorCode::BindingOutlivesCredential);
        }
        Ok(VerifiedBinding {
            identity: self.credential.pubkey,
            device: self.device,
            leaf_id: self.leaf_id,
            signature_key: self.signature_key,
            expires_at: self.expires_at,
            home_box: self.home_box,
            credential_id,
            credential_expires_at,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde::Deserialize;

    pub(crate) fn hex(value: &str) -> Vec<u8> {
        assert!(value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()));
        (0..value.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn hex32(value: &str) -> [u8; 32] {
        hex(value).try_into().unwrap()
    }

    #[derive(Deserialize)]
    pub(crate) struct NostrEvent {
        pub id: String,
        pub pubkey: String,
        pub created_at: u64,
        pub kind: u16,
        pub tags: Vec<Vec<String>>,
        pub content: String,
        pub sig: String,
    }

    impl NostrEvent {
        pub(crate) fn credential(&self) -> DeviceCredential {
            DeviceCredential {
                pubkey: hex32(&self.pubkey),
                created_at: self.created_at,
                tags: self.tags.clone(),
                content: self.content.clone(),
                sig: hex(&self.sig).try_into().unwrap(),
            }
        }
    }

    #[derive(Deserialize)]
    struct CredentialSuite {
        now: u64,
        tombstone: NostrEvent,
        cases: Vec<CredentialCase>,
    }

    #[derive(Deserialize)]
    struct CredentialCase {
        name: String,
        event: NostrEvent,
        expect: CredentialExpect,
        #[serde(default)]
        tombstoned: bool,
        ok: bool,
    }

    #[derive(Deserialize)]
    struct CredentialExpect {
        identity: Option<String>,
    }

    /// The profile's own device-credential vectors, read by this verifier:
    /// every event id recomputes, every signature verifies, and the person
    /// rules agree with the reference verifier case by case.
    #[test]
    fn device_credential_vectors_agree_with_the_person_rules() {
        let suite: CredentialSuite =
            serde_json::from_str(include_str!("../../vectors/device-credential.json")).unwrap();
        assert_eq!(suite.tombstone.kind, 5);
        let revoked: Vec<[u8; 32]> = suite
            .tombstone
            .tags
            .iter()
            .filter(|tag| tag[0] == "e")
            .map(|tag| hex32(&tag[1]))
            .collect();
        for case in suite.cases {
            assert_eq!(case.event.kind, DEVICE_CREDENTIAL_KIND);
            let credential = case.event.credential();
            assert_eq!(credential.id(), hex32(&case.event.id), "{}", case.name);
            let Some(identity) = case.expect.identity.as_deref().map(hex32) else {
                // Room-form expectations: a person verifier must refuse every
                // room credential, and the room form is not this crate's job.
                if credential.single_tag("scope").unwrap().is_none() {
                    assert_eq!(
                        credential.verify_person(suite.now, &BindingPolicy::default()),
                        Err(ErrorCode::CredentialNotPersonScoped),
                        "{}",
                        case.name
                    );
                }
                continue;
            };
            let policy = BindingPolicy {
                expected_identity: Some(&identity),
                revoked_credentials: if case.tombstoned { &revoked } else { &[] },
            };
            let result = credential.verify_person(suite.now, &policy);
            assert_eq!(result.is_ok(), case.ok, "{}: {result:?}", case.name);
        }
    }

    #[test]
    fn json_escaping_matches_json_stringify() {
        let mut out = Vec::new();
        push_json_string(
            &mut out,
            "a\"b\\c\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}\u{2019}\u{2028}",
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}\u{2019}\u{2028}\""
        );
        assert_eq!(parse_decimal("0"), Some(0));
        for bad in [
            "",
            "01",
            "+1",
            "1e9",
            " 1",
            "9007199254740992",
            "12345678901234567",
        ] {
            assert_eq!(parse_decimal(bad), None, "{bad}");
        }
        assert_eq!(parse_lower_hex_32(&"AB".repeat(32)), None);
    }
}
