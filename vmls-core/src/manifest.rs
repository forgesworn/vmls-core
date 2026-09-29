//! The canonical state manifest a restore witness protects (contract §4.4).
//!
//! ```text
//! manifest = [1, subject bstr32, installation bstr32,
//!             schema_manifest_hash bstr32, entries]
//! entries  = [[key bstr, value_hash bstr32], ...]   sorted by key bytes
//! key      = canonical CBOR [namespace tstr, primary_key_fields...]
//! value_hash = SHA-256(canonical CBOR value)
//! digest   = SHA-256("VMLS/1 state manifest" || manifest)
//! ```
//!
//! Every encoding is definite-length with shortest heads. Keys are compared
//! as raw bytes, lexicographically; a duplicate key is refused. Values keep
//! their type: the byte string `a`, the text `a`, `0` and null all hash
//! differently. Which tables and columns are covered, and in what order, is
//! the adapter's frozen schema manifest, whose hash is bound here.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::ErrorCode;
use crate::cbor;

/// The only manifest version.
pub const MANIFEST_VERSION: u64 = 1;
/// Domain tag for the state digest.
pub const MANIFEST_TAG: &[u8] = b"VMLS/1 state manifest";

/// A column value, a primary-key field, or a row of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
}

impl Value {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => cbor::write_null(out),
            Self::Int(value) => cbor::write_int(out, *value),
            Self::Bytes(bytes) => cbor::write_bytes(out, bytes),
            Self::Text(text) => cbor::write_text(out, text),
            Self::Array(items) => {
                cbor::write_array(out, items.len());
                for item in items {
                    item.encode_into(out);
                }
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
}

/// The key bytes for one record: `[namespace, primary_key...]`.
pub fn entry_key(namespace: &str, primary_key: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_array(&mut out, 1 + primary_key.len());
    cbor::write_text(&mut out, namespace);
    for field in primary_key {
        field.encode_into(&mut out);
    }
    out
}

/// SHA-256 of the canonical encoding of `value`.
pub fn value_hash(value: &Value) -> [u8; 32] {
    Sha256::digest(value.encode()).into()
}

/// A manifest under construction. Entries may arrive in any order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub subject: [u8; 32],
    pub installation: [u8; 32],
    pub schema_manifest_hash: [u8; 32],
    entries: BTreeMap<Vec<u8>, [u8; 32]>,
}

impl Manifest {
    pub fn new(subject: [u8; 32], installation: [u8; 32], schema_manifest_hash: [u8; 32]) -> Self {
        Self {
            subject,
            installation,
            schema_manifest_hash,
            entries: BTreeMap::new(),
        }
    }

    /// Adds one record. A second record with the same key is refused.
    pub fn insert(
        &mut self,
        namespace: &str,
        primary_key: &[Value],
        value: &Value,
    ) -> Result<(), ErrorCode> {
        self.insert_hashed(entry_key(namespace, primary_key), value_hash(value))
    }

    /// Adds one record from an already-encoded key and a cached value hash,
    /// for adapters that keep per-row hashes. The result must equal a full
    /// recomputation.
    pub fn insert_hashed(&mut self, key: Vec<u8>, value_hash: [u8; 32]) -> Result<(), ErrorCode> {
        match self.entries.entry(key) {
            std::collections::btree_map::Entry::Occupied(_) => Err(ErrorCode::NonCanonical),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(value_hash);
                Ok(())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_array(&mut out, 5);
        cbor::write_uint(&mut out, MANIFEST_VERSION);
        cbor::write_bytes(&mut out, &self.subject);
        cbor::write_bytes(&mut out, &self.installation);
        cbor::write_bytes(&mut out, &self.schema_manifest_hash);
        cbor::write_array(&mut out, self.entries.len());
        for (key, hash) in &self.entries {
            cbor::write_array(&mut out, 2);
            cbor::write_bytes(&mut out, key);
            cbor::write_bytes(&mut out, hash);
        }
        out
    }

    /// The digest the witness stores.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(MANIFEST_TAG)
            .chain_update(self.encode())
            .finalize()
            .into()
    }
}
