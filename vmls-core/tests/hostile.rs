//! Hostile input for every VMLS/1 parser: random bytes, every truncation,
//! every single-bit flip, oversize and non-canonical forms. The properties:
//! no parser panics; an accepted input re-encodes to exactly the same bytes
//! (so there is one encoding); and no mutation of a signed binding verifies.

mod common;

use common::{Lcg, TestAead, hex};
use serde_json::Value;
use vmls_core::ErrorCode;
use vmls_core::binding::{BindingPolicy, CarryingLeaf, LeafBinding, MAX_BINDING_BYTES};
use vmls_core::capability::{CapabilityRecord, MAX_CAPABILITY_BYTES};
use vmls_core::record::{self, MailboxKind};

fn vector(file: &str, name: &str, field: &str) -> Vec<u8> {
    let suite: Value = serde_json::from_str(file).unwrap();
    let case = suite["cases"]
        .as_array()
        .or(suite["records"].as_array())
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"));
    hex(case[field].as_str().unwrap())
}

fn valid_binding() -> Vec<u8> {
    vector(
        include_str!("../vectors/vmls-binding-v1.json"),
        "valid",
        "bindingHex",
    )
}

fn valid_capability() -> Vec<u8> {
    vector(
        include_str!("../vectors/vmls-capability-v1.json"),
        "valid",
        "capabilityHex",
    )
}

const NOW: u64 = 1_793_577_600;

/// The leaf that carries the published valid binding.
fn with_leaf<T>(f: impl FnOnce(&CarryingLeaf<'_>) -> T) -> T {
    let binding = LeafBinding::decode(&valid_binding()).unwrap();
    let identity = binding.credential_identity();
    f(&CarryingLeaf {
        credential_identity: &identity,
        signature_key: &binding.signature_key,
    })
}

fn binding_outcome(input: &[u8]) -> Result<(), ErrorCode> {
    let binding = LeafBinding::decode(input)?;
    assert_eq!(binding.encode(), input, "accepted bindings are canonical");
    with_leaf(|leaf| {
        binding
            .verify(NOW, leaf, &BindingPolicy::default())
            .map(|_| ())
    })
}

fn capability_outcome(input: &[u8]) -> Result<(), ErrorCode> {
    let capability = CapabilityRecord::decode(input)?;
    assert_eq!(
        capability.encode().unwrap(),
        input,
        "accepted capabilities are canonical"
    );
    with_leaf(|leaf| {
        capability
            .verify(NOW, leaf, &BindingPolicy::default())
            .map(|_| ())
    })
}

#[test]
fn binding_random_bytes_truncations_and_flips() {
    let valid = valid_binding();
    assert_eq!(binding_outcome(&valid), Ok(()));
    let mut lcg = Lcg(0xb1d1_0001);
    for len in 0..1024 {
        let mut bytes = lcg.bytes(len);
        if len > 0 && len % 2 == 0 {
            bytes[0] = 0xa8; // an eight-entry map, to reach the field parsers
        }
        let _ = binding_outcome(&bytes);
    }
    for len in 0..valid.len() {
        assert!(
            binding_outcome(&valid[..len]).is_err(),
            "truncation at {len}"
        );
    }
    for bit in 0..valid.len() * 8 {
        let mut flipped = valid.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        assert!(
            binding_outcome(&flipped).is_err(),
            "bit {bit} flipped and still verified"
        );
    }
    let mut oversize = valid.clone();
    oversize.resize(MAX_BINDING_BYTES + 1, 0);
    assert_eq!(LeafBinding::decode(&oversize), Err(ErrorCode::TooLarge));
}

#[test]
fn binding_structural_splices_are_refused() {
    let valid = valid_binding();
    // Every prefix spliced onto every other suffix: exercises misaligned
    // heads, claimed lengths beyond the input and wrong major types.
    let mut lcg = Lcg(0x5911_ce00);
    for _ in 0..4000 {
        let cut = usize::from(lcg.byte()) * valid.len() / 256;
        let resume = usize::from(lcg.byte()) * valid.len() / 256;
        if cut == resume {
            continue;
        }
        let mut spliced = valid[..cut].to_vec();
        spliced.extend_from_slice(&valid[resume..]);
        let _ = binding_outcome(&spliced);
    }
    // A claimed length far beyond the input never allocates or panics.
    for head in [0x5a, 0x5b, 0x7a, 0x7b, 0x9a, 0x9b, 0xba, 0xbb] {
        let mut bytes = vec![0xa8, 0x01, 0x01, 0x02, head];
        bytes.extend_from_slice(&[0xff; 8]);
        assert!(LeafBinding::decode(&bytes).is_err());
    }
}

#[test]
fn capability_random_bytes_truncations_and_flips() {
    let valid = valid_capability();
    assert_eq!(capability_outcome(&valid), Ok(()));
    let binding_at = valid
        .windows(valid_binding().len())
        .position(|window| window == valid_binding())
        .unwrap();
    let binding_end = binding_at + valid_binding().len();
    let mut lcg = Lcg(0xca9a_0001);
    for len in 0..1024 {
        let mut bytes = lcg.bytes(len);
        if len > 0 && len % 2 == 0 {
            bytes[0] = 0xa8;
        }
        let _ = capability_outcome(&bytes);
    }
    for len in 0..valid.len() {
        assert!(
            capability_outcome(&valid[..len]).is_err(),
            "truncation at {len}"
        );
    }
    for bit in 0..valid.len() * 8 {
        let mut flipped = valid.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        let outcome = capability_outcome(&flipped);
        // The capability record is sealed, not signed: a flip in an unsigned
        // field may still parse. A flip anywhere in the binding must not.
        if (binding_at..binding_end).contains(&(bit / 8)) {
            assert!(outcome.is_err(), "bit {bit} in the binding still verified");
        }
    }
    let mut oversize = valid.clone();
    oversize.resize(MAX_CAPABILITY_BYTES + 1, 0);
    assert_eq!(
        CapabilityRecord::decode(&oversize),
        Err(ErrorCode::TooLarge)
    );
}

#[test]
fn record_random_bytes_truncations_and_flips_are_silent_drops() {
    let suite: Value =
        serde_json::from_str(include_str!("../vectors/vmls-record-v1.json")).unwrap();
    let case = suite["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "mls-message")
        .unwrap();
    let secret: [u8; 32] = hex(case["recordSecretHex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let mailbox: [u8; 32] = hex(case["mailboxHex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let valid = hex(case["sealedHex"].as_str().unwrap());
    assert!(record::open(&TestAead, &secret, &mailbox, &valid, MailboxKind::Leaf).is_ok());
    let mut lcg = Lcg(0x4ec0_0001);
    for len in [0usize, 1, 32, 47, 48, 49, 1023, 1024, 1025, 4096, 16_384] {
        for _ in 0..8 {
            assert!(
                record::open(
                    &TestAead,
                    &secret,
                    &mailbox,
                    &lcg.bytes(len),
                    MailboxKind::Leaf
                )
                .is_err()
            );
        }
    }
    for len in 0..valid.len() {
        assert!(
            record::open(
                &TestAead,
                &secret,
                &mailbox,
                &valid[..len],
                MailboxKind::Leaf
            )
            .is_err()
        );
    }
    for bit in 0..valid.len() * 8 {
        let mut flipped = valid.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            record::open(&TestAead, &secret, &mailbox, &flipped, MailboxKind::Leaf)
                .map_err(|drop| drop.0),
            Err(ErrorCode::OuterSealFailed)
        );
    }
    let mut oversize = valid.clone();
    oversize.resize(record::BUCKETS[4] + 1, 0);
    assert_eq!(
        record::open(&TestAead, &secret, &mailbox, &oversize, MailboxKind::Leaf)
            .map_err(|drop| drop.0),
        Err(ErrorCode::BadRecordLength)
    );
}

#[test]
fn record_plaintext_hostile_forms_inside_a_valid_seal() {
    // The inner parser sees only authenticated bytes, but a member can still
    // send anything; it must refuse without panicking.
    let mut lcg = Lcg(0x91a1_0001);
    for bucket in record::BUCKETS.into_iter().take(3) {
        let len = bucket - record::RECORD_OVERHEAD;
        for round in 0..512 {
            let mut bytes = vec![0u8; len];
            let prefix = 1 + round % 24;
            bytes[..prefix].copy_from_slice(&lcg.bytes(prefix));
            if round % 2 == 0 {
                bytes[..2].copy_from_slice(&[0xa2, 0x01]);
            }
            if let Ok(inner) = record::decode_plaintext(&bytes) {
                assert_eq!(record::encode_plaintext(&inner).unwrap(), bytes);
            }
        }
    }
}
