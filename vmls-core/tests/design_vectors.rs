//! The frozen design bytes for slot receipts, witness receipts, fork
//! evidence and the fork derivations, plus the witness-request and state
//! manifest suites. Expected values come only from
//! `vectors/vmls-security-design-v1.json`, produced independently with
//! node:crypto and noble, never from these codecs.

mod common;

use common::{hex, hex32};
use serde::Deserialize;
use vmls_core::ErrorCode;
use vmls_core::derive;
use vmls_core::evidence::{self, ForkEvidence};
use vmls_core::manifest::{self, Manifest, Value};
use vmls_core::receipt::{self, SlotReceipt, WitnessReceipt, WitnessStatus};
use vmls_core::witness::{AdvanceRequest, ReadRequest};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Design {
    node_hex: String,
    installation_hex: String,
    envelope_hex: String,
    other_envelope_hex: String,
    slot_receipt_hex: String,
    other_slot_receipt_hex: String,
    slot_digest_hex: String,
    evidence_hex: String,
    relabelled_slot_receipt_hex: String,
    relabelled_evidence_hex: String,
    attempt_order_evidence_hex: String,
    foreign_installation_hex: String,
    foreign_slot_receipt_hex: String,
    witness_hex: String,
    epoch_secret_hex: String,
    leaf_hex: String,
    fork_mailbox_hex: String,
    fork_record_secret_hex: String,
}

fn design() -> Design {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/vmls-security-design-v1.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const CHALLENGE: [u8; 32] = [0x77; 32];

#[test]
fn slot_receipts_verify_and_round_trip() {
    let d = design();
    let node = hex32(&d.node_hex);
    for (raw, envelope) in [
        (hex(&d.slot_receipt_hex), hex(&d.envelope_hex)),
        (hex(&d.other_slot_receipt_hex), hex(&d.other_envelope_hex)),
    ] {
        let parsed = SlotReceipt::verified(&raw, &node).unwrap();
        assert_eq!(parsed.encode().as_slice(), raw.as_slice());
        assert_eq!(parsed.envelope_hash, receipt::envelope_hash(&envelope));
        assert_eq!(parsed.installation, hex32(&d.installation_hex));
    }
    let first = SlotReceipt::parse(&hex(&d.slot_receipt_hex)).unwrap();
    assert_eq!(first.digest(), hex32(&d.slot_digest_hex));
    assert_eq!(
        receipt::slot_digest(
            &first.installation,
            &first.slot,
            first.attempt,
            &first.envelope_hash
        ),
        hex32(&d.slot_digest_hex)
    );

    let relabelled = SlotReceipt::verified(&hex(&d.relabelled_slot_receipt_hex), &node).unwrap();
    assert_eq!(relabelled.envelope_hash, first.envelope_hash);
    assert_eq!(relabelled.attempt, first.attempt + 1);
    let foreign = SlotReceipt::verified(&hex(&d.foreign_slot_receipt_hex), &node).unwrap();
    assert_eq!(foreign.installation, hex32(&d.foreign_installation_hex));
    assert!(!foreign.same_slot(&first));
}

#[test]
fn the_installation_is_inside_the_signed_digest() {
    let d = design();
    let node = hex32(&d.node_hex);
    let mut moved = SlotReceipt::parse(&hex(&d.slot_receipt_hex)).unwrap();
    moved.installation = hex32(&d.foreign_installation_hex);
    assert_eq!(
        SlotReceipt::verified(&moved.encode(), &node),
        Err(ErrorCode::ReceiptSignatureInvalid)
    );
}

#[test]
fn every_single_bit_flip_of_a_slot_receipt_refuses() {
    let d = design();
    let node = hex32(&d.node_hex);
    for raw in [hex(&d.slot_receipt_hex), hex(&d.other_slot_receipt_hex)] {
        for at in 0..raw.len() {
            for bit in 0..8 {
                let mut changed = raw.clone();
                changed[at] ^= 1 << bit;
                assert!(
                    SlotReceipt::verified(&changed, &node).is_err(),
                    "byte {at} bit {bit}"
                );
            }
        }
    }
}

#[test]
fn slot_receipt_refusals_are_specific() {
    let d = design();
    let node = hex32(&d.node_hex);
    let raw = hex(&d.slot_receipt_hex);
    assert_eq!(
        SlotReceipt::verified(&raw, &[0; 32]),
        Err(ErrorCode::ReceiptWrongNode)
    );
    assert_eq!(
        SlotReceipt::verified(&raw[..196], &node),
        Err(ErrorCode::Malformed)
    );
    let mut long = raw.clone();
    long.push(0);
    assert_eq!(
        SlotReceipt::verified(&long, &node),
        Err(ErrorCode::Malformed)
    );
    let mut version = raw.clone();
    version[0] = 2;
    assert_eq!(
        SlotReceipt::verified(&version, &node),
        Err(ErrorCode::UnsupportedVersion)
    );
    let mut signature = raw.clone();
    signature[196] ^= 1;
    assert_eq!(
        SlotReceipt::verified(&signature, &node),
        Err(ErrorCode::ReceiptSignatureInvalid)
    );
    let mut attempt = raw;
    attempt[100] ^= 1;
    assert_eq!(
        SlotReceipt::verified(&attempt, &node),
        Err(ErrorCode::ReceiptSignatureInvalid)
    );
}

#[test]
fn witness_receipt_verifies_and_refuses() {
    let d = design();
    let node = hex32(&d.node_hex);
    let raw = hex(&d.witness_hex);
    let parsed = WitnessReceipt::verified(&raw, &node, &CHALLENGE).unwrap();
    assert_eq!(parsed.status, WitnessStatus::Current);
    assert_eq!(parsed.seq, 9);
    assert_eq!(parsed.encode().as_slice(), raw.as_slice());

    assert_eq!(
        WitnessReceipt::verified(&raw, &node, &[0x78; 32]),
        Err(ErrorCode::WitnessChallengeMismatch)
    );
    assert_eq!(
        WitnessReceipt::verified(&raw, &[0; 32], &CHALLENGE),
        Err(ErrorCode::ReceiptSignatureInvalid)
    );
    for at in 0..raw.len() {
        let mut changed = raw.clone();
        changed[at] ^= 1;
        assert!(
            WitnessReceipt::verified(&changed, &node, &CHALLENGE).is_err(),
            "byte {at}"
        );
    }
    let mut status = raw.clone();
    status[1] = 3;
    assert_eq!(WitnessReceipt::parse(&status), Err(ErrorCode::Malformed));
    let mut overflow = raw.clone();
    overflow[34..42].copy_from_slice(&(1u64 << 53).to_be_bytes());
    assert_eq!(WitnessReceipt::parse(&overflow), Err(ErrorCode::Malformed));
    assert_eq!(
        WitnessReceipt::parse(&raw[..169]),
        Err(ErrorCode::Malformed)
    );
}

#[test]
fn evidence_is_a_verified_equivocation_pair() {
    let d = design();
    let node = hex32(&d.node_hex);
    let raw = hex(&d.evidence_hex);
    assert_eq!(raw.len(), evidence::TWO_RECEIPT_BYTES);
    let parsed = ForkEvidence::parse(&raw).unwrap();
    parsed.verify(&node).unwrap();
    assert_eq!(parsed.pre_epoch(), 7);
    assert_eq!(parsed.encode(), raw);
    let ForkEvidence::Equivocation { first, second, .. } = &parsed else {
        panic!("expected a pair");
    };
    assert_eq!(
        ForkEvidence::equivocation(7, second.clone(), first.clone()).unwrap(),
        parsed,
        "a pair built in either order encodes canonically"
    );
    assert_eq!(parsed.verify(&[0; 32]), Err(ErrorCode::ReceiptWrongNode));
}

#[test]
fn evidence_layout_rules_refuse() {
    let d = design();
    let raw = hex(&d.evidence_hex);
    let one = hex(&d.slot_receipt_hex);
    let header = |count: u8| {
        let mut out = vec![1];
        out.extend_from_slice(&7u64.to_be_bytes());
        out.push(count);
        out
    };

    let mut single = header(1);
    single.extend_from_slice(&one);
    assert_eq!(single.len(), evidence::ONE_RECEIPT_BYTES);
    assert!(matches!(
        ForkEvidence::parse(&single),
        Ok(ForkEvidence::Observation { .. })
    ));
    assert_eq!(ForkEvidence::parse(&single).unwrap().encode(), single);

    let mut wrong_count = raw.clone();
    wrong_count[9] = 1;
    assert_eq!(ForkEvidence::parse(&wrong_count), Err(ErrorCode::Malformed));
    for count in [0, 3] {
        let mut bad = raw.clone();
        bad[9] = count;
        assert_eq!(ForkEvidence::parse(&bad), Err(ErrorCode::Malformed));
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(ForkEvidence::parse(&trailing), Err(ErrorCode::Malformed));
    let mut version = raw.clone();
    version[0] = 2;
    assert_eq!(
        ForkEvidence::parse(&version),
        Err(ErrorCode::UnsupportedVersion)
    );

    let (first, second) = raw[10..].split_at(197);
    let mut descending = header(2);
    descending.extend_from_slice(second);
    descending.extend_from_slice(first);
    assert_eq!(
        ForkEvidence::parse(&descending),
        Err(ErrorCode::EvidenceNotEquivocation)
    );
    let mut duplicate = header(2);
    duplicate.extend_from_slice(first);
    duplicate.extend_from_slice(first);
    assert_eq!(
        ForkEvidence::parse(&duplicate),
        Err(ErrorCode::EvidenceNotEquivocation)
    );
    // Node, installation or slot differ: never one slot's pair.
    for offset in [1, 33, 65] {
        let mut moved = raw.clone();
        moved[10 + 197 + offset] ^= 1;
        assert_eq!(
            ForkEvidence::parse(&moved),
            Err(ErrorCode::EvidenceNotEquivocation),
            "second receipt differs at field offset {offset}"
        );
    }
    // A higher attempt on the second receipt keeps the order ascending, so
    // the layout accepts it (P2-R-01); its signature then fails.
    let mut later = raw.clone();
    later[10 + 197 + 100] ^= 4;
    let parsed = ForkEvidence::parse(&later).unwrap();
    assert_eq!(
        parsed.verify(&hex32(&d.node_hex)),
        Err(ErrorCode::ReceiptSignatureInvalid)
    );

    // A pair whose receipts name different installations (T40). The foreign
    // receipt has the relabelled receipt's key, which does pair with the
    // slot receipt, so only the installation refuses it.
    let slot_receipt = hex(&d.slot_receipt_hex);
    let a = SlotReceipt::parse(&slot_receipt).unwrap();
    let relabelled = SlotReceipt::parse(&hex(&d.relabelled_slot_receipt_hex)).unwrap();
    let foreign = SlotReceipt::parse(&hex(&d.foreign_slot_receipt_hex)).unwrap();
    assert_eq!(foreign.pair_key(), relabelled.pair_key());
    assert!(ForkEvidence::equivocation(7, a.clone(), relabelled).is_ok());
    let mut mixed = header(2);
    mixed.extend_from_slice(&slot_receipt);
    mixed.extend_from_slice(&hex(&d.foreign_slot_receipt_hex));
    assert_eq!(
        ForkEvidence::parse(&mixed),
        Err(ErrorCode::EvidenceNotEquivocation)
    );
    assert_eq!(
        ForkEvidence::equivocation(7, a, foreign),
        Err(ErrorCode::EvidenceNotEquivocation)
    );
}

#[test]
fn per_slot_pairs_order_by_attempt_then_hash() {
    let d = design();
    let node = hex32(&d.node_hex);
    for raw in [
        hex(&d.relabelled_evidence_hex),
        hex(&d.attempt_order_evidence_hex),
    ] {
        assert_eq!(raw.len(), evidence::TWO_RECEIPT_BYTES);
        let parsed = ForkEvidence::parse(&raw).unwrap();
        parsed.verify(&node).unwrap();
        assert_eq!(parsed.encode(), raw);
        let ForkEvidence::Equivocation { first, second, .. } = &parsed else {
            panic!("expected a pair");
        };
        assert_eq!(first.attempt + 1, second.attempt);
        assert_eq!(
            ForkEvidence::equivocation(7, second.clone(), first.clone()).unwrap(),
            parsed
        );

        let mut descending = raw[..10].to_vec();
        descending.extend_from_slice(&raw[10 + 197..]);
        descending.extend_from_slice(&raw[10..10 + 197]);
        assert_eq!(
            ForkEvidence::parse(&descending),
            Err(ErrorCode::EvidenceNotEquivocation)
        );
    }

    // One hash under two labels.
    let ForkEvidence::Equivocation { first, second, .. } =
        ForkEvidence::parse(&hex(&d.relabelled_evidence_hex)).unwrap()
    else {
        panic!("expected a pair");
    };
    assert_eq!(first.envelope_hash, second.envelope_hash);

    // The attempt decides before the hash.
    let ForkEvidence::Equivocation { first, second, .. } =
        ForkEvidence::parse(&hex(&d.attempt_order_evidence_hex)).unwrap()
    else {
        panic!("expected a pair");
    };
    assert!(first.envelope_hash > second.envelope_hash);
}

#[test]
fn fork_derivations_match() {
    let d = design();
    let secret = hex32(&d.epoch_secret_hex);
    let leaf = hex32(&d.leaf_hex);
    let mailbox = derive::fork_mailbox(&secret, &leaf);
    assert_eq!(mailbox, hex32(&d.fork_mailbox_hex));
    assert_eq!(
        derive::fork_record_secret(&secret, &leaf, &mailbox),
        hex32(&d.fork_record_secret_hex)
    );
    assert_ne!(mailbox, derive::mailbox(&secret, &leaf));
}

#[derive(Deserialize)]
struct WitnessSuite {
    cases: Vec<WitnessCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessCase {
    name: String,
    op: String,
    body_hex: String,
    expect: WitnessExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessExpect {
    ok: bool,
    error: Option<String>,
    subject_hex: Option<String>,
    challenge_hex: Option<String>,
    expected_seq: Option<u64>,
    expected_digest_hex: Option<String>,
    next_digest_hex: Option<String>,
}

#[test]
fn witness_request_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/vmls-witness-request-v1.json"
    );
    let suite: WitnessSuite =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(!suite.cases.is_empty());
    for case in suite.cases {
        let body = hex(&case.body_hex);
        let e = &case.expect;
        let field = |v: &Option<String>| hex32(v.as_deref().unwrap());
        match (case.op.as_str(), e.ok) {
            ("read", true) => {
                let parsed = ReadRequest::parse(&body).unwrap();
                assert_eq!(parsed.subject, field(&e.subject_hex), "{}", case.name);
                assert_eq!(parsed.challenge, field(&e.challenge_hex), "{}", case.name);
                assert_eq!(parsed.encode(), body, "{}", case.name);
            }
            ("advance", true) => {
                let parsed = AdvanceRequest::parse(&body).unwrap();
                let expected = AdvanceRequest {
                    subject: field(&e.subject_hex),
                    expected_seq: e.expected_seq.unwrap(),
                    expected_digest: field(&e.expected_digest_hex),
                    next_digest: field(&e.next_digest_hex),
                    challenge: field(&e.challenge_hex),
                };
                assert_eq!(parsed, expected, "{}", case.name);
                assert_eq!(parsed.encode(), body, "{}", case.name);
            }
            (op, false) => {
                let error = ErrorCode::from_code(e.error.as_deref().unwrap()).unwrap();
                let actual = match op {
                    "read" => ReadRequest::parse(&body).map(drop),
                    "advance" => AdvanceRequest::parse(&body).map(drop),
                    other => panic!("op {other}"),
                };
                assert_eq!(actual, Err(error), "{}", case.name);
            }
            (other, _) => panic!("op {other}"),
        }
    }
}

#[derive(Deserialize)]
struct ManifestSuite {
    cases: Vec<ManifestCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestCase {
    name: String,
    subject_hex: String,
    installation_hex: String,
    schema_manifest_hash_hex: String,
    entries: Vec<ManifestEntry>,
    manifest_hex: String,
    digest_hex: String,
}

#[derive(Deserialize)]
struct ManifestEntry {
    namespace: String,
    key: Vec<TypedValue>,
    value: TypedValue,
}

#[derive(Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum TypedValue {
    Null,
    Int { v: i64 },
    Bytes { hex: String },
    Text { v: String },
    Array { items: Vec<TypedValue> },
}

impl TypedValue {
    fn value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Int { v } => Value::Int(*v),
            Self::Bytes { hex: h } => Value::Bytes(hex(h)),
            Self::Text { v } => Value::Text(v.clone()),
            Self::Array { items } => Value::Array(items.iter().map(Self::value).collect()),
        }
    }
}

#[test]
fn manifest_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/vmls-manifest-v1.json");
    let suite: ManifestSuite =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(!suite.cases.is_empty());
    for case in suite.cases {
        let mut manifest = Manifest::new(
            hex32(&case.subject_hex),
            hex32(&case.installation_hex),
            hex32(&case.schema_manifest_hash_hex),
        );
        for entry in &case.entries {
            let key: Vec<Value> = entry.key.iter().map(TypedValue::value).collect();
            manifest
                .insert(&entry.namespace, &key, &entry.value.value())
                .unwrap();
        }
        assert_eq!(manifest.encode(), hex(&case.manifest_hex), "{}", case.name);
        assert_eq!(manifest.digest(), hex32(&case.digest_hex), "{}", case.name);

        // A cached per-row hash gives the same manifest as recomputing.
        let mut cached = Manifest::new(
            manifest.subject,
            manifest.installation,
            manifest.schema_manifest_hash,
        );
        for entry in case.entries.iter().rev() {
            let key: Vec<Value> = entry.key.iter().map(TypedValue::value).collect();
            cached
                .insert_hashed(
                    manifest::entry_key(&entry.namespace, &key),
                    manifest::value_hash(&entry.value.value()),
                )
                .unwrap();
        }
        assert_eq!(cached.digest(), manifest.digest(), "{}", case.name);
    }
}

#[test]
fn manifest_refuses_a_duplicate_key() {
    let mut manifest = Manifest::new([1; 32], [2; 32], [3; 32]);
    manifest
        .insert("x", &[Value::Int(1)], &Value::Null)
        .unwrap();
    assert_eq!(
        manifest.insert("x", &[Value::Int(1)], &Value::Int(0)),
        Err(ErrorCode::NonCanonical)
    );
    assert_eq!(manifest.len(), 1);
}

#[test]
fn negative_integers_use_major_type_one() {
    assert_eq!(Value::Int(-1).encode(), [0x20]);
    assert_eq!(Value::Int(-25).encode(), [0x38, 0x18]);
    assert_eq!(
        Value::Int(i64::MIN).encode(),
        [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(Value::Int(i64::MAX).encode()[0], 0x1b);
}
