//! The published VMLS/1 known-answer suites, read by the Rust codecs.
//! They are produced by `vectors/generate-vmls.mjs` with noble and
//! node:crypto and read independently by `vectors/verify-vmls.mjs`.

mod common;

use common::{TestAead, hex, hex32};
use serde::Deserialize;
use vmls_core::ErrorCode;
use vmls_core::binding::{BindingPolicy, CarryingLeaf, LeafBinding};
use vmls_core::capability::CapabilityRecord;
use vmls_core::derive;
use vmls_core::lane::{self, Choice, Conversation, GroupState, LaneInput};
use vmls_core::record::{self, InnerRecord, MailboxKind, RecordType};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeafJson {
    identity_hex: String,
    signature_key_hex: String,
}

/// The carrying leaf's identity and signature key: a case's override, or
/// the suite's leaf.
fn carrier(leaf: &LeafJson, identity: &Option<String>, key: &Option<String>) -> (Vec<u8>, Vec<u8>) {
    (
        hex(identity.as_deref().unwrap_or(&leaf.identity_hex)),
        hex(key.as_deref().unwrap_or(&leaf.signature_key_hex)),
    )
}

fn code(name: &str) -> ErrorCode {
    ErrorCode::from_code(name).unwrap_or_else(|| panic!("unknown vector error {name}"))
}

// ---- leaf-binding/1 ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindingSuite {
    now: u64,
    revoked_credential_ids: Vec<String>,
    leaf: LeafJson,
    cases: Vec<BindingCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindingCase {
    name: String,
    binding_hex: String,
    expected_identity_hex: Option<String>,
    #[serde(default)]
    revoked: bool,
    leaf_identity_hex: Option<String>,
    leaf_signature_key_hex: Option<String>,
    expect: BindingExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindingExpect {
    ok: bool,
    error: Option<String>,
    identity_hex: Option<String>,
    device_hex: Option<String>,
    leaf_id_hex: Option<String>,
    credential_id_hex: Option<String>,
    expires_at: Option<u64>,
    home_box_hex: Option<String>,
}

#[test]
fn binding_suite_matches() {
    let suite: BindingSuite =
        serde_json::from_str(include_str!("../vectors/vmls-binding-v1.json")).unwrap();
    let revoked: Vec<[u8; 32]> = suite
        .revoked_credential_ids
        .iter()
        .map(|id| hex32(id))
        .collect();
    assert!(suite.cases.len() >= 30);
    for case in suite.cases {
        let input = hex(&case.binding_hex);
        let expected = case.expected_identity_hex.as_deref().map(hex32);
        let policy = BindingPolicy {
            expected_identity: expected.as_ref(),
            revoked_credentials: if case.revoked { &revoked } else { &[] },
        };
        let result = LeafBinding::decode(&input).and_then(|binding| {
            // Every accepted encoding is the one canonical encoding.
            assert_eq!(binding.encode(), input, "{}", case.name);
            let (identity, key) = carrier(
                &suite.leaf,
                &case.leaf_identity_hex,
                &case.leaf_signature_key_hex,
            );
            let leaf = CarryingLeaf {
                credential_identity: &identity,
                signature_key: &key,
            };
            binding.verify(suite.now, &leaf, &policy)
        });
        if case.expect.ok {
            let verified = result.unwrap_or_else(|e| panic!("{}: {e}", case.name));
            let e = &case.expect;
            assert_eq!(verified.identity, hex32(e.identity_hex.as_deref().unwrap()));
            assert_eq!(verified.device, hex32(e.device_hex.as_deref().unwrap()));
            assert_eq!(verified.leaf_id, hex32(e.leaf_id_hex.as_deref().unwrap()));
            assert_eq!(
                verified.credential_id,
                hex32(e.credential_id_hex.as_deref().unwrap()),
                "{}",
                case.name
            );
            assert_eq!(verified.expires_at, e.expires_at.unwrap());
            assert_eq!(verified.home_box, hex32(e.home_box_hex.as_deref().unwrap()));
        } else {
            assert_eq!(
                result.err(),
                Some(code(case.expect.error.as_deref().unwrap())),
                "{}",
                case.name
            );
        }
    }
}

// ---- capability/1 ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitySuite {
    now: u64,
    revoked_credential_ids: Vec<String>,
    leaf: LeafJson,
    cases: Vec<CapabilityCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityCase {
    name: String,
    capability_hex: String,
    expected_identity_hex: Option<String>,
    #[serde(default)]
    revoked: bool,
    leaf_identity_hex: Option<String>,
    leaf_signature_key_hex: Option<String>,
    expect: CapabilityExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityExpect {
    ok: bool,
    error: Option<String>,
    package_id_hex: Option<String>,
    key_package_hex: Option<String>,
    welcome_mailbox_hex: Option<String>,
    welcome_transport_hex: Option<String>,
    welcome_secret_hex: Option<String>,
    expires_at: Option<u64>,
    identity_hex: Option<String>,
    leaf_id_hex: Option<String>,
    binding_expires_at: Option<u64>,
}

#[test]
fn capability_suite_matches() {
    let suite: CapabilitySuite =
        serde_json::from_str(include_str!("../vectors/vmls-capability-v1.json")).unwrap();
    let revoked: Vec<[u8; 32]> = suite
        .revoked_credential_ids
        .iter()
        .map(|id| hex32(id))
        .collect();
    for case in suite.cases {
        let input = hex(&case.capability_hex);
        let expected = case.expected_identity_hex.as_deref().map(hex32);
        let policy = BindingPolicy {
            expected_identity: expected.as_ref(),
            revoked_credentials: if case.revoked { &revoked } else { &[] },
        };
        let decoded = CapabilityRecord::decode(&input);
        let result = decoded.clone().and_then(|capability| {
            assert_eq!(capability.encode().unwrap(), input, "{}", case.name);
            let (identity, key) = carrier(
                &suite.leaf,
                &case.leaf_identity_hex,
                &case.leaf_signature_key_hex,
            );
            let leaf = CarryingLeaf {
                credential_identity: &identity,
                signature_key: &key,
            };
            capability.verify(suite.now, &leaf, &policy)
        });
        if case.expect.ok {
            let e = &case.expect;
            let capability = decoded.unwrap();
            let verified = result.unwrap_or_else(|err| panic!("{}: {err}", case.name));
            assert_eq!(
                verified.package_id,
                hex32(e.package_id_hex.as_deref().unwrap())
            );
            assert_eq!(
                capability.key_package,
                hex(e.key_package_hex.as_deref().unwrap())
            );
            assert_eq!(
                capability.welcome_mailbox,
                hex32(e.welcome_mailbox_hex.as_deref().unwrap())
            );
            assert_eq!(
                capability.welcome_transport,
                hex32(e.welcome_transport_hex.as_deref().unwrap())
            );
            assert_eq!(
                capability.welcome_secret,
                hex32(e.welcome_secret_hex.as_deref().unwrap())
            );
            assert_eq!(verified.expires_at, e.expires_at.unwrap());
            assert_eq!(
                verified.binding.identity,
                hex32(e.identity_hex.as_deref().unwrap())
            );
            assert_eq!(
                verified.binding.leaf_id,
                hex32(e.leaf_id_hex.as_deref().unwrap())
            );
            assert_eq!(verified.binding.expires_at, e.binding_expires_at.unwrap());
        } else {
            assert_eq!(
                result.err(),
                Some(code(case.expect.error.as_deref().unwrap())),
                "{}",
                case.name
            );
        }
    }
}

// ---- derivations and records ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordSuite {
    exporter: Exporter,
    buckets: Vec<usize>,
    derivations: Derivations,
    records: Vec<RecordCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Exporter {
    label: String,
    context_hex: String,
    length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Derivations {
    epoch_secret_hex: String,
    leaves: Vec<Leaf>,
    commit_slots: Vec<CommitSlot>,
    commit_hash: CommitHash,
    record_keys: Vec<RecordKey>,
    introduction: Introduction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Leaf {
    leaf_id_hex: String,
    mailbox_hex: String,
    record_secret_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitSlot {
    attempt: u32,
    slot_hex: String,
    record_secret_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitHash {
    message_hex: String,
    hash_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordKey {
    record_secret_hex: String,
    record_id_hex: String,
    key_hex: String,
    nonce_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Introduction {
    test_only_joiner_rz_priv_hex: String,
    test_only_adder_rz_priv_hex: String,
    joiner_rz_hex: String,
    adder_rz_hex: String,
    ecdh_x_hex: String,
    cases: Vec<IntroductionCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntroductionCase {
    recipient_rz_hex: String,
    counter: u64,
    mailbox_hex: String,
    record_secret_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordCase {
    name: String,
    record_secret_hex: String,
    mailbox_hex: String,
    kind: String,
    sealed_hex: String,
    expect: RecordExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordExpect {
    ok: bool,
    error: Option<String>,
    record_id_hex: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<u64>,
    payload_hex: Option<String>,
}

/// x coordinate of `scalar * lift_x(point)`, as the platform ECDH returns.
fn ecdh_x(scalar_hex: &str, x_only_hex: &str) -> [u8; 32] {
    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use k256::{AffinePoint, EncodedPoint, NonZeroScalar, ProjectivePoint};
    let scalar = NonZeroScalar::try_from(hex(scalar_hex).as_slice()).unwrap();
    let mut compressed = vec![0x02];
    compressed.extend_from_slice(&hex(x_only_hex));
    let point =
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&compressed).unwrap()).unwrap();
    let shared = (ProjectivePoint::from(point) * *scalar).to_affine();
    shared
        .to_encoded_point(false)
        .x()
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
}

#[test]
fn record_suite_matches() {
    let suite: RecordSuite =
        serde_json::from_str(include_str!("../vectors/vmls-record-v1.json")).unwrap();
    assert_eq!(suite.exporter.label, derive::EXPORTER_LABEL);
    assert_eq!(hex(&suite.exporter.context_hex), derive::EXPORTER_CONTEXT);
    assert_eq!(suite.exporter.length, derive::EXPORTER_LENGTH);
    assert_eq!(suite.buckets, record::BUCKETS);

    let d = &suite.derivations;
    let epoch = hex32(&d.epoch_secret_hex);
    for leaf in &d.leaves {
        let leaf_id = hex32(&leaf.leaf_id_hex);
        let mailbox = derive::mailbox(&epoch, &leaf_id);
        assert_eq!(mailbox, hex32(&leaf.mailbox_hex));
        assert_eq!(
            derive::record_secret(&epoch, &leaf_id, &mailbox),
            hex32(&leaf.record_secret_hex)
        );
    }
    for slot in &d.commit_slots {
        let derived = derive::commit_slot(&epoch, slot.attempt);
        assert_eq!(derived, hex32(&slot.slot_hex));
        assert_eq!(
            derive::slot_record_secret(&epoch, &derived),
            hex32(&slot.record_secret_hex)
        );
    }
    assert_eq!(
        derive::commit_hash(&hex(&d.commit_hash.message_hex)),
        hex32(&d.commit_hash.hash_hex)
    );
    for key in &d.record_keys {
        let (k, n) =
            derive::record_key_nonce(&hex32(&key.record_secret_hex), &hex32(&key.record_id_hex));
        assert_eq!(k.as_slice(), hex(&key.key_hex));
        assert_eq!(n.as_slice(), hex(&key.nonce_hex));
    }
    let intro = &d.introduction;
    let from_joiner = ecdh_x(&intro.test_only_joiner_rz_priv_hex, &intro.adder_rz_hex);
    let from_adder = ecdh_x(&intro.test_only_adder_rz_priv_hex, &intro.joiner_rz_hex);
    assert_eq!(from_joiner, from_adder, "ECDH must agree from either side");
    assert_eq!(from_joiner, hex32(&intro.ecdh_x_hex));
    for case in &intro.cases {
        let derived =
            derive::introduction(&from_joiner, &hex32(&case.recipient_rz_hex), case.counter);
        assert_eq!(derived.mailbox, hex32(&case.mailbox_hex));
        assert_eq!(derived.record_secret, hex32(&case.record_secret_hex));
    }

    for case in suite.records {
        let secret = hex32(&case.record_secret_hex);
        let mailbox = hex32(&case.mailbox_hex);
        let sealed = hex(&case.sealed_hex);
        let kind = match case.kind.as_str() {
            "leaf" => MailboxKind::Leaf,
            "commit-slot" => MailboxKind::CommitSlot,
            "welcome" => MailboxKind::Welcome,
            "introduction" => MailboxKind::Introduction,
            other => panic!("mailbox kind {other}"),
        };
        let result = record::open(&TestAead, &secret, &mailbox, &sealed, kind);
        if case.expect.ok {
            let opened = result.unwrap_or_else(|drop| panic!("{}: {:?}", case.name, drop));
            let record_id = hex32(case.expect.record_id_hex.as_deref().unwrap());
            let expected = InnerRecord {
                record_type: RecordType::from_value(case.expect.record_type.unwrap()).unwrap(),
                payload: hex(case.expect.payload_hex.as_deref().unwrap()),
            };
            assert_eq!(opened.record_id, record_id);
            assert_eq!(opened.record, expected, "{}", case.name);
            // Sealing is deterministic given the record id.
            assert_eq!(
                record::seal(&TestAead, &secret, &mailbox, &record_id, &expected).unwrap(),
                sealed,
                "{}",
                case.name
            );
            if expected.record_type == RecordType::Capability {
                CapabilityRecord::decode(&expected.payload).unwrap();
            }
        } else {
            assert_eq!(
                result.err().map(|drop| drop.0),
                Some(code(case.expect.error.as_deref().unwrap())),
                "{}",
                case.name
            );
        }
    }
}

// ---- lane table ----

#[derive(Deserialize)]
struct LaneSuite {
    cases: Vec<LaneCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaneCase {
    input: LaneJson,
    expect: DecisionJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaneJson {
    conversation: String,
    group_state: String,
    peer_capability: bool,
    sheltered_route: bool,
    choice: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionJson {
    action: String,
    indicator: String,
    wording: String,
    offer_public: bool,
}

#[test]
fn lane_suite_matches_every_input_in_order() {
    let suite: LaneSuite =
        serde_json::from_str(include_str!("../vectors/vmls-lane-v1.json")).unwrap();
    let inputs = lane::all_inputs();
    assert_eq!(suite.cases.len(), inputs.len());
    for (case, input) in suite.cases.iter().zip(inputs) {
        let parsed = LaneInput {
            conversation: match case.input.conversation.as_str() {
                "sheltered" => Conversation::Sheltered,
                "public" => Conversation::Public,
                "new" => Conversation::New,
                other => panic!("conversation {other}"),
            },
            group_state: match case.input.group_state.as_str() {
                "active" => GroupState::Active,
                "needs-recovery" => GroupState::NeedsRecovery,
                other => panic!("group state {other}"),
            },
            peer_capability: case.input.peer_capability,
            sheltered_route: case.input.sheltered_route,
            choice: match case.input.choice.as_str() {
                "none" => Choice::None,
                "start-public" => Choice::StartPublic,
                other => panic!("choice {other}"),
            },
        };
        assert_eq!(parsed, input, "vector order");
        let out = lane::decide(parsed);
        assert_eq!(out.action.as_str(), case.expect.action, "{parsed:?}");
        assert_eq!(out.indicator.as_str(), case.expect.indicator, "{parsed:?}");
        assert_eq!(out.wording.as_str(), case.expect.wording, "{parsed:?}");
        assert_eq!(out.offer_public, case.expect.offer_public, "{parsed:?}");
    }
}

// ---- hostile corpus: the JavaScript reader's code for every input ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostileSuite {
    now: u64,
    leaf: LeafJson,
    suites: Vec<Hostile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hostile {
    structure: String,
    base_hex: String,
    seed: u32,
    splices: usize,
    randoms: usize,
    random_length: serde_json::Value,
    random_head_hex: String,
    codes: Vec<u16>,
}

/// Regenerates the inputs exactly as the file's note describes.
fn hostile_inputs(suite: &Hostile) -> Vec<Vec<u8>> {
    let base = hex(&suite.base_hex);
    let head = hex(&suite.random_head_hex);
    let mut out = Vec::new();
    for len in 0..base.len() {
        out.push(base[..len].to_vec());
    }
    for bit in 0..base.len() * 8 {
        let mut flipped = base.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        out.push(flipped);
    }
    let mut lcg = common::Lcg(suite.seed);
    for _ in 0..suite.splices {
        let cut = usize::from(lcg.byte()) * base.len() / 256;
        let resume = usize::from(lcg.byte()) * base.len() / 256;
        let mut spliced = base[..cut].to_vec();
        spliced.extend_from_slice(&base[resume..]);
        out.push(spliced);
    }
    for i in 0..suite.randoms {
        let mut input = match suite.random_length.as_u64() {
            None => {
                assert_eq!(suite.random_length, "base");
                let mut input = vec![0u8; base.len()];
                for byte in input.iter_mut().take(1 + i % 24) {
                    *byte = lcg.byte();
                }
                input
            }
            Some(max) => {
                let len = ((usize::from(lcg.byte()) << 8) | usize::from(lcg.byte())) % max as usize;
                lcg.bytes(len)
            }
        };
        if i % 2 == 0 && input.len() >= head.len() {
            input[..head.len()].copy_from_slice(&head);
        }
        out.push(input);
    }
    out
}

#[test]
fn hostile_codes_match_the_independent_reader_on_every_input() {
    let file: HostileSuite =
        serde_json::from_str(include_str!("../vectors/vmls-hostile-v1.json")).unwrap();
    let identity = hex(&file.leaf.identity_hex);
    let key = hex(&file.leaf.signature_key_hex);
    let leaf = CarryingLeaf {
        credential_identity: &identity,
        signature_key: &key,
    };
    let policy = BindingPolicy::default();
    for suite in &file.suites {
        let inputs = hostile_inputs(suite);
        assert_eq!(inputs.len(), suite.codes.len(), "{}", suite.structure);
        for (index, (input, expected)) in inputs.iter().zip(&suite.codes).enumerate() {
            let result = match suite.structure.as_str() {
                "binding" => LeafBinding::decode(input)
                    .and_then(|b| b.verify(file.now, &leaf, &policy))
                    .map(|_| ()),
                "capability" => CapabilityRecord::decode(input)
                    .and_then(|c| c.verify(file.now, &leaf, &policy))
                    .map(|_| ()),
                "plaintext" => record::decode_plaintext(input).map(|_| ()),
                other => panic!("structure {other}"),
            };
            let actual = result.err().map_or(0, ErrorCode::number);
            assert_eq!(actual, *expected, "{} input {index}", suite.structure);
        }
    }
}
