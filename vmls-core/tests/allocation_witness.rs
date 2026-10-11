//! Independent Node-produced bytes plus strict-verifier hostile inputs.
//! Does not establish service tokens, firmware signing or allocation genesis.
mod common;

use common::{Lcg, hex, hex32};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vmls_core::allocation_witness::{
    ForwardedRequest, ForwardingError, MAX_ENVELOPE_BYTES, Method, REQUEST_TAG, Request,
};
use vmls_core::witness::AdvanceRequest;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../vectors/signer-allocation-witness-v1.json")).unwrap()
}
fn field(f: &Value, key: &str) -> Vec<u8> {
    hex(f[key].as_str().unwrap())
}
fn witness(f: &Value) -> [u8; 32] {
    hex32(f["witnessHex"].as_str().unwrap())
}
fn key(f: &Value) -> SigningKey {
    SigningKey::from_bytes(&hex32(f["writerSeedHex"].as_str().unwrap()))
}

// Assemble hostile, correctly signed raw bodies without relying on the codec.
fn signed_body(f: &Value, method: u8, body: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut raw = vec![1, method];
    raw.extend(field(f, "writerHex"));
    raw.extend(field(f, "courierTokenHex"));
    raw.extend((body.len() as u16).to_be_bytes());
    raw.extend(body);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(witness(f))
        .chain_update(&raw)
        .finalize()
        .into();
    raw.extend(key(f).sign(&digest).to_bytes());
    raw
}

#[test]
fn independent_known_answers_and_signature_verified_identity() {
    let f = fixture();
    for (name, method) in [("read", Method::Read), ("advance", Method::Advance)] {
        let vector = &f[name];
        let raw = field(vector, "envelopeHex");
        assert_eq!(
            raw.len(),
            vector["envelopeBytes"].as_u64().unwrap() as usize
        );
        let parsed = ForwardedRequest::parse(&raw, method).unwrap();
        assert_eq!(parsed.encode(), raw);
        assert_eq!(
            parsed.digest_to_sign(&witness(&f)).as_slice(),
            field(vector, "signatureMessageHex")
        );
        assert_eq!(
            key(&f)
                .sign(&parsed.digest_to_sign(&witness(&f)))
                .to_bytes()
                .as_slice(),
            field(vector, "signatureHex")
        );
        let verified = parsed.verify(&witness(&f)).unwrap();
        assert_eq!(verified.writer().as_slice(), field(&f, "writerHex"));
        assert_eq!(
            verified.courier_token().as_slice(),
            field(&f, "courierTokenHex")
        );
        match verified.request() {
            Request::Read(r) => {
                assert_eq!(r.subject.as_slice(), field(&f, "subjectHex"));
                assert_eq!(r.challenge.as_slice(), field(&f, "challengeHex"));
                assert_eq!(r.encode(), field(vector, "requestHex"));
            }
            Request::Advance(r) => {
                assert_eq!(r.subject.as_slice(), field(&f, "subjectHex"));
                assert_eq!(r.challenge.as_slice(), field(&f, "challengeHex"));
                assert_eq!(r.expected_seq, 7);
                assert_eq!(r.expected_digest.as_slice(), field(&f, "expectedDigestHex"));
                assert_eq!(r.next_digest.as_slice(), field(&f, "nextDigestHex"));
                assert_eq!(r.encode(), field(vector, "requestHex"));
            }
        }
    }
}

#[test]
fn every_bit_mutation_truncation_and_extension_is_refused() {
    let f = fixture();
    for (name, method) in [("read", Method::Read), ("advance", Method::Advance)] {
        let raw = field(&f[name], "envelopeHex");
        for length in 0..raw.len() {
            assert!(ForwardedRequest::verified(&raw[..length], method, &witness(&f)).is_err());
        }
        for bit in 0..raw.len() * 8 {
            let mut changed = raw.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert!(
                ForwardedRequest::verified(&changed, method, &witness(&f)).is_err(),
                "{name} bit {bit}"
            );
        }
        let mut extended = raw;
        extended.push(0);
        assert!(ForwardedRequest::verified(&extended, method, &witness(&f)).is_err());
    }
}

#[test]
fn route_method_witness_domain_and_plain_message_transposition_fail() {
    let f = fixture();
    let raw = field(&f["read"], "envelopeHex");
    assert_eq!(
        ForwardedRequest::parse(&raw, Method::Advance),
        Err(ForwardingError::WrongMethod)
    );
    let mut other = witness(&f);
    other[0] ^= 1;
    assert_eq!(
        ForwardedRequest::verified(&raw, Method::Read, &other),
        Err(ForwardingError::SignatureInvalid)
    );
    let body = field(&f["read"], "requestHex");
    let old_domain = signed_body(&f, 1, &body, b"VMLS/1 witness receipt");
    assert_eq!(
        ForwardedRequest::verified(&old_domain, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    let missing_nul = signed_body(&f, 1, &body, b"VMLS/1 allocation witness request");
    assert_eq!(
        ForwardedRequest::verified(&missing_nul, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    let mut plain = raw.clone();
    let end = plain.len() - 64;
    let signature = key(&f).sign(&plain[..end]).to_bytes();
    plain[end..].copy_from_slice(&signature);
    assert_eq!(
        ForwardedRequest::verified(&plain, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
}

#[test]
fn correctly_signed_noncanonical_and_malformed_bodies_are_rejected() {
    let f = fixture();
    let read = field(&f["read"], "requestHex");
    let advance = field(&f["advance"], "requestHex");
    let mut trailing = read.clone();
    trailing.push(0);
    let mut reordered = read.clone();
    reordered[1] = 2;
    reordered[3] = 1;
    let mut duplicate = read.clone();
    duplicate[38] = 2;
    let mut noncanonical = advance.clone();
    noncanonical.splice(39..40, [0x18, 7]);
    for (method, body) in [
        (Method::Read, advance),
        (Method::Advance, read),
        (Method::Read, trailing),
        (Method::Read, reordered),
        (Method::Read, duplicate),
        (Method::Advance, noncanonical),
    ] {
        let raw = signed_body(&f, method as u8, &body, REQUEST_TAG);
        assert_eq!(
            ForwardedRequest::parse(&raw, method),
            Err(ForwardingError::InvalidRequest)
        );
    }
    for body in [vec![], vec![0; 257]] {
        assert!(
            ForwardedRequest::parse(&signed_body(&f, 1, &body, REQUEST_TAG), Method::Read).is_err()
        );
    }
    let request = Request::Advance(AdvanceRequest {
        subject: [1; 32],
        expected_seq: vmls_core::MAX_SAFE_INTEGER,
        expected_digest: [2; 32],
        next_digest: [3; 32],
        challenge: [4; 32],
    });
    assert_eq!(
        ForwardedRequest::new([5; 32], [6; 32], request, [0; 64]),
        Err(ForwardingError::InvalidRequest)
    );
}

#[test]
fn strict_ed25519_rejects_identity_keys_small_order_r_and_noncanonical_s() {
    let f = fixture();
    let raw = field(&f["read"], "envelopeHex");
    let end = raw.len() - 64;
    // Identity public key and identity R with S=0 are a weak-key forgery.
    let mut identity = raw.clone();
    identity[2..34].fill(0);
    identity[2] = 1;
    identity[end..].fill(0);
    identity[end] = 1;
    assert_eq!(
        ForwardedRequest::verified(&identity, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    // Order-two key with identity R and S=0 passes cofactored verifiers.
    // The shared strict path must refuse it in both std and no_std builds.
    let mut order_two = identity;
    order_two[2..34].copy_from_slice(&hex32(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    assert_eq!(
        ForwardedRequest::verified(&order_two, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    let mut small_r = raw.clone();
    small_r[end..end + 32].fill(0);
    small_r[end] = 1;
    assert_eq!(
        ForwardedRequest::verified(&small_r, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    let mut noncanonical_s = raw.clone();
    noncanonical_s[end + 32..].fill(0xff);
    assert_eq!(
        ForwardedRequest::verified(&noncanonical_s, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
    let mut invalid_key = raw;
    invalid_key[2..34].fill(0xff);
    assert_eq!(
        ForwardedRequest::verified(&invalid_key, Method::Read, &witness(&f)),
        Err(ForwardingError::SignatureInvalid)
    );
}

#[test]
fn hostile_bytes_are_bounded_and_any_accepted_parse_is_exactly_canonical() {
    let f = fixture();
    let mut lcg = Lcg(0xa110_ca7e);
    assert_eq!(
        ForwardedRequest::parse(&vec![0; MAX_ENVELOPE_BYTES + 1], Method::Read),
        Err(ForwardingError::TooLarge)
    );
    for length in 0..1024 {
        let mut raw = lcg.bytes(length);
        if length > 68 {
            raw[0] = 1;
            raw[1] = 1;
        }
        if let Ok(parsed) = ForwardedRequest::parse(&raw, Method::Read) {
            assert_eq!(parsed.encode(), raw);
            let _ = parsed.verify(&witness(&f));
        }
    }
}
