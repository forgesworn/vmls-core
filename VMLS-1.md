# VMLS/1 transport contract

Status: **source-derived draft for review**, revised 2026-11-06

Original baseline: `vmls-core` 0.1.0, commit
`53fa9a48ac745895eb61aa6f25679bb92c593f57`.
Current normative revision: the containing Git commit; the original baseline is
retained for provenance and is not claimed to contain every rule below.

This document specifies the formats and decisions implemented by the baseline
crate. It does not implement MLS, establish independent security assurance, or
record downstream/device acceptance. Until this draft is reviewed and approved,
the Rust implementation and the vectors listed in appendix A remain the
reference for exact behaviour.

After approval, a conforming change must preserve these bytes and decisions or
use a new format/profile version. Existing error numbers must never be reused.

## 1. Scope and conventions

VMLS/1 defines the data around MLS: envelopes, sealed records, leaf bindings,
one-time capabilities, derivations, receipts, restore-witness requests, fork
evidence, state manifests, allocation-witness forwarding, and the send-lane
table. MLS group operation, storage, transport services, user interfaces, and
key enrolment are outside this crate.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe
interoperability requirements, not a claim of independent standardisation.

Notation:

- `bstr`, `tstr`, `uint`, array, and map denote CBOR values.
- `bstr(N)` has exactly `N` bytes; `bstr(1..N)` is non-empty and at most `N`.
- `u8`, `u16be`, `u32be`, and `u64be` are fixed-width, big-endian binary fields,
  not CBOR integers.
- `a || b` is byte concatenation.
- `MAX_SAFE_INTEGER = 2^53 - 1 = 9007199254740991`.
- Hexadecimal text is lowercase unless a rule says otherwise.

## 2. Common encoding and cryptography

### 2.1 Deterministic CBOR subset

CBOR structures use the deterministic RFC 8949 subset implemented in
`vmls-core/src/cbor.rs`:

- Only unsigned integers, byte strings, UTF-8 text strings, definite-length
  arrays, and definite-length maps are generally permitted. State-manifest
  values additionally permit negative integers and null.
- Every integer and length uses its shortest encoding. Indefinite lengths,
  reserved additional-information values, non-shortest heads, and trailing
  bytes are rejected.
- Maps have exactly the specified entries. Integer keys occur once, in the
  stated ascending order. Missing, duplicate, reordered, and unknown keys are
  rejected.
- Lengths are bounded before allocation or slicing. A claimed length beyond
  the remaining input is rejected.
- Timestamps are unsigned integers no greater than `MAX_SAFE_INTEGER`.
- Text is valid UTF-8. A control byte below `0x20` is rejected unless it is
  backspace, tab, line feed, form feed, or carriage return. This preserves the
  NIP-01/`JSON.stringify` serialisation used by device credentials.

An accepted CBOR object MUST re-encode to exactly its accepted bytes.

Typed construction is not proof of conformance. The typed encoders for
`DeviceCredential`, `LeafBinding`, `CapabilityRecord`, `AdvanceRequest`,
`WitnessReceipt`, and `ForkEvidence` are not general validation APIs. Before
signing or emitting a caller-constructed value, the caller MUST enforce every
applicable bound in sections 6 through 10, including nested credential tag/text
limits, timestamp ranges, witness sequence limits, and evidence pair invariants.
A successful decode of the emitted bytes provides structural prevalidation; it
does not replace signature verification or the adapter and service checks in
section 15. `ForwardedRequest::new` performs this structural round-trip check
for its request body.

For example, a caller can validate a constructed binding with
`LeafBinding::decode(&binding.encode())` and sign the checked result. Any later
structural mutation invalidates that validation and requires a fresh round-trip
before signing or emission. Placeholder signatures may be used for this
structural check; semantic verification is still separate.

### 2.2 Primitive profiles

- Hashes and HKDF use SHA-256. HKDF follows RFC 5869.
- Slot, witness, and allocation-writer signatures use plain Ed25519
  (RFC 8032, not Ed25519ph) over a 32-byte SHA-256 digest. Verification is
  strict, including rejection of weak/small-order and non-canonical forms.
- Leaf-binding and device-credential signatures use BIP-340 Schnorr signatures
  over 32-byte messages with secp256k1 x-only public keys.
- The suite-`0x0001` record profile uses AES-128-GCM with a 16-byte key,
  12-byte nonce, and 16-byte tag. The production AEAD is supplied by the MLS
  suite provider; the crate does not select or implement MLS itself.
- Callers pin Ed25519 node/witness keys independently. A receipt or forwarded
  request never introduces a trusted key.

## 3. Outer envelope

The only accepted envelope profile is `1`:

```text
envelope = {
  1: 1,                    ; profile
  2: bstr(32),             ; mailbox capability
  3: bstr                  ; sealed record
}
```

The map uses the common canonical rules. Ciphertext length is
`1..1_048_576` bytes. A decoder MUST compare the mailbox with the active
mailbox supplied by its caller and reject a mismatch. The box can route and
store the envelope without understanding MLS or opening key 3.

Envelope errors map to stable codes as follows: malformed input to `Malformed`,
non-canonical input to `NonCanonical`, another short-form profile to
`UnsupportedVersion`, mailbox mismatch to `WrongMailbox`, empty ciphertext to
`Empty`, and excess ciphertext to `TooLarge`. The envelope API names the last
two variants `EmptyCiphertext` and `CiphertextTooLarge`; those are the strings
used by the envelope vector before conversion to `ErrorCode`.

Validation and error precedence is observable. A decoder MUST validate the map
and profile, then the exact mailbox head and mailbox equality, then the
ciphertext head and length, and finally trailing data. The profile is read as a
raw byte: another value up to 23 is `UnsupportedVersion`; 24 or above is
`NonCanonical`. The mailbox head MUST be exactly `58 20`; any other head is
`NonCanonical`, as an explicit exception to the usual fixed-field `Malformed`
rule. Mailbox equality is checked before any ciphertext field is read.
Ciphertext length heads wider than `5a` (four length bytes) are `NonCanonical`.
Empty and excess length checks precede remaining-input and trailing-data checks.

## 4. Exporter and secret derivations

### 4.1 Epoch root

The MLS engine makes exactly one exporter call per epoch:

```text
epoch_secret = MLS-Exporter("VMLS/1 epoch", "", 32)
```

Except for record AEAD and introductions, the derivations below use
HKDF-Expand-SHA256 directly with `epoch_secret` as the PRK. There is no
additional HKDF-Extract step. Every output is 32 bytes.

```text
mailbox             = Expand(epoch, "VMLS/1 mailbox" || leaf_id)
record_secret       = Expand(epoch, "VMLS/1 record" || leaf_id || mailbox)
commit_slot         = Expand(epoch, "VMLS/1 commit-slot" || attempt:u32be)
slot_record_secret  = Expand(epoch, "VMLS/1 slot record" || slot)
fork_mailbox        = Expand(epoch, "VMLS/1 fork mailbox" || leaf_id)
fork_record_secret  = Expand(epoch, "VMLS/1 fork record" || leaf_id || fork_mailbox)
```

Attempts are read from zero. A void attempt passes the epoch's Commit to the
next attempt. Fork values are derived from the departed epoch, never the
post-transition secret.

The retention profile retains two previous epochs and deletes a retained epoch
when drained or after 72 hours. Enforcement belongs to the MLS/application
engine.

The commit identifier used for replay state is:

```text
commit_hash = SHA-256("VMLS/1 commit" || exact_commit_message_bytes)
```

A slot receipt instead names the SHA-256 hash of the exact deposited envelope.

### 4.2 Record AEAD key and nonce

For a 32-byte `record_secret` and random 32-byte `record_id`:

```text
prk       = HKDF-Extract-SHA256(salt = record_id, IKM = record_secret)
okm       = HKDF-Expand-SHA256(prk, "VMLS/1 record aead", 28)
key       = okm[0..16]
nonce     = okm[16..28]
```

The sender draws `record_id` from a platform CSPRNG. Because both the key and
nonce are derived from `record_secret` and `record_id`, an id MUST NOT seal two
different padded plaintexts under one record secret. Reusing the key/nonce pair
would expose the plaintext XOR and undermine GCM authentication. A retry MUST
resend the exact stored sealed bytes.

### 4.3 Pairwise introduction

The platform supplies the 32-byte secp256k1 ECDH x coordinate `ecdh_x` between
the two rendezvous keys. For the recipient's 32-byte x-only rendezvous key
`recipient_rz` and a `u64` counter:

```text
prk              = HKDF-Extract-SHA256(
                     salt = "VMLS/1 introduction", IKM = ecdh_x)
counter_suffix   = recipient_rz || counter:u64be
mailbox          = Expand(prk,
                     "VMLS/1 introduction mailbox" || counter_suffix)
record_secret    = Expand(prk,
                     "VMLS/1 introduction record" || counter_suffix)
```

The recipient fixes direction; the counter makes each capability mailbox
single-use. ECDH and rendezvous-key handling remain platform responsibilities.

## 5. Sealed inner records

### 5.1 Types and mailbox kinds

| Type | Value | Payload | Permitted mailbox kind |
|---|---:|---|---|
| `MlsMessage` | 1 | MLS `PrivateMessage` that is not a Commit | Leaf |
| `Welcome` | 2 | Welcome sealed again to the welcome transport | Welcome |
| `Capability` | 3 | `capability/1` | Introduction |
| `Commit` | 4 | MLS `PrivateMessage` carrying a Commit | Commit slot |
| `ForkEvidence` | 5 | fork-evidence payload | Fork evidence |

A known type found at any other mailbox kind is an unexpected-type failure and
a silent drop. Other type values are unsupported.

### 5.2 Plaintext and buckets

```text
plaintext = { 1: uint(type), 2: bstr(payload) }
padded    = plaintext || zero_bytes
sealed    = record_id[32] || AEAD(padded) || tag[16]
aad       = "VMLS/1 record" || mailbox[32] || record_id[32]
```

The payload is non-empty and at most `1_048_519` bytes. The padded plaintext
length is `bucket - 48`. The sealed length is exactly the smallest bucket whose
plaintext capacity contains the complete canonical plaintext:

```text
1024, 4096, 16384, 65536, 1048576 bytes
```

All bytes after the canonical plaintext are zero. A non-bucket length, nonzero
padding, or a larger bucket than required is rejected. The type and every
MLS-sensitive field remain inside the AEAD.

### 5.3 Opening, retries, and replay

Every failure while opening a record is a **silent drop**: it is not displayed,
not counted as recovery, and not escalated. Anyone holding a mailbox value can
produce an invalid record.

A retry under one record id MUST resend the exact stored sealed bytes, not a
fresh sealing. A receiver adds the id to replay state only after successful
authentication, canonical decoding, and mailbox/type validation.

## 6. `leaf-binding/1`

The binding is carried in MLS LeafNode extension type `0xF0B1`, in the RFC 9420
private-use range. The group's required-capabilities mechanism MUST require it
so every member verifies every leaf.

```text
leaf-binding/1 = {
  1: 1,                    ; version
  2: bstr(37),             ; "vmls1" || leaf_id[32]
  3: bstr(32),             ; MLS Ed25519 signature public key
  4: credential,
  5: bstr(32),             ; device BIP-340 x-only public key
  6: uint,                 ; expires_at, Unix seconds
  7: bstr(32),             ; home-box Link node id
  8: bstr(64)              ; BIP-340 signature by key 5
}

credential = {
  1: bstr(32),             ; identity x-only public key
  2: uint,                 ; created_at
  3: [* [+ tstr]],         ; tags exactly as signed
  4: tstr,                 ; content exactly as signed
  5: bstr(64)              ; credential BIP-340 signature
}
```

An encoded binding is at most 8192 bytes. A credential has at most 16 tags;
each tag has 1..8 values, each value at most 512 UTF-8 bytes, and content is at
most 1024 UTF-8 bytes. The Nostr kind is fixed at 20460 and is not carried in
the CBOR.

The signed binding body is the canonical seven-entry map of keys 1..7:

```text
binding_digest = SHA-256(
  "VMLS/1 leaf-binding" || canonical_binding_map_keys_1_to_7)
```

The credential id and signature message are:

```text
nip01 = [0, lowercase_hex(pubkey), created_at, 20460, tags, content]
credential_id = SHA-256(JSON.stringify-compatible nip01 serialisation)
```

### 6.1 Verification requirements

Verification is against the carrying leaf as parsed by the MLS engine, the
caller-supplied current time, optional expected person identity, and credential
ids named by verified kind-5 tombstones.

1. Key 2 MUST equal the leaf's BasicCredential identity and key 3 its signature
   key. Uniqueness of `leaf_id` within the group is an MLS-engine check.
2. The device key and binding signature MUST verify under BIP-340.
3. The credential id and signature MUST verify. Its single `d` tag MUST be the
   lowercase hexadecimal identity pubkey and its single `scope` tag MUST be
   `person`; room-form credentials are not accepted.
4. If an expected identity is supplied, it MUST equal the credential pubkey.
5. One `device` tag MUST contain exactly 64 lowercase hexadecimal digits and
   name the binding's device key. One `expiration` tag MUST contain an unsigned
   decimal timestamp with no sign or leading zero and no more than
   `MAX_SAFE_INTEGER`. Duplicate or malformed required tags are rejected.
6. Credential expiration MUST be later than `now`; `created_at` MUST be no more
   than 600 seconds ahead of `now`; expiration MUST be no more than 30 days
   after both `created_at` and `now`; and the id MUST NOT be revoked.
7. Binding expiration MUST be later than `now` and no later than credential
   expiration.

Verification order is observable through the stable error result: carrying-leaf
match, binding signature, person credential rules, device equality, then the
binding lifetime rules. Within the person credential rules, the `d` tag is
evaluated before `scope`; expiration is checked before `created_at` skew,
followed by both lifetime ceilings and then revocation.

## 7. `capability/1`

A capability privately offers a one-time KeyPackage to an adder. Receiving a
valid capability is the only VMLS/1 capability signal; nothing is advertised.

```text
capability/1 = {
  1: 1,                    ; version
  2: bstr(32),             ; package_id
  3: bstr(1..16384),       ; opaque MLS KeyPackage
  4: bstr(1..8192),        ; leaf-binding/1
  5: bstr(32),             ; single-use welcome_mailbox
  6: bstr(32),             ; welcome-transport X25519 public key
  7: bstr(32),             ; welcome_secret outer-record secret
  8: uint                  ; expires_at
}
```

The encoded capability is at most 32768 bytes and travels as a `Capability`
record to an introduction mailbox.

Capability expiration MUST be later than `now`, no more than seven days ahead,
and no later than binding expiration. Its binding MUST verify against the leaf
parsed from key 3 and the caller's binding policy. Verification returns
`CapabilityExpired` or `CapabilityLifetimeTooLong` before binding errors, then
verifies the binding, and finally checks `CapabilityOutlivesBinding`.

**Adapter obligation:** key 4 MUST be byte-identical to the binding extension
in the KeyPackage. `CapabilityRecord::verify` receives only the leaf identity
and signature key, so it does not itself perform this whole-extension byte
comparison. The single-use welcome mailbox and package replay state also need
service-level enforcement.

## 8. Slot and witness receipts

### 8.1 Slot receipt

A slot receipt is exactly 197 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version = `1` (`u8`) |
| 1 | 32 | home-box node id |
| 33 | 32 | installation/genesis id |
| 65 | 32 | commit slot |
| 97 | 4 | attempt (`u32be`) |
| 101 | 32 | envelope hash |
| 133 | 64 | Ed25519 signature |

```text
envelope_hash = SHA-256(exact_deposited_envelope_bytes)
slot_digest   = SHA-256(
  "VMLS/1 slot receipt" || installation || slot ||
  attempt:u32be || envelope_hash)
```

The node field MUST equal the caller-pinned home-box key, which strictly
verifies the signature over `slot_digest`.

### 8.2 Witness receipt

A witness receipt is exactly 170 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version = `1` (`u8`) |
| 1 | 1 | status: current `0`, conflict `1`, retired `2` |
| 2 | 32 | subject |
| 34 | 8 | sequence (`u64be`, at most `MAX_SAFE_INTEGER`) |
| 42 | 32 | state digest |
| 74 | 32 | challenge |
| 106 | 64 | Ed25519 signature |

```text
witness_digest = SHA-256(
  "VMLS/1 witness receipt" || receipt_bytes[0..106])
```

The caller-pinned witness key strictly verifies the signature. The receipt
MUST echo the caller's fresh challenge. The caller MUST separately check the
subject and status against its request and intended transition.

## 9. Restore-witness requests

Request bodies are canonical CBOR and at most 256 bytes before parsing.

```text
read = {
  1: 1,
  2: bstr(32),             ; subject
  3: bstr(32)              ; fresh challenge
}

advance = {
  1: 1,
  2: bstr(32),             ; subject
  3: uint,                 ; expected_seq, strictly below MAX_SAFE_INTEGER
  4: bstr(32),             ; expected_digest
  5: bstr(32),             ; next_digest
  6: bstr(32)              ; fresh challenge
}
```

A subject at the sequence limit needs a new installation. The witness service
MUST treat advance as an atomic expectation check and transition, returning its
current state on conflict. Challenge generation, store consistency, retirement,
and replay/authorisation policy are service responsibilities.

## 10. Fork evidence

Fork evidence is the payload of record type 5:

```text
evidence = version:u8(1) || pre_epoch:u64be || count:u8 || slot_receipt[count]
```

`count` is exactly 1 or 2, giving total lengths 207 or 404 bytes. One receipt is
an observation. Two receipts are a candidate equivocation only when:

- node, installation, and slot are identical; and
- their 36-byte `attempt:u32be || envelope_hash` pair keys are distinct and in
  strictly ascending lexicographic order.

Attempts may differ; hashes may be equal when attempts differ. Layout and pair
rules are checked before any receipt signature; every receipt MUST then strictly
verify against the pinned home-box node in encoded order. Thus a non-pair is
`EvidenceNotEquivocation` even when a receipt signature is also invalid.
`pre_epoch` is not covered by the receipt signatures. The MLS/application engine
MUST associate the evidence with the correct session and transition before
acting on it.

## 11. Canonical state manifest

```text
manifest = [
  1,
  subject bstr(32),
  installation bstr(32),
  schema_manifest_hash bstr(32),
  entries
]
entries = [[key bstr, value_hash bstr(32)], ...]
key = canonical CBOR [namespace tstr, primary_key_fields...]
value_hash = SHA-256(canonical CBOR value)
digest = SHA-256("VMLS/1 state manifest" || manifest)
```

Entries are sorted by raw key bytes, lexicographically. Duplicate keys are
rejected. Manifest values preserve their types: null, signed 64-bit integer,
byte string, text string, or nested array. Nonnegative integers use CBOR major
type 0; negative integers use major type 1 with argument `-1 - value`.
Manifest namespaces and text values permit any valid UTF-8, including control
characters, as an explicit exception to the §2.1 control-byte restriction.
Readers of JSON vectors MUST preserve the full signed 64-bit range exactly and
MUST NOT pass these integers through a floating-point representation.

The adapter's frozen schema manifest determines covered tables, columns, and
primary-key order. Its hash is bound into every state manifest. An adapter
using `insert_hashed` MUST supply exactly the canonical `entry_key` bytes; that
cached-path method does not revalidate the supplied key encoding. This crate
constructs and digests manifests; schema selection and storage reconciliation
remain adapter responsibilities.

## 12. Allocation-witness forwarding

A firmware-writer request through an untrusted witness courier has this fixed
binary framing:

```text
forwarded = version:u8(1) || method:u8 ||
            writer[32] || courier_token[32] || body_length:u16be ||
            body || signature[64]
```

Method is read `1` or advance `2`. The body MUST be the corresponding canonical
request from section 9, at most 256 bytes. Total length is exactly
`132 + body_length`, with a maximum of 388 bytes. The decoder is given the
expected method and rejects a different one.

```text
forwarding_digest = SHA-256(
  "VMLS/1 allocation witness request\0" ||
  pinned_witness[32] || forwarded_without_signature)
```

The writer key strictly verifies the Ed25519 signature. The domain tag includes
its terminating NUL byte.

Signature verification proves only that the writer signed this request for this
witness. It does **not** prove writer enrolment, token liveness, store
membership, freshness, or allocation semantics. Before touching its witness
store, a service MUST atomically consume the one-use courier token for the
verified Link peer. Forwarding failures use the separate byte-free
`ForwardingError` enum; they do not allocate stable VMLS error numbers.

## 13. Send-lane decision table

The lane decision is a pure function of conversation, local group state,
whether a valid peer capability is held, whether the sheltered box route is
currently available, and an explicit public-lane choice.

| Conversation | Choice | Other relevant state | Action | Indicator / wording | Offer public |
|---|---|---|---|---|---|
| Public | any | all other input ignored | Send NIP-17 | public / public | no |
| Sheltered | start-public | group and route ignored | Start public conversation | public / public | no |
| Sheltered | none | needs recovery | Hold | not-sent / needs-recovery | yes |
| Sheltered | none | active, route available | Send sheltered | sheltered / sheltered | no |
| Sheltered | none | active, route unavailable | Hold | not-sent / sheltered-unavailable | yes |
| New | start-public | capability and route ignored | Start public conversation | public / public | no |
| New | none | no peer capability | Offer public | not-sent / start-separate-public | yes |
| New | none | capability and route available | Create sheltered conversation | sheltered / sheltered | no |
| New | none | capability, no route | Hold | not-sent / sheltered-unavailable | yes |

A sheltered conversation never silently produces NIP-17. Starting public opens
a separate, empty conversation and copies no GroupId, binding, roster, draft,
or read state. Even the user's unsent text requires a further explicit action.
A public conversation never silently becomes sheltered. Wording values are
keys into the client's wording table, not localised user-facing text.

The vector contains all 48 input combinations, including ignored fields.

## 14. Stable error identifiers

Errors contain no input bytes, key material, or free-form text. Vector files
use strings; FFI/wasm adapters may use strings or numbers.

| Number | Code | Number | Code |
|---:|---|---:|---|
| 1 | `Malformed` | 2 | `NonCanonical` |
| 3 | `UnsupportedVersion` | 4 | `WrongMailbox` |
| 5 | `Empty` | 6 | `TooLarge` |
| 10 | `BadRecordLength` | 11 | `OuterSealFailed` |
| 12 | `BadPadding` | 13 | `UnsupportedRecordType` |
| 14 | `UnexpectedRecordType` | 20 | `BadLeafIdentity` |
| 21 | `BadDeviceKey` | 22 | `BindingSignatureInvalid` |
| 23 | `BindingExpired` | 24 | `BindingOutlivesCredential` |
| 25 | `CredentialMalformed` | 26 | `CredentialSignatureInvalid` |
| 27 | `CredentialNotPersonScoped` | 28 | `CredentialWrongIdentity` |
| 29 | `CredentialWrongDevice` | 30 | `CredentialExpired` |
| 31 | `CredentialLifetimeTooLong` | 32 | `CredentialRevoked` |
| 33 | `CredentialNotYetValid` | 34 | `BindingLeafMismatch` |
| 40 | `CapabilityExpired` | 41 | `CapabilityLifetimeTooLong` |
| 42 | `CapabilityOutlivesBinding` | 50 | `AeadUnavailable` |
| 60 | `ReceiptWrongNode` | 61 | `ReceiptSignatureInvalid` |
| 62 | `WitnessChallengeMismatch` | 63 | `EvidenceNotEquivocation` |

Reserved ranges are 1..9 codec, 10..19 record, 20..39 binding/credential,
40..49 capability, 50..59 caller-supplied primitives, and 60..69
receipts/evidence. A retired code keeps its number.

## 15. Required caller and service checks

A successful codec call does not by itself establish:

- MLS group validity, required-capabilities enforcement, or leaf-id uniqueness;
- current key authority, enrolment, revocation, freshness, or replay state;
- the byte-identical capability/KeyPackage extension comparison;
- CSPRNG quality, constant-time platform primitives, or secret erasure;
- atomic mailbox consumption, commit-slot transition, or witness advance;
- the association of a receipt or evidence payload with a particular session;
- correct schema-manifest coverage and storage reconciliation;
- no logging of sensitive fields by an adapter; or
- constrained-device memory, stack, timing, and runtime acceptance.

These checks belong at the named integration boundaries and are required for
end-to-end assurance.

## Appendix A. Compatibility vectors

Hashes are SHA-256 of the exact JSON file bytes at the containing commit. Test
keys and secrets in these files are public fixtures and MUST NOT be used in
production.

| File | Contents | SHA-256 |
|---|---|---|
| `vmls-core/vectors/vmls-envelope-v1.json` | 14 envelope cases | `07e519984ea0cc88399471bc173c12a27c3cdfe21930eb81d11b781d78c43bd1` |
| `vmls-core/vectors/vmls-record-v1.json` | derivations, keys, and 21 record cases | `29baa766796a853ef4d8eeb0b5803f8530e663150bcb3e3d181e669105c8d7a7` |
| `vmls-core/vectors/vmls-binding-v1.json` | 43 binding cases | `58324190ddce444003f50cedc212e23f272e6bb9c9b3cfd2e3ef58de5018dc4f` |
| `vmls-core/vectors/vmls-capability-v1.json` | 17 capability cases | `8bae8df6c0005e9daff2263561a5e4ac859e1a87a92af0792ff27cb5da3142ab` |
| `vectors/device-credential.json` | 8 device-credential cases plus tombstone | `6db2ac7d9ba680dcc952028974bbe00ed6e69f9fe4054ea1ed12277c687f0f7e` |
| `vmls-core/vectors/vmls-lane-v1.json` | all 48 lane inputs | `05ea8fb2a5090a677bbf0822e4448e8935616c735835b4a97738698286af131f` |
| `vmls-core/vectors/vmls-security-design-v1.json` | receipts, evidence and precedence, fork derivations | `609fab73d1968b9a6c3ee590f3ffc3d1f9a7ab1a594e5737d66184c21e998e17` |
| `vmls-core/vectors/vmls-witness-request-v1.json` | 13 witness-request cases | `75be62ea1ff27f6d503817d06dafe951da67fe50b21c2909844545d7d8eafb1f` |
| `vmls-core/vectors/vmls-manifest-v1.json` | 12 manifest cases | `c969886c2d48ab51dd1ceb78d00462a49a9a2e31b6fc1ff96ed275efec5e0f57` |
| `vmls-core/vectors/signer-allocation-witness-v1.json` | independently signed read and advance envelopes | `9cd6d7e48032bbece0b15a03b388a68bbe24217073dd38fd9fd614519d073d04` |
| `vmls-core/vectors/vmls-hostile-v1.json` | 7324 binding, 9079 capability, and 12284 plaintext outcomes | `39ec6902a1dd2af388dae2d35ff691015773f00ee23223f33578983fdda8dda9` |

The hostile corpus deterministically regenerates truncations, every single-bit
flip, structural splices, and seeded random inputs. Its expected result is zero
for success or the stable numeric error code. Consumers should compare every
case, not only valid examples.
