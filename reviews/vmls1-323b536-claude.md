# Independent AI review: VMLS/1 323b536

- **Reviewer/model and review date:** Claude Fable 5.1 (claude-fable-5-1), independent AI reviewer; 2026-11-06.
- **Exact commit and tree verification performed:** `.git/HEAD` points at `refs/heads/main`, which contains `323b536a775a9e2a92dae979f92ae6435846dc10`. The reflog (`.git/logs/HEAD:24`) shows a fast-forward pull to that commit as the last movement. The session's git status snapshot showed no modified tracked files and only `reviews/` untracked. No shell was available, so I did not run `git` commands or recompute Appendix A vector hashes.
- **Scope and files inspected:** `VMLS-1.md`, `AUDIT-INTEROP.md` (§4 to §7 first, §8 last), `README.md`, all of `vmls-core/src/` (`lib.rs`, `cbor.rs`, `error.rs`, `derive.rs`, `record.rs`, `binding.rs`, `capability.rs`, `receipt.rs`, `witness.rs`, `evidence.rs`, `manifest.rs`, `allocation_witness.rs`, `lane.rs`), all of `vmls-core/tests/`, `vectors/verify-vmls.mjs`, `vmls-core/Cargo.toml`, `vmls-core/Cargo.lock`, `.github/workflows/vmls-core.yml`, and the vector files (small files in full; case names, expected codes, and corpus metadata for the large ones).
- **Commands/checks performed:** read-only source review; no tests rerun; no hashes recomputed. The CI, Node reader, and local results quoted in the request are maintainer evidence, not checks I performed.

## Findings

No Critical, High, or Medium findings. All confirmed findings are Low or Informational. Both implementations reject every input discussed below. The findings concern which stable code is returned, API robustness, and documentation. Residual uncertainty is listed under limitations.

### F-01 (Low) Error precedence is not pinned by the contract, and the reference and the independent reader already disagree

**Confirmed.** Contract §3 (`VMLS-1.md:103-108`) maps envelope failures to codes but states no precedence. The Rust reference and the Node reader return different stable codes on inputs no vector covers:

- **Mailbox of the wrong length.** Rust compares the two-byte head literally and returns `NonCanonical` (`vmls-core/src/lib.rs:130-132`). The reader uses `fixed(32)` and returns `Malformed` (`vectors/verify-vmls.mjs:776`, `:222-225`). The crate's own `ErrorCode::Malformed` doc says a field of the wrong fixed length is `Malformed` (`vmls-core/src/error.rs:16-17`), and every other fixed field in the crate follows that via `Reader::fixed` (`vmls-core/src/cbor.rs:134-139`). The envelope is the outlier.
- **Wrong mailbox combined with any later defect.** Rust checks the mailbox before reading the ciphertext (`lib.rs:135-137`), so wrong mailbox plus a trailing byte, an oversize claim, or truncation yields `WrongMailbox`. The reader parses to the end first and compares the mailbox afterwards (`verify-vmls.mjs:770-782`), yielding `NonCanonical`, `TooLarge`, or `Malformed`.
- **Profile value 24 or above in shortest form** (bytes `18 18`). Rust reads the profile as a raw byte and returns `NonCanonical` for anything above 23 (`lib.rs:121-128`). The reader decodes a CBOR uint and returns `UnsupportedVersion` (`verify-vmls.mjs:774`).
- **Eight-byte ciphertext length head** (`5b`). Rust returns `NonCanonical` unconditionally (`lib.rs:223`). The reader returns `Malformed` when truncated, `NonCanonical` below 2^32, and `TooLarge` at or above it (`verify-vmls.mjs:184-196`).
- **Fork evidence pair rule versus signatures.** Rust `ForkEvidence::parse` applies the pair rule before any signature check (`vmls-core/src/evidence.rs:73-76`, `:116-124`). The reader verifies each receipt's node and signature inside parsing, before the pair rule (`verify-vmls.mjs:703-709`). Contract §10 is silent on order.

The nine envelope cases (`vmls-core/vectors/vmls-envelope-v1.json:7-15`) cover none of these, and the hostile corpus has no envelope or evidence suite (`vmls-hostile-v1.json:11-37`). AUDIT §3 (`AUDIT-INTEROP.md:154`) lists "wrong lengths" as required envelope coverage, which is only partly met.

**Scenario.** A third implementation cannot know which precedence to follow. An FFI adapter that routes on `WrongMailbox` versus `NonCanonical` will behave differently depending on which reference it was validated against. The hostile corpus compares numeric codes exactly, so a future envelope corpus would fail for one of the two existing implementations.

**Resolution.** Pin precedence in §3 and §10 (recommend the Rust order as reference, with wrong-length mailbox changed to `Malformed` for consistency with `error.rs:16-17`, or document the exception). Add envelope vectors for a 31-byte mailbox, wrong mailbox plus trailing byte, profile `18 18`, and a `5b` head, plus an evidence vector with a bad signature and a non-pair. Align the reader.

### F-02 (Low) The independent reader's credential check order contradicts contract §6.1 and the reference

**Confirmed.** Contract §6.1 (`VMLS-1.md:285-298`) lists rule 6 as expiration, then `created_at` skew, then lifetime, then revocation, and states that "verification order is observable through the stable error result". Rust follows that order (`vmls-core/src/binding.rs:282-287`) and checks the `d` tag before `scope` (`binding.rs:263-266`). The reader checks `scope` before `d` (`verify-vmls.mjs:431-433`) and `CredentialNotYetValid` before `CredentialExpired` (`verify-vmls.mjs:442-443`).

Two input classes therefore produce different codes:

- A duplicate `d` tag with `scope` absent or not `person`: Rust `CredentialMalformed`, reader `CredentialNotPersonScoped`.
- `created_at` more than 600 seconds ahead of `now` and `expiration` at or before `now`: Rust `CredentialExpired`, reader `CredentialNotYetValid`.

The binding suite has `duplicate-d-tag`, `credential-created-in-future`, and `credential-expired` as separate cases (`vmls-binding-v1.json:249`, `:67`, `:169`) but no combined case. All 7,324 hostile binding outcomes agree, so no corpus input reaches either combination.

**Scenario.** A downstream implementer who ports from the reader rather than the Rust source will pass every published vector and still disagree with the reference on a documented, observable order.

**Resolution.** Reorder the reader to match §6.1. Add two binding vectors covering the combinations above so the order is pinned by evidence, not prose.

### F-03 (Low) `ForkEvidence::Equivocation` can be constructed around the pair rule; `encode` then emits bytes `parse` rejects and `verify` does not re-check

**Confirmed.** The enum and its variant fields are public (`vmls-core/src/evidence.rs:29-40`). The doc on the enum asserts an invariant ("A pair is always the same node, installation and slot with distinct keys in ascending order") that only the `equivocation` constructor (`evidence.rs:45-57`) and `parse` (`:73-76`) enforce. `encode` (`:87-103`) and `verify` (`:116-124`) do not call `check_pair` (`:127-132`). This type is not in the MRR-01 list or in contract §2.1 (`VMLS-1.md:62-70`), so the caller obligation is undocumented.

**Scenario (hypothesis, not observed).** An engine that assembles an `Equivocation` by struct literal from two receipts for different slots, or two identical receipts, gets `Ok` from `verify` and may act on a false fork signal locally. The encoded payload is rejected by every conforming peer with `EvidenceNotEquivocation`, so the failure is local and self-inflicted. No acceptance-side weakening.

**Resolution.** Make `verify` re-run `check_pair` for the `Equivocation` variant. This is a pure strengthening with no wire change. Add `ForkEvidence` to §2.1 and to the enum rustdoc. Regression test: build a descending pair via the variant, assert `verify` returns `EvidenceNotEquivocation` and `parse(encode())` returns the same.

### F-04 (Low) Record id reuse is AES-GCM key and nonce reuse; the contract states the rule but not the consequence

**Confirmed from source.** Both the AEAD key and nonce are derived from `record_secret` and `record_id` only (`vmls-core/src/derive.rs:130-143`), and `seal` is deterministic by design (`vmls-core/src/record.rs:226-245`). Contract §4.2 requires a CSPRNG id (`VMLS-1.md:160`) and §5.3 requires exact resend on retry (`VMLS-1.md:223-224`), but the retry rule sits under "Opening, retries, and replay" and never says why.

**Scenario (hypothesis).** A sender re-seals a modified payload, or the same payload after a bucket change, under a previously used id. The two ciphertexts share key and nonce, which leaks the XOR of the padded plaintexts and allows GCM authentication-key recovery for that key and nonce pair. The codec cannot prevent this.

**Resolution.** Add one sentence to §4.2 stating that a record id MUST NOT seal two different padded plaintexts under one record secret because key and nonce are both derived from it. Mirror it in the `seal` rustdoc. No test is possible beyond documentation.

### F-05 (Informational) Contract and audit headers still name baseline 0.1.0 at 53fa9a4

`VMLS-1.md:3-5` and `AUDIT-INTEROP.md:5` state the 0.1.0 baseline, but §2.1 contains text added at 791798e and the crate is 0.1.2 (`vmls-core/Cargo.toml:3`). A reader cannot tell from the document which contract revision they hold. AUDIT §8 records a contract hash externally (`AUDIT-INTEROP.md:333-334`) but the contract carries no revision line. Add a revision line and the commit that last changed normative text.

### F-06 (Informational) CI does not enforce the vector-hash policy, formatting, or dependency audit

AUDIT §2 (`AUDIT-INTEROP.md:103-104`) makes any vector change a versioned contract decision, but `.github/workflows/vmls-core.yml:21-42` has no step comparing the eleven files against Appendix A. `cargo fmt --check` and `cargo audit` run only locally (`AUDIT-INTEROP.md:409-410`). A PR that regenerates fixtures and updates both the Rust tests and the reader would pass CI. Add a hash step; the Python snippet in AUDIT §2 is sufficient.

### F-07 (Informational) The reader cannot evidence strict Ed25519 or weak-form BIP-340 rejection

The reader's Ed25519 path is `node:crypto` (`verify-vmls.mjs:682`, `:693`), which is not a strict verifier, and its BIP-340 check only requires `s < n` (`verify-vmls.mjs:378`) whereas k256 rejects `s = 0` at parse (`vmls-core/src/binding.rs:194-201`). The reader runs no weak-key or small-order negative cases. The strictness claim in contract §2.2 (`VMLS-1.md:75-77`) is therefore evidenced only by the Rust tests (`vmls-core/tests/design_vectors.rs:192-214`, `vmls-core/tests/allocation_witness.rs:195-238`), which rely on ed25519-dalek's own `verify_strict`. The `s = 0` divergence has no practical effect; finding such a signature is infeasible. State this limitation in AUDIT §3 or add negative cases to the reader.

## Checklist disposition

- **Canonical parsing and resource bounds: accepted, with F-01.** Shortest-form heads, major types, exact keys and order, trailing bytes, timestamps, UTF-8 and control bytes are enforced in `cbor.rs:59-78`, `:96-124`, `:145-156`. Every length is bounded on the raw 64-bit argument before conversion or slicing (`cbor.rs:87-94`, `:128-131`), so 32-bit targets return the same codes. Allocations follow validated lengths (`binding.rs:329`, `:335`, `capability.rs:74`, `lib.rs:141`). Envelope and forwarding bounds precede parsing (`lib.rs:139-141`, `allocation_witness.rs:130-146`). Accepted objects re-encode identically per the hostile tests (`tests/hostile.rs:57`, `:67-71`). Panic paths behind `expect` are all length-guarded (`receipt.rs:52-56`, `evidence.rs:67`, `allocation_witness.rs:148-153`, `derive.rs:75-77`).
- **Derivations and record protection: accepted, with F-04.** Single exporter label and empty context (`derive.rs:23-27`); HKDF-Expand directly on the epoch secret (`derive.rs:66-78`) versus Extract then Expand for record AEAD (`derive.rs:134-137`) and introductions (`derive.rs:158`); big-endian counters (`derive.rs:94`, `:160`); 28-byte split (`derive.rs:136-141`). AAD binds mailbox and record id (`record.rs:164-170`). Smallest bucket and zero padding are checked after authentication (`record.rs:214-218`, `:269-275`). Every open failure is `SilentDrop` (`record.rs:254-280`). Replay-state timing, CSPRNG, secret lifetime, and adapter logging are external, as documented at `record.rs:251-253` and `VMLS-1.md:543-558`.
- **BIP-340 bindings and credentials: accepted, with F-02.** NIP-01 serialisation matches `JSON.stringify` escaping (`binding.rs:173-192`, test `:614-623`). Carrying-leaf equality precedes signature (`binding.rs:476-480`). Required tags, person scope, identity, device, skew, both 30-day limits, revocation, and binding lifetime follow §6.1 (`binding.rs:254-299`, `:486-496`). Capability expiry and seven-day limit precede binding errors (`capability.rs:145-154`). The whole key-4 versus KeyPackage extension comparison, required-capabilities, and leaf-id uniqueness are clearly documented adapter checks (`VMLS-1.md:327-331`, `capability.rs:8-9`, `:137-138`), not codec bypasses.
- **Ed25519 receipts, evidence, and forwarding: accepted, with F-03 and F-07.** `verify_strict` against the pinned key only (`receipt.rs:46-50`, `:111-116`, `:246-251`); node and installation inside the signed digest (`receipt.rs:30-44`); challenge echo (`receipt.rs:247-249`); subject and status left to the caller (`receipt.rs:243-245`, `VMLS-1.md:379-381`). Evidence pair identity and ascending order (`evidence.rs:127-132`); unsigned `pre_epoch` documented (`evidence.rs:9-11`, `VMLS-1.md:425-426`). Forwarding: NUL-terminated domain (`allocation_witness.rs:20`), expected method (`:139-141`), canonical body round-trip at construction (`:76-81`, `:119`), pinned witness in the digest (`:177-184`). The writer key is self-asserted and the contract says so (`VMLS-1.md:481-486`); token consumption is a service obligation.
- **Lane safety: accepted for the pure table.** `decide` (`lane.rs:187-203`) matches the §13 table and the reader's independent restatement (`verify-vmls.mjs:900-923`). The invariants test (`lane.rs:237-292`) proves no sheltered input yields NIP-17 and that public output from a non-public composer requires the explicit choice. Separate-conversation creation, draft isolation, and wording-key use are downstream UI acceptance, not codec guarantees.
- **Manifest: accepted for canonical construction.** Raw-byte key ordering and duplicate refusal via `BTreeMap` (`manifest.rs:87`, `:113-121`); typed values including major-type-1 negatives (`cbor.rs:205-211`, test `design_vectors.rs:566-574`); schema hash bound into the array (`manifest.rs:131-145`). `insert_hashed` trusting the caller's key is documented (`manifest.rs:110-112`, `VMLS-1.md:450-452`). Schema coverage and storage reconciliation are adapter scope. No decoder exists, so the §2.1 text-control rule has no enforcement point for manifest values; this is harmless for digest agreement.

## MRR-01 disposition

**Accepted with conditions.**

The practical risk is correctly rated Low. Every decoder stays strict, so a caller that emits an out-of-bounds binding, capability, advance request, or witness receipt harms only itself: peers reject with `Malformed` or `TooLarge`, and a device may waste a signature over a body no one accepts. No acceptance-side weakening and no key exposure results. The listed signing and encoding entry points carry the obligation in rustdoc (`binding.rs:391-392`, `:403-405`, `capability.rs:60-62`, `witness.rs:75-76`, `receipt.rs:214-215`), and `ForwardedRequest::new` enforces it for its body (`allocation_witness.rs:76-81`, test `tests/allocation_witness.rs:181-191`).

Conditions before this can be recorded as closed:

1. **Add the undocumented API.** `ForkEvidence::Equivocation` (F-03) is an affected encoder outside the list, and its `verify` path is weaker than the documented ones. Either re-check the pair in `verify` or add it to §2.1 and the rustdoc.
2. **Annotate the remaining signing path.** `WitnessReceipt::digest_to_sign` (`receipt.rs:234-241`) is the witness's signing entry point and carries no sequence-limit note; only `encode` does. Add the same sentence there.
3. **Add regression evidence for decode-as-prevalidation.** No test currently shows the documented round-trip catching a bad typed value for the listed types. Add one assertion each: `LeafBinding::decode(&b.encode())` with `expires_at = 2^53` returns `Malformed` and with 17 tags returns `TooLarge`; `WitnessReceipt::parse(&r.encode())` with `seq = 2^53` returns `Malformed`; `AdvanceRequest::parse(&a.encode())` at `MAX_SAFE_INTEGER` returns `Malformed`.

If the maintainer prefers a checked API, a `try_encode` returning `Result` on each type would resolve the whole class without changing wire bytes, but it is not required for this gate.

## Contract and vector compatibility recommendation

**Approve with findings.** The published vectors, the Rust reference, and the independent reader agree on every published case, and the wire formats, derivations, and verification rules in `VMLS-1.md` match the source at 323b536 wherever I compared them. The findings do not change any accepted byte or any accepted-versus-rejected outcome. They do show that error precedence is under-specified (F-01, F-02) and should be pinned with vectors before a third implementation is validated against this revision. This recommendation covers the contract and vector compatibility gate only, not production readiness.

## Remaining limitations and next action

- **This is an independent AI review, not a human security audit or production approval.** It is source-backed and read-only. It did not execute tests, the reader, builds, or hash recomputation, and relies on the maintainer's quoted CI and local results for those.
- **Unreviewed or unverifiable here:** Appendix A hashes against file bytes; the exact 29,130 assertion count; non-canonical point encodings for Ed25519 keys and `R` under curve25519-dalek 4.1.3 (I did not trace the dependency's decompression rules); k256 0.14 x-only key parsing edge cases beyond on-curve and range checks; constant-time behaviour of any comparison; the dependency advisory referenced in `Cargo.toml:21`.
- **External acceptance gates still open, as the pack states:** independent regeneration of the vectors (the generator is absent from the repository), downstream interoperability matrix (§5), physical-device budgets (§6), coverage-guided fuzzing, side-channel assessment, formal proof, and a private security-reporting route.
- **Smallest concrete next action:** add the envelope and binding precedence vectors from F-01 and F-02, align the reader's order with §6.1, and write the precedence sentences into §3, §6.1, and §10. That closes the only gap that affects a third implementer, and the MRR-01 conditions can land in the same change.
