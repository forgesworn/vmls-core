# Independent AI review: VMLS/1 323b536

- **Reviewer/model and review date:** OpenAI Codex (GPT-6), 6 November 2026.
- **Exact commit and tree verification performed:** HEAD is `323b536a775a9e2a92dae979f92ae6435846dc10`; tree is `2665fddc0cfb713a1180720c2ae999af5a228d24`. Git reported no differences between the reviewed tracked files and that commit. An untracked `reviews/` directory was left unread.
- **Scope and files inspected:** `VMLS-1.md`; every file under `vmls-core/src/` and `vmls-core/tests/`; all eleven public vector files and their formats; `vectors/verify-vmls.mjs`; Cargo manifest and lockfile; CI workflow; AUDIT-INTEROP §§4–7. Section 8 was read after the initial implementation/test assessment.
- **Commands/checks performed:** Read-only source review; **no tests rerun**. Used Git identification/diff commands, numbered source reads, searches, and read-only JSON/hash inspection. Every Appendix A vector hash matched. Contract SHA-256 is `49a5c8b8cfe3f8b4cf7ec061a46099be3c4a00f97a6cec25baa0a86462f48268`. Supplied CI/test results were not independently rerun or fetched.
- Required host startup instructions caused local Z1P skill reads outside the repository. No memory, secret files, dependency caches, other reviewer output, or network services were consulted. No files were changed.

## Findings

The following are confirmed source-level inconsistencies. Counterexamples describe consequences derived from the code; they were not executed. No Critical, High, or Medium finding was confirmed.

### F1 — Low: constructed fork evidence can verify without satisfying the pair rules

**Evidence:** [evidence.rs:30](vmls-core/src/evidence.rs:30) exposes directly constructible variants. [evidence.rs:116](vmls-core/src/evidence.rs:116) verifies both signatures without calling `check_pair`, whose checks appear at line 127. Its rustdoc describes a verified `Equivocation` as portable proof.

**Contract:** [VMLS-1.md:416](VMLS-1.md:416) requires matching node/installation/slot and distinct, ascending pair keys.

**Failure scenario:** Construct `Equivocation` with the same valid `SlotReceipt` twice. `verify(pinned_node)` succeeds, but `parse(evidence.encode())` returns `EvidenceNotEquivocation`. Two valid receipts for different installations also pass this typed verification path.

An adapter assembling evidence from stored receipts could therefore mistake authenticated observations for equivocation. The byte parser prevents this scenario; this is **not a demonstrated network-decoder bypass**.

**Resolution and regression:** Call `check_pair` before verifying an `Equivocation`. Document the encoding prerequisite or provide checked encoding. Test directly constructed duplicate, reversed, different-slot, and different-installation pairs, including valid signatures.

### F2 — Low: manifest text construction contradicts the common control-character rule

**Evidence:** [manifest.rs:43](vmls-core/src/manifest.rs:43) writes `Value::Text` without validation; [manifest.rs:66](vmls-core/src/manifest.rs:66) does the same for namespaces. [cbor.rs:194](vmls-core/src/cbor.rs:194) copies arbitrary Rust UTF-8 strings.

**Contract:** [VMLS-1.md:44](VMLS-1.md:44) extends the common subset for manifests with negative integers and null, while lines 56–58 reject other control bytes.

**Failure scenario:** `Value::Text` containing U+0000 encodes as `61 00` and receives a hash. A separate implementation applying §2.1 literally must reject that value. The implementations then disagree about which database state can have a conforming manifest. This concerns canonical construction, independently of schema or restore correctness.

**Resolution and regression:** Clarify that unrestricted valid UTF-8 is permitted in manifest text, if that is intended; otherwise provide validation and define rejection. Add control-character cases for values, primary keys, and namespaces.

### F3 — Low: the independent reader differs from Rust on error precedence

**Evidence:** Rust checks envelope mailbox equality before ciphertext/trailing-data validation at [lib.rs:135](vmls-core/src/lib.rs:135). The Node reader checks trailing data first at [verify-vmls.mjs:779](vectors/verify-vmls.mjs:779).

Credential precedence also differs: Rust checks expiration before future creation at [binding.rs:282](vmls-core/src/binding.rs:282); Node reverses those checks at [verify-vmls.mjs:442](vectors/verify-vmls.mjs:442).

**Contract/checklist:** VMLS §14 defines stable errors; AUDIT-INTEROP §4 explicitly requires matching error precedence. The draft identifies Rust and the published vectors as the current exact-behaviour reference.

**Failure scenario:** An otherwise canonical envelope with both a wrong mailbox and trailing data returns `WrongMailbox` in Rust and `NonCanonical` in Node. A correctly signed credential that is both expired and excessively future-dated produces another disagreement.

Both implementations reject these inputs. The reported assertion count establishes agreement on the supplied corpus, not general diagnostic compatibility.

**Resolution and regression:** Specify the intended precedence and align the reader. Add combined-failure vectors, including signed credentials whose signatures remain valid.

### F4 — Low: manifest vector reading loses valid signed-64-bit integers

**Evidence:** [verify-vmls.mjs:124](vectors/verify-vmls.mjs:124) uses ordinary `JSON.parse`; [verify-vmls.mjs:718](vectors/verify-vmls.mjs:718) subsequently converts the parsed number to `BigInt`. Rust deserialises the same field directly as `i64` at [design_vectors.rs:494](vmls-core/tests/design_vectors.rs:494).

**Contract:** [VMLS-1.md:444](VMLS-1.md:444) permits signed 64-bit manifest integers, without the timestamp safe-integer restriction.

**Failure scenario:** A vector containing `{"t":"int","v":9007199254740993}` supplies an exact legal `i64` to Rust. Node rounds it before `BigInt` conversion and constructs different CBOR and hashes. Current fixtures avoid this boundary; their supplied pass is not contradicted.

**Resolution and regression:** Use lossless integer parsing or a versioned decimal-string representation. Cover both `i64` endpoints and nonrepresentable JavaScript integers immediately above and below the safe range.

### F5 — Low: MRR-01’s method-level signing documentation remains incomplete

**Evidence:** [receipt.rs:235](vmls-core/src/receipt.rs:235) exposes `WitnessReceipt::digest_to_sign` without the sequence prerequisite documented on `encode` at line 214. [binding.rs:205](vmls-core/src/binding.rs:205) and line 234 expose credential serialisation and its signature message through `serialize_nip01`/`id`, without structural-bound prerequisites.

**Contract:** [VMLS-1.md:62](VMLS-1.md:62) requires prevalidation **before signing**, not only before emission. AUDIT-INTEROP §8.2 claims method-level documentation covers affected signing entry points.

**Failure scenario:** A witness service obtains and signs the digest of a receipt with `seq = MAX_SAFE_INTEGER + 1`; recipients reject its encoded receipt. Similarly, an oversized constructed credential can be signed through `id()` before its eventual binding encoding is rejected.

The global contract assigns responsibility, but the method documentation does not consistently expose it where signing occurs.

**Resolution and regression/documentation evidence:** Add prerequisites to these signing helpers and clarify that typed verification assumes structural prevalidation. Demonstrate validation with placeholder signatures before signing, and revalidation after structural mutation.

### F6 — Informational: one unit-test assertion fails on 32-bit targets

**Evidence:** [cbor.rs:234](vmls-core/src/cbor.rs:234) includes `2^32`, then casts it to `usize` when computing the expected encoded size at line 237.

**Relevant requirement:** AUDIT-INTEROP §4 requires reviewing 32-bit behaviour; VMLS §2.1 requires shortest integer encodings.

**Failure scenario:** On a 32-bit target, that cast becomes zero. The assertion compares the actual nine-byte integer encoding with an expected one-byte head and fails. This is a test-portability defect, not evidence of a decoder defect. Compile-only bare-metal checks do not execute it.

**Resolution and regression:** Compute expected integer-head sizes using `u64` or explicit expected lengths. Execute this test on a supported 32-bit hosted target.

## Checklist disposition

“Accepted” below applies to the inspected codec or pure-table boundary, not downstream acceptance.

| AUDIT-INTEROP §4 area | Disposition | Evidence and boundary |
|---|---|---|
| Canonical parsing and resource bounds | **Finding** | Exact map counts/key order, shortest heads, trailing rejection, UTF-8 and timestamp checks are present. `Reader::bounded` compares `u64` before narrowing; slicing uses checked addition. Binding/capability/request sizes are bounded before parsing. F2–F6 qualify construction, reader compatibility, and portability. |
| Derivations and record protection | **Accepted** | `derive.rs:66–164` distinguishes direct epoch PRK expansion from record/introduction extraction. Labels, fixed-width suffixes, counter endianness, and 16/12 key split match §4. `record.rs:173–279` enforces payload limits, minimal buckets, zero padding, mailbox/id AAD, and silent-drop wrapping. |
| BIP-340 bindings and credentials | **Accepted**, with documentation finding F5 | Raw BIP-340 verification, NIP-01 escaping, lowercase hex, required-tag duplication, identity/device matching, revocation, skew, both lifetime ceilings, carrying-leaf equality, and capability expiry order are implemented. Representative positive/negative tests exist. |
| Ed25519 receipts, evidence, forwarding | **Finding** | Receipt and forwarding verification select `verify_strict`. Fixed layouts, digest domains, pinning, witness challenge, expected forwarding method, terminating NUL, and canonical body validation match the contract. Representative weak-key/R/noncanonical-S tests exist. F1 concerns constructed evidence; F5 concerns signing prerequisites. |
| Lane safety | **Accepted for the pure table** | `lane.rs:187–202` matches §13; enumeration and tests cover all 48 inputs. No sheltered input directly selects `SendNip17`. Empty-composer creation, copying prevention, and displayed wording remain client acceptance obligations. |
| Manifest scope | **Finding** | Construction sorts raw keys, rejects duplicates without replacement, preserves value types, and binds the schema hash. Cached/full recomputation tests exist. F2 and F4 remain. Schema coverage, reconciliation, and restore acceptance are external. |

Additional accepted external obligations:

- The whole capability key-4/KeyPackage extension comparison is explicitly assigned to the adapter by §7. `CarryingLeaf` cannot establish that equality; this is **not a codec bypass finding**.
- MLS validity, required-capabilities, leaf uniqueness, ECDH/key handling, CSPRNG quality, replay timing, exact-byte retries, retention, and erasure remain engine/platform obligations.
- Witness subject/status and transition checks, receipt/session association, writer enrolment, and atomic courier-token consumption remain caller/service obligations. Unsigned `pre_epoch` is not sufficient association evidence.
- Manifest recursion, total construction size, allocator failure, and device budgets require integration limits. No unbounded allocation driven solely by a decoded claimed length was identified.
- Reviewed production `expect`/indexing paths have preceding length checks or fixed-size invariants. This does not establish allocator-failure resilience.

Cargo and CI inspection found locked primitive versions, strict-verifier selection, read-only workflow permissions, pinned checkout action, and disabled persisted checkout credentials. CI covers hosted feature modes and bare-metal compilation. Dependency internals, current advisory status, and actual CI logs were not independently verified.

## MRR-01 disposition

**Accepted with conditions.**

Caller prevalidation is acceptable for this source-only codec API: rejected constructed values do not automatically bypass the strict byte decoders, and structural validation can occur before signing without changing wire bytes.

Conditions:

1. Complete the signing-entry documentation identified in F5.
2. Provide a concrete pre-sign structural-validation example and negative boundary evidence for the four named types.
3. State that mutation invalidates prior structural validation.
4. Address F1 separately; the current MRR-01 list does not cover `ForkEvidence`.

A checked/versioned replacement API is not mandatory to close MRR-01. `ForwardedRequest::new` already provides the stronger invariant through body round-trip validation and private fields.

## Contract and vector compatibility recommendation

**Do not approve** the contract/vector compatibility gate at this revision.

The existing corpus hashes match, and this review does not contradict its supplied passing results. However, the manifest text rule remains inconsistent, the reader cannot represent the full manifest integer domain, diagnostic precedence differs, and the typed evidence verification claim is stronger than its implementation.

These are narrow, repairable issues; they do not require changing valid VMLS/1 wire bytes.

## Remaining limitations and next action

- No builds, tests, vector runner, or counterexamples were executed.
- Cryptographic dependency internals and exhaustive Ed25519 point-encoding behaviour were not reviewed.
- Independent regeneration, downstream exchange/replay tests, physical-device budgets, coverage-guided fuzzing, side-channel assessment, and formal proof remain incomplete.
- No service, UI, storage, firmware, or production acceptance is established.

The smallest next action is a focused follow-up covering F1–F5, with direct-construction, combined-error, manifest-control, and full-`i64` regression evidence, followed by review of its exact commit. F6 is nonblocking for current hosted results.

**This is an independent AI review, not a human security audit or production approval.**