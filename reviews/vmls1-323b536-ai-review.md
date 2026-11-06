# Consolidated independent AI review: VMLS/1 323b536

Status: **two independent AI reviews complete; compatibility approval remains open pending focused fixes and re-review**

- Review target: `323b536a775a9e2a92dae979f92ae6435846dc10`.
- Review date: 2026-11-06.
- Shared read-only prompt: [vmls1-323b536-review-prompt.md](vmls1-323b536-review-prompt.md).
- Claude report: [vmls1-323b536-claude.md](vmls1-323b536-claude.md).
- Codex report: [vmls1-323b536-codex.md](vmls1-323b536-codex.md).

These are independent AI reviews, not a human security audit or production approval. The reviewers did not see each other's reports. Both inspected the target before reading the maintainer's section 8 conclusions. Neither reran the build or test suite. Codex independently recomputed all Appendix A vector hashes; Claude did not. The maintainer separately checked the cited source for every consolidated finding below. Counterexamples and new regression tests have not yet been executed.

## Reviewer identities and methods

- **Claude Fable 5.1 (`claude-fable-5-1`), Claude Code 2.1.319:** read-only source review using Read/Grep/Glob and local Git metadata only; no network tools, subagents, tests, or tracked-file changes. Claude reported all low/informational findings and recommended **approve with findings**.
- **OpenAI Codex, self-reported GPT-6, Codex CLI 0.166.0:** read-only source review covering all source, tests, vector files, reader, manifest, lockfile and workflow; no tests rerun or tracked-file changes. Codex recomputed all Appendix A vector hashes and the contract hash. It reported five low findings and one informational issue and recommended **do not approve** pending repairs.

The `reviews/` directory was untracked during both reviews and was excluded from their tracked-tree comparisons. The only local effects of the review task are the prompt and review reports.

## Consolidated findings

### AI-01 — Low: directly constructed fork evidence bypasses pair invariants

Reviewers: Claude F-03; Codex F1. **Maintainer source-confirmed.**

`ForkEvidence::Equivocation` and its fields are public, so callers can bypass the checked constructor. `verify` checks both signatures without calling `check_pair`, while `encode` can emit bytes `parse` rejects (`vmls-core/src/evidence.rs:30`, `:87`, `:116`, `:127`). Duplicate, reversed, different-slot, or different-installation pairs can therefore be treated locally as verified equivocation despite the contract's pair rules (`VMLS-1.md:407-426`). This is not a network-decoder bypass, but an adapter assembling evidence can act on a false fork signal.

Required resolution: re-run `check_pair` in `verify`; document checked encoding obligations. Add directly constructed duplicate, reversed, different-slot, and different-installation regression cases with valid signatures.

### AI-02 — Low: envelope and evidence error precedence is under-specified and divergent

Reviewers: Claude F-01; Codex F3 (envelope portion). **Maintainer source-confirmed.**

Rust checks envelope mailbox equality before ciphertext/trailing validation (`vmls-core/src/lib.rs:130-143`); the reader checks these afterwards (`vectors/verify-vmls.mjs:770-782`). Wrong mailbox plus a later defect therefore returns different stable codes. Additional uncovered divergences include:

- Wrong mailbox head length: Rust `NonCanonical`, reader `Malformed`.
- Profile `18 18`: Rust `NonCanonical`, reader `UnsupportedVersion`.
- Eight-byte ciphertext length head `5b`: different malformed/noncanonical/oversize precedence.
- Evidence: Rust checks pair rules before signatures; the reader verifies signatures first (`vectors/verify-vmls.mjs:697-710`; `vmls-core/src/evidence.rs:73-76`).

The current vectors do not pin these combined or boundary cases, although AUDIT-INTEROP §4 requires matching error precedence. Acceptance/rejection itself does not differ.

Required resolution: specify the intended order in contract §§3 and 10, align the reader with the Rust reference, and add the boundary/combined-failure vectors. Decide explicitly whether the envelope's wrong-length mailbox remains a documented `NonCanonical` exception or changes to `Malformed`.

### AI-03 — Low: credential error precedence differs from the contract and Rust

Reviewers: Claude F-02; Codex F3 (credential portion). **Maintainer source-confirmed.**

Rust checks expiration before future creation and evaluates `d` before `scope` (`vmls-core/src/binding.rs:263-266`, `:282-287`). The reader reverses both orders (`vectors/verify-vmls.mjs:431-443`). Combined defects therefore return `CredentialExpired` versus `CredentialNotYetValid`, or `CredentialMalformed` versus `CredentialNotPersonScoped`, despite the observable order required by contract §6.1.

Required resolution: align the reader with Rust and contract §6.1, and add correctly signed combined-failure vectors for both cases.

### AI-04 — Low: manifest text construction conflicts with the common control-character rule

Reviewer: Codex F2. **Maintainer source-confirmed contract ambiguity.** Claude accepted manifest construction and judged the absence of a decoder made this harmless; the maintainer does not treat that as removing the cross-implementation contract ambiguity.

Manifest values and namespaces encode arbitrary valid Rust UTF-8 (`vmls-core/src/manifest.rs:43-53`, `:66-72`; `vmls-core/src/cbor.rs:194-197`). Contract §2.1 rejects control bytes other than five short escapes, while §11 does not explicitly exempt manifest text (`VMLS-1.md:44-58`, `:428-452`). A second implementation can therefore reject a manifest value the Rust constructor hashes.

Required resolution: explicitly permit unrestricted valid UTF-8 for manifest text if intended, or add checked construction and rejection rules. Add control-character cases for values, primary keys, and namespaces.

### AI-05 — Low: the independent reader loses valid signed-64-bit manifest integers

Reviewer: Codex F4. **Maintainer source-confirmed.**

The reader uses ordinary `JSON.parse` (`vectors/verify-vmls.mjs:124-126`) and only later converts numbers to `BigInt` (`:715-720`). Contract §11 permits signed 64-bit integers, but integers outside JavaScript's exact safe range are rounded before encoding. Rust deserialises the same JSON field directly as `i64` (`vmls-core/tests/design_vectors.rs:490-507`). Current vectors avoid this boundary.

Required resolution: use lossless integer parsing or a versioned decimal-string representation. Add both `i64` endpoints and values immediately above and below the JavaScript safe range.

### AI-06 — Low: MRR-01 signing/prevalidation documentation and evidence remain incomplete

Reviewers: Codex F5; Claude MRR-01 conditions. **Maintainer source-confirmed.**

`WitnessReceipt::digest_to_sign` lacks the sequence prerequisite documented on `encode` (`vmls-core/src/receipt.rs:214-240`). `DeviceCredential::serialize_nip01` and `id` expose signing-message construction without structural-bound prerequisites (`vmls-core/src/binding.rs:203-236`). `ForkEvidence` is also missing from the original MRR-01 type list. No regression demonstrates the documented decode-as-prevalidation path for all four named types.

Required resolution: complete signing-entry rustdoc, state that mutation invalidates previous structural validation, add a concrete pre-sign validation example, and add negative boundary tests for bindings, capabilities, advance requests, and witness receipts. Resolve AI-01 separately.

### AI-07 — Low: the record-id rule does not state the AES-GCM nonce-reuse consequence

Reviewer: Claude F-04. **Maintainer source-confirmed documentation gap.**

Record key and nonce both derive solely from `record_secret` and `record_id` (`vmls-core/src/derive.rs:129-143`), and sealing is deterministic (`vmls-core/src/record.rs:225-245`). The contract requires random ids and exact-byte retry but does not explain that sealing different padded plaintexts under one id reuses the AES-GCM key/nonce pair, exposing plaintext XOR and undermining authentication.

Required resolution: state this consequence explicitly in contract §4.2 and `record::seal` rustdoc. Preserve the existing exact-byte retry rule; no wire change is needed.

### AI-08 — Informational: contract revision headers still name the 0.1.0 baseline

Reviewer: Claude F-05. **Maintainer source-confirmed.**

`VMLS-1.md:3-5` and `AUDIT-INTEROP.md:5` name the original 0.1.0 baseline even though normative text has changed and the crate is 0.1.2. Section 8 records the new contract hash externally, but the contract has no revision line identifying the commit that last changed it.

Recommended resolution: add explicit original-baseline and current-normative-revision identifiers.

### AI-09 — Informational: CI does not enforce vector hashes, formatting, or dependency audit

Reviewer: Claude F-06. **Maintainer source-confirmed.**

The workflow runs the reader, tests, toolchains, and target compilation, but not the Appendix A hash comparison, `cargo fmt --check`, or `cargo audit` (`.github/workflows/vmls-core.yml:21-42`). Those checks currently have local-only evidence.

Recommended resolution: add these policy checks to CI, with a deterministic expected-hash manifest rather than regenerating vectors during validation.

### AI-10 — Informational: the independent reader does not evidence strict-signature negative forms

Reviewer: Claude F-07. **Maintainer confirmed as an evidence limitation, not an exploit.**

The Rust suites test strict Ed25519 weak/small-order and noncanonical forms. The Node reader uses `node:crypto` without those negative cases, and its test-only BIP-340 arithmetic checks `s < n` but not `s = 0` (`vectors/verify-vmls.mjs:372-382`). No practical signature forgery is demonstrated. The reader's coverage claims should not be read as duplicating Rust's strict-negative evidence.

Recommended resolution: document the limitation and add practical negative cases where the independent primitive stack can represent them.

### AI-11 — Informational: one CBOR unit-test assertion is not 32-bit portable

Reviewer: Codex F6. **Maintainer source-confirmed test defect.**

The test includes `2^32` and casts it to `usize` when calculating the expected encoded size (`vmls-core/src/cbor.rs:233-238`). On a 32-bit target this truncates to zero and makes the assertion incorrect. The production decoder compares before narrowing and is not implicated. Bare-metal CI compiles but does not execute this hosted test.

Recommended resolution: compute the expectation using `u64` or explicit lengths and run the test on a supported hosted 32-bit target.

## MRR-01 disposition

Both reviewers selected **accepted with conditions**, not unconditional closure. They accept caller prevalidation as a valid low-risk approach for this source-only codec API and do not require a checked/versioned API. Closure requires AI-01 and AI-06 to be resolved with documentation and negative regression evidence, including the omitted `ForkEvidence` type and remaining signing helpers.

## Contract/vector compatibility disposition

- Claude: **approve with findings**.
- Codex: **do not approve** before repairs.
- Consolidated maintainer gate status: **open**. The existing vectors still pass and no reviewer identified a Critical, High, or Medium issue or a change to accepted valid wire bytes. However, the confirmed contract/reader/API inconsistencies prevent recording consolidated compatibility approval at this revision. A focused fix and re-review are required; this is not a human reviewer rejection or a production-readiness decision.

## Next action

Prepare a focused follow-up resolving AI-01 through AI-07 with regression evidence. Include the low-cost documentation/CI/test repairs AI-08, AI-09, and AI-11, and record AI-10 accurately. Run the full Node/Rust/toolchain/target suite, then ask both AI reviewers to review the exact follow-up commit and their prior findings. Keep downstream interoperability, independent regeneration, physical-device acceptance, fuzzing, side-channel assessment, formal proof, human review, and production approval as separate gates.
