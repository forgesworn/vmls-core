# Independent AI re-review: VMLS/1 99fcaa1

- **Reviewer/model and review date:** OpenAI Codex, GPT-6 (self-reported), 6 November 2026.
- **Exact commit/tree verification:** HEAD is `99fcaa1302b50f6427b0c9e7bdccfea05c969743`; tree is `adb8babc074219b52d13b89266b6182fc027dc11`. Tracked files match HEAD. The pre-existing untracked re-review prompt was untouched.
- **Scope and checks performed:** Read the consolidated findings, reviewed the complete implementation/contract/vector/workflow diff from `323b536a775a9e2a92dae979f92ae6435846dc10`, and inspected affected implementations and tests. Independently checked all 11 Appendix A hashes, preservation of prior vector data, all 12 manifest encodings/digests, and diff whitespace. Targeted, in-memory Node probes checked signatures and error counterexamples without creating artifacts. Rust results below are supplied evidence; I did not rerun builds or the full suites. No network, package installation, edits, or contact with another reviewer.

## AI-01 through AI-11 disposition

| Finding | Disposition | Evidence and remaining condition |
|---|---|---|
| **AI-01** | **partially resolved** | `vmls-core/src/evidence.rs:122` now calls `check_pair` before either signature. Encoding obligations appear at `evidence.rs:87`. Direct-construction regressions cover all four pair defects at `vmls-core/tests/design_vectors.rs:598`. However, the different-slot case changes `slot` while retaining the old signature at `design_vectors.rs:625`; it is not the requested valid-signature regression. |
| **AI-02** | **partially resolved** | Envelope precedence is documented at `VMLS-1.md:120`; evidence pair-before-signature precedence at `VMLS-1.md:449`. Reader repairs appear at `vectors/verify-vmls.mjs:714`, `:779`, and `:803`. New vectors cover the reported mailbox/profile/ciphertext cases at `vmls-core/vectors/vmls-envelope-v1.json:16` and evidence combined failures at `vmls-security-design-v1.json:25`. Additional envelope and evidence precedence divergences remain, detailed below. |
| **AI-03** | **resolved** | Rust evaluates `d`, then `scope`, at `vmls-core/src/binding.rs:268`, and expiration before creation skew at `:287`. Node now matches at `vectors/verify-vmls.mjs:437` and `:448`; the contract specifies this at `VMLS-1.md:320`. Combined-failure vectors are at `vmls-core/vectors/vmls-binding-v1.json:376` and `:377`. My probes verified both the binding and credential signatures in each new case. |
| **AI-04** | **resolved** | `VMLS-1.md:477` explicitly exempts manifest namespaces/text from the common control restriction. The `control-text` vector at `vmls-core/vectors/vmls-manifest-v1.json:259` covers namespace, primary-key text, and value text. Rust consumes these through `vmls-core/tests/design_vectors.rs:545`. Independent recomputation agrees with its bytes and digest. |
| **AI-05** | **resolved** | `vectors/verify-vmls.mjs:128` quotes integer tokens before JSON parsing; `:730` converts them directly to `BigInt`. Rust deserialises integers as `i64` at `vmls-core/tests/design_vectors.rs:515`. Vectors at `vmls-core/vectors/vmls-manifest-v1.json:255`–`:258` cover both endpoints and ±9007199254740993. All independently recomputed correctly. |
| **AI-06** | **resolved** | Credential helpers document prevalidation at `vmls-core/src/binding.rs:206` and `:237`; binding signing/encoding at `:394` and `:406`; capability encoding at `vmls-core/src/capability.rs:58`; advance encoding at `vmls-core/src/witness.rs:75`; witness signing at `vmls-core/src/receipt.rs:234`. `VMLS-1.md:65` includes the omitted types, and `:76` gives a concrete round-trip example and mutation invalidation. Negative round-trips cover all four original MRR-01 types at `vmls-core/tests/hostile.rs:80` and `design_vectors.rs:643`. |
| **AI-07** | **partially resolved** | `VMLS-1.md:180` explicitly explains key/nonce reuse, plaintext XOR exposure, authentication damage, and exact-byte retries. `vmls-core/src/record.rs:227` documents derivation and prohibition but omits the requested explicit confidentiality/authentication consequences. |
| **AI-08** | **resolved** | Original provenance and current normative revision are distinguished at `VMLS-1.md:5` and `AUDIT-INTEROP.md:5`. The current revision is identified by the containing Git commit. |
| **AI-09** | **resolved** | `.github/workflows/vmls-core.yml:21` enforces all 11 Appendix A hashes; `:38` enforces formatting; `:40` runs dependency audit. These are executable CI steps. I verified the current hashes locally, but did not observe a hosted workflow run. |
| **AI-10** | **resolved** | `AUDIT-INTEROP.md:126` accurately limits Node’s strict-Ed25519 negative evidence. `vectors/verify-vmls.mjs:384` explicitly rejects zero BIP-340 `s`. This does not establish independent strict-Ed25519 equivalence. |
| **AI-11** | **partially resolved** | `vmls-core/src/cbor.rs:237` computes expected sizes using the original `u64`, eliminating the narrowing defect. Supplied Android test compilation establishes compilation only. Hosted 32-bit execution remains unperformed and is accurately recorded at `AUDIT-INTEROP.md:472`. |

## New or remaining findings

**No confirmed new findings.** The following prior conditions remain.

### Low — AI-02: stable error precedence still differs

Two concrete counterexamples remain outside the added vectors:

- **Envelope `b8`, or `a3 18`:** Rust returns `NonCanonical` immediately from its literal map/key checks (`vmls-core/src/lib.rs:117`, `:176`). Node returns `Malformed` while attempting to read the extended CBOR argument (`vectors/verify-vmls.mjs:181`, `:206`, `:210`, `:801`). I reproduced the Node results; Rust results follow directly from the inspected branches.
- **Evidence `02000000000000000000` — ten bytes with an unsupported version:** Rust checks the minimum header length, then version, returning `UnsupportedVersion` (`vmls-core/src/evidence.rs:61`). Node rejects its total length first, returning `Malformed` (`vectors/verify-vmls.mjs:709`).

**Consequence:** rejection remains consistent, but stable diagnostic codes do not. The unqualified reader/Rust alignment claim at `AUDIT-INTEROP.md:453` exceeds the evidence.

**Minimal resolution:** use literal envelope map/key checks matching Rust; match Rust’s evidence header/version/count-length ordering; specify that ordering and add shared counterexample vectors.

### Low — AI-01: one requested regression condition remains

The different-slot regression at `vmls-core/tests/design_vectors.rs:625` retains a signature over the previous slot. My probe confirmed that receipt fails signature verification.

**Consequence:** the test demonstrates pair-before-signature precedence, but does not provide the explicitly requested different-slot pair with two valid signatures.

**Minimal resolution:** use a separately signed receipt for another slot, assert both receipts individually verify, then assert directly constructed evidence returns `EvidenceNotEquivocation`.

### Low — AI-07: rustdoc omits the explicit reuse consequences

`vmls-core/src/record.rs:227` gives the correct prohibition and retry rule, but only `VMLS-1.md:183` explains plaintext XOR exposure and undermined authentication.

**Consequence:** API-only readers receive an incomplete explanation of this security-critical requirement.

**Minimal resolution:** add those consequences to `record::seal` rustdoc.

## MRR-01 disposition

**Retain “accepted with conditions”; do not record unconditional closure yet.**

AI-06’s documentation and original four-type negative regressions satisfy its conditions. AI-01’s implementation repair is correct, but its requested valid-signature different-slot regression remains outstanding. A checked/versioned API is not required for this disposition.

## Contract/vector compatibility recommendation

**Do not approve** this gate yet, because stable error compatibility remains incomplete under AI-02.

Existing valid wire bytes appear preserved: every prior vector case and field remains unchanged, and the sole executable Rust production change adds pair validation to directly constructed evidence. All 11 published hashes match. The new manifest vectors independently recompute correctly; the new credential combined-failure vectors have valid signatures; the added evidence precedence vectors return their stated Node outcomes.

These observations support the repairs, but do not justify an unrestricted error-equivalence claim.

## Remaining limitations and next action

Repair the remaining precedence differences, add their shared vectors and the valid-signature different-slot regression, complete the sealing rustdoc, then re-review the exact resulting revision.

Hosted 32-bit test **execution remains not run**. Android test compilation and bare-metal compilation do not replace it. The supplied Node/Rust/toolchain/audit/formatting results were not rerun as full suites during this review.

Human review on issue #7, downstream interoperability, independent vector regeneration, physical-device acceptance and resource budgets, coverage-guided fuzzing, side-channel assessment, formal proof, and production approval remain separate gates (`AUDIT-INTEROP.md:489`).

**This is an independent AI review, not a human security audit or production approval.**