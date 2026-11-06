# Independent AI review request: VMLS/1 at 323b536

You are one of two independent AI reviewers. Perform a separate source-backed contract and security review. Do not assume the maintainer's conclusions are correct, and do not seek the other AI reviewer's output.

## Hard boundaries

- Work only in the current repository root.
- Review exact commit `323b536a775a9e2a92dae979f92ae6435846dc10`.
- This is a read-only review. Do not edit or create repository files, commit, push, install packages, run formatters that write, or contact anyone.
- Do not use network tools or external services. Do not inspect files outside this repository or any secret files.
- Use only read-only source/search operations and, if available, read-only Git commands to verify the commit and tree. Do not run builds or tests that create artifacts. Existing verification evidence is supplied below; distinguish it from checks you perform yourself.
- Return your review as the final response. Do not ask for interactive input.

## Scope and method

Review `VMLS-1.md`, all of `vmls-core/src/`, `vmls-core/tests/`, the public vector formats, `vmls-core/Cargo.toml` and `Cargo.lock`, and `.github/workflows/vmls-core.yml`. The independent reader is `vectors/verify-vmls.mjs`; its reported results are evidence to assess, not a substitute for your source review.

First inspect the contract, implementation, and tests independently. Read `AUDIT-INTEROP.md` sections 4 through 7 for the checklist and acceptance boundaries. Section 8 contains the maintainer's pre-review and MRR-01; assess it only after forming your own initial view.

Cover at least:

1. Canonical CBOR parsing, exact map/key rules, trailing data, integer and UTF-8 bounds, allocation limits, and 32-bit behaviour.
2. Exporter/HKDF distinctions and inputs, ECDH boundary, record AEAD key/nonce derivation, AAD, bucket/padding rules, silent drops, retry and replay obligations.
3. BIP-340 binding and device-credential serialisation, identity/device/lifetime/revocation rules, carrying-leaf binding, and capability expiry.
4. The whole capability/KeyPackage extension comparison and other adapter obligations; do not misclassify clearly documented external checks as codec bypasses.
5. Strict Ed25519 verification, signed bytes/domains, weak/small-order forms, receipt pinning, witness challenges, evidence ordering/session association, and allocation forwarding/token boundaries.
6. Manifest canonical construction and lane invariants, while distinguishing pure codec/table guarantees from downstream UI or storage acceptance.
7. Public typed APIs that can produce values their decoders reject, panic paths, untrusted allocation, error precedence, and contract/source/test mismatches.

For every finding, provide:

- Severity: Critical, High, Medium, Low, or Informational.
- Exact `path:line` evidence and the relevant contract rule.
- A concrete failure or interoperability scenario; label hypotheses clearly and do not present speculation as confirmed.
- A minimal recommended resolution and regression test or documentation evidence.

Avoid vague best-practice suggestions without a demonstrated consequence. Explicitly distinguish confirmed findings, open questions, accepted external obligations, and unreviewed areas.

## MRR-01 decision

Maintainer finding MRR-01 (Low) says caller-constructed `LeafBinding`, `CapabilityRecord`, `AdvanceRequest`, and `WitnessReceipt` values could be encoded without every decoder-enforced bound being validated. Contract §2.1 and method rustdoc now require caller prevalidation before signing or emitting constructed values; a successful decode is offered as structural prevalidation. `ForwardedRequest::new` already checks its request body.

Decide whether this documentation/caller-prevalidation resolution is acceptable, acceptable only with conditions, or unacceptable and requiring a checked/versioned API. Explain the practical risk and assess whether any affected API or signing path remains undocumented.

## Existing evidence, not your approval

- PR CI run 42192707619 passed at source commit `791798e`.
- Main CI run 42193186863 passed at target `323b536`.
- The Node reader reports 11 suites and 29,130 independent assertions.
- Each Rust feature mode reports 48 tests passed; Rust 1.87.0/1.94.1, `thumbv7em-none-eabi`, formatting, vector hashes, and dependency audit passed locally.
- Independent regeneration, downstream interoperability, physical-device acceptance, coverage-guided fuzzing, side-channel assessment, and formal proof remain uncompleted.

## Required final report format

# Independent AI review: VMLS/1 323b536

- Reviewer/model and review date:
- Exact commit and tree verification performed:
- Scope and files inspected:
- Commands/checks performed (or `read-only source review; no tests rerun`):

## Findings

List findings in severity order with the evidence required above. If none, say `No confirmed findings` and identify residual uncertainty rather than implying proof of security.

## Checklist disposition

Record each AUDIT-INTEROP §4 area as accepted, finding, or not applicable, with concise evidence. Include manifest and lane scope explicitly.

## MRR-01 disposition

State `accepted`, `accepted with conditions`, or `not accepted`, with reasons and any required follow-up.

## Contract and vector compatibility recommendation

Choose `approve`, `approve with findings`, `do not approve`, or `insufficient evidence`. This recommendation applies only to the contract/vector compatibility gate, not production readiness.

## Remaining limitations and next action

List unreviewed scope, external acceptance gates, and the smallest concrete next action. State explicitly that this is an independent AI review, not a human security audit or production approval.
