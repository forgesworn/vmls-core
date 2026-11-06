# Independent final AI review: VMLS/1 2d08414

- **Reviewer/model and review date:** OpenAI Codex, GPT-6; 6 November 2026.
- **Exact commit/tree verification:** HEAD is `2d0841442194a939e0e946f199b3a00bbcc73916`; tree is `b5c0e595889e2203f31a81d17adb03c793bd4f40`. Tracked files match HEAD. An untracked review prompt was excluded.
- **Scope and checks performed:** Read the two consolidated historical reports; inspected the complete implementation, documentation, workflow, test and vector changes from `323b536`, including the residual patch after `99fcaa1`. Independently recomputed all 11 Appendix A hashes: all matched. Ran the artifact-free Node reader under Node v24.21.0: **PASS 11 suites, 29169 independent assertions**. `git diff --check 323b536 2d08414` passed. Rust tests/builds, formatting, dependency audit and target compilation were **not rerun**. No files were changed, packages installed, network tools used, or other reviewer’s new output consulted.

## Residual conditions

1. **Resolved — literal envelope bytes.** Rust compares the map and keys directly with `a3`, `01`, `02`, `03`; Node now uses literal `expect` calls. Both immediately return `NonCanonical` for `b8` and `a3 18`. These fixtures passed in my Node run; Rust’s vector harness exercises them. See [Rust decoder](vmls-core/src/lib.rs:118), [Node decoder](vectors/verify-vmls.mjs:800) and [fixtures](vmls-core/vectors/vmls-envelope-v1.json:21).

2. **Resolved — evidence precedence.** Both implementations require at least 10 bytes, check version, then count/exact total length, decode receipt layouts, check pair rules, and finally verify signatures. The 10-byte unsupported-version fixture returns `UnsupportedVersion`, including in my Node run. See [Rust parser](vmls-core/src/evidence.rs:60), [Node verifier](vectors/verify-vmls.mjs:712) and [fixture](vmls-core/vectors/vmls-security-design-v1.json:27).

3. **Resolved — valid different-slot signatures.** The regression changes the second receipt’s slot, signs its new digest using the public fixture seed, and individually verifies both receipts before expecting `EvidenceNotEquivocation` from the constructed pair. See [regression](vmls-core/tests/design_vectors.rs:605). I inspected this test; I did not execute Rust.

4. **Resolved — nonce-reuse consequences.** `record::seal` explicitly states that sealing different padded plaintexts under one id exposes their XOR and undermines GCM authentication, followed by the exact-byte retry instruction. See [rustdoc](vmls-core/src/record.rs:225).

5. **Resolved — duplicate-check order.** Contract §6.1 explicitly places the `d` duplicate check first, the `scope` duplicate check second, and both before value comparison. This matches Rust and Node. See [contract](VMLS-1.md:322) and [Rust implementation](vmls-core/src/binding.rs:268).

6. **Resolved — bounded audit claim.** The follow-up says the reader “implements the documented Rust order”; it does not assert unrestricted equivalence. The independent strict-Ed25519 coverage limitation remains explicit. See [follow-up claim](AUDIT-INTEROP.md:453) and [coverage limitation](AUDIT-INTEROP.md:126).

7. **Resolved — hosted 32-bit compilation gate.** CI includes `cargo check --tests --target i686-unknown-linux-gnu --locked` on Ubuntu. This compiles tests without executing them. Hosted 32-bit execution remains explicitly unclaimed. See [workflow](.github/workflows/vmls-core.yml:66) and [audit limitation](AUDIT-INTEROP.md:473).

## AI-01 through AI-11 and new findings

| Finding | Final disposition |
|---|---|
| AI-01 | Resolved: verification rechecks pair invariants; constructed-pair regressions include valid different-slot signatures. |
| AI-02 | Resolved: envelope and evidence precedence now agree with the documented rules and added fixtures. |
| AI-03 | Resolved: credential duplicate/value and expiry/skew ordering agree; signed combined-failure fixtures pass Node verification. |
| AI-04 | Resolved: §11 explicitly permits manifest UTF-8 controls; namespace, key and value coverage is present. |
| AI-05 | Resolved: manifest integers reach `BigInt` losslessly; both `i64` endpoints and values beyond JavaScript’s safe range pass. |
| AI-06 | Resolved: signing prerequisites, mutation invalidation, prevalidation example and four-type negative regressions are present. |
| AI-07 | Resolved: contract and sealing rustdoc state confidentiality and authentication damage. |
| AI-08 | Resolved: current normative revision is distinguished from the historical baseline. |
| AI-09 | Resolved in workflow configuration: hash, formatting and audit gates are present. Exact-commit hosted success remains unverified here. |
| AI-10 | Resolved through accurate coverage scoping; independent strict-Ed25519 negative coverage remains a limitation. |
| AI-11 | Test defect resolved: expected sizes use `u64` ranges without narrowing. Hosted 32-bit execution remains outstanding validation. |

No original implementation or contract defect remains open. Existing vector cases were preserved; the changed suites add cases without modifying or removing earlier cases.

**No confirmed new defect or regression was found.**

## MRR-01 disposition

**Can be recorded as closed for this AI compatibility review at `2d08414`.** The documented caller-prevalidation approach is acceptable within the source-only codec scope. Contract §2.1 covers the omitted types, requires renewed validation after structural mutation, and distinguishes structural validation from semantic verification. Relevant signing helpers and negative boundary tests support that approach.

Named human acceptance remains a separate gate.

## Contract/vector compatibility recommendation

**approve**

The reviewed changes resolve the compatibility defects and residual conditions. All published hashes match, and the independent Node reader passes. This recommendation covers the contract/vector compatibility gate only.

## Remaining limitations and next action

Record successful CI for **this exact commit**; the earlier `99fcaa1` run does not establish it. Hosted 32-bit **execution remains not run**.

Human review, downstream interoperability, independent vector regeneration, physical-device acceptance and budgets, fuzzing, side-channel assessment, formal proof and production approval remain separate acceptance gates.

**This is an independent AI review, not a human security audit or production approval.**