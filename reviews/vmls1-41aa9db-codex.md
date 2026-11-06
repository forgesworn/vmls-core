# Independent final AI review: VMLS/1 vector generator 41aa9db

- **Reviewer/model and review date:** OpenAI Codex, GPT-6; 6 November 2026.
- **Exact commit/tree verification:** HEAD is `41aa9db7e0bb4ed0df7352885d28cf1d8141ec60`; tree is `99d9d03a537bafb53ffc0687eaa2d109fb1efd47`. Tracked files match that commit. Untracked review files were left unread and untouched.
- **Scope and checks performed:** Read-only inspection of both complete scripts, CI, README, AUDIT-INTEROP §11, the specified consolidated review, historical findings and supporting fixtures/Rust source/tests. Independently recomputed all 11 Appendix A hashes: all match. No builds, test suites, generator execution, writes, installations, network access or contacts. Supplied execution results remain supplied evidence.

## Remaining independence and reporting dispositions

1. **Standalone device-reader independence — corrected.**  
   Scope comes from scenario names and targets from event/room keys; acceptance never reads `expect` ([vectors/verify-vmls.mjs:1022](vectors/verify-vmls.mjs:1022)). The poison control changes `room-presented-as-person` to an expected room scope while requiring rejection ([vectors/verify-vmls.mjs:1058](vectors/verify-vmls.mjs:1058)). This meaningfully exercises the previous defect: the former expectation-driven implementation would accept that poisoned scenario.

2. **Explicit slot and attempt inputs — corrected.**  
   The fixture defines `slotHex`, `baseAttempt`, `relabelledAttempt` and `foreignAttempt` ([vmls-security-design-v1.json:23](vmls-core/vectors/vmls-security-design-v1.json:23)). `buildSlot` allocates a fresh body and writes the supplied slot/attempt; every rebuilt receipt and evidence pair receives these inputs ([vectors/generate-vmls.mjs:268](vectors/generate-vmls.mjs:268), [line 295](vectors/generate-vmls.mjs:295)). The attempt control requires input `5` to reach the decoded rebuilt receipt ([line 527](vectors/generate-vmls.mjs:527)); the published relabelled attempt is `4`, making this a real change.

3. **Tombstone target derivation — corrected.**  
   NIP-01 serialization hashes the event fields, excluding its retained `id`; the revocation target is computed from the `person-passes` event before rebuilding and verifying the tombstone ([vectors/generate-vmls.mjs:213](vectors/generate-vmls.mjs:213), [line 234](vectors/generate-vmls.mjs:234)).

4. **Default checking and write reporting — corrected.**  
   Default mode requires both deep semantic equality and equality with independently rendered bytes ([vectors/generate-vmls.mjs:533](vectors/generate-vmls.mjs:533)). Rendering derives from regenerated objects, without an original-text fallback ([line 407](vectors/generate-vmls.mjs:407)). Write mode bypasses compatibility comparisons, writes rendered output, and reports “files written” ([line 543](vectors/generate-vmls.mjs:543)). Bare `--write` is excluded from positional-root selection at [line 38](vectors/generate-vmls.mjs:38).

5. **CI and execution guards — corrected for documented invocations.**  
   CI selects Node 20 through a commit-pinned setup action, asserts both reader PASS counts, runs the reader through a symlink, and asserts generator completion ([workflow:21](.github/workflows/vmls-core.yml:21), [line 47](.github/workflows/vmls-core.yml:47)). The reader’s guard resolves real paths, handles absent arguments and stdin, and catches missing-path failures ([vectors/verify-vmls.mjs:850](vectors/verify-vmls.mjs:850)). Imports therefore avoid suite execution.

6. **Evidence wording — corrected.**  
   AUDIT-INTEROP explicitly distinguishes rebuilt receipt fields from retained witness bodies/evidence headers and retained, independently verified binding/capability inputs ([AUDIT-INTEROP.md:543](AUDIT-INTEROP.md:543)). This matches receipt rebuilding, witness re-signing and evidence-header retention in the implementation. README accurately separates checking from writing and identifies retained signatures/inputs ([README.md:57](README.md:57)). The consolidated corrections are supported by source ([review:18](reviews/vmls1-14894cb-ai-review.md:18)); its execution claims remain supplied evidence.

## New or remaining findings

**No confirmed new findings.**

## Regeneration and negative-control assessment

All **11 families** have regeneration dispatch entries ([vectors/generate-vmls.mjs:485](vectors/generate-vmls.mjs:485)): envelope, binding, capability, derivations/records, lanes, device credentials, security design, witness requests, manifests, allocation forwarding and hostile inputs.

I checked coverage against the published fixtures: 16 envelope cases, 43 bindings, 17 capabilities, 21 records, 48 lanes, eight device cases plus tombstone, security receipts/evidence, 13 witness requests, 12 manifests, read/advance allocation envelopes, and 28,687 hostile outcomes.

Full-`i64` values are preserved before JSON parsing and encoded through `BigInt` ([vectors/verify-vmls.mjs:129](vectors/verify-vmls.mjs:129), [line 732](vectors/verify-vmls.mjs:732)). Both endpoints and values beyond JavaScript’s safe-integer range are present. Rendering covers pretty JSON, compact cases, appended compact cases, raw integer tokens and single-line hostile arrays ([vectors/generate-vmls.mjs:419](vectors/generate-vmls.mjs:419)).

Controls meaningfully cover trailing-byte outcome/rendering changes, expected-identity independence, retained-key rejection, installation rebuilding, attempt propagation and standalone-reader scope independence.

**Yes: the implementation and supplied runs establish reproducible independent generation within the documented fixture-driven scope.** Independence is from Rust; generator and reader share their Node primitive stack. Retained signed inputs and scenario bodies remain the explicitly documented boundaries.

## Contract/vector compatibility recommendation

**approve**

The six corrections are supported by source, and all 11 independently recomputed Appendix A hashes match. This reviewer supports closing the independent-regeneration gate at this exact revision. Any requirement for two independent approvals still requires recording the second reviewer’s disposition.

## Remaining limitations and next action

Record this report against the exact commit and update §11 after collecting the required independent dispositions.

I did not independently execute the supplied Node, Rust, toolchain, target, formatting, audit or workflow checks. Hosted 32-bit execution remains **not run**. Downstream interoperability, physical-device acceptance and other external gates remain separate. Node verification does not establish independent strict-Ed25519 rejection of every weak/noncanonical form, as documented at [AUDIT-INTEROP.md:126](AUDIT-INTEROP.md:126).

This is an **independent AI review, not a human security audit or production approval**.