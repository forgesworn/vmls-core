# Consolidated first AI re-review: VMLS/1 99fcaa1

Status: **two independent AI re-reviews complete; residual conditions carried into the next candidate**

- Review target: `99fcaa1302b50f6427b0c9e7bdccfea05c969743`.
- Claude report: [vmls1-99fcaa1-claude.md](vmls1-99fcaa1-claude.md).
- Codex report: [vmls1-99fcaa1-codex.md](vmls1-99fcaa1-codex.md).
- Re-review prompt: [vmls1-99fcaa1-re-review-prompt.md](vmls1-99fcaa1-re-review-prompt.md).

These are independent AI reviews, not human security audits or production approval. Both inspected the committed follow-up without changing source or rerunning full suites. Codex independently recomputed all vector hashes and manifest encodings and ran in-memory Node probes. Claude performed read-only source inspection.

## Recommendations and dispositions

Claude found AI-01 through AI-11 resolved and MRR-01 closed, recommending **approve with findings**. Codex found AI-03 through AI-06 and AI-08 through AI-10 resolved, with AI-01, AI-02, AI-07, and AI-11 partially resolved. It retained MRR-01 as accepted with conditions and recommended **do not approve** until the remaining conditions were repaired.

The reviewers agreed on the remaining implementation conditions:

1. Envelope map/key handling still decoded extended CBOR heads instead of comparing literal bytes, creating `Malformed` versus `NonCanonical` divergence on `b8` and `a3 18`.
2. Evidence version/total-length precedence differed; the reader needed to check the 10-byte header and version before total length.
3. The different-slot regression needed two independently valid receipt signatures rather than a mutated, invalid signature.
4. `record::seal` rustdoc needed to state plaintext-XOR exposure and authentication damage, not only the prohibition.

Claude additionally identified imprecise `d`/`scope` wording, an unqualified reader-alignment claim, and the absence of a hosted 32-bit test-compile CI step. Codex confirmed the new binding signatures, manifest bytes/digests, and Appendix A hashes independently.

## Applied follow-up

- The reader now compares envelope map/key bytes literally and checks evidence header length and version before count/total length. Contract §§3 and 10 specify the same order. Envelope `b8`/`a3 18` and unsupported-version evidence cases were added.
- Contract §6.1 now states that the `d` duplicate check precedes the `scope` duplicate check and both precede value comparison.
- The different-slot receipt is signed independently with the public fixture seed and individually verified before the constructed pair is rejected.
- `record::seal` rustdoc now states both confidentiality and authentication consequences.
- The audit claim is limited to the documented Rust order rather than unrestricted equivalence.
- CI now compiles tests for `i686-unknown-linux-gnu` in addition to the local Android 32-bit compile. Hosted 32-bit execution remains unavailable and unclaimed.

The reader reports **29,169 assertions** after these additions. Final full-suite verification and a new exact-commit AI re-review are required before compatibility approval.
