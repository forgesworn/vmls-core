# Codex review: Vennel c154087

Scope: read-only independent AI review of `c154087ecfc43ee9404fa4d548cdc94c0789afef` and parent `9ceaf3317ed2fd28f0abb4073dfd4e4e6258c6ab`. Not human, security, production or dependency-exception approval.

## Initial findings

Codex did not approve `9ceaf33` and identified:

1. The design generator copied attempt fields and expected outcomes, allowing contradictory or poisoned fixtures to pass.
2. The sync omitted caller-prevalidation warnings for constructed credentials, bindings and evidence.

## Final verdict

The earlier implementation and review-evidence findings are resolved, with no additional code correctness finding identified. The dependency gate remains open and blocks the PR.

Codex independently confirmed:

- declared attempts drive receipt bytes and precedence expectations are independently calculated; both negative controls reject as required;
- prevalidation warnings and pair-invariant checks are present with regression tests;
- consumer counts change `199→211`, `241→253`, `200→212`, with matching recorded lock hashes and SBOM checksums;
- retained consumer `crypto-bigint` 0.5.5 is distinguished from the patched core line;
- provenance limitations and locked CI commands are documented;
- all 11 shared vector inputs and the core lock match standalone `1c0adec` byte for byte.

The unresolved blocker is the recorded fresh audit: `RUSTSEC-2026-0387`, `RUSTSEC-2026-0330` and `RUSTSEC-2026-0331` in every consumer lock, outside the existing exception and pending owner disposition or remediation. Codex did not rerun full `npm run check` or refresh the audit feed; those results are separately evidenced locally.
