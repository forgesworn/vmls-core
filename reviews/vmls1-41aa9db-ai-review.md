# Consolidated final AI review: VMLS/1 vector generator 41aa9db

Status: **independent AI reviews approve independent regeneration; final delivery pending**

- Approved review target: `41aa9db7e0bb4ed0df7352885d28cf1d8141ec60`.
- Claude report: [vmls1-41aa9db-claude.md](vmls1-41aa9db-claude.md).
- Codex report: [vmls1-41aa9db-codex.md](vmls1-41aa9db-codex.md).
- Final review prompt: [vmls1-41aa9db-generator-review.md](vmls1-41aa9db-generator-review.md).

Claude recommended **approve with findings**; Codex recommended **approve**. These are independent AI reviews, not human security audits or production approval.

## Final dispositions

Both found all six correction classes supported by source: independent device-scope derivation, explicit slot/attempt inputs, recomputed tombstone targets, meaningful default checking and write reporting, guarded CI execution with Node 20, and accurate retained/rebuilt evidence wording. Codex independently recomputed all 11 Appendix A hashes and found no confirmed new finding. Claude identified two small residual issues, now corrected:

- Historical assertion counts in AUDIT-INTEROP §9 and §10 are restored to 29,169. Only the current generator record claims 29,170, introduced by the new standalone expected-scope control.
- Tombstoned cases now assert that their recomputed event id equals the regenerated revocation target, matching the standalone reader's existing check.

The unused receipt parameter was also removed to make rebuilt-body construction explicit.

## Evidence and limitations

All 11 fixture families pass semantic and independently rendered byte comparison and all negative controls. Bare `--write` reports files written and is a byte-identical no-op on compatible fixtures. Direct and symlinked readers report 29,170 assertions. Rust tests pass 53 per feature mode, with both toolchains, bare-metal and Android/Linux 32-bit compilation, formatting, dependency audit, all Appendix A hashes, workflow YAML parsing, and diff checks passing. Hosted 32-bit execution remains not run.

Independent regeneration is now reproducible within the documented fixture-driven scope. Retained signed inputs, witness bodies, and evidence headers remain explicit boundaries. Human review on issue #7, downstream interoperability, physical-device acceptance, fuzzing, side-channel assessment, formal proof, and production approval remain separate gates.

Next action: run final CI for the resulting delivery commit, merge PR #9, and continue downstream acceptance without presenting independent AI approval as human or production approval.
