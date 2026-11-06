# Independent final delivery review: VMLS/1 generator 52a8e5d

**Reviewer/model and exact commit checked:** Claude Fable 5.1 (`claude-fable-5-1`), 2026-11-06. The HEAD symbolic ref points at the generator branch, and that ref file contains `52a8e5dec502983ceeee410a681cd06681a47e1b`. The reflog's last two entries record the moves from `41aa9db` to `1b6a0f5` and then to `52a8e5d`. The session's starting git status reported no modified tracked files and one untracked review file, so the tracked files I read are the committed tree. I had no shell and executed nothing. The supplied PASS lines, Rust results, and hash checks are the author's evidence, not mine.

## Check dispositions

1. **Historical counts restored. Confirmed.** `AUDIT-INTEROP.md:495` and `AUDIT-INTEROP.md:522` now read 29,169, matching the contemporaneous reports at `reviews/vmls1-2d08414-ai-review.md:25` and `reviews/vmls1-2d08414-re-review-prompt.md:30`. Only the current reader and generator records claim 29,170, at `AUDIT-INTEROP.md:121` and `AUDIT-INTEROP.md:585`, consistent with the CI assertions at `.github/workflows/vmls-core.yml:52` and `:57`.

2. **Tombstone consistency assertion. Confirmed.** `vectors/generate-vmls.mjs:243` asserts that a tombstoned case's recomputed event id equals the revocation target computed at line 234 from the `person-passes` event. Both values are hex strings, so the strict equality compares like types. The fixture supports it: the `revoked-by-tombstone` event at `vectors/device-credential.json:260-288` is field-identical to `person-passes`, and the tombstone `e` tag at line 18 carries that id. This mirrors the reader's existing check at `vectors/verify-vmls.mjs:1056`.

3. **Unused parameter and old decodes removed without changing bodies. Confirmed.** `buildSlot` at `vectors/generate-vmls.mjs:269-278` now takes only seed, node, envelope, installation, slot, and attempt. It allocates a fresh 197-byte body and writes version, node, installation, slot, big-endian attempt, and envelope hash before signing. The four callers at lines 303-306 pass scenario fields and no longer decode the published receipts. I checked the layout against the fixture: the committed receipts at `vmls-core/vectors/vmls-security-design-v1.json:9-17` have attempt bytes 3, 3, 4, 4 at offset 97 and the foreign installation at offset 33, matching the arguments. `buildEvidence` at lines 288-294 still takes the raw evidence only to retain the ten-byte header, which the documentation states. The supplied default-mode PASS line is the execution evidence that rendered bytes are unchanged.

4. **§11 and review artefacts. Confirmed.** `AUDIT-INTEROP.md:545` records Claude as approve with findings and Codex as approve, which matches `reviews/vmls1-41aa9db-claude.md:39` and `reviews/vmls1-41aa9db-codex.md:45`. The status line at `AUDIT-INTEROP.md:541` records the review complete with delivery pending, and §7 line 315 ticks only the regeneration gate. The 41aa9db prompt, both reports, and the consolidated report are tracked. The 52a8e5d prompt is present only as an untracked file, which is expected since it postdates the commit.

5. **No new defect or overclaim found.** The negative control at `vectors/generate-vmls.mjs:514-520` still runs the device regeneration, now including the new assertion, and the expected-identity poison remains deep-equal to the fixture. The audit header, §10, §11, README line 31, and the consolidated report all keep AI review distinct from human or production approval.

## Findings

**No confirmed issues.**

Informational only, pre-existing and not introduced by these commits: `vmls-core/tests/vectors.rs:2` and `vmls-core/tests/design_vectors.rs:5` describe the generator as using noble, while the committed generator imports only Node built-ins and the reader. A one-line comment update would remove the inconsistency.

## Recommendation

**Approve** for the contract/vector compatibility gate only. The changes through `52a8e5d` resolve both residual findings from my `41aa9db` review and introduce nothing that alters the compatibility evidence. This covers the generator and compatibility evidence, not production readiness.

This is an independent AI review, not a human security audit or production approval. Hosted 32-bit execution, exact-commit CI for `52a8e5d`, downstream interoperability, physical-device acceptance, fuzzing, side-channel assessment, formal proof, named human review, and a private security-reporting route remain open as the pack states.
