# Consolidated AI re-review: VMLS/1 vector generator 14894cb

Status: **first re-review complete; remaining independence and reporting issues corrected**

- Review target: `14894cba2eb5e8e7f8ea960ebbaa233dfb670d70`.
- Claude report: [vmls1-14894cb-claude.md](vmls1-14894cb-claude.md).
- Codex report: [vmls1-14894cb-codex.md](vmls1-14894cb-codex.md).
- Re-review prompt: [vmls1-14894cb-generator-review.md](vmls1-14894cb-generator-review.md).

Claude recommended **approve with findings**; Codex recommended **do not approve** until the remaining independence issues were fixed. These are independent AI reviews, not human security approval.

## Initial dispositions

Both confirmed meaningful mixed-layout rendering, realpath-based direct execution, PASS assertions, correct flag handling, independent device scope generation, and rebuilt installation/envelope fields. Codex found two medium independence defects and one low reporting defect. Claude found lower-severity precision and tombstone issues, plus the unpinned Node runtime.

## Remaining issues and corrections

- **Standalone reader expected-output dependence:** the device reader now derives scope from scenario definitions and targets from event/room keys, then compares the computed outcome. A dedicated expected-scope poison control raises the reader to 29,170 assertions.
- **Retained slot and attempt:** `slotHex`, `baseAttempt`, `relabelledAttempt`, and `foreignAttempt` are explicit scenario inputs. All receipt/evidence construction uses them instead of encoded receipt values. An attempt-poison control verifies the changed value reaches the rebuilt receipt.
- **Write-mode reporting:** write mode now reports files written, not unchecked compatibility equality. Default mode retains semantic and independently rendered byte checks.
- **Tombstone target:** the revocation target is recomputed with NIP-01 instead of read from the retained event id.
- **Evidence wording:** the audit distinguishes explicit scenario slot/attempt fields from retained witness bodies and evidence headers, and states that signed binding/capability inputs are retained and verified rather than regenerated.
- **Node 20 evidence:** CI now uses `actions/setup-node` at a pinned commit with `node-version: 20`.

All 11 files pass semantic and independently rendered byte comparison and every negative control. Bare `--write` remains a byte-identical no-op on compatible fixtures. Full project verification and a final independent review are required before closing the regeneration gate.
