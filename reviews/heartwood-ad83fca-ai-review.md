# Consolidated AI review: Heartwood scoped interoperability

Status: **implementation and documentation reviews complete; scoped gate only**

Implementation target: Heartwood `ad83fca8dd34bea00e2468764cec7a35c4f9852a`.
Evidence target: VMLS `612b3722ff6c2be982d2e53169fa66b8a0e3552b`.

Raw reports:

- `reviews/heartwood-ad83fca-claude.md`
- `reviews/heartwood-ad83fca-codex.md`
- `reviews/heartwood-interop-612b372-claude.md`
- `reviews/heartwood-interop-612b372-codex.md`

Both implementation reviewers recommend approve, conditional on hosted firmware
size CI. Both documentation reviewers recommend approve; Codex has no confirmed
issues and Claude has two documentation corrections. These are independent AI
reviews, not named human, end-to-end or production approval.

## Dispositions

1. **Review evidence location.** Resolved by retaining the four reports and this
   disposition, linked from `AUDIT-INTEROP.md` section 12.
2. **Stale section 1 evidence gap.** Resolved: it now names the scoped Heartwood
   result and still asserts no physical-device result.
3. **Historical Heartwood image wording.** Resolved in Heartwood `1c376a6`,
   which labels the earlier 2,071,424-byte measurement historical and records
   hosted candidate/post-merge evidence.
4. **Hosted image provenance.** The `app-heltec-v4` artifact was downloaded from
   run 42278785850 and measured locally at 2,094,800 bytes, leaving 2,352 bytes
   in the 2,097,152-byte slot. PR CI passed every job. Post-merge CI 42281172418
   also passed at Heartwood `472ae52`.
5. **Commit title ambiguity.** The PR title explicitly says crate 0.1.2 and pins
   full SHA `1c0adec`; no source change was needed.

The pass remains limited to allocation/witness/fresh-R host suites and fixture
exchange. Scenarios 1–5, 8 and 9, live service/deployment behaviour and physical
acceptance remain not run. Local old/new images were both oversize and are not
claimed as a pass.
