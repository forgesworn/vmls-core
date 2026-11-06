# Independent AI re-review: VMLS/1 vector generator 14894cb

- **Reviewer/model and review date:** OpenAI Codex, GPT-6; 6 November 2026.
- **Exact commit/tree verification:** HEAD is `14894cba2eb5e8e7f8ea960ebbaa233dfb670d70`; tree is `2eee7544313323556c766c70fcbe02a789285f39`. Reviewed tracked files match that commit. The untracked re-review report was left unread.
- **Scope and checks performed:** Read-only inspection of both scripts, workflow, README, AUDIT-INTEROP §11, consolidated initial review, and supporting fixtures/tests. Compared corrections against `5a0522b` and independently recomputed all 11 Appendix A hashes: all match. No builds, suites, generators, writes, installations, network access or contacts. Supplied execution results remain supplied evidence.

## Initial findings disposition

1. **Exact-byte rendering — corrected for published layouts.**  
   `vectors/generate-vmls.mjs:407–482` constructs pretty, compact envelope/security, appended compact, full-`i64`, and hostile-array layouts from regenerated objects. There is no original-text fallback. Default mode independently compares semantic content and rendered bytes at `vectors/generate-vmls.mjs:529–537`. Lossless integer loading is at `vectors/verify-vmls.mjs:129–132`.

2. **Symlink execution and zero-suite CI success — corrected for documented invocations.**  
   The reader resolves the entry path through `realpathSync` at `vectors/verify-vmls.mjs:850`. CI runs both direct and symlinked readers and requires the exact suite/assertion PASS text at `.github/workflows/vmls-core.yml:44–54`. Generator PASS output is checked at lines 55–60.

3. **Bare `--write` — corrected.**  
   Generator parsing excludes flags when selecting the positional root at `vectors/generate-vmls.mjs:38–41`; imported loaders use the same rule at `vectors/verify-vmls.mjs:17–19`. Write mode bypasses compatibility assertions and reaches `writeFileSync` at `vectors/generate-vmls.mjs:534–539`, permitting deliberate changes.

4. **Device expectation independence — corrected in generator; incomplete in reader.**  
   Generator scope comes from scenario names, targets from event/room keys, and expectations are replaced at `vectors/generate-vmls.mjs:228–255`. Retained event and tombstone signatures are verified at lines 237 and 242. Expected-identity and public-key controls appear at lines 513–519. However, the standalone reader still chooses scope and target from `test.expect` at `vectors/verify-vmls.mjs:1025–1026`.

5. **Security receipt rebuilding — partially corrected.**  
   Node, scenario installation and fresh envelope hashes are written into newly allocated bodies at `vectors/generate-vmls.mjs:268–277`; scenario-specific calls and evidence rebuilding are at lines 288–309. Installation sensitivity is checked at lines 521–526. Slot and attempt still come from the old encoded receipt, rather than independent scenario definitions.

## New or remaining findings

**Medium — standalone device reader remains dependent on expected outputs.**

At `vectors/verify-vmls.mjs:1025–1036`, expected fields affect the computed acceptance decision. Source-derived counterexample: replace `room-presented-as-person`’s expected identity with `{roomId: file.roomId}`. The reader then evaluates the unchanged signed event as room-scoped and computes acceptance as true; changing expected `ok` accordingly lets that case pass.

The corrected generator catches this inconsistency, so this is a standalone-reader evidence defect, not a demonstrated CI bypass.

**Minimal fix:** derive reader scope from scenario definitions and targets from event/room keys; compare expectations only afterwards. Add a control that poisons the expected scope field.

**Medium — receipt slot/attempt regeneration remains self-referential.**

`vectors/generate-vmls.mjs:269–275` decodes the old output and copies `old.slot` and `old.attempt`. `buildEvidence` repeats this through existing embedded receipts at lines 288–292. Thus regeneration independently establishes signatures and several body fields, but cannot independently establish the intended slot and attempt values.

This leaves the stronger reconstruction claim in `AUDIT-INTEROP.md:548–550` unsupported.

**Minimal fix:** define slot and per-scenario attempts independently, pass them into `buildSlot`, and construct evidence from those definitions. Add controls that poison encoded slot/attempt outputs while preserving scenario inputs.

**Low — write mode reports equality it did not check.**

Compatibility comparisons execute only under `!write` at `vectors/generate-vmls.mjs:534–537`, but line 543 always prints “content and exact bytes match”. A deliberate changed write can therefore emit misleading compatibility evidence.

**Minimal fix:** give write mode a separate completion message describing written files and completed controls.

## Regeneration and negative-control assessment

All **11 families** have regeneration dispatch entries at `vectors/generate-vmls.mjs:485–496`. Exact-byte checks are meaningful across every published layout and no longer succeed by returning original text.

The controls meaningfully check trailing-byte outcome/rendering changes, generator expected-identity independence, retained-key signature rejection, and installation rebuilding (`vectors/generate-vmls.mjs:503–526`). They do **not** establish reader expectation independence or independent slot/attempt construction.

No Node.js 20 incompatibility was identified by source inspection: the scripts use built-ins and language features available there. CI invokes the scripts correctly, but does not explicitly select Node 20; minimum-version execution is therefore not established by the workflow alone.

## Contract/vector compatibility recommendation

**Do not approve** closure of all five correction classes yet. Rendering, invocation and argument parsing are repaired, but device-reader independence and complete receipt-body independence remain incomplete.

## Remaining limitations and next action

AUDIT-INTEROP §11 correctly retains pending AI review and external acceptance gates, including hosted 32-bit execution. Its supplied verification counts are consistent with this review’s input, but were not independently executed here. Its receipt reconstruction wording needs correction or the implementation fix above.

Address the two medium findings, correct write-mode reporting, then rerun the reader, regeneration, compatibility and expanded negative controls against the resulting exact revision.

This is an **independent AI review, not a human security audit or production approval**.