# Codex review: Heartwood VMLS interoperability `ad83fca`

Reviewer/model: OpenAI Codex, `gpt-6.1-sol`, read-only on 2026-11-06.
Exact commit: `ad83fca8dd34bea00e2468764cec7a35c4f9852a`.
This is independent AI source review, not human or production approval.

## Finding

P3, non-blocking: the older 2,071,424-byte local V4 measurement in Heartwood's
strict-history document should be labelled as historical so it is not confused
with the new 2,126,304-byte local measurement or candidate slot fit.

## Verified

- Both manifests and locks consistently pin VMLS `1c0adec`, crate 0.1.2, with
  default features disabled.
- Heartwood's consumed APIs remain compatible. The upstream runtime change
  strengthens fork-evidence verification without a supply-chain regression.
- Documentation scopes host/vector and cross-implementation evidence and leaves
  broader MLS and physical acceptance not run.
- Independent offline pin/lock comparisons, the upstream reader's 11 suites and
  29,170 assertions, and regeneration of all 11 vector files passed. Heartwood
  test/build results were supplied evidence and were not rerun by Codex.

## Verdict

**APPROVE — AI source review only.** Candidate hosted firmware-size CI remained
required at review time and subsequently passed as run 42278785850. The
historical-measurement wording is corrected in Heartwood `1c376a6`.
