# Claude review: Heartwood VMLS interoperability `ad83fca`

Reviewer: Claude Code, non-interactive read-only review on 2026-11-06.
Exact commit: `ad83fca8dd34bea00e2468764cec7a35c4f9852a`.
This is independent AI source review, not human or production approval.

## Findings

1. Low: the commit title's `v0.1.2` could be read as the upstream tag rather
   than the crate version. The full SHA is authoritative; use clearer PR wording.
2. Low: final/post-merge CI and the hosted main image size were not verifiable
   in the offline review environment.
3. Informational: VMLS source and fixtures at merged `1c0adec` match reviewed
   `52a8e5d`; later Rust changes are test comments only.
4. Informational: the new fork-evidence verification is not reachable from
   Heartwood's consumed modules.

## Verified

- Both manifests and locks pin full VMLS `1c0adec`, crate 0.1.2, default
  features disabled, with no other dependency movement.
- Consumed APIs remain compatible. Existing caller prevalidation satisfies the
  new encoder contracts.
- No new dependency, build script, patch or source-policy weakening appeared.
- Documentation correctly limits the result to scoped host/vector and fixture
  interoperability and leaves broader MLS and physical acceptance not run.
- Local old/new images are both oversize; hosted candidate size CI is required.

## Verdict

**APPROVE**, conditional on hosted firmware-build CI passing its size check for
this commit. The PR title uses the clearer crate-version wording, and that CI
subsequently passed as run 42278785850.
