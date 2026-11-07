# Focused read-only re-review: Android 8b9fe70

Review exact HEAD `8b9fe70e541ecc7d906bdb3d0864545d724ea524` in `<workspace>/kithmoot-android-vmls-interop-20261107`. Work read-only: no edits, builds, commits, pushes, releases or PRs.

Prior Claude review of `98829b71` required changes; Codex approved with one stale comment. The follow-up is intended to resolve every finding without weakening the evidence. Inspect `git diff 98829b71e2c0e3e824a4cdecc67082013ce46394..8b9fe70e541ecc7d906bdb3d0864545d724ea524` and relevant current files, plus the complete `b0d8a2f2..8b9fe70` delta if needed.

Verify:

1. `scripts/fetch-vmls-ffi.sh` has the correct feea45f tag and current comment. The evidence explicitly says publishing that prerelease is a hosted-CI precondition; it has not been published yet.
2. `scripts/prepare-admin-vmls-dev.py` pins feea45f, and the explicitly selected Admin2 debug/instrumentation build passed. Release remains prohibited for that profile.
3. The evidence says no production caller writes `revokeCredential`, so both inspection and native capability revocation enforcement lack production coverage. Do not confuse correct plumbing with live enforcement.
4. The evidence now distinguishes 38 framed independent Kotlin reader cases from five unframed synthetic checks, records 684 protocol and 3,387 app test results, and notes the capability/lab and pending-witness precedence limits.
5. The redundant valid-case assertion is now exact, and no new API, lifecycle or provenance issue was introduced.
6. Remaining release/lint is still pending, not claimed as passed. No live-box/relay, physical GrapheneOS, independent second-person, deployment or production approval is claimed.

Report confirmed remaining findings with file:line and severity. Distinguish unverified checks. End with **OPEN PR** or **CHANGES REQUIRED**. OPEN PR permits publication and hosted CI after release/lint completes, not human, merge or production approval.
