Review of `8b9fe70e` is complete. The repository index refresh was denied under plan mode, so evidence comes from git, bounded reads, on-disk build outputs and read-only GitHub API calls. The full report is saved at `~/.claude/plans/focused-read-only-unified-puffin.md`.

**Confirmed**

1. **Fetch script.** `scripts/fetch-vmls-ffi.sh:22` targets `vmls-ffi-android-feea45f` and line 4 says it is proposed and unpublished. GitHub confirms that release does not exist. Every CI workflow calls this script, so hosted CI fails until publication, and both docs say so.
2. **Admin2 pin and release refusal.** `scripts/prepare-admin-vmls-dev.py:12` pins feea45f and the prepared bundle on disk matches. `app/build.gradle.kts:62-67` refuses any Release task for that profile.
3. **Revocation coverage.** `revokeCredential` has no production caller. `EngineSessions.kt:40` uses the constructor without revocations. All eleven inspection call sites pass the vault list. The evidence states both gaps and claims no live enforcement.
4. **Test evidence.** Fixture has 43 cases, 38 framed, 6 valid, 5 unframed, last two names as asserted. Recorded JUnit XML shows 684 protocol tests and 3,387 app tests with the stated failure and skip counts, timestamped after the source edits. The pending-witness precedence note is accurate against `MlsVault.kt:1355` and `EngineSessions.kt:171`.
5. **Exact assertion and API.** `LeafBindingTest.kt:59` asserts exactly six. Every native call matches the generated binding signatures. The local archive hash matches the pin, and Vennel run 42355481980 is a successful bundle run on `main` for a commit identical to `main`.
6. **Nothing overclaimed.** Lint and release are listed as pending, and no lint report or release APK exists. All disclaimers are present.

**Unverified from here, not contradicted**

- Admin2 debug build. The latest generated `BuildConfig.java` shows the standard profile, so the APK on disk cannot be attributed to the Admin2 run.
- Emulator instrumentation counts. No connected test results exist on disk.
- Hosted artefact bytes versus the pinned SHA. The artefact exists and is unexpired, but was not downloaded.

**Low severity, non-blocking**

- `LeafBindingTest.kt:51` maps four framed leaf-mismatch and signature cases to "ok", so they are asserted as decode success only. A one-clause note in the evidence would make the "38 framed reader cases" wording exact.
- `docs/2026-11-07-android-vmls-interop.md:3` names release and re-review pending but omits lint. Line 38 is correct.

**Out of scope.** `docs/2026-10-25-admin-invitation-candidate.md:56-64`, already on `main`, contains absolute home-directory paths that the owner's privacy rule forbids.

**OPEN PR.** Publication and hosted CI may follow once lint and the release build complete and the feea45f prerelease is published. This is not human, merge or production approval.
