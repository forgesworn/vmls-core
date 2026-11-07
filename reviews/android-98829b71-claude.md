Review of `98829b71` is complete. The full report is saved at `~/.claude/plans/read-only-independent-proud-shell.md`. Nothing was edited, built, run, downloaded or published.

## Findings

**High. The fetch tag points at a release that does not exist.** `scripts/fetch-vmls-ffi.sh:22` downloads from tag `vmls-ffi-android-feea45f`. On forgesworn/kithmoot-android both the release and the tag ref return 404, while the old `vmls-ffi-android-5b3eb5f` release exists. CI runs the fetch before the prepare step in three jobs (`.github/workflows/ci.yml:50,153,293`), so every hosted job fails until the prerelease is published with the byte-identical hosted archive. Neither the commit nor the evidence doc states this precondition. The script header at `scripts/fetch-vmls-ffi.sh:4-5` still says the 5b3eb5f asset is "proposed and not yet published", which is now wrong on both counts. Check 4 fails on coherence.

**Medium. The inspection revocation list is always empty in production.** `MlsVault.revokeCredential` (`MlsVault.kt:334`) is the only writer of the revoked list and has no production caller. So the new accessor at `MlsVault.kt:344` returns an empty list on every production path, and the revocation argument now passed at all eleven inspection sites has no live source. Vennel documents the parameter as the caller vault's tombstone list, and this app has no tombstone writer. Both docs say inspection "passes the vault's current revoked credential ids" without the "not production coverage" caveat they give for `EngineSessions`. Plumbing is correct; coverage is overstated.

**Medium. The Admin2 development bundle no longer compiles against main source.** `scripts/prepare-admin-vmls-dev.py:12` still pins 5b3eb5f and Gradle selects it under the admin bundle flag (`app/build.gradle.kts:68,89`). That binding lacks the platform parameter on `complete` and `openCapability` and the revocation parameter on the inspect functions, so the migrated call sites cannot build against it. Re-pin or retire the path.

**Low.** The doc's "all 43 independent Kotlin binding cases" overstates: the reader runs 38 framed cases, and the 5 unframed cases are counted and covered by synthesised equivalents (`LeafBindingTest.kt:68-100`). The review path now reads the vault before inspecting (`VmlsRuntime.kt:766,912`), so a coordinated vault with a pending witness surfaces a `JoinRefusedException` message in the preview where it previously reached the engine first. No capability change, but unstated. `LeafBindingTest.kt:59` keeps a redundant `>= 4` assertion.

## Verified

- Every changed UniFFI call matches the new binding: pending introductions take the platform, pending invitation and create completions do not, and both inspect functions take authorization bytes before revoked ids. No old-signature call remains anywhere under `app/src`.
- `admissible` and all three callers pass the single `EngineSessions.platform`. The accessor exposes only public credential ids and wipes the device record.
- The fixture has exactly 43 cases, 38 framed, 5 unframed, 6 valid, the two new precedence cases last, and is byte-identical to the standalone 1c0adec blob and the vennel feea45f copy.
- Archive, manifest and payload hashes match the pins, the hosted CI unpacked artefact and the prepared bundle. The vennel run is a successful push-to-main build of feea45f with its artefact present. The commit contains 11 text files and no binaries.
- `EngineSessions` still uses the plain constructor; the binding's `newWithRevocations` is unused, as the docs say.
- Local test XMLs postdate the source edits: protocol at 09:10 after 09:09 edits, app unit at 09:54 after the last main edit at 09:36. No lint or release outputs exist, matching the pending status.

## Not verified here

- Emulator results were not re-run and no connected-test XMLs exist; accepted on your statement only. None of the five classes run exercise `admissible`, `addJoins` or `openCapability`, and `VmlsJoinLabTest` needs the lab box, so the platform-threaded capability path has compile-time evidence only.
- The hosted artefact was not re-downloaded; the local copies may share one download.
- Release lint and build remain pending and are not treated as passed.

## Verdict

**CHANGES REQUIRED.** Publish the `vmls-ffi-android-feea45f` prerelease and state that precondition in the evidence doc, fix the fetch script comment, add the tombstone-writer caveat to both docs, and re-pin or retire the admin development script.
