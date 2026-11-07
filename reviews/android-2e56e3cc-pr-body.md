## Summary

- Upgrade the pinned VMLS FFI hand-off to merged Vennel `feea45fc4ca172b05ea671579df51e936c5804b6` and its hosted Android CI archive.
- Synchronise the independent Kotlin binding fixture to standalone `1c0adec`: exactly 43 cases, six valid framed cases and five unframed cases, including both new precedence cases.
- Pass the current `VmlsPlatform` through capability opening and pending-introduction completion, including retries and alternative inviters.
- Pass the vault's current revoked credential ids through invitation inspection, with an exact accessor unit assertion.
- Re-pin the explicitly selected Admin2 development bundle to the same merged source; release builds remain excluded.
- Keep production revocation coverage explicitly limited: `EngineSessions` retains the empty-revocation-list constructor and no production caller writes `revokeCredential`, so inspection and capability enforcement have no live tombstone source.

## Verification

- `./gradlew :protocol:test`: 684 tests passed with no failures, errors or skips, including all 38 framed independent Kotlin reader cases. The five unframed cases are counted and covered by synthetic framing checks, not presented as independent exchanges.
- `./gradlew :app:testDebugUnitTest`: 3,386 tests passed, one skipped and no failures or errors, including the revocation-accessor assertion.
- `python3 scripts/check-vmls-prepared.py build/vmls-ffi-android.zip`: all five exact/forge/refusal checks passed.
- `./gradlew :app:assembleDebug :app:assembleDebugAndroidTest`: passed, including the explicitly selected Admin2 development profile.
- Android 15 arm64 Google APIs emulator: all 23 tests passed across `SessionHostEngineTest`, `SessionDriverEngineTest`, `CoordinatedVaultEngineTest`, `CoordinatedVaultRestartTest` and `SessionRestartTest`.
- Hosted Vennel Android bundle run 42355481980 supplied the pinned archive; generated Kotlin matches the local build byte for byte.
- `:app:lintDebug`, `:app:lintRelease` and `:app:assembleRelease` are pending and are not claimed as passing.

## Scope and limits

The `vmls-ffi-android-feea45f` prerelease is published and the public fetch/prepare path passes. `admissible`, `addJoins` and `openCapability` have compile-time evidence only here; the live-box join lab was not run. Reading the vault before inspection can surface `JoinRefusedException` before the native inspection error that previously led.

No two-emulator/live-box lab, public relay, independent live mailbox/witness/allocation service or physical GrapheneOS device was exercised. No independent second-person end-to-end exchange, deployment, production enablement or human security approval is claimed. See `docs/2026-11-07-android-vmls-interop.md` for exact hashes, commands and limits.
