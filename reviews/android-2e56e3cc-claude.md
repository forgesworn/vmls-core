All checks pass. Nothing further to request.

**Verdict: no confirmed issues at HEAD `2e56e3cc34d8901ad63285a2378a0a01a41b4bec`.** The diff from `3d4aadf8` touches only the three named files, six lines in and six out, all prose.

**1. Fetch tag unchanged, comment updated.** The download URL at `scripts/fetch-vmls-ffi.sh:22` still targets the feea45f release asset. Only the comment at line 4 changed, from "proposed and not yet published" to "published from hosted CI".

**2. Evidence states publication and the public fetch path.** The status line at `docs/2026-11-07-android-vmls-interop.md:3` now reads "prerelease published; lint and release build pending". Line 29 records all five prepared-bundle checks passing, including the public fetch path. Line 40 replaces "has not yet occurred" with the release URL. The hand-off note at `docs/vmls-ffi-android.md:56` now says the prerelease is published from hosted CI and required for hosted CI.

**3. Pending items retained, nothing widened.** Line 39 of the interop doc still lists lintDebug, lintRelease and assembleRelease as pending. Lines 41 to 44 keep every prior limit unchanged. The pins at `scripts/prepare-vmls-ffi.py:13` through 18 are untouched and equal the hashes quoted in both docs.

**External confirmation, read-only via the GitHub API.** The tag exists as a non-draft prerelease on main, author TheCryptoDonkey, published 2026-11-07 at 13:14:06Z. Its single asset carries the digest below, equal to the pinned archive hash. The manifest match stated at line 40 follows from archive identity and was not separately opened. The commit landed at 13:16:52Z, after publication, so the public fetch claim is consistent in time.

| Item | Value |
|------|-------|
| Asset | `vmls-ffi-android.zip` |
| API digest | `sha256:0de096b79e7ef3a7d98c97dac74ea0582d5b1856d8bdb8d646d911b82aceaa26` |
| Pinned `EXPECTED_ARCHIVE_SHA256` | identical |

Commit identity is the TheCryptoDonkey persona and the diff contains no forbidden names or paths. No edit, build, commit, publish or PR was made.

**OPEN PR**. This permits publication and hosted CI only, not human, merge or production approval.
