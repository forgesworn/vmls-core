# Independent review: Vennel db669f9

HEAD confirmed as `db669f9ebc94b7f6367df2bccf7a544a531d8717`, working tree clean. Diffed against `c154087`. Nothing edited, committed, pushed or installed. Verification was read-only: git, offline `cargo tree` and `cargo audit`, registry and advisory-database reads, two crates.io and two GitHub fetches. This review grants no human, security, merge, deployment or production approval.

## Findings, by severity

**Low 1. Exposure text overstates where libcrux-kem lives.** `docs/gate/2026-09-28-vmls-mls-dependency-exception.md:166-167` says the vulnerable implementation "remains in the lock and compiled dependency graph". It is lock-only. `libcrux-kem` 0.0.9, `hpke-rs-libcrux` 0.7.0 and `libcrux-ml-kem` 0.0.10 have no normal or build path from vmls-mls, vmls-ffi or vmls-wasm on any target (checked with `cargo tree -e normal,build --target all -i` on all three manifests). The mechanism is that `hpke-rs` 0.7.0 declares `hpke-rs-libcrux` optional behind its `libcrux` feature, and `openmls_rust_crypto` 0.6.0 enables only `experimental`, `hazmat` and `serialization`. Existing build artefacts agree: every target directory holds libcrux sha3, intrinsics, platform, secrets and traits rlibs and no libcrux-kem or hpke-rs-libcrux. Line 165 credits the non-selection to disabled draft features, which is true but weaker than the real reason. Related and pre-existing: the committed SBOM and `scripts/check-vmls-graphs.mjs:34-47` walk `cargo metadata` resolve, which lists these crates per target and disagrees with cargo tree and the artefacts. That over-approximates, the safe direction for the "flagged unit unreachable" check, but the 161/172/161 package counts include packages never built. The direction is conservative, so not blocking. Recommend a one-sentence correction in the PR before merge review.

**Low 2. crypto-bigint path attribution is incomplete.** Lines 151-153 attribute the `crypto-bigint` 0.5.5 path to the RustCrypto provider only. `p256` 0.13.2 and `p384` 0.13.1 are also reached directly from `openmls_basic_credential` 0.6.0, pinned at `vmls-mls/Cargo.toml:23`, and `k256` 0.13.4 is a dev-dependency at `vmls-mls/Cargo.toml:39` and `vmls-ffi/Cargo.toml:32`. The published crate sources use P-256 and P-384 only under ECDSA signature schemes, so the suite-narrowing argument holds. Incomplete, not wrong.

**Info 3.** Line 157 says "crypto-bigint 0.7.6 line". All four locks carry 0.7.10; 0.7.6 is the declared minimum at `vmls-core/Cargo.toml:22`.

**Info 4.** The Scope section at lines 16-31 still says "exactly one advisory in exactly one crate" with no pointer forward to the 7 November entry at line 132. The recheck rule at lines 81-82 names one lock while the closure conditions at line 195 require four audits.

**Info 5.** `docs/gate/evidence/2026-11-07-vmls-consumer-cargo-audit.txt:3-6` asserts the unignored scans report exactly three IDs but records only the ignored runs. I reproduced it against the same 1,422-advisory database:

| Lock | Unignored | Ignored (three IDs) |
| --- | --- | --- |
| vmls-core | exit 0, nothing | n/a |
| vmls-mls | exit 1, 0387 0330 0331, warn 0173 | exit 0, warn 0173 |
| vmls-ffi | exit 1, 0387 0330 0331, warn 0173 0374 | exit 0, warn 0173 0374 |
| vmls-wasm | exit 1, 0387 0330 0331, warn 0173 | exit 0, warn 0173 |

**Info 6.** Upstream sha `28369d5b…` is a 2026-10-28 test-only commit (nightly randomised group operations test, five test files). Its tree carries `openmls_rust_crypto` with hpke-rs 0.8 and p256/p384 0.14 at package version 0.6.0, so unreleased. The doc's "main at <sha> contains" wording at lines 180-182 is accurate as a snapshot statement.

## Check results

1. **Diff scope: confirmed.** Four files only: `.github/workflows/ci.yml` gains four trigger lines, plus the contract §8 paragraph, the exception doc and the new evidence file. No Rust source, lockfile, vector or production configuration.
2. **Exception content: confirmed.** Names the owner decision and date, exactly three IDs, and SHA-256 values matching the committed locks byte for byte. Lines 145-147 exclude other graphs, new advisories, forks, backports, unreleased pins, deployment and shipping.
3. **Exposure wording: confirmed** on the suite distinction and on hedging the timing issue (lines 158-161 echo the advisory's own caveats). Suite enforced at `vmls-mls/src/config.rs:7` and five refusal points in `vmls-mls/src/session.rs`. Advisory texts match the descriptions. Findings 1 and 2 are precision issues.
4. **Remediation account: confirmed.** Registry manifests show `openmls_rust_crypto` 0.6.0 and `openmls_libcrux_crypto` 0.4.0 require hpke-rs 0.7, and `hpke-rs-libcrux` 0.7.0 requires `libcrux-kem` exactly 0.0.9. crates.io today lists those as the newest provider releases, none yanked.
5. **Audit evidence: confirmed and reproduced** (Info 5). Four locks, three ignores only, warnings retained, no registry error.
6. **CI trigger: confirmed.** Parses to push and pull_request on main plus workflow_dispatch. Permissions unchanged. The adapter job runs `scripts/test-vmls-adapters.sh`, which invokes the WASM build script at lines 22 and 28, and that builds with `--locked` at line 97. CI builds the nodejs wasm-bindgen target, not the web target, from the same lock.
7. **Contract consistency: confirmed.** `docs/2026-09-29-mls-implementation-contract.md:1344-1350` mirrors the exception. Line 1360 keeps shipping blocked by D1 review. The graph-check script finds the current hashes in §8.

## Not verified

- The owner's approval itself. I relied on the review brief; the doc cites a date but no artefact.
- Hosted CI passing. The workflow was dispatch-only before, and these jobs were not observed running hosted.
- The cause of the `cargo metadata` versus `cargo tree` discrepancy in Finding 1.
- crates.io and GitHub facts are as of today.
- The full test matrix was not rerun.

The full report is also saved at `~/.claude/plans/read-only-independent-functional-thimble.md`.

**Verdict: OPEN PR.** Ready to open for hosted CI and further review only. The one substantive finding overstates exposure rather than understating it and is a one-line documentation correction to make before merge review. Not approval to merge or ship.
