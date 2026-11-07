# Focused read-only re-review: Vennel 517dfd4

Review exact HEAD `517dfd42eefc13ad0433d0b8240d1ddc5f347192` in `<workspace>/vennel-browser-vmls-interop-20261106`. Work read-only: no edits, branch changes, commits, pushes, PRs or installs.

The preceding review of `db669f9ebc94b7f6367df2bccf7a544a531d8717` returned OPEN PR with these non-blocking findings:

1. The libcrux-kem exposure wording incorrectly said compiled dependency graph; targeted cargo-tree evidence shows it is lock-only in normal/build graphs.
2. crypto-bigint attribution omitted `openmls_basic_credential` and direct k256 development dependencies.
3. The declared crypto-bigint minimum is 0.7.6 but current locks contain 0.7.10.
4. The original single-warning scope needed a forward pointer and the recheck rule needed all four locks.
5. The audit transcript needed raw unignored consumer runs, each expected to exit 1 with exactly RUSTSEC-2026-0387/0330/0331.

Inspect `git diff db669f9ebc94b7f6367df2bccf7a544a531d8717..517dfd42eefc13ad0433d0b8240d1ddc5f347192` and relevant current files. Confirm those findings are resolved accurately, the Cargo-metadata SBOM caveat is not overstated, no new issue was introduced, and the complete `c154087..517dfd4` branch delta still contains only intended docs/evidence plus PR/push CI triggers. Verify lock/source immutability and, if useful, rerun targeted non-mutating cargo-tree/audit checks. Do not repeat the full implementation review or test matrix.

The owner approved only the exact non-shipping exception; this review grants no human, security, merge, deployment or production approval. Report any remaining confirmed finding with file:line. Distinguish unverified checks. End with **OPEN PR** or **CHANGES REQUIRED**, where OPEN PR permits hosted CI and further review only.
