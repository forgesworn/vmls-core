## Summary

- Synchronise the shared VMLS 0.1.2 codecs and vectors from standalone `vmls-core` `1c0adece2ec71ccfca0d98cafc7e3ddb0ebf33a2`, preserving Vennel-only invitation/admin modules and record variants.
- Pass the introducer's current `Platform` through introduction/capability calls, including retries and alternative inviters.
- Make design-vector attempts and precedence outcomes independently computed, with negative controls.
- Record the owner-approved, exact-scope **non-shipping exception** for `RUSTSEC-2026-0387`, `RUSTSEC-2026-0330` and `RUSTSEC-2026-0331`; enable PR and post-merge Vennel CI.

## Verification

- `cargo test --locked`: 61 core tests passed; the engine's 247 tests passed in the full check.
- `cargo test --locked --no-default-features`: 61 core tests passed.
- Rust 1.87 library checks passed in both feature modes.
- `npm run check`: passed, including vector/conformance checks.
- `npm run test:vmls-adapters`: 28 native/WASM tests passed.
- Dependency graph target matrix passed; all 11 shared vector files regenerate byte-identically to standalone `1c0adec`; both generator negative controls reject correctly.
- Fresh `cargo audit` over 1,422 advisories: no core issue; consumer scans with exactly the three approved ignores succeeded with no additional vulnerability. Maintenance warnings remain visible.

## Dependency and delivery limits

The exception applies only to the three recorded consumer lock hashes and non-shipping development. It grants no deployment, production or shipping approval and no unreleased dependency pin, provider fork or backport. Merge remains a separate decision after hosted CI and review.

See `docs/gate/2026-09-28-vmls-mls-dependency-exception.md` and `docs/gate/evidence/2026-11-07-vmls-consumer-cargo-audit.txt` for exact hashes, exposure analysis and closure conditions. No live external service, deployment, physical device, human security approval or production acceptance is claimed.
