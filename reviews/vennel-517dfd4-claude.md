All five prior findings are resolved accurately at 517dfd4, nothing new is introduced, and locks and source are untouched. Full write-up is at `~/.claude/plans/focused-read-only-wiggly-flame.md`.

**Delta and immutability.** The range from c154087 to 517dfd4 touches only the CI workflow (push and PR triggers on main, from db669f9), the contract doc, the exception doc and the audit transcript. The db669f9 to 517dfd4 step touches only the last two. Current lock SHA-256s match the exception table and contract section 8, so the graph checker's hash gate passes. No CI-invoked script runs cargo audit, so the three approved advisories cannot fail hosted CI. Commits are authored as TheCryptoDonkey with no forbidden strings or home paths.

**Prior findings, each verified by rerun:**

1. **libcrux-kem wording** now says lock-only. Inverse cargo-tree for libcrux-kem and hpke-rs-libcrux over normal, build and dev edges prints nothing in all three consumers.
2. **crypto-bigint attribution** now includes openmls_basic_credential and the direct k256 dev-dependencies in vmls-mls and vmls-ffi. Confirmed by cargo-tree and the manifests. The P-256/P-384 ECDSA-only claim matches the published credential provider source.
3. **0.7.6 minimum versus 0.7.10 lock** is stated correctly. Confirmed in `vmls-core/Cargo.toml:22` and the locks.
4. **Forward pointer and four-lock recheck rule** are present at exception doc lines 15 to 17, 84 to 85 and 215.
5. **Raw unignored runs** are appended at transcript lines 234 to 627. Reproduced with cargo audit against the local 1,422-advisory database: core exits 0, each consumer exits 1 with exactly RUSTSEC-2026-0387, 0331 and 0330, and each consumer with the three ignores exits 0.

**SBOM caveat** is not overstated in substance. Cargo metadata lists an hpke-rs-libcrux edge under hpke-rs without the libcrux feature enabled, libcrux-kem appears in all three SBOM target lists, and proc-macro-error2 appears in none.

**Remaining non-blocking findings:**

- `docs/gate/2026-09-28-vmls-mls-dependency-exception.md:181` says "deliberately over-approximate feature/target resolution". Neither script records this as a design choice, and target/cfg is filtered. Only optional-dependency activation is over-approximated.
- `docs/gate/evidence/2026-11-07-vmls-consumer-cargo-audit.txt:234` onward. The raw runs carry no command lines, and exit codes are asserted in the header rather than captured.

**Out of scope but worth knowing.** The bothy-discovery lock under interop, unchanged on this branch and not a VMLS consumer, reports 12 vulnerabilities including RUSTSEC-2026-0387. The exception text explicitly excludes other Rust locks. It is not a finding against 517dfd4.

**Not re-verified.** Suite-refusal logic beyond the fixed ciphersuite constant, the network-dependent remediation-investigation claims, SBOM regeneration and the graph checker rerun, and the September unit-count table.

This review grants no human, security, merge, deployment or production approval. ExitPlanMode is not available in this session, so the review ends here.

**OPEN PR**
