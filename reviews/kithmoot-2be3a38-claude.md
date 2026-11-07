# Claude review: KithMoot 2be3a38

Scope: read-only independent AI review of the checked-out `2be3a38` candidate. Claude had no shell or worktree-HEAD verification in this session, so its source comparison was content-level rather than a byte check against the pinned revision. Not human, merge, production or dependency-exception approval.

## Findings and disposition

- **No high-severity code finding.** Platform arguments are semantically correct: every changed introduction/capability call uses the adder's platform consistently, including competing and alternative branches. Production and UI paths are unchanged.
- **Medium — tombstone gating is inert in product.** Production `Platform` construction omits revoked credential IDs, so the new gating cannot fire. This is pre-existing and was not independently covered. The evidence document now states it explicitly; production MLS remains disabled.
- **Low — loose vector threshold.** `binding.test.ts` allowed one framed vector to disappear silently. The assertion now enumerates all five unframed fixtures and passes all 44 tests.
- **Low — separate-person fixture reuses the adder's rendezvous key.** It changes the person credential but is not a complete second-person exchange proof. The evidence document now states this limit.
- **Medium process gap — dependency enforcement.** The asset hash check and npm audit do not remediate or reject the affected Rust consumer graph. `RUSTSEC-2026-0387`, `RUSTSEC-2026-0330` and `RUSTSEC-2026-0331` remain blocking; no reachability or production approval is claimed.

Claude confirmed the binding vector and both new precedence cases, the intentional compact formatting, the 44-test reconciliation, and the evidence limits for lane behaviour, host WebKit and independent implementations. The supplied full build/unit/browser results were not rerun by Claude.
