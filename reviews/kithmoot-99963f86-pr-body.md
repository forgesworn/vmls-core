## Summary

- Pin the Browser VMLS WASM artefact and manifest to Vennel source `c154087ecfc43ee9404fa4d548cdc94c0789afef` and the standalone `1c0adec` binding fixture.
- Update the MLS engine and browser session fixtures for the synchronised VMLS 0.1.2 interface, including current-introducer `Platform` forwarding.
- Require all 43 binding fixtures, explicitly reconciling six valid and five unframed cases.
- Record the owner-approved Vennel **non-shipping dependency exception** at `517dfd42eefc13ad0433d0b8240d1ddc5f347192`; no WASM asset changed in those documentation/CI commits.

## Verification

- `npx vitest run src/vmls/binding.test.ts`: 44 passed.
- `npm run typecheck`: passed.
- `npm run build`: passed, including pinned Link/VMLS checks.
- `npm audit --omit=dev`: zero vulnerabilities.
- `npm test`: 514 files passed; 8,942 tests passed, eight skipped and one file skipped.
- `npm run build:lib && npx playwright test -c playwright.mls-app.config.ts`: four app lifecycle/production-gate tests passed.
- `playwright.mls.config.ts`: all 623 Chromium, 623 Firefox and 623 WebKit cases passed (1,869/1,869). WebKit ran in the exact pinned CI container; the host failure is reproduced on the unmodified baseline.
- `node scripts/check-vmls-wasm.mjs`: pinned source and all three asset hashes verified.

## Scope and dependency limits

Independent cross-implementation exchange is limited to the TypeScript/Rust binding fixture. Scenario 3 has upstream vector/adapter evidence rather than a separate Browser end-to-end exchange; scenario 9 was not run in Browser. No live mailbox, witness, allocation, box, public network, deployment, physical device, human security approval or production acceptance is claimed. Production MLS remains disabled and revocation enforcement is not covered.

The owner-approved exception covers only `RUSTSEC-2026-0387`, `RUSTSEC-2026-0330` and `RUSTSEC-2026-0331` at Vennel's three exact consumer lock hashes. It permits non-shipping PR review and hosted CI, not merge, deployment, production use or shipping. See `docs/2026-11-07-browser-vmls-interop.md` for full evidence and limits.
