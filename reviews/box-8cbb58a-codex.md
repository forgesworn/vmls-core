No blocking findings in `82b9f88..8cbb58a`; the three-file documentation/comment change resolves both findings without new issues.

- **VMLS pins:** `docs/ECOSYSTEM.md:14`, `docs/ECOSYSTEM.md:31` and `docs/allocation-witness-courier.md:26` now match `Cargo.toml:167` and `Cargo.lock:4045`. No tracked `0edf250` references remain.
- **k256/p256 comment:** `Cargo.toml:163–166` correctly distinguishes VMLS’s k256 0.14 from retained k256 0.13 and dev-only p256 0.13. Supported by `Cargo.lock:1982`, `Cargo.lock:4050`, `crates/bothy-core/Cargo.toml:62` and `crates/bothy-link/Cargo.toml:85`.
- **Exposure remains structural:** Link rendezvous ECDH receives secret scalars at `crates/bothy-link/src/material.rs:135–136`, `:353`, `:361` and `:367–370`. This does **not demonstrate the advisory’s specific affected arithmetic**, or establish exploitability.
- **Lock unchanged:** both revisions hash to `27d4a79f78236df11e3dca15896704f47661bbc2447593bec4fbcc3e58f35249`.

Working tree clean. No edits, builds/tests, fetches or network use.

OPEN PR