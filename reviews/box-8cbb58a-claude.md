I re-reviewed `82b9f88..8cbb58a` without editing, building, testing or using the network. Neither finding is blocking and the commit adds no new issues.

**Range.** It is one commit, `8cbb58a`, touching three files with 6 insertions and 5 deletions. No source file or `Cargo.lock` changed in the range.

**Stale VMLS pin references: resolved**
- No tracked file at `8cbb58a` still contains `0edf250`.
- All references now agree on `d9a8d24673ad3da7117b1510a2e786767c2bc250`:
  - the manifest pin at `Cargo.toml:167`
  - the diagram edge at `docs/ECOSYSTEM.md:14`
  - the table row at `docs/ECOSYSTEM.md:31`
  - the codec commit in `docs/allocation-witness-courier.md:26`
- The lock matches: `Cargo.lock:4043-4045` has `vmls-core` 0.1.2 at that rev.
- The lock's SHA-256 is still `27d4a79f78236df11e3dca15896704f47661bbc2447593bec4fbcc3e58f35249`.
- The Link rev `7aad8bf` in `docs/ECOSYSTEM.md` still matches `Cargo.toml:150-157`.

**k256/p256 comment: resolved and accurate**

The new comment at `Cargo.toml:163-166` matches the manifests and the lock:
- **k256 0.14:** used by vmls-core, which also brings in crypto-bigint 0.7.10 (`Cargo.lock:1917-1918`, `904-905`).
- **k256 0.13.4:** Bothy's own direct dependency. It is declared at `Cargo.toml:234` and used as a normal dependency in `crates/bothy-link/Cargo.toml:17`. `link-core` also depends on it.
- **p256 0.13.2:** declared at `Cargo.toml:238` and used only as a dev dependency. It appears under `[dev-dependencies]` in `crates/bothy-core/Cargo.toml:56,62` and `crates/bothy-link/Cargo.toml:57,85`, with no other section in between.
- **Duplicate lines:** the lock has elliptic-curve 0.13.8 and 0.14.3 (`Cargo.lock:1101`, `1121`), so the comment's "duplicate elliptic-curve lines" wording is correct. The old, narrower `cargo tree -d` wording has been replaced.

**Exposure precision: still only structural**
- `static_x` at `crates/bothy-link/src/material.rs:127-139` passes our Nostr secret scalar to `link_core::rendezvous::ecdh_x`.
- `material.rs:173` builds a `k256::SecretKey` from the ephemeral scalar.
- Both go through k256 0.13.4, then elliptic-curve 0.13.8, then crypto-bigint 0.5.5 (`Cargo.lock:1101-1108`).
- So Link rendezvous ECDH does run secret-scalar arithmetic on the older line.
- Nothing in the repo shows that the advisory's specific affected arithmetic is on that path. Exposure stays structural, not shown to be exploitable.
- This commit touches no source, so that assessment is unchanged from `82b9f88`.

OPEN PR
