Review complete. The lock hash matches the candidate, both commits are lock or manifest only, and nothing blocking was found.

**Scope reviewed.** Commits 95961cd and 82b9f88 over merge-base 7510db5. The canonical crate was read from git at d9a8d24. The vmls-core checkout HEAD is ahead by docs-only commits and its crate tree is identical to the pinned rev.

## Findings, most severe first

1. **Security precision note, non-blocking under the approved exception.** The residual advisory RUSTSEC-2026-0387 sits on crypto-bigint 0.5.5 via elliptic-curve 0.13.8 via k256 0.13.4. That path is structurally reachable from Bothy's own secret material. `crates/bothy-link/src/material.rs:136`, `:353`, `:361` and `:370` call the Link rendezvous ECDH helper, which runs k256 0.13 Diffie-Hellman on the ephemeral or Nostr secret scalar. Bothy's only direct k256 0.13 use on a secret is `from_scalar` at `crates/bothy-link/src/material.rs:173`, which its doc scopes to vectors and tests. Not shown here: that this ECDH exercises the specific arithmetic the advisory describes with secret-dependent inputs. The path pre-exists on main and neither commit introduces or widens it. The owner approved the exception at this exact lock. This is a precision note for the exception record, not a newly demonstrated affected operation. The owner may read it differently.

2. **Low, non-blocking: three docs still name the old codec pin.** `docs/ECOSYSTEM.md:14` and `docs/ECOSYSTEM.md:31` say vmls-core is at rev 0edf250. `docs/allocation-witness-courier.md:26` names the full old commit as the pinned published codec. After this PR the pin is d9a8d24 at 0.1.2.

3. **Low, non-blocking: Cargo.toml comment slightly incomplete.** `Cargo.toml:164-165` names the direct k256 0.13 line as what retains the vulnerable crypto-bigint. The dev-only p256 0.13 sits on the same elliptic-curve 0.13.8 line. Accurate as far as it goes.

## Checks that passed

- **Dependency scope.** Sixteen new crates.io packages, all checksummed, all in the RustCrypto 0.14 graph plus crypto-bigint 0.7.10 and its constant-time helpers. Package count 411 to 427 matches the audit record. sha2 0.11.1, digest 0.11.3, rand_core 0.10.1, hybrid-array, crypto-common 0.2.2 and const-oid 0.10.2 already existed at the merge-base.
- **MSRV.** The workspace floor of 1.88 covers vmls-core's 1.87. Every new crate's declared rust-version in the local registry cache is at or below 1.88.
- **k256 0.14 exposure.** Reached only through vmls-core's binding and capability schnorr verification, which no Bothy call site uses. Bothy uses Envelope, receipts and the forwarding envelope on ed25519, witness requests on CBOR and the manifest on sha2.
- **API compatibility.** vmls-core removed its refusal header constants from the witness module. Bothy defines its own at `crates/bothy-link/src/witness.rs:75`, so no call site is affected. No signature changes to any symbol Bothy imports. The dropped zero-length check in the forwarding parser is dead code, since the overhead-length check already rejects that case. The unsigned encoder lost an expect-panic path. ForkEvidence verification was tightened but Bothy does not use it. The no_std refactor keeps the std feature on by default and Bothy takes defaults.
- **Wire compatibility.** Vector diffs are additions only. No existing fixture byte changed, so the envelope, receipt, witness request and manifest layouts Bothy relies on are unchanged.
- **Advisory commit.** quinn-proto 0.11.18, rustls-webpki 0.103.16, webpki-roots and webpki-root-certs 1.0.10. The tempfile 3.27.0 getrandom edge moved from 0.4.3 to the already-locked 0.3.4. That release declares a range covering both, so the normalisation is valid, dev-only and changes no version.
- **Comment accuracy.** `Cargo.toml:159-166` is accurate: both k256 lines now appear in the duplicate tree. The p256 comment about elliptic-curve already being in the lock still holds for the 0.13 line.
- **Duplicate test.** `crates/bothy-core/tests/deps.rs` guards only nostr and secp256k1, so the new k256 duplicate passes it by design.
- **Commit identity.** TheCryptoDonkey on a forgesworn remote. No forbidden names in the diff.

## Non-blocking limitations

- Advisory IDs and the claim that only RUSTSEC-2026-0387 remains were not checked against the RustSec database. No network. I relied on the canonical audit record's Box section.
- I cannot confirm remote main has not advanced past 7510db5. No fetch.
- The G3 Android shared-object size gate was not re-measured. The android workflow enforces it in CI.
- Bothy resolved newer patches than vmls-core's own lock: elliptic-curve 0.14.3 versus 0.14.2, der 0.8.3 versus 0.8.2, sha2 0.11.1 versus 0.11.0. The canonical CI evidence was produced against the older patches.
- The deps test and the full gates were not run here.

OPEN PR
