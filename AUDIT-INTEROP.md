# VMLS/1 audit and interoperability pack

Status: **prepared locally; independent review and downstream acceptance pending**

Source baseline: `53fa9a48ac745895eb61aa6f25679bb92c593f57` (`vmls-core` 0.1.0)

Contract: [VMLS-1.md](VMLS-1.md)

This pack gives an auditor or independent implementer a reproducible baseline,
the existing evidence, focused review questions, and acceptance procedures. It
is not an audit report and does not assert Heartwood, browser, Android, box,
firmware, or physical-device acceptance.

## 1. Review target

Review the exact baseline commit and record any later review commit separately.
The security-sensitive target includes:

- `vmls-core/src/`: all canonical codecs, derivations, verification, and lane
  decisions;
- `vmls-core/tests/`: known-answer and hostile-input checks;
- `vmls-core/vectors/` and `vectors/device-credential.json`: public fixtures;
- `vmls-core/Cargo.toml` and `Cargo.lock`: primitive versions and feature modes;
- `.github/workflows/vmls-core.yml`: the automated acceptance commands; and
- `VMLS-1.md`: the source-derived contract under review.

The crate uses hosted `std` by default and `no_std + alloc` without default
features. An allocator remains required. MLS itself, service implementations,
platform key storage, user interfaces, and deployment infrastructure are
outside this repository and need separate review at their integration boundary.

### Baseline evidence

At the baseline commit:

- 48 tests passed in each feature mode, including doc-tests;
- Rust 1.87 and 1.94.1 checks passed in both modes;
- `thumbv7em-none-eabi` compilation passed;
- formatting, dependency policy, and dependency audit checks passed according
  to the v0.1.0 source pre-release record; and
- [main CI run 42006767871](https://github.com/forgesworn/vmls-core/actions/runs/42006767871)
  completed successfully.

These are baseline assertions, not evidence for any later documentation or
source revision. Re-run the relevant checks on the exact review candidate.

### Known evidence gaps

- The VMLS/1 contract is a new source-derived draft and has not been
  independently approved.
- Test comments identify `vectors/generate-vmls.mjs` and
  `vectors/verify-vmls.mjs` as the independent producer and reader, but those
  scripts are not included in this source repository. Independent regeneration
  therefore cannot be reproduced from this checkout alone.
- No independent security audit, coverage-guided fuzzing result, formal proof,
  or side-channel assessment is asserted.
- No downstream interoperability or physical-device result is asserted.
- Bare-metal compilation does not measure final image size, allocator demand,
  stack use, latency, or power consumption.

## 2. Reproduce the reference checks

Use a clean checkout and the lockfile. Record the OS, Rust toolchain, target,
and dependency audit output with the review.

```sh
cargo test --manifest-path vmls-core/Cargo.toml --locked
cargo test --manifest-path vmls-core/Cargo.toml --no-default-features --locked

rustup toolchain install 1.87.0 --profile minimal
cargo +1.87.0 check --manifest-path vmls-core/Cargo.toml --lib --locked
cargo +1.87.0 check --manifest-path vmls-core/Cargo.toml \
  --no-default-features --lib --locked

rustup toolchain install 1.94.1 --profile minimal
cargo +1.94.1 check --manifest-path vmls-core/Cargo.toml --lib --locked
cargo +1.94.1 check --manifest-path vmls-core/Cargo.toml \
  --no-default-features --lib --locked

rustup target add thumbv7em-none-eabi
cargo check --manifest-path vmls-core/Cargo.toml \
  --no-default-features --target thumbv7em-none-eabi --lib --locked
```

Expected result: every command succeeds; each test mode reports 48 passed and
zero failed. A target compile is only a compile gate, not device acceptance.

Verify every vector hash against appendix A of the contract before comparing
outputs. For example:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path

for path in sorted(Path('vmls-core/vectors').glob('*.json')):
    print(hashlib.sha256(path.read_bytes()).hexdigest(), path)
print(hashlib.sha256(Path('vectors/device-credential.json').read_bytes()).hexdigest(),
      'vectors/device-credential.json')
PY
```

Any vector difference requires an explicit versioned contract decision; do not
regenerate fixtures merely to make a changed implementation pass.

## 3. Independent vector acceptance

An independent runner MUST NOT obtain expected values from the Rust functions
being tested. It may consume the published expected bytes, and should also
recompute cryptographic values with an independent primitive stack.

For every valid case:

1. Decode the exact input bytes.
2. Check every supplied field and verification result.
3. Re-encode and require byte-for-byte equality.
4. Where applicable, derive or seal again and require the same bytes.

For every invalid case:

1. Require rejection and the stated stable string/numeric error where defined.
2. Require no panic, hang, out-of-bounds access, or allocation based solely on
   an unbounded claimed length.
3. For sealed records, require the externally visible behaviour to be a silent
   drop regardless of the internal diagnostic code.
4. For signed objects, verify that mutation, truncation, extension, wrong
   pinned keys, wrong domains, and weak/small-order forms fail.

The hostile suite contains 7324 binding, 9079 capability, and 12284 plaintext
outcomes. Regenerate its inputs exactly from each suite's `baseHex`, `seed`,
`splices`, `randoms`, `randomLength`, and `randomHeadHex`; the algorithm is in
`vmls-core/tests/vectors.rs`. Compare every numeric outcome with `codes`.

### Minimum suite coverage

| Suite | Required independent checks |
|---|---|
| Envelope | Canonical map, profile, active mailbox, ciphertext limits, wrong lengths and trailing data |
| Record | Exporter root, every HKDF formula, ECDH agreement, record key/nonce split, all five types, buckets, AAD, silent drops |
| Binding and device credential | NIP-01 bytes and id, BIP-340, leaf match, person scope, expiry/skew, revocation, device equality |
| Capability | Opaque KeyPackage preservation, binding verification, seven-day and binding expiry limits |
| Security design | Strict Ed25519, slot digest, witness challenge, evidence ordering, fork derivations |
| Witness request | Read/advance layouts, sequence bounds, canonical errors |
| Manifest | Typed values, negative integers, raw-key sorting, duplicate refusal, schema hash and digest |
| Allocation forwarding | Exact method/body framing, NUL-terminated domain, pinned witness, strict writer signature |
| Lane | All 48 ordered inputs and all four decision outputs |

## 4. Security review checklist

Record each item as accepted, finding, or not applicable, with source and test
evidence. A valid signature alone must not be treated as current authorisation.

### Canonical parsing and resource bounds

- Check shortest-form heads, major types, exact map keys/order, duplicate and
  unknown fields, trailing bytes, integer bounds, and UTF-8/control handling.
- Check every bound before allocation and on 32-bit as well as 64-bit targets.
- Exercise authenticated but malicious record plaintexts; an MLS member can
  create them.
- Check that accepted objects always re-encode identically and that error
  precedence matches the vectors.
- Check typed encoders for inputs their decoders would reject, including
  out-of-range timestamps/sequences and oversized constructed bindings. Require
  caller prevalidation or a versioned API fix rather than assuming encode and
  decode are symmetric for every typed value.

### Derivations and record protection

- Check the single exporter call, exact ASCII domain strings, HKDF-Extract
  versus HKDF-Expand usage, field order, big-endian counters, and output split.
- Confirm record AAD binds both mailbox and record id, and that retries cannot
  reuse an id with different sealed bytes.
- Confirm the smallest bucket and zero padding are enforced after authentication.
- Review replay-state timing, random record-id generation, secret lifetime, and
  any adapter logging. These are not solved by the codec alone.

### BIP-340 bindings and credentials

- Recompute NIP-01 serialisation independently, including quotes, backslashes,
  short escapes, other controls, non-ASCII text, and lowercase hex.
- Check duplicate required tags, malformed decimal/hex values, room scope,
  expected identity, revocation, clock skew, both 30-day limits, and binding
  expiry.
- Confirm adapters require the extension through MLS required-capabilities and
  enforce leaf-id uniqueness.
- For capabilities, explicitly test the whole key-4 binding extension against
  the KeyPackage extension. `CapabilityRecord::verify` alone checks the leaf
  identity and signature key, not whole-extension byte equality.

### Ed25519 receipts, evidence, and forwarding

- Check strict verification, canonical signatures, weak/small-order keys and
  points, exact signed bytes, domain separation, and pinned-key equality.
- Check that witness subject/status and session association are validated by
  the caller in addition to signature and challenge.
- Check evidence pair identity/order and that unsigned `pre_epoch` cannot be
  used to associate evidence with an unrelated session.
- For allocation forwarding, check the terminating NUL in the domain, expected
  method, canonical inner body, and witness binding.
- Verify the service atomically consumes the courier token for the verified
  Link peer before touching its witness store. Test token replay and uncertain
  store outcomes; signature verification is not token authorisation.

### Lane safety

- Show that sheltered conversations never silently fall back to NIP-17,
  including route loss and recovery states.
- Show that starting public creates a separate empty conversation and copies no
  group or draft state without a further explicit user action.
- Check clients use wording keys rather than treating them as localised text.

## 5. Interoperability acceptance matrix

Use the same contract and vector revision in every implementation. Record
**not run**, **pass**, or **fail**, plus build and evidence location. Do not
turn a compile or unit-test pass into an end-to-end pass.

| Implementation | Unit/vector suite | Cross-implementation exchange | Failure/replay cases | Evidence |
|---|---|---|---|---|
| Rust reference | baseline pass; rerun on candidate | not applicable | baseline hostile suite | local/CI logs |
| Heartwood | pending | pending | pending | reviewer to supply |
| Browser | pending | pending | pending | reviewer to supply |
| Android | pending | pending | pending | reviewer to supply |
| Box service | pending | pending | pending | reviewer to supply |
| Firmware/allocation service | pending | pending | pending | reviewer to supply |

### End-to-end scenarios

At minimum, exercise these between independent implementations:

1. **Binding lifecycle:** valid leaf; wrong carrying leaf; expired, future,
   overlong, revoked, wrong-device, and room-form credentials.
2. **Capability and Welcome:** valid capability; non-identical KeyPackage
   extension; expired capability; replayed package and welcome mailbox.
3. **Every record kind:** correct type/mailbox pair, wrong pair, bad secret,
   bad mailbox, mutated bytes, non-bucket lengths, and every padding boundary.
4. **Record retry/replay:** resend identical bytes under one id; reject a
   different sealing under that id; update replay state only after open.
5. **Commit slots:** ordered attempts, void attempt, exact envelope receipt,
   wrong node, contradictory pair, reordered pair, and unrelated-session
   evidence.
6. **Witness transitions:** read, successful advance, conflict, retired
   subject, wrong challenge, wrong subject/status, and sequence limit.
7. **Allocation forwarding:** read/advance, wrong method or witness, invalid
   writer, token replay, and an uncertain store result after token consumption.
8. **Manifest restore:** insertion-order independence, typed-value differences,
   duplicate key, schema mismatch, and digest equality after restore.
9. **Lane behaviour:** capability absence, route loss, recovery, explicit public
   choice, and proof that no sheltered content silently crosses lanes.

For each scenario, preserve inputs, expected outputs, actual outputs, logs,
versions, and the responsible reviewer. Test public-network or deployment
behaviour separately from loopback fixtures.

## 6. Constrained-device acceptance

Run these on the intended firmware image and physical target, not only the
host or an emulator:

- final image size and remaining flash/RAM budgets;
- peak heap allocation for each parser and the largest accepted object;
- peak stack use during parsing and strict verification;
- latency and timeout behaviour for each record bucket and signature operation;
- random record-id generation and platform entropy health;
- token consumption, replay rejection, interrupted writes, and recovery;
- production feature/dependency selection and debug-log inspection; and
- repeated operation under memory pressure.

Record target, clock, compiler, linker options, allocator, firmware hash,
measurement method, and results. No numeric device budget is established by
this repository, so the product owner must supply acceptance thresholds.

## 7. Release gates and evidence record

Before removing pre-release status or claiming production readiness:

- [ ] The contract and vector compatibility policy have named reviewer approval.
- [ ] Independent vector generation or reading is reproducible and all cases pass.
- [ ] Security findings have severity, resolution, and regression evidence.
- [ ] Each required downstream implementation has completed the matrix.
- [ ] Physical-device results meet explicitly supplied budgets.
- [ ] Distribution remains source-only or the chosen crate/binary artefacts,
      signatures, notices, and update instructions have been verified.
- [ ] A private security-reporting route is supplied by the owner; none is
      identified in this repository.

For each review run, record:

```text
Review commit and dirty-tree state:
Contract/vector hashes:
Reviewer and review date:
Build/dependency/tool versions:
Commands and results:
Test/log/evidence locations:
Findings and affected versions:
Downstream/device evidence:
Unresolved limitations and next action:
```

No external reviewer has been contacted and no external publication has been
performed as part of preparing this pack.
