# VMLS/1 audit and interoperability pack

Status: **prepared locally; independent review and downstream acceptance pending**

Original source baseline: `53fa9a48ac745895eb61aa6f25679bb92c593f57`
(`vmls-core` 0.1.0). Current review source is the containing Git commit; later
review records identify their exact candidates separately.

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
- Test comments identify `vectors/generate-vmls.mjs` as the independent
  producer. That generator is included and regenerates every expected object and
  outcome for all 11 files, with a negative control.
- No independent security audit, coverage-guided fuzzing result, formal proof,
  or side-channel assessment is asserted.
- No physical-device result is asserted. Heartwood has only the scoped
  host/vector interoperability result recorded in sections 5 and 12.
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

Expected result: every command succeeds; each test mode reports 53 passed and
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

The checkout includes such a reader. From the repository root, with Node.js 20
or later and no package installation:

```sh
node --check vectors/verify-vmls.mjs
node vectors/verify-vmls.mjs
```

The expected final line is `PASS 11 suites, 29170 independent assertions`.
The reader uses `node:crypto`, a separate canonical CBOR reader, and test-only
BigInt secp256k1 arithmetic. It recomputes signatures, derivations, ECDH,
sealed bytes, manifests and all hostile outcomes without calling Rust. Its
arithmetic is not constant-time and is restricted to the public fixtures. The
Node suite does not duplicate the Rust strict-Ed25519 weak/small-order and
noncanonical-form negative tests; `node:crypto` is not claimed to be an
independent strict verifier for those forms. Manifest JSON integers are parsed
losslessly across the full signed 64-bit range. This is reproducible
implementation evidence, not named reviewer approval or an independent security
audit.

Regenerate every expected object and outcome with the same dependency-free
primitive stack and require exact source bytes to remain compatible:

```sh
node --check vectors/generate-vmls.mjs
node vectors/generate-vmls.mjs
```

The expected final line is `PASS 11 vector files regenerated; content and exact
bytes match; negative control passed`. The generator recomputes all expected
fields and error outcomes from the fixture inputs, including deterministic
signatures and every hostile code. It never calls Rust or copies expected fields
without recomputation. The negative control changes an input and requires the
regenerated outcome to differ. Importing the reader as a library does not run
the suites.

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
| Heartwood | pass: scoped allocation/witness/fresh-R host suites | pass: Python journal and 36 Introduction fixture exchanges | pass: scoped allocation/witness host cases; other scenarios not run | Heartwood `ad83fca`; PR #272 CI 42278785850; §12 |
| Browser | pass (local, scoped): binding/vector suites, 1,869 browser tests and 8,942 unit tests | pass (local): TypeScript/Rust binding fixture; other exchanges are host/browser fixtures | pass (local, scoped): scenarios 1–8 with stated limits; scenario 3 Browser exchange and scenario 9 not run | merged: Vennel `feea45f`, KithMoot `3d5acf7`; PR and post-merge CI passed; §§13–14 |
| Android | pass (local, scoped): 684 protocol and 3,386 app tests plus one skip; 23 emulator tests | pass (local): 38 framed Kotlin reader cases; other exchanges are host/FFI fixtures | pass (local, scoped): session/commit-slot/vault/restart fixtures; live-box join lab and production revocation not covered | merged `6deaaca`; PR and post-merge CI passed; §15 |
| Box service | pending | pending | pending | reviewer to supply |
| Firmware/allocation service | pending | pending | pending | reviewer to supply |

Heartwood's pass cells are not end-to-end acceptance. Scenarios 1–5, 8 and 9
remain **not run** there; scenarios 6 and 7 have host-fixture coverage only.
No public-network, deployment or physical-device behaviour is claimed.

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
- [x] Independent vector reading and regeneration are reproducible and all
      published cases pass (§3).
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

## 8. Maintainer pre-review record: v0.1.2

Status: **local maintainer pre-review complete; named independent review pending**

- Review date: 2026-11-06.
- Reviewed implementation: v0.1.2, commit
  `6ffaafa3ebaee5bf81df5c6658faade0fe0420a8`.
- Resulting tree: an uncommitted contract, review-record, and rustdoc patch on
  that commit. No executable code, vector, dependency, or public API signature
  changed. A reviewer must record the commit containing this patch separately.
- Reviewer: Kimi Code CLI. This is source-backed maintainer pre-review, not an
  independent security audit or named reviewer approval.
- Resulting contract SHA-256:
  `49a5c8b8cfe3f8b4cf7ec061a46099be3c4a00f97a6cec25baa0a86462f48268`.
  All appendix A vector hashes matched the reviewed checkout.

### 8.1 Checklist disposition

- **Canonical parsing and resource bounds:** accepted within codec scope. The
  envelope, CBOR, binding, capability, record, witness, receipt, evidence, and
  allocation-forwarding paths enforce their stated lengths and canonical forms.
  Seeded hostile inputs, every published truncation/bit-flip case, and accepted
  re-encoding checks passed. This is not coverage-guided fuzzing or a formal
  proof.
- **Derivations and record protection:** accepted within codec scope. The
  exporter inputs, HKDF-Extract/Expand distinction, domain strings, field order,
  counters, key/nonce split, AAD, bucket selection, zero padding, and silent-drop
  behaviour match the independent vectors. CSPRNG quality, replay-state timing,
  secret erasure, and adapter logging remain integration checks.
- **Bindings and credentials:** accepted within codec scope. NIP-01
  serialisation, BIP-340 verification, carrying-leaf equality, required-tag,
  identity, expiry/skew, revocation, device, and lifetime rules agree with the
  vectors. Required-capabilities, leaf-id uniqueness, and the whole
  capability/KeyPackage extension comparison remain adapter checks and were not
  run here.
- **Receipts, evidence, and forwarding:** accepted within codec scope. Strict
  Ed25519 verification, weak/small-order rejection, signed bytes, challenges,
  evidence ordering, method/domain separation, and bounded canonical request
  parsing passed. Subject/status, session association, writer enrolment, atomic
  token consumption, and uncertain store outcomes remain service checks.
- **Lane safety:** accepted for the pure decision table; all 48 combinations
  passed. Actual client conversation separation, draft behaviour, and wording
  remain downstream UI/integration acceptance.
- **Manifest:** accepted for canonical construction, typed-value hashing,
  raw-byte key ordering, insertion-order independence, and duplicate refusal.
  Schema coverage and storage reconciliation remain adapter checks.

### 8.2 Finding and resolution

**MRR-01 — Low, interoperability/API robustness:** caller-constructed
`LeafBinding`, `CapabilityRecord`, `AdvanceRequest`, and `WitnessReceipt` values
could be encoded without all decoder-enforced bounds being checked. In
particular, nested binding credential limits, timestamps, and witness sequence
limits were not uniformly validated by the typed encoders. The contract did not
clearly assign the required prevalidation, allowing a caller to emit a
non-conforming object despite using the provided API.

Resolved locally without changing the wire format or public signatures:
contract §2.1 now requires callers to enforce all applicable bounds before
signing or emitting constructed values and permits a successful decode as
structural prevalidation. Method-level rustdoc at the affected signing/encoding
entry points states the same obligation. `ForwardedRequest::new` already
performs the request-body round-trip check. The full compatibility suite below
passed after this documentation resolution. Named review should confirm that
caller prevalidation is acceptable; a checked or versioned API remains an
alternative if it is not.

No additional codec finding was identified in this pass. That is not evidence
of absence, independent approval, side-channel assurance, or production
readiness.

### 8.3 Candidate verification

Environment: macOS 14.6.1, Node.js v24.21.0, rustc 1.94.1; Rust 1.87.0 and the
`thumbv7em-none-eabi` target were installed through rustup. All commands ran
from the repository root on the resulting review tree:

```sh
node --check vectors/verify-vmls.mjs
node vectors/verify-vmls.mjs
cargo test --manifest-path vmls-core/Cargo.toml --locked
cargo test --manifest-path vmls-core/Cargo.toml --no-default-features --locked
cargo +1.87.0 check --manifest-path vmls-core/Cargo.toml --lib --locked
cargo +1.87.0 check --manifest-path vmls-core/Cargo.toml --no-default-features --lib --locked
cargo +1.94.1 check --manifest-path vmls-core/Cargo.toml --lib --locked
cargo +1.94.1 check --manifest-path vmls-core/Cargo.toml --no-default-features --lib --locked
cargo check --manifest-path vmls-core/Cargo.toml \
  --no-default-features --target thumbv7em-none-eabi --lib --locked
cargo fmt --manifest-path vmls-core/Cargo.toml --check
cargo audit --file vmls-core/Cargo.lock
git diff --check
```

Results: all passed. The Node reader reported 11 suites and 29,130 independent
assertions. Each Rust feature mode reported 48 passed and zero failed, including
doc-tests. The dependency audit scanned 71 locked dependencies and reported no
vulnerability. `git diff --check` reported no whitespace error. Vector hashes
were independently recomputed with Python SHA-256 and all matched appendix A.

Downstream interoperability, independent regeneration, physical-device
acceptance, coverage-guided fuzzing, side-channel assessment, and formal proof
remain **not run**. No external reviewer was contacted during this local review.

Next action: a named independent reviewer should review the exact commit
containing this patch, confirm MRR-01's resolution, and record findings against
sections 4 through 7. Downstream implementations can then execute the matrix in
section 5; the product owner must supply device budgets before section 6 can be
accepted.

## 9. Independent AI review follow-up

Status: **implementation and local verification complete; AI re-review pending**

The original review target was `323b536a775a9e2a92dae979f92ae6435846dc10`.
Claude Fable 5.1 and OpenAI Codex independently reviewed that commit without
editing source. Their raw reports and the consolidated findings are in
`reviews/vmls1-323b536-claude.md`, `reviews/vmls1-323b536-codex.md`, and
`reviews/vmls1-323b536-ai-review.md`. Claude recommended approve with findings;
Codex recommended do not approve before repairs. Both accepted MRR-01 only with
conditions. These are independent AI reviews, not human security approval.

The follow-up addresses every consolidated finding:

- AI-01: `ForkEvidence::verify` now rechecks pair invariants before signatures;
  duplicate, reversed, different-installation, and different-slot constructed
  pairs have regression tests.
- AI-02/AI-03: contract §§3, 6.1, and 10 pin error order; the Node reader
  implements the documented Rust order. Envelope, correctly signed binding, and
  evidence combined-failure vectors cover the identified divergences.
- AI-04: contract §11 explicitly permits any valid UTF-8 in manifest text and
  namespaces, with control-character known-answer coverage.
- AI-05: manifest JSON integers are parsed losslessly through conversion to
  BigInt; both `i64` endpoints and values immediately outside JavaScript's safe
  range have known-answer coverage.
- AI-06: all identified signing helpers document prevalidation, contract §2.1
  includes `DeviceCredential` and `ForkEvidence` and invalidation after mutation,
  and all four original MRR-01 types have negative structural round-trip tests.
- AI-07: contract §4.2 and `record::seal` explain why different padded
  plaintexts must never share a record id under one record secret.
- AI-08: contract and audit headers distinguish the original 0.1.0 baseline from
  the current normative revision in the containing commit.
- AI-09: CI now checks every Appendix A vector hash, formatting, dependency
  audit, and hosted 32-bit test compilation in addition to the existing reader,
  test, toolchain, and target gates.
- AI-10: section 3 explicitly limits the Node reader's strict-signature negative
  evidence; the reader also rejects zero BIP-340 scalars.
- AI-11: the CBOR test computes expected head sizes without narrowing `u64` to
  `usize`. Both Android and Linux 32-bit test compiles pass locally, and CI now
  compiles tests for `i686-unknown-linux-gnu`. Hosted 32-bit execution remains
  **not run** because no runnable hosted 32-bit target is available locally.

### Verification

On the follow-up tree, Node reported `PASS 11 suites, 29169 independent
assertions`. Each Rust feature mode reported **53 passed and zero failed**,
including all new regressions. Rust 1.87.0 and 1.94.1 checks passed in both
modes; `thumbv7em-none-eabi`, `i686-linux-android`, and
`i686-unknown-linux-gnu` compilation passed. Formatting, `cargo audit` over 71
locked dependencies, all 11 Appendix A hashes, workflow YAML parsing, and
`git diff --check` passed. The workflow now runs the same vector-hash,
formatting, dependency-audit, and hosted 32-bit test-compilation gates.

Next action: commit this exact follow-up with the review evidence, ask Claude
and Codex to re-review it against AI-01 through AI-11, then deliver the reviewed
change. Human review on issue #7, downstream interoperability, independent
regeneration, physical-device acceptance, fuzzing, side-channel assessment,
formal proof, hosted 32-bit test execution, and production approval remain
separate gates.

## 10. Final independent AI compatibility review

Status: **Claude and Codex independently approve the contract/vector
compatibility gate at `2d08414`; MRR-01 closed**

Approved implementation: `2d0841442194a939e0e946f199b3a00bbcc73916`.
Their final reports are `reviews/vmls1-2d08414-claude.md` and
`reviews/vmls1-2d08414-codex.md`; the consolidated approval is
`reviews/vmls1-2d08414-ai-review.md`. Both found AI-01 through AI-11 resolved,
all seven residual first-re-review conditions closed, and no confirmed new
finding. Codex independently recomputed all 11 vector hashes and ran the Node
reader, obtaining `PASS 11 suites, 29169 independent assertions`. Both accepted
caller prevalidation as sufficient to close MRR-01. These are independent AI
reviews, not human security approval or production readiness.

[PR CI run 42209686581](https://github.com/forgesworn/vmls-core/actions/runs/42209686581)
passed every step at the approved commit: all 11 vector hashes, formatting,
dependency audit, Node reader, both Rust feature modes, Rust 1.87.0 and 1.94.1,
`thumbv7em-none-eabi`, and `i686-unknown-linux-gnu` test compilation. Local
Android 32-bit compilation also passed. Hosted 32-bit execution remains not run.

The final review-report delivery commit is documentation-only and does not alter
the approved implementation. Independent regeneration is now reproducible (§3).
Issue #7 remains open for named human review. Downstream interoperability,
physical-device acceptance, fuzzing, side-channel assessment, formal proof,
hosted 32-bit execution, a private security-reporting route, and production
approval remain separate gates.

## 11. Independent vector regeneration

Status: **complete; merged at `1c0adec`**

Final reports: `reviews/vmls1-52a8e5d-claude.md`,
`reviews/vmls1-52a8e5d-codex.md`, and `reviews/vmls1-52a8e5d-ai-review.md`.
Claude and Codex both recommend approve with no confirmed issues. The final
record also restores the historical 29,169 counts in sections 9 and 10 and adds
the tombstone consistency assertion. Delivery CI 42228895288 passed at
`45190c7`; post-merge CI 42230089240 passed at `1c0adec`.

`vectors/generate-vmls.mjs` is included and uses only Node.js built-ins and the
independent reader's primitive stack, never Rust. It recomputes all expected
fields and error outcomes for every published fixture family: envelope, binding,
capability, derivations/records, lanes, device credentials, security design,
witness requests, manifests, allocation forwarding, and the hostile corpus.
Deterministic receipt, evidence, witness, and allocation signatures are
recomputed from public fixture seeds. Receipt bodies, installations, slots,
attempts, and envelope hashes are rebuilt from explicit scenario fields rather
than signed unchanged. Witness bodies and evidence headers retain their
scenario-provided values. Signed binding and capability inputs are retained and
independently verified rather than regenerated.

Run from the repository root with Node.js 20 or later:

```sh
node --check vectors/generate-vmls.mjs
node vectors/generate-vmls.mjs
```

Expected result: `PASS 11 vector files regenerated; content and exact bytes
match; negative control passed`. Default mode requires deep semantic equality
and independently rendered source-byte equality for all 11 files. The renderer
preserves pretty JSON, compact envelope/security cases, appended compact cases,
full-`i64` numeric tokens, and single-line hostile code arrays. `--write` permits
a deliberate versioned fixture change; it is not run by CI. BIP-340 credential
signatures use random auxiliary data, so they are independently verified but not
regenerated; that limitation is explicit and does not affect deterministic
Ed25519 signatures.

Negative controls require a trailing-byte envelope to change outcome and rendered
bytes, prove that changing only an expected identity cannot influence validation,
reject a changed retained public key, and require changed installation and attempt
inputs to alter the rebuilt receipt. Write mode reports files written rather than
compatibility equality. Importing `verify-vmls.mjs` as a library does not execute
the suites. Direct execution resolves the entry path's real path and reports
`PASS 11 suites, 29170 independent assertions`, including through a symlink.

CI runs the reader and generator and asserts their PASS lines. Local verification
also passed 53 Rust tests in each feature mode, both Rust toolchains,
`thumbv7em-none-eabi`, Android and Linux 32-bit test compilation, formatting,
dependency audit, all Appendix A hashes, workflow YAML parsing, and
`git diff --check`.

Next action: continue downstream interoperability (§12). Physical-device
acceptance, hosted 32-bit execution, and the other external gates remain open.

## 12. Heartwood scoped interoperability

Status: **scoped host/vector interoperability pass; complete acceptance not run**

Heartwood PR [#272](https://github.com/forgesworn/heartwood-esp32/pull/272)
merged as `472ae52ba9342dfde61bb8a20347b1aad22d8d9e`. Its implementation
commit `ad83fca8dd34bea00e2468764cec7a35c4f9852a` pins both Heartwood manifests
and locks to this repository's `1c0adec` revision (crate 0.1.2), with default
features disabled and no other dependency movement. Claude and Codex reviewed
that exact commit read-only and both recommend approve, conditional on hosted
firmware-size CI. Their reports are `reviews/heartwood-ad83fca-claude.md` and
`reviews/heartwood-ad83fca-codex.md`; the consolidated disposition and later
documentation reviews are in `reviews/heartwood-ad83fca-ai-review.md`. These are
independent AI reviews, not human or production approval.

Local rustc 1.94.1 verification passed 1230 full k256 unit tests and 13
integration tests, 359 secp256k1 baseline unit tests and ten integration tests,
98 firmware-backend allocation tests, and five fresh-R tests. The real adapter
executes strict receipts, forwarding, witness transitions, response/replay
rejection and storage faults. Independent inputs and expected outputs are in
Heartwood's `common/tests/fixtures/`; the exchange evidence includes its Python
journal generator and 36 actual-ECDH VMLS Introduction vectors. `cargo deny`
reported advisories, bans, licences and sources OK.

Heartwood PR CI 42278785850 passed every job, including V3, V4, T-Display, C6
and ESP8266 builds. Post-merge CI 42281172418 also passed at `472ae52`. The V4
app image is 2,094,800 bytes against the
2,097,152-byte slot, leaving 2,352 bytes. Local old/new images were both
oversize (2,126,656/2,126,304 bytes), so local size is explicitly not a pass;
the hosted candidate result is the accepted compilation/image evidence. No
board was flashed and no physical timing, stack, RAM or power measurement was
made.

The matrix pass is limited to allocation/witness/fresh-R host suites and fixture
exchange. Binding/capability/Welcome, general record exchange and replay,
commit slots, manifest restore and lane behaviour remain **not run** in
Heartwood. Witness and allocation forwarding have host-fixture coverage, not a
live external service or deployment test. Detailed evidence is in Heartwood's
`docs/2026-10-11-allocation-strict-history.md` and the PR 272 CI logs.

Next action: continue downstream with Android, then the Box service and
firmware/allocation service. Physical-device acceptance and all other separate
assurance gates remain open.

## 13. Browser upstream candidate and dependency disposition

Status: **merged at `feea45f`; PR and post-merge CI passed**

The Browser engine source is Vennel `c154087ecfc43ee9404fa4d548cdc94c0789afef`,
including `9ceaf3317ed2fd28f0abb4073dfd4e4e6258c6ab`. It synchronises the shared
codec/vector revision `1c0adec` while retaining Vennel-only invitation/admin
modules and record variants. All 11 shared input files regenerate byte-identically;
both core feature modes pass 61 tests each, both Rust 1.87 library modes pass,
full `npm run check` passes, and 28 native/WASM adapter tests pass. The dependency
graph target matrix and both design-generator negative controls pass.

Claude and Codex independently confirm that the earlier implementation and
review-evidence findings are resolved. Their reports are
`reviews/vennel-c154087-claude.md` and `reviews/vennel-c154087-codex.md`. This is
AI review only, not human, production or dependency-exception approval.

A fresh cargo-audit run (1,422 advisories) reports no issue in the 71-package
core lock. Every consumer lock reports `RUSTSEC-2026-0387` through the retained
OpenMLS `crypto-bigint` 0.5.5 line and `RUSTSEC-2026-0330`/`RUSTSEC-2026-0331`
through `libcrux-kem` 0.0.9. Each consumer lock gains 12 packages for the new
`k256` 0.14 line, but the direct 0.7.6 minimum does not remediate the older
OpenMLS line. Raw outputs are `reviews/vennel-c154087-vmls-core-audit.txt`,
`reviews/vennel-c154087-vmls-mls-audit.txt`,
`reviews/vennel-c154087-vmls-ffi-audit.txt` and
`reviews/vennel-c154087-vmls-wasm-audit.txt`; all shared input hashes are in
`reviews/vennel-c154087-vector-hashes.txt`.

On 7 November 2026 the owner explicitly approved a non-shipping exception for
exactly those three advisories at the unchanged consumer lock hashes. Vennel
`517dfd42eefc13ad0433d0b8240d1ddc5f347192` records the exact scope, exposure
analysis, remediation investigation, raw unignored findings, successful audits
with only those IDs ignored, and closure conditions in its implementation
contract, dependency exception and
`docs/gate/evidence/2026-11-07-vmls-consumer-cargo-audit.txt`. The exposure
record distinguishes lock-only `libcrux-kem` from the conservative
Cargo-metadata SBOM over-approximation and includes all crypto-bigint paths.
The exception commits change documentation and CI only; the reviewed engine
source and all lockfiles remain those at `c154087`. They enable PR and
post-merge Vennel CI. No stable compatible provider remediation is currently
released, and no unreleased pin, provider fork or backport is authorised. The
exception permits PR review and hosted CI; merge, deployment, production use
and shipping remain separate gates. Any new advisory, changed lock, provider,
feature, target or flag, enabled draft/hybrid/other ciphersuite, or newly
demonstrated reachable affected operation requires a new disposition.

Final read-only Claude and Codex reviews of `517dfd4` both returned **OPEN PR**
with no blocking findings: `reviews/vennel-517dfd4-claude.md` and
`reviews/vennel-517dfd4-codex.md`. They independently confirmed the corrected
exposure scope, lock/source immutability, raw and approved-ignore audit results,
SBOM caveat and CI triggers. Earlier review rounds are retained as
`reviews/vennel-db669f9-{claude,codex}.md`. Claude's remaining non-blocking
notes concern optional-dependency wording and explicit raw command/exit-code
capture; a separate Bothy discovery lock is outside this exception and was not
changed. These are AI reviews only, not human, merge, security or production
approval. Vennel's pre-push hook reran the full `npm run check` successfully.
[PR #351](https://github.com/forgesworn/vennel/pull/351) merged as
`feea45fc4ca172b05ea671579df51e936c5804b6` on 7 November 2026. PR runs
42352905770 and 42352905624 passed before merge. Post-merge Profile run
42355481994 passed core, engine, adapters and both Node profiles; Android
bundle run 42355481980 also passed. The task branch is an ancestor of remote
`main`. No deployment or production approval was given.

## 14. KithMoot Browser scoped interoperability

Status: **merged at `3d5acf7`; PR and full post-merge CI passed; complete acceptance not run**

KithMoot delivery commit `99963f862c12a9a494af054d923267fd103212ea` records
the dependency disposition and complete closure triggers. It adds documentation
only to implementation commit `d358f0e873dfc2f35f0785c2718d0af7bb218645`
(including `397f3f9308f8b9432220ec700c52c8696d46a76c`, `c0e4c662` and
`2be3a38`). The Vennel `c154087` browser engine, standalone `1c0adec` binding
fixture, manifest, loader and generated assets remain unchanged and agree. The
detailed run record is KithMoot's `docs/2026-11-07-browser-vmls-interop.md`.

Local KithMoot checks pass: 44 TypeScript binding tests; 8,942 unit tests with
eight skipped and one file skipped; all 623 Chromium and all 623 Firefox MLS
cases; all 623 WebKit cases in the exact pinned Playwright CI container; four
app lifecycle/production-gate cases; typecheck; production build; and
`npm audit --omit=dev`. The one-hour combined Chromium/Firefox process timed out
only after all 1,246 cases had passed. Host WebKit fails during page creation
with `Unknown setting: PushAPIEnabled`, identically on the unmodified baseline;
the passing WebKit result comes from the pinned container, not the host.

The independent cross-implementation exchange is the TypeScript/Rust binding
fixture. Capability/Welcome, retry/replay, commit slots, witness transitions,
allocation forwarding and manifest restore have scoped vector/WASM/browser
fixture coverage. Production `Platform` construction omits revoked credential
IDs, so the new tombstone gating cannot fire in product; no revocation-enforcement
coverage is claimed. The `separatePerson` fixture reuses the adder's rendezvous
key and gives the person no independent identity: it equals the current guest
device in the ordinary path and the previous guest in competing variants, so it
is not a complete second-person proof.
Every-record-kind exchange is an upstream vector/adapter pass,
not a separate Browser end-to-end run. Browser lane behaviour is **not run**:
the 48 upstream lane vectors pass, but production MLS/lane wiring is unavailable.
No live external mailbox, witness, allocation or box service is exercised, and no
public-network, deployment, physical-device, human or production acceptance is
claimed. No screen or user interaction changed.

The exception in §13 permits PR review and hosted CI despite the retained
consumer vulnerabilities; it grants no merge, deployment or production approval.
Claude and Codex confirm all earlier implementation findings resolved with no
new findings in `reviews/kithmoot-d358f0e8-claude.md` and
`reviews/kithmoot-d358f0e8-codex.md`. Final read-only reviews of `99963f86`
both returned **OPEN PR** in `reviews/kithmoot-99963f86-claude.md` and
`reviews/kithmoot-99963f86-codex.md`; the earlier closure-list note is resolved
and no blocking finding remains. Earlier delivery rounds are retained as
`reviews/kithmoot-34f0b3b4-{claude,codex}.md`. These are AI reviews only, not
human, merge, security or production approval.
[PR #731](https://github.com/forgesworn/kithmoot/pull/731) merged as
`3d5acf777d0fac8b81f6db59e55c2ed85edf414d` on 7 November 2026. PR runs
42352922016 and 42352922074 passed before merge; their skipped heavy browser
jobs were not relabelled as hosted evidence. Full post-merge CI run 42356022622
passed every job, including browser regressions, acceptance, protected startup
and call/media coverage; Combined realtime adapter run 42356022613 also passed.
The task branch is an ancestor of remote `main`. No deployment or production
approval was given.

## 15. Android scoped VMLS interoperability

Status: **merged at `6deaaca`; prerelease published; PR and post-merge CI passed**

Android PR [#399](https://github.com/forgesworn/kithmoot-android/pull/399)
pins Vennel `feea45fc4ca172b05ea671579df51e936c5804b6`, the merged VMLS 0.1.2
revision on `main`, and the standalone `1c0adec` binding fixture. The hosted
Android bundle run 42355481980 supplies archive SHA-256
`0de096b79e7ef3a7d98c97dac74ea0582d5b1856d8bdb8d646d911b82aceaa26`, with
`manifest.json` `7ae7edf6658ba386cc4cd3ece43877b7e6ab970e69f2922de505f7b16385a946`
and `manifest.txt` `ce443a3d85d8baf01eb2dc390bb9bb9ec04aa16ac86512c2cd4d262d3ce6b3d0`.
The public [`vmls-ffi-android-feea45f` prerelease](https://github.com/forgesworn/kithmoot-android/releases/tag/vmls-ffi-android-feea45f)
is published and its fetch/prepare path passes all five checks. Generated Kotlin
is byte-identical between local and hosted builds; native binaries differ, so
the hosted archive is the pinned hand-off. The detailed record is Android's
`docs/2026-11-07-android-vmls-interop.md`.

Local checks pass: 684 protocol tests with no failures/errors/skips; 3,386 app
tests with one skip and no failures/errors; all 38 framed independent Kotlin
reader cases; all five prepared-bundle forge/refusal checks; and both debug and
instrumentation builds, including the explicitly selected Admin2 profile. The
five unframed cases are counted and covered by synthetic framing checks, not
independent exchanges. Four framed leaf-mismatch/signature cases assert unsigned
decode success only. Android 15 arm64 Google APIs emulator tests pass 19
session/driver/coordinated-vault cases plus two coordinated-vault restarts and
two session restarts, 23 in total. This is not GrapheneOS evidence.

Final read-only Claude and Codex reviews at `2e56e3cc` both returned **OPEN PR**
with no confirmed issues: `reviews/android-2e56e3cc-claude.md` and
`reviews/android-2e56e3cc-codex.md`. Earlier implementation/review rounds at
`98829b71`, `8b9fe70` and `3d4aadf8` are retained. These are AI reviews only,
not human, merge, security or production approval.

`EngineJoin` and `VmlsRuntime` pass the current platform through capability
opening and pending-introduction completion. Inspection passes the vault's
current revoked IDs, and `admissible` takes the platform explicitly. Existing
`EngineSessions` still uses the empty-revocation-list constructor and no
production caller writes `revokeCredential`, so both inspection and native
capability revocation enforcement lack production coverage. `admissible`,
`addJoins` and `openCapability` have compile-time evidence only; the live-box
join lab was not run. Reading the vault before inspection can surface
`JoinRefusedException` before the native inspection error that previously led.

No two-emulator/live-box lab, public relay, independent live mailbox/witness/
allocation service, physical device or independent second-person end-to-end
exchange is claimed. PR #399 merged as
`6deaaca258ef276470841b03a0157fc0131c5046` on 7 November 2026. Its full PR
run 42376715868 passed after the media-only recording job was rerun; post-merge
CI run 42381466043 passed every job. The task branch is an ancestor of remote
`main`. No deployment, production enablement or human security approval has
occurred. Next: Box service.

## 16. Box service baseline and dependency-audit gate

Status: **six findings remediated; one residual non-shipping exception approved**

The clean Bothy worktree is `bothy-node-vmls-interop-20261107` at
`81b67c2ef1632862c58c2ce4c3f3ba2fa0337f3e`, on branch
`feat/box-vmls-interop-20261107`. Its existing manifest pins VMLS core
`0edf2501e526bfb35a342c10cc7b5932542dc2b7`. The unchanged 411-package combined
baseline `Cargo.lock` had SHA-256
`4bee0a1658cf38111e7c3230f87ad2742bb929d1c5d7ed6e73aaa0df34e69f44`.
No dependency, implementation or test file had been edited at that baseline.

The owner then authorised compatible remediation. Precise updates moved
quinn-proto to 0.11.18, rustls-webpki to 0.103.16, webpki-root-certs and
webpki-roots to 1.0.10. Only `Cargo.lock` changed; its 411-package SHA-256 is now
`395473ce3f2c886cd5247dd32e4cc45a75cca472f9b8415b25bb61d9603bd130`.
Cargo also normalised tempfile 3.27.0's existing dependency edge from getrandom
0.4.3 to the already locked 0.3.4; no tempfile version changed. The full audit
now clears the six QUIC/TLS findings and retains only `RUSTSEC-2026-0387`.
A direct crypto-bigint 0.7.6 update fails without changing the lock because
elliptic-curve 0.13.8 requires `crypto-bigint ^0.5`; 0.7.6 is also yanked. The
current k256/p256 0.13 consumers therefore have no drop-in compatible fix. Their
latest released line is 0.14.0, a broader migration not silently undertaken.
The complete unignored output is `reviews/box-81b67c2-remediated-audit.txt`.
The residual advisory describes secret-dependent timing variability in arithmetic
and possible cryptographic-secret leakage, with practical exploitability depending
on the downstream algorithm, compiler, target CPU and observer. That is not a
Box-specific reachability finding. Against this remediated lock, all 21
`bothy-link` VMLS tests and all nine explicit `bothyd --test vmls_two_daemons`
cases pass. The previously failing witness-down case passed in this full parallel
run. This is scoped VMLS evidence, not full workspace CI.

The unmodified baseline passes all 21 `bothy-link` VMLS tests. The initial
`cargo test -p bothyd vmls_two_daemons` name filter ran zero cases and is not
counted as coverage. The explicit `--test vmls_two_daemons` target ran all nine:
eight passed and `p2r07_with_the_witness_down_the_daemon_disable_holds` failed
with `Db(VmlsPending)` at `crates/bothyd/tests/vmls_two_daemons.rs:882`. That
case passed when rerun alone (one passed, eight filtered), so the full parallel
suite is not green and the failure is concurrency-sensitive or intermittent;
its root cause has not been established or changed. This is a scoped baseline,
not full workspace CI.

The pre-existing combined lock fails cargo audit with seven vulnerabilities:
`RUSTSEC-2026-0387` (`crypto-bigint` 0.5.5), `RUSTSEC-2026-0343`,
`RUSTSEC-2026-0338` and `RUSTSEC-2026-0340` (`quinn-proto` 0.11.17),
`RUSTSEC-2026-0382` (`rustls-webpki` 0.103.15), `RUSTSEC-2026-0383`
(`webpki-root-certs` 1.0.9) and `RUSTSEC-2026-0381` (`webpki-roots` 1.0.9).
`libcrux-kem` is absent. Dependency tracing confirms crypto-bigint through the
existing k256/elliptic-curve graph, quinn-proto through the pinned Link endpoint,
rustls-webpki through the combined TLS graph, and webpki-roots through
hyper-rustls; webpki-root-certs is target-specific and did not print in the
default-host inverse tree. Those four patch updates have now been tested as
recorded above; no drop-in compatible crypto-bigint remediation exists in the
current 0.13 elliptic-curve consumer line.

The owner-approved Vennel exception in §13 does **not** cover this lock. On
7 November 2026 the owner accepted the residual-exception recommendation and
approved a Box-only non-shipping exception for exactly `RUSTSEC-2026-0387` at
lock SHA-256 `395473ce3f2c886cd5247dd32e4cc45a75cca472f9b8415b25bb61d9603bd130`.
The unignored audit still fails with that one vulnerability. The audit ignoring
only that ID succeeds, with all five warnings still visible; raw output is
`reviews/box-81b67c2-approved-ignore-audit.txt`. No other advisory or warning is
ignored or approved by this exception.

The exception permits local/hosted testing, implementation, independent review
and PR evaluation only. It grants no deployment, shipping, production-use or
production-MLS approval. Any changed lock, dependency, feature, target or flag,
or newly demonstrated reachable affected operation, requires a new disposition.
Closure requires migrating every affected consumer to a fixed crypto-bigint line
and passing the full unignored audit; production acceptance remains a separate
owner/security gate. Upstream Box `main` advanced during this work and must be
integrated and retested before a PR.

The implementation candidate updates the VMLS pin to canonical 0.1.2 revision
`d9a8d24673ad3da7117b1510a2e786767c2bc250`, with no Box Rust-source changes.
Canonical API inspection found no affected Box call sites. Its 427-package lock
has SHA-256 `27d4a79f78236df11e3dca15896704f47661bbc2447593bec4fbcc3e58f35249`.
VMLS now brings k256 0.14.0 and crypto-bigint 0.7.10; the vulnerable 0.5.5 path
is retained only by Link/Bothy's older k256/p256 0.13 line. The candidate's full
unignored audit still reports only `RUSTSEC-2026-0387`, with the same five
warnings; raw output is `reviews/box-d9a8d24-candidate-audit.txt`. Against that
exact candidate, 97 core VMLS tests, 21 link VMLS tests and all nine explicit
two-daemon cases pass, including the previously intermittent witness-down case.
Formatting and diff checks pass. The dependency remediation is rebased onto Box
`main` `7510db5`; this is scoped evidence, not full workspace CI. The changed
lock is outside the exact exception above and requires a fresh owner disposition
before independent review or a PR.
