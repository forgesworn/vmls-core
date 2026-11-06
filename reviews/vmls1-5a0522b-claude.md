# Independent AI review: VMLS/1 vector generator 5a0522b

- **Reviewer/model and review date:** Claude Fable 5.1 (`claude-fable-5-1`), independent AI reviewer, 2026-11-06.
- **Exact commit/tree verification:** `.git/HEAD` points at `refs/heads/feat/independent-vector-generator`, and that ref file contains `5a0522baf8cabfb1583159ab13f20c9da5c56987`. The session's starting git status reported no modified tracked files and one untracked file, `reviews/vmls1-5a0522b-generator-review.md`, which is the review prompt. I had no shell access, so I did not run `git` to compare per-file blob hashes against the commit tree. The files reviewed are the working-tree copies that git reported as unmodified at that commit.
- **Scope and checks performed:** Read-only source review of `vectors/generate-vmls.mjs` (all 416 lines), `vectors/verify-vmls.mjs` (all 1169 lines), `.github/workflows/vmls-core.yml`, README, AUDIT-INTEROP §3, §7 and §11, and the fixture files the generator consumes (envelope, binding header, device credential, security design, manifest, lane, record and witness-request structure, hostile suite parameters). I traced each regeneration function against the corresponding reader suite and the fixture layout. I did not execute anything; the supplied PASS lines are the author's evidence, not mine.

## Findings

### F1. Medium. The exact-byte check is a tautology, so "exact bytes match" is unconditionally true and `--write` can never write anything new

Evidence: `vectors/generate-vmls.mjs:408-411`.

```js
const canonical = JSON.stringify(regenerated, null, 2) + "\n";
const rendered = canonical === originalText ? canonical : originalText;
assert.equal(rendered, originalText, `${relative}: exact bytes differ`);
if (write) writeFileSync(path.join(root, relative), rendered);
```

`rendered` equals `originalText` in both branches of the conditional, so the assertion cannot fail and the write always rewrites the file's existing bytes. The fixtures confirm that the canonical rendering does not in fact match the source for several files: `vmls-core/vectors/vmls-envelope-v1.json:7-22` and `vmls-security-design-v1.json:25-27` use one-case-per-line compact layout, and the manifest file is loaded through `jsonExactInts` (`verify-vmls.mjs:128-131`), which quotes every `"v"` integer, so its stringified form would contain `"v": "0"` where the source at `vmls-manifest-v1.json:29` has `"v": 0`. The author's PASS line would have printed identically had the generator emitted any serialization at all.

Consequence: README.md:49-50, AUDIT-INTEROP.md:133-134, 141-142 and 558-560 claim "exact source-byte compatibility for all 11 files". That claim has no evidence behind it. The deep semantic check at line 407 is real and is what actually gates the run. The `--write` flag satisfies "cannot silently alter compatible fixtures" only because it cannot alter anything, and because the semantic assertion at line 407 aborts before the write on any difference, it also cannot be used to refresh fixtures after a deliberate versioned change.

Minimal resolution: remove lines 408-411 and the "exact bytes" wording from the three documents, stating that the generator enforces deep semantic equality while CI's Appendix A hash step enforces exact bytes. If a byte-level check is wanted, it needs a renderer that reproduces the repository's mixed layout and preserves manifest integers.

### F2. Medium. The reader's direct-execution guard silently runs zero suites and exits 0 under a symlinked checkout

Evidence: `vectors/verify-vmls.mjs:849`.

```js
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
```

Node resolves `process.argv[1]` to an absolute path but not to a real path, while the main module's `import.meta.url` is derived from the real path unless `--preserve-symlinks-main` is set. When the repository sits under a symlinked directory, for example `/tmp` on macOS which resolves to `/private/tmp`, the comparison is false, no suite runs, nothing is printed, and the process exits 0. The CI step at `.github/workflows/vmls-core.yml:44-47` does not check for the `PASS 11 suites` line, so it would pass green in that situation. GitHub's `/home/runner/work` path is not symlinked, so the supplied CI evidence is not invalidated, but an independent reviewer reproducing locally can get a false pass.

Minimal resolution: compare `realpathSync(process.argv[1])` on both sides, or track whether any suite ran and exit non-zero otherwise. In CI, fail the step unless the output contains `PASS 11 suites` and `PASS 11 vector files`.

### F3. Low. `node vectors/generate-vmls.mjs --write` treats `--write` as the root directory

Evidence: `vectors/generate-vmls.mjs:36-37`. The root is `process.argv[2]` whenever present, so the documented flag only works as the third argument after an explicit root. With the flag alone, `readText` fails with ENOENT. The same line uses `new URL("..", import.meta.url).pathname` rather than `fileURLToPath`, which the reader itself was corrected to use at `verify-vmls.mjs:17`. Paths containing spaces or percent-encoded characters, and Windows drive paths, break the generator but not the reader. Resolution: filter flags out of argv before choosing the root, and use `fileURLToPath`.

### F4. Low. Device-credential regeneration uses the event's own `d` tag as the acceptance target for person scope

Evidence: `vectors/generate-vmls.mjs:226-229` versus `vectors/verify-vmls.mjs:1024-1027`. The reader compares the `d` tag against the published `expect.identity`. The generator sets `target` to the `d` tag itself for person cases, so that comparison is vacuous and acceptance rests on the `scope` and lifetime checks alone. For the current eight cases the `ok` values coincide because every mismatch case also fails scope. The generator also does not recompute or validate `expect.identity`, `expect.roomId`, the tombstone target, or any BIP-340 signature in this file, so `expect` here is copied, which slightly overstates AUDIT-INTEROP.md:144-145 ("never ... copies expected fields without recomputation"). Resolution: derive the person target from `event.pubkey` and compare the tombstone's `e` tag to the regenerated id; note in §11 that BIP-340 signatures are verified by the reader and not regenerated because the fixture uses random auxiliary data.

### F5. Low. Security-design receipts are re-signed but their bodies are copied

Evidence: `vectors/generate-vmls.mjs:242-264` and `270-277`. `signSlot`, `signWitness` and `signEvidence` overwrite only the 64-byte signature region. The node bytes at offset 1, the installation, slot, attempt, envelope hash, and the witness receipt's status, subject, seq, state digest and challenge all come from the fixture. The regenerated `nodeHex` at line 269 is never written back into the receipts. The reader independently checks envelope hash, installation, attempt relabelling, epoch 7 and seq 9 at `verify-vmls.mjs:1043-1066`, so the published relationships are covered, but by the reader rather than the generator. Resolution: construct each receipt from `installationHex`, `sha256(envelopeHex)`, the attempt, and the regenerated node before signing.

Residual uncertainty: I could not execute the scripts, so I did not confirm the supplied assertion count, the Node 20 run, or the hash step. I found no Node 20 incompatibility by inspection: `structuredClone`, `Object.hasOwn`, `pathToFileURL`, `TextDecoder` with `fatal`, and the AES-GCM and Ed25519 `node:crypto` calls are all available in Node 20.

## Regeneration and negative-control assessment

Genuinely regenerated from inputs, with no Rust and no expected-field shortcut:

- **Envelope:** every `expect` recomputed from `encodedHex` (lines 44-68).
- **Binding and capability:** every `expect` recomputed via the independent CBOR reader, BigInt Schnorr verify and credential policy (lines 84-129). The signed `bindingHex`/`capabilityHex` inputs are necessarily copied because the stack has no BIP-340 signer.
- **Derivations and records:** mailbox, record secret, commit slot, commit hash, record key and nonce, ECDH and introduction derivations recomputed; successful `sealedHex` re-sealed with deterministic AES-128-GCM from the opened record (lines 131-184).
- **Lanes:** decision table re-evaluated for all 48 inputs (lines 186-202).
- **Witness requests:** success `bodyHex` re-encoded and all `expect` recomputed (lines 289-310).
- **Manifests:** `manifestHex` and `digestHex` fully recomputed with lossless integers (lines 312-320).
- **Allocation forwarding:** both public keys, both request bodies, framing, digests and Ed25519 signatures recomputed from seeds (lines 322-353).
- **Hostile corpus:** all outcome codes recomputed over the LCG-derived inputs (lines 355-373).

Partially regenerated: device credentials (ids and `ok` recomputed, signatures and `expect` copied, F4) and security design (signatures, node, fork derivations and precedence outcomes recomputed, receipt bodies copied, F5).

The deep semantic check at line 407 is meaningful: it compares the fully regenerated object tree against a fresh load of the file with `deepStrictEqual`, and `outcome` rethrows non-protocol errors, so a divergence or crash fails the run. The exact-byte check is not meaningful (F1). The negative control at lines 393-400 is genuine but narrow: it appends a byte to the valid `canonical-short` envelope case, confirms the regenerated outcome differs from the original and equals `NonCanonical`. It exercises one family and the regeneration function directly, not the per-file comparison path.

## Contract/vector compatibility recommendation

**Approve with findings.** The generator independently recomputes the expected fields and error outcomes for all 11 files, and the semantic comparison plus CI's Appendix A hash step together give reproducible compatibility evidence. Approval is conditioned on F1: the "exact bytes match" claim in README, AUDIT §3 and §11 must be corrected or implemented before the audit text accurately describes the evidence. F2 should be fixed before relying on local reproduction by third parties. This covers only the generator and compatibility evidence, not production readiness.

## Remaining limitations and next action

This is an independent AI review, not a human security audit or production approval. I did not execute the reader, generator, Rust tests or hash step. Hosted 32-bit execution, downstream interoperability, physical-device acceptance, fuzzing, side-channel assessment, formal proof, and named human review remain open as the pack states. BIP-340 binding and credential signatures are verified but not regenerated by this tooling, and that boundary should be stated in §11.

Next action: fix F1 (remove or implement the byte check and correct the three documents), harden the F2 guard and add PASS-line checks to CI, correct the F3 argument handling, then re-run both scripts and update §11's status line.
