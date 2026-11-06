# Independent AI review: VMLS/1 vector generator 5a0522b

- **Reviewer/model and review date:** Codex, GPT-6-based; 6 November 2026.
- **Exact commit/tree verification:** HEAD is `5a0522baf8cabfb1583159ab13f20c9da5c56987`; tree is `7dc213e847b30b4ea7244692fbfa48cf23fa79a7`. Reviewed tracked files match that commit. An untracked review file was excluded and unread.
- **Scope and checks performed:** Read-only Git inspection and static review of the generator, reader, fixtures, workflow, README, contract and AUDIT-INTEROP §11. No builds, tests, network access, modifications or consultation of another reviewer’s output. Supplied verification results were not treated as my execution evidence.

## Findings

1. **High — Exact-byte assertion cannot fail.**  
   **Evidence:** [vectors/generate-vmls.mjs:408](vectors/generate-vmls.mjs:408), particularly lines 409–410.  
   Whenever generated serialisation differs, `rendered` becomes `originalText`; the following assertion therefore compares the original text with itself. Formatting differences and serialisation defects pass. This also conceals the manifest loader’s conversion of integer tokens into strings. `--write` preserves existing text, but does not demonstrate independent byte reproduction.  
   **Minimal resolution:** Produce output using an explicit, lossless renderer that reproduces the existing fixture layouts and integer tokens; compare that independently rendered output directly against the original bytes.

2. **Medium — Device expected fields are copied and influence computation.**  
   **Evidence:** [vectors/generate-vmls.mjs:220](vectors/generate-vmls.mjs:220), lines 221–237.  
   The function clones `test.expect`, uses the presence of `expect.identity` to select person versus room validation, and never regenerates that expected object. For person cases, `target` comes from the event’s own `d` tag, making the identity comparison self-referential. Changing an expected identity value alone would escape generator detection. Event and tombstone signatures are also retained without verification by this function.  
   **Minimal resolution:** Define presentation scope and target independently of expected outputs, regenerate expectations, and independently verify retained signatures. The fixture explicitly uses random auxiliary signing data (`vectors/device-credential.json:3`); disclose that limitation rather than claim deterministic reproduction of those signatures.

3. **Medium — Security-design generation retains derived receipt bodies.**  
   **Evidence:** [vectors/generate-vmls.mjs:242](vectors/generate-vmls.mjs:242), lines 242–277.  
   Receipt, evidence and witness generation copies existing wire bodies and replaces signatures. Slot envelope hashes and installation fields are not rebuilt from the corresponding source fields. For example, changing only `installationHex` would leave regeneration successful while receipts still contain the old installation. The reader checks some such relationships, but that does not establish complete generation.  
   **Minimal resolution:** Construct valid receipt/evidence bodies from explicit scenario inputs, including freshly computed envelope hashes, then sign them. Apply explicit mutations to construct hostile cases.

4. **Low — Bare `--write` is interpreted as the repository directory.**  
   **Evidence:** [vectors/generate-vmls.mjs:36](vectors/generate-vmls.mjs:36) and `vectors/verify-vmls.mjs:18`.  
   `node vectors/generate-vmls.mjs --write` resolves its root to a directory named `--write`, causing fixture reads to fail. An explicit root before the flag is currently necessary.  
   **Minimal resolution:** Parse options separately from positional arguments and give both generator and imported loaders the same resolved root.

The completeness and exact-byte claims in `README.md:49`, `AUDIT-INTEROP.md:142`, and `AUDIT-INTEROP.md:544–560` overstate the implementation. The completed regeneration gate at `AUDIT-INTEROP.md:315` should be revisited alongside these fixes.

## Regeneration and negative-control assessment

**All 11 families are dispatched, but complete independent regeneration is not established.**

| Families | Static assessment |
|---|---|
| Envelope, binding, capability | Expected fields and errors are recomputed from encoded inputs; binding signatures are independently verified. |
| Derivations/records | HKDF, ECDH, keys/nonces and decoded expectations are recomputed; successful records are independently re-sealed. |
| Lanes | Decisions are recomputed from inputs. |
| Device credentials | Partial; expectations are retained and used to select behaviour. |
| Security design | Partial; signatures and derivations are recomputed, but receipt bodies retain derived output bytes. |
| Witness requests | Outcomes and successful encodings are recomputed. |
| Manifests | Manifest bytes and digests are recomputed with lossless integer handling. |
| Allocation forwarding | Keys, framing, digests, signatures and envelopes are recomputed. |
| Hostile corpus | Inputs and every outcome code are recomputed. |

The deep semantic comparison is meaningful for overwritten results, but cannot validate copied expectations. The exact-byte comparison is ineffective.

The negative control at `vectors/generate-vmls.mjs:393–399` is genuine: appending a byte changes the canonical envelope’s regenerated expectation to `NonCanonical`. It covers one decoder path; it does not establish independence across every family or validate serialisation.

No Rust invocation or expected-output shortcut was found in the deterministic Ed25519 signing calculations themselves. Unexpected exceptions propagate through `outcome`; no new general exception swallowing was found.

Static inspection confirms all 11 reader suites are inside the direct-execution guard and importing the reader executes none. CI explicitly invokes both scripts at `.github/workflows/vmls-core.yml:44–51`.

## Contract/vector compatibility recommendation

**do not approve**

The generator does not yet meet the stated complete-regeneration and exact-byte evidence requirements. These findings do not establish that the existing contract or fixture bytes are incorrect.

## Remaining limitations and next action

Fix the findings, correct the documentation, and add controls that poison expected fields and exercise byte rendering across all families. Re-run against the revised commit.

No unsupported Node.js 20 API was identified statically, but Node 20 execution was not independently verified, and CI does not explicitly select that version. Hosted 32-bit execution remains unrun. Strict-signature, downstream interoperability, physical-device and other external assurance limits remain open.

This is an **independent AI review**, not a human security audit or production approval.