# Consolidated first AI review: VMLS/1 vector generator 5a0522b

Status: **initial AI reviews complete; implementation issues corrected and re-review pending**

- Review target: `5a0522baf8cabfb1583159ab13f20c9da5c56987`.
- Claude report: [vmls1-5a0522b-claude.md](vmls1-5a0522b-claude.md).
- Codex report: [vmls1-5a0522b-codex.md](vmls1-5a0522b-codex.md).
- Review prompt: [vmls1-5a0522b-generator-review.md](vmls1-5a0522b-generator-review.md).

These are independent AI reviews, not human security audits or production approval. Claude recommended **approve with findings**. Codex recommended **do not approve** until the generation and byte-evidence defects were repaired.

## Initial findings

1. **Byte rendering/checking was ineffective.** The renderer fell back to the original text, making exact-byte success unconditional and preventing deliberate writes.
2. **Direct execution could silently skip every suite under a symlink.**
3. **Bare `--write` was parsed as a repository path, including by imported loaders.**
4. **Device expectations influenced computation.** Person identity was self-referential, expected fields were retained, and retained signatures were not independently verified.
5. **Security receipts were only re-signed.** Installation and other body fields were retained instead of rebuilt from scenario inputs and fresh envelope hashes.

## Corrections

- Added independent renderers for every fixture layout: pretty JSON, compact envelope/security cases, appended compact binding/manifest cases, raw signed-64-bit integer tokens, and single-line hostile arrays. Default `--check` now compares actual rendered bytes, while `--write` permits deliberate versioned changes.
- The reader resolves the entry path with `realpathSync`; CI asserts both PASS lines and executes through a symlink.
- Both root resolvers ignore flags before selecting the positional root and use `fileURLToPath`. Bare `--write` now succeeds without changing compatible bytes.
- Device scenarios derive scope from case definitions and targets from event/room keys. Expected identity is regenerated, expected-output poisoning has no effect, changed public keys fail signature verification, and the tombstone target is regenerated. Random-auxiliary BIP-340 signatures are verified rather than regenerated and documented as such.
- Security receipts and evidence are rebuilt with regenerated node and scenario installation, slot, attempt, and freshly computed envelope hashes before signing. Changing installation changes the receipt and fails the negative control.
- Negative controls now cover trailing-byte output/rendering, expected-identity poisoning, retained-key signature rejection, and installation rebuilding.

All 11 files pass semantic and independently rendered byte comparison, every negative control passes, and bare `--write` is a byte-identical no-op on compatible fixtures. Full project verification and independent re-review are still required before closing the regeneration gate.
