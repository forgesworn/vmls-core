# Claude review: Vennel c154087

Scope: read-only independent AI review of `c154087ecfc43ee9404fa4d548cdc94c0789afef` and parent `9ceaf3317ed2fd28f0abb4073dfd4e4e6258c6ab`. Not human, security, production or dependency-exception approval.

## Initial findings

Claude did not approve `9ceaf33` and requested:

- the 12-package consumer delta and retained `crypto-bigint` 0.5.5 status;
- fresh cargo-audit and SBOM evidence;
- clarification of standalone/Vennel provenance;
- locked CI commands.

Codex separately identified copied design attempt fields/outcomes and omitted caller-prevalidation warnings. The follow-up addressed all of these.

## Final verdict

The earlier code and review-evidence findings are resolved. No production approval is given. The consumer dependency gate remains open and blocks PR/merge.

Claude confirmed the package counts and both crypto-bigint lines, the regenerated SBOM, provenance clarification, locked CI commands, input-driven receipts, independently recomputed precedence outcomes and caller-prevalidation warnings. It found only the intended Vennel additions: invitation/admin modules, invitation record variants and crate-visible `schnorr_verify` for those extensions.

Residual evidence limitations noted by Claude: the November audit initially had prose but no archived raw output; the SBOM retains its historical September filename; Vennel CI is manual-only; and its graph script does not run cargo audit. Remediation must also account for direct `k256` 0.13.4 dependencies in `vmls-mls` and `vmls-ffi`, not only OpenMLS's transitive line. These do not change the explicit dependency block.

Raw output is now retained as `vennel-c154087-vmls-core-audit.txt`, `vennel-c154087-vmls-mls-audit.txt`, `vennel-c154087-vmls-ffi-audit.txt` and `vennel-c154087-vmls-wasm-audit.txt`. All 11 shared input hashes are in `vennel-c154087-vector-hashes.txt`.
