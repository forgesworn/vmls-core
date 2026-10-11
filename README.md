# vmls-core

Canonical VMLS/1 wire codecs: the outer envelope a box stores, the
bucket-padded inner record, the `leaf-binding/1` extension with its BIP-340
and device-credential checks, the one-time KeyPackage capability record, the
exporter-based derivations and the send-lane decision table.

Default builds support hosted callers. Disable default features to compile
with `no_std + alloc`; an allocator is still required. This preserves the same
canonical layouts and strict Ed25519 verifier. A target build alone does not
prove constrained-device image size, stack use or runtime acceptance.

It deliberately does not implement MLS. It owns every byte layout VMLS/1 puts
around MLS so that browsers, phones and boxes parse with one codec, and a box
can store and route records without linking MLS at all.

Every layout has known-answer vectors in `vmls-core/vectors/` and a bounded
hostile-input suite. The device credential rules follow NIP-DEVICE-CREDENTIAL
in [forgesworn/nip-drafts](https://github.com/forgesworn/nip-drafts).

This repository is generated from ForgeSworn's working tree; changes are made
there and copied here. Status: pre-release, not independently audited.

```sh
cd vmls-core && cargo test
cargo test --no-default-features
```
