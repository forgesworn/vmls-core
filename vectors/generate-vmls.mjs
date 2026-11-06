#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ERROR_NUMBERS,
  Reader,
  concat,
  decodePlaintext,
  decodeSlotReceipt,
  ecdhX,
  edPrivateKey,
  edPublicFromSeed,
  edSign,
  encodeWitnessRequest,
  envelopeCiphertext,
  fail,
  hex,
  hkdfExpand,
  hkdfExtract,
  hostileInputs,
  json,
  jsonExactInts,
  manifestFor,
  openRecord,
  outcome,
  parseWitnessRequest,
  recordKeyNonce,
  sealRecord,
  schnorrVerify,
  sha256,
  verifyBinding,
  verifyCapability,
  verifyEvidence,
} from "./verify-vmls.mjs";

const args = process.argv.slice(2);
const write = args.includes("--write");
const rootArgument = args.find((argument) => !argument.startsWith("--"));
const root = path.resolve(rootArgument ?? fileURLToPath(new URL("..", import.meta.url)));
const clone = (value) => structuredClone(value);
const hexText = (value) => value.toString("hex");
const readText = (relative) => readFileSync(path.join(root, relative), "utf8");
const failure = (actual) => ({ ok: false, error: actual.error });
const success = (fields) => ({ ok: true, ...fields });

function regenerateEnvelope(file) {
  const out = clone(file);
  for (const test of out.cases) {
    const actual = outcome(() => {
      const r = new Reader(hex(test.encodedHex));
      r.expect(0xa3);
      r.expect(1);
      const profile = r.byte();
      if (profile !== 1) {
        if (profile <= 23) fail("UnsupportedVersion");
        fail("NonCanonical");
      }
      r.expect(2);
      if (!r.take(2).equals(Buffer.from([0x58, 32]))) fail("NonCanonical");
      const mailbox = r.take(32);
      if (!mailbox.equals(hex(test.activeMailboxHex ?? out.mailboxHex))) fail("WrongMailbox");
      r.expect(3);
      const ciphertext = envelopeCiphertext(r);
      r.finish();
      return { ciphertext };
    });
    test.expect = actual.ok ? success({ ciphertextHex: hexText(actual.value.ciphertext) }) : failure(actual);
  }
  return out;
}

function policy(file, test) {
  return {
    expectedIdentity: test.expectedIdentityHex ? hex(test.expectedIdentityHex) : null,
    revokedCredentials: test.revoked ? file.revokedCredentialIds.map(hex) : [],
  };
}

function leaf(file, test) {
  return {
    identity: hex(test.leafIdentityHex ?? file.leaf.identityHex),
    signatureKey: hex(test.leafSignatureKeyHex ?? file.leaf.signatureKeyHex),
  };
}

function regenerateBinding(file) {
  const out = clone(file);
  const now = BigInt(out.now);
  for (const test of out.cases) {
    const actual = outcome(() => verifyBinding(hex(test.bindingHex), now, leaf(out, test), policy(out, test)));
    if (!actual.ok) {
      test.expect = failure(actual);
      continue;
    }
    const value = actual.value;
    test.expect = success({
      identityHex: hexText(value.identity),
      deviceHex: hexText(value.device),
      leafIdHex: hexText(value.leafId),
      credentialIdHex: hexText(value.credentialId),
      expiresAt: Number(value.expiresAt),
      homeBoxHex: hexText(value.homeBox),
    });
  }
  return out;
}

function regenerateCapability(file) {
  const out = clone(file);
  const now = BigInt(out.now);
  for (const test of out.cases) {
    const actual = outcome(() => verifyCapability(hex(test.capabilityHex), now, leaf(out, test), policy(out, test)));
    if (!actual.ok) {
      test.expect = failure(actual);
      continue;
    }
    const value = actual.value;
    test.expect = success({
      packageIdHex: hexText(value.packageId),
      keyPackageHex: hexText(value.keyPackage),
      welcomeMailboxHex: hexText(value.welcomeMailbox),
      welcomeTransportHex: hexText(value.welcomeTransport),
      welcomeSecretHex: hexText(value.welcomeSecret),
      expiresAt: Number(value.expiresAt),
      identityHex: hexText(value.binding.identity),
      leafIdHex: hexText(value.binding.leafId),
      bindingExpiresAt: Number(value.binding.expiresAt),
    });
  }
  return out;
}

function regenerateRecord(file) {
  const out = clone(file);
  const d = out.derivations;
  const epoch = hex(d.epochSecretHex);
  for (const leaf of d.leaves) {
    const leafId = hex(leaf.leafIdHex);
    leaf.mailboxHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 mailbox"), leafId)));
    leaf.recordSecretHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 record"), leafId, hex(leaf.mailboxHex))));
  }
  for (const slot of d.commitSlots) {
    slot.slotHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 commit-slot"), (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(slot.attempt);
      return b;
    })())));
    slot.recordSecretHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 slot record"), hex(slot.slotHex))));
  }
  d.commitHash.hashHex = hexText(sha256(Buffer.from("VMLS/1 commit"), hex(d.commitHash.messageHex)));
  for (const record of d.recordKeys) {
    const { key, nonce } = recordKeyNonce(hex(record.recordSecretHex), hex(record.recordIdHex));
    record.keyHex = hexText(key);
    record.nonceHex = hexText(nonce);
  }
  const intro = d.introduction;
  const shared = ecdhX(hex(intro.testOnlyJoinerRzPrivHex), hex(intro.adderRzHex));
  intro.ecdhXHex = hexText(shared);
  for (const test of intro.cases) {
    const prk = hkdfExtract(Buffer.from("VMLS/1 introduction"), shared);
    const suffix = concat(hex(test.recipientRzHex), (() => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64BE(BigInt(test.counter));
      return b;
    })());
    test.mailboxHex = hexText(hkdfExpand(prk, concat(Buffer.from("VMLS/1 introduction mailbox"), suffix)));
    test.recordSecretHex = hexText(hkdfExpand(prk, concat(Buffer.from("VMLS/1 introduction record"), suffix)));
  }
  for (const test of out.records) {
    const secret = hex(test.recordSecretHex);
    const mailbox = hex(test.mailboxHex);
    const actual = outcome(() => openRecord(secret, mailbox, hex(test.sealedHex), test.kind));
    if (!actual.ok) {
      test.expect = failure(actual);
      continue;
    }
    const value = actual.value;
    test.sealedHex = hexText(sealRecord(secret, mailbox, value.recordId, value.recordType, value.payload));
    test.expect = success({
      recordIdHex: hexText(value.recordId),
      type: value.recordType,
      payloadHex: hexText(value.payload),
    });
  }
  return out;
}

function regenerateLane(file) {
  const out = clone(file);
  for (const test of out.cases) {
    const input = test.input;
    let decision;
    if (input.conversation === "public") decision = ["send-nip17", "public", "public", false];
    else if (input.choice === "start-public") decision = ["start-public-conversation", "public", "public", false];
    else if (input.conversation === "sheltered" && input.groupState === "needs-recovery") decision = ["hold", "not-sent", "needs-recovery", true];
    else if (input.conversation === "new" && !input.peerCapability) decision = ["offer-public", "not-sent", "start-separate-public", true];
    else if (!input.shelteredRoute) decision = ["hold", "not-sent", "sheltered-unavailable", true];
    else if (input.conversation === "new") decision = ["create-sheltered-conversation", "sheltered", "sheltered", false];
    else decision = ["send-sheltered", "sheltered", "sheltered", false];
    const [action, indicator, wording, offerPublic] = decision;
    test.expect = { action, indicator, wording, offerPublic };
  }
  return out;
}

function singleTag(tags, name) {
  const matches = tags.filter((tag) => tag[0] === name);
  return matches.length === 1 ? matches[0][1] : null;
}

function nostrIdBytes(event) {
  return sha256(Buffer.from(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ])));
}

function nostrId(event) {
  return hexText(nostrIdBytes(event));
}

function verifierUsesPersonScope(test) {
  return !["room-passes", "person-presented-to-room", "room-with-scope-tag"].includes(test.name);
}

function regenerateDeviceCredentials(file) {
  const out = clone(file);
  const revokedId = out.cases.find((test) => test.name === "person-passes").event.id;
  out.tombstone.tags = out.tombstone.tags.map((tag) => tag[0] === "e" ? ["e", revokedId] : tag);
  out.tombstone.id = nostrId(out.tombstone);
  assert(schnorrVerify(hex(out.tombstone.pubkey), nostrIdBytes(out.tombstone), hex(out.tombstone.sig)), "tombstone signature");
  for (const test of out.cases) {
    const event = test.event;
    const id = nostrIdBytes(event);
    event.id = hexText(id);
    assert(schnorrVerify(hex(event.pubkey), id, hex(event.sig)), `${test.name}: signature`);
    const verifierPerson = verifierUsesPersonScope(test);
    const target = verifierPerson ? event.pubkey : out.roomId;
    const expiry = Number(singleTag(event.tags, "expiration"));
    const accepted = singleTag(event.tags, "d") === target
      && singleTag(event.tags, "device") === out.testOnlyKeys.device
      && (verifierPerson ? singleTag(event.tags, "scope") === "person" : singleTag(event.tags, "scope") === null)
      && event.created_at <= out.now + 600
      && expiry > out.now
      && expiry <= event.created_at + 30 * 86400
      && expiry <= out.now + 30 * 86400
      && !test.tombstoned;
    test.expect = verifierPerson ? { identity: event.pubkey } : { roomId: out.roomId };
    test.ok = accepted;
  }
  return out;
}

function signSlot(raw, seed) {
  const receipt = decodeSlotReceipt(raw);
  const signature = edSign(null, receipt.digest, edPrivateKey(seed));
  const out = Buffer.from(raw);
  signature.copy(out, 133);
  return out;
}

function buildSlot(raw, seed, node, envelope, installation) {
  const old = decodeSlotReceipt(raw);
  const out = Buffer.alloc(197);
  out[0] = 1;
  node.copy(out, 1);
  installation.copy(out, 33);
  old.slot.copy(out, 65);
  out.writeUInt32BE(old.attempt, 97);
  sha256(envelope).copy(out, 101);
  return signSlot(out, seed);
}

function signWitness(raw, seed) {
  const digest = sha256(Buffer.from("VMLS/1 witness receipt"), raw.subarray(0, 106));
  const signature = edSign(null, digest, edPrivateKey(seed));
  const out = Buffer.from(raw);
  signature.copy(out, 106);
  return out;
}

function buildEvidence(raw, seed, node, envelopes, installation) {
  const out = Buffer.from(raw);
  for (let i = 0; i < out[9]; i += 1) {
    buildSlot(out.subarray(10 + i * 197, 10 + (i + 1) * 197), seed, node, envelopes[i], installation).copy(out, 10 + i * 197);
  }
  return out;
}

function regenerateSecurityDesign(file) {
  const out = clone(file);
  const seed = hex(out.seedHex);
  const node = edPublicFromSeed(seed);
  const installation = hex(out.installationHex);
  out.nodeHex = hexText(node);
  out.slotReceiptHex = hexText(buildSlot(hex(out.slotReceiptHex), seed, node, hex(out.envelopeHex), installation));
  out.otherSlotReceiptHex = hexText(buildSlot(hex(out.otherSlotReceiptHex), seed, node, hex(out.otherEnvelopeHex), installation));
  out.relabelledSlotReceiptHex = hexText(buildSlot(hex(out.relabelledSlotReceiptHex), seed, node, hex(out.envelopeHex), installation));
  out.foreignSlotReceiptHex = hexText(buildSlot(hex(out.foreignSlotReceiptHex), seed, node, hex(out.envelopeHex), hex(out.foreignInstallationHex)));
  out.slotDigestHex = hexText(decodeSlotReceipt(hex(out.slotReceiptHex)).digest);
  out.evidenceHex = hexText(buildEvidence(hex(out.evidenceHex), seed, node, [hex(out.otherEnvelopeHex), hex(out.envelopeHex)], installation));
  out.relabelledEvidenceHex = hexText(buildEvidence(hex(out.relabelledEvidenceHex), seed, node, [hex(out.envelopeHex), hex(out.envelopeHex)], installation));
  out.attemptOrderEvidenceHex = hexText(buildEvidence(hex(out.attemptOrderEvidenceHex), seed, node, [hex(out.envelopeHex), hex(out.otherEnvelopeHex)], installation));
  out.witnessHex = hexText(signWitness(hex(out.witnessHex), seed));
  const epoch = hex(out.epochSecretHex);
  const leaf = hex(out.leafHex);
  out.forkMailboxHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 fork mailbox"), leaf)));
  out.forkRecordSecretHex = hexText(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 fork record"), leaf, hex(out.forkMailboxHex))));
  for (const test of out.precedence.cases) {
    const actual = outcome(() => verifyEvidence(hex(test.evidenceHex), hex(out.nodeHex)));
    test.expect = actual.ok ? success({}) : failure(actual);
  }
  return out;
}

function regenerateWitnessRequests(file) {
  const out = clone(file);
  for (const test of out.cases) {
    const actual = outcome(() => parseWitnessRequest(hex(test.bodyHex), test.op));
    if (!actual.ok) {
      test.expect = failure(actual);
      continue;
    }
    const value = actual.value;
    test.bodyHex = hexText(encodeWitnessRequest(test.op, value));
    const expected = { ok: true, subjectHex: hexText(value.subject) };
    if (test.op === "advance") Object.assign(expected, {
      expectedSeq: Number(value.expectedSeq),
      expectedDigestHex: hexText(value.expectedDigest),
      nextDigestHex: hexText(value.nextDigest),
    });
    expected.challengeHex = hexText(value.challenge);
    test.expect = expected;
  }
  return out;
}

function regenerateManifest(file) {
  const out = clone(file);
  for (const test of out.cases) {
    const manifest = manifestFor(test);
    test.manifestHex = hexText(manifest);
    test.digestHex = hexText(sha256(Buffer.from("VMLS/1 state manifest"), manifest));
  }
  return out;
}

function regenerateAllocation(file) {
  const out = clone(file);
  out.writerHex = hexText(edPublicFromSeed(hex(out.writerSeedHex)));
  out.witnessHex = hexText(edPublicFromSeed(hex(out.witnessSeedHex)));
  for (const [name, method] of [["read", 1], ["advance", 2]]) {
    const vector = out[name];
    const fields = {
      subject: hex(out.subjectHex),
      challenge: hex(out.challengeHex),
      expectedSeq: BigInt(out.expectedSeq),
      expectedDigest: hex(out.expectedDigestHex),
      nextDigest: hex(out.nextDigestHex),
    };
    const body = encodeWitnessRequest(name, fields);
    const length = Buffer.alloc(2);
    length.writeUInt16BE(body.length);
    const unsigned = concat(Buffer.from([1, method]), hex(out.writerHex), hex(out.courierTokenHex), length, body);
    const digest = sha256(Buffer.from("VMLS/1 allocation witness request\0"), hex(out.witnessHex), unsigned);
    const signature = edSign(null, digest, edPrivateKey(hex(out.writerSeedHex)));
    const envelope = concat(unsigned, signature);
    Object.assign(vector, {
      requestBytes: body.length,
      requestHex: hexText(body),
      unsignedHex: hexText(unsigned),
      signatureMessageHex: hexText(digest),
      signatureHex: hexText(signature),
      envelopeBytes: envelope.length,
      envelopeHex: hexText(envelope),
    });
  }
  return out;
}

function regenerateHostile(file) {
  const out = clone(file);
  const now = BigInt(out.now);
  const carryingLeaf = { identity: hex(out.leaf.identityHex), signatureKey: hex(out.leaf.signatureKeyHex) };
  const policy = { expectedIdentity: null, revokedCredentials: [] };
  for (const suite of out.suites) {
    const inputs = hostileInputs(suite);
    suite.codes = inputs.map((input) => {
      const actual = outcome(() => {
        if (suite.structure === "binding") return verifyBinding(input, now, carryingLeaf, policy);
        if (suite.structure === "capability") return verifyCapability(input, now, carryingLeaf, policy);
        if (suite.structure === "plaintext") return decodePlaintext(input);
        throw new Error(`unknown hostile structure ${suite.structure}`);
      });
      return actual.ok ? 0 : ERROR_NUMBERS[actual.error];
    });
  }
  return out;
}

function compactValue(value) {
  if (Array.isArray(value)) return `[${value.map(compactValue).join(", ")}]`;
  if (value && typeof value === "object") {
    return `{ ${Object.entries(value).map(([key, item]) => `${JSON.stringify(key)}: ${compactValue(item)}`).join(", ")} }`;
  }
  return JSON.stringify(value);
}

function compactCase(value) {
  return compactValue(value);
}

function renderEnvelope(file) {
  const lines = ["{"];
  const entries = Object.entries(file);
  for (const [index, [key, value]] of entries.entries()) {
    const comma = index === entries.length - 1 ? "" : ",";
    if (key === "cases") {
      lines.push('  "cases": [');
      for (const [caseIndex, test] of value.entries()) {
        lines.push(`    ${compactCase(test)}${caseIndex === value.length - 1 ? "" : ","}`);
      }
      lines.push(`  ]${comma}`);
    } else {
      lines.push(`  ${JSON.stringify(key)}: ${JSON.stringify(value)}${comma}`);
    }
  }
  lines.push("}", "");
  return lines.join("\n");
}

function renderSecurityDesign(file) {
  const lines = ["{"];
  const entries = Object.entries(file);
  for (const [index, [key, value]] of entries.entries()) {
    const comma = index === entries.length - 1 ? "" : ",";
    if (key === "precedence") {
      lines.push('  "precedence": {');
      lines.push('    "cases": [');
      for (const [caseIndex, test] of value.cases.entries()) {
        lines.push(`      ${compactCase(test)}${caseIndex === value.cases.length - 1 ? "" : ","}`);
      }
      lines.push("    ]", `  }${comma}`);
    } else {
      lines.push(`  ${JSON.stringify(key)}: ${JSON.stringify(value)}${comma}`);
    }
  }
  lines.push("}", "");
  return lines.join("\n");
}

function renderPrettyWithCompactTail(file, firstCompactIndex) {
  const head = JSON.stringify({ ...file, cases: file.cases.slice(0, firstCompactIndex) }, null, 2);
  const closing = "  ]\n}";
  const compact = file.cases.slice(firstCompactIndex);
  if (compact.length === 0) return `${head}\n`;
  const prefix = head.slice(0, -closing.length).trimEnd();
  const rendered = compact.map((test, index) => `    ${JSON.stringify(test)}${index === compact.length - 1 ? "" : ","}`);
  return `${prefix},\n${rendered.join("\n")}\n  ]\n}\n`;
}

function renderHostile(file) {
  return (JSON.stringify(file, null, 2) + "\n").replace(/"codes": \[\n([\s\S]*?)\n\s*\]/g, (_, values) => {
    return `"codes": [${values.replace(/\s+/g, "")}]`;
  });
}

function render(relative, regenerated) {
  if (relative.endsWith("vmls-envelope-v1.json")) return renderEnvelope(regenerated);
  if (relative.endsWith("vmls-security-design-v1.json")) return renderSecurityDesign(regenerated);
  if (relative.endsWith("vmls-binding-v1.json")) return renderPrettyWithCompactTail(regenerated, 41);
  if (relative.endsWith("vmls-manifest-v1.json")) {
    return renderPrettyWithCompactTail(regenerated, 7).replace(/("t":\s*"int",\s*"v":\s*)"(-?\d+)"/g, "$1$2");
  }
  if (relative.endsWith("vmls-hostile-v1.json")) return renderHostile(regenerated);
  return JSON.stringify(regenerated, null, 2) + "\n";
}

const generators = {
  "vmls-core/vectors/vmls-envelope-v1.json": regenerateEnvelope,
  "vmls-core/vectors/vmls-binding-v1.json": regenerateBinding,
  "vmls-core/vectors/vmls-capability-v1.json": regenerateCapability,
  "vmls-core/vectors/vmls-record-v1.json": regenerateRecord,
  "vmls-core/vectors/vmls-lane-v1.json": regenerateLane,
  "vectors/device-credential.json": regenerateDeviceCredentials,
  "vmls-core/vectors/vmls-security-design-v1.json": regenerateSecurityDesign,
  "vmls-core/vectors/vmls-witness-request-v1.json": regenerateWitnessRequests,
  "vmls-core/vectors/vmls-manifest-v1.json": regenerateManifest,
  "vmls-core/vectors/signer-allocation-witness-v1.json": regenerateAllocation,
  "vmls-core/vectors/vmls-hostile-v1.json": regenerateHostile,
};

function load(relative) {
  return relative.endsWith("vmls-manifest-v1.json") ? jsonExactInts(relative) : json(relative);
}

function negativeControl() {
  const relative = "vmls-core/vectors/vmls-envelope-v1.json";
  const original = regenerateEnvelope(load(relative));
  const changed = clone(original);
  changed.cases[0].encodedHex = `${changed.cases[0].encodedHex}00`;
  const regenerated = regenerateEnvelope(changed);
  assert.notDeepStrictEqual(regenerated.cases[0].expect, original.cases[0].expect);
  assert.equal(regenerated.cases[0].expect.error, "NonCanonical");
  assert.notEqual(render(relative, regenerated), readText(relative));

  const credentials = load("vectors/device-credential.json");
  const expectedPoison = clone(credentials);
  expectedPoison.cases[0].expect.identity = "ff".repeat(32);
  assert.deepStrictEqual(regenerateDeviceCredentials(expectedPoison), credentials);
  const keyPoison = clone(credentials);
  keyPoison.cases[0].event.pubkey = "00".repeat(32);
  assert.throws(() => regenerateDeviceCredentials(keyPoison), /signature/);

  const design = load("vmls-core/vectors/vmls-security-design-v1.json");
  const installationPoison = clone(design);
  installationPoison.installationHex = "44".repeat(32);
  const rebuilt = regenerateSecurityDesign(installationPoison);
  assert.notEqual(rebuilt.slotReceiptHex, design.slotReceiptHex);
  assert(decodeSlotReceipt(hex(rebuilt.slotReceiptHex)).installation.equals(Buffer.alloc(32, 0x44)));
}

for (const [relative, generate] of Object.entries(generators)) {
  const originalText = readText(relative);
  const original = load(relative);
  const regenerated = generate(original);
  const rendered = render(relative, regenerated);
  if (!write) {
    const current = load(relative);
    assert.deepStrictEqual(regenerated, current, `${relative}: regenerated content differs`);
    assert.equal(rendered, originalText, `${relative}: exact bytes differ`);
  }
  if (write) writeFileSync(path.join(root, relative), rendered);
  console.log(`ok ${relative}`);
}
negativeControl();
console.log("PASS 11 vector files regenerated; content and exact bytes match; negative control passed");
