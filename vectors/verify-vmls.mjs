#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const defaultRoot = fileURLToPath(new URL("..", import.meta.url));
const rootArgument = process.argv.slice(2).find((argument) => !argument.startsWith("--"));
const root = path.resolve(rootArgument ?? defaultRoot);
const MAX_SAFE = (1n << 53n) - 1n;
const BUCKETS = [1024, 4096, 16384, 65536, 1048576];
const ERROR_NUMBERS = {
  Malformed: 1,
  NonCanonical: 2,
  UnsupportedVersion: 3,
  WrongMailbox: 4,
  Empty: 5,
  EmptyCiphertext: 5,
  TooLarge: 6,
  BadRecordLength: 10,
  OuterSealFailed: 11,
  BadPadding: 12,
  UnsupportedRecordType: 13,
  UnexpectedRecordType: 14,
  BadLeafIdentity: 20,
  BadDeviceKey: 21,
  BindingSignatureInvalid: 22,
  BindingExpired: 23,
  BindingOutlivesCredential: 24,
  CredentialMalformed: 25,
  CredentialSignatureInvalid: 26,
  CredentialNotPersonScoped: 27,
  CredentialWrongIdentity: 28,
  CredentialWrongDevice: 29,
  CredentialExpired: 30,
  CredentialLifetimeTooLong: 31,
  CredentialRevoked: 32,
  CredentialNotYetValid: 33,
  BindingLeafMismatch: 34,
  CapabilityExpired: 40,
  CapabilityLifetimeTooLong: 41,
  CapabilityOutlivesBinding: 42,
  AeadUnavailable: 50,
  ReceiptWrongNode: 60,
  ReceiptSignatureInvalid: 61,
  WitnessChallengeMismatch: 62,
  EvidenceNotEquivocation: 63,
};
let assertions = 0;
let suites = 0;

class VmlsError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new VmlsError(code);
}

function hex(value) {
  assert.match(value, /^(?:[0-9a-f]{2})*$/);
  return Buffer.from(value, "hex");
}

function concat(...parts) {
  return Buffer.concat(parts.map((part) => Buffer.isBuffer(part) ? part : Buffer.from(part)));
}

function sha256(...parts) {
  return createHash("sha256").update(concat(...parts)).digest();
}

function hmac(key, ...parts) {
  return createHmac("sha256", key).update(concat(...parts)).digest();
}

function hkdfExtract(salt, ikm) {
  return hmac(salt, ikm);
}

function hkdfExpand(prk, info, length = 32) {
  assert(length <= 32);
  return hmac(prk, info, Buffer.from([1])).subarray(0, length);
}

function u32be(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function u64be(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function equal(actual, expected, label) {
  assertions += 1;
  if (Buffer.isBuffer(actual) || Buffer.isBuffer(expected)) {
    assert(Buffer.isBuffer(actual) && Buffer.isBuffer(expected) && actual.equals(expected), label);
  } else {
    assert.deepStrictEqual(actual, expected, label);
  }
}

function ok(value, label) {
  assertions += 1;
  assert(value, label);
}

function json(relative) {
  return JSON.parse(readFileSync(path.join(root, relative), "utf8"));
}

function jsonExactInts(relative) {
  const source = readFileSync(path.join(root, relative), "utf8");
  const quoted = source.replace(/("v"\s*:\s*)(-?(?:0|[1-9]\d*))(?=\s*[,}\]])/g, '$1"$2"');
  return JSON.parse(quoted);
}

function outcome(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    if (error instanceof VmlsError) return { ok: false, error: error.code, stack: error.stack };
    throw error;
  }
}

function checkOutcome(label, actual, expected) {
  if (actual.ok !== expected.ok || actual.error !== expected.error) console.error(actual.stack);
  equal(actual.ok, expected.ok, `${label}: outcome ${actual.error ?? "success"}, expected ${expected.error ?? "success"}`);
  if (!expected.ok) equal(actual.error, expected.error, `${label}: error`);
}

function suite(name, fn) {
  fn();
  suites += 1;
  console.log(`ok ${name}`);
}

class Reader {
  constructor(input) {
    this.input = input;
    this.at = 0;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || this.at + length > this.input.length) {
      fail("Malformed");
    }
    const out = this.input.subarray(this.at, this.at + length);
    this.at += length;
    return out;
  }

  byte() {
    return this.take(1)[0];
  }

  expect(expected) {
    if (this.byte() !== expected) fail("NonCanonical");
  }

  head(major) {
    const initial = this.byte();
    if (initial >> 5 !== major) fail("NonCanonical");
    const info = initial & 31;
    if (info <= 23) return BigInt(info);
    let value;
    let floor;
    if (info === 24) {
      value = BigInt(this.byte());
      floor = 24n;
    } else if (info === 25) {
      value = BigInt(this.take(2).readUInt16BE());
      floor = 0x100n;
    } else if (info === 26) {
      value = BigInt(this.take(4).readUInt32BE());
      floor = 0x10000n;
    } else if (info === 27) {
      value = this.take(8).readBigUInt64BE();
      floor = 0x100000000n;
    } else {
      fail("NonCanonical");
    }
    if (value < floor) fail("NonCanonical");
    return value;
  }

  bounded(major, max) {
    const length = this.head(major);
    if (length > BigInt(max)) fail("TooLarge");
    return Number(length);
  }

  map(entries) {
    if (this.head(5) !== BigInt(entries)) fail("NonCanonical");
  }

  key(expected) {
    if (this.head(0) !== BigInt(expected)) fail("NonCanonical");
  }

  uint() {
    return this.head(0);
  }

  timestamp() {
    const value = this.uint();
    if (value > MAX_SAFE) fail("Malformed");
    return value;
  }

  bytes(max) {
    return this.take(this.bounded(2, max));
  }

  fixed(length) {
    if (this.head(2) !== BigInt(length)) fail("Malformed");
    return this.take(length);
  }

  text(max) {
    const bytes = this.take(this.bounded(3, max));
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      fail("Malformed");
    }
    for (const byte of bytes) {
      if (byte < 0x20 && ![0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(byte)) fail("Malformed");
    }
    return text;
  }

  array(max) {
    return this.bounded(4, max);
  }

  finish() {
    if (this.at !== this.input.length) fail("NonCanonical");
  }
}

function writeHead(major, input) {
  const value = BigInt(input);
  const prefix = major << 5;
  if (value <= 23n) return Buffer.from([prefix | Number(value)]);
  if (value <= 0xffn) return Buffer.from([prefix | 24, Number(value)]);
  if (value <= 0xffffn) {
    const out = Buffer.alloc(3);
    out[0] = prefix | 25;
    out.writeUInt16BE(Number(value), 1);
    return out;
  }
  if (value <= 0xffffffffn) {
    const out = Buffer.alloc(5);
    out[0] = prefix | 26;
    out.writeUInt32BE(Number(value), 1);
    return out;
  }
  return concat(Buffer.from([prefix | 27]), u64be(value));
}

const cborUint = (value) => writeHead(0, value);
const cborBytes = (value) => concat(writeHead(2, value.length), value);
const cborText = (value) => cborBytesLike(3, Buffer.from(value, "utf8"));
const cborArray = (length) => writeHead(4, length);
const cborMap = (length) => writeHead(5, length);
function cborBytesLike(major, value) {
  return concat(writeHead(major, value.length), value);
}

// Public-fixture arithmetic only: BigInt operations are not constant-time.
const P = (1n << 256n) - (1n << 32n) - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const INF = { x: 0n, y: 0n, z: 0n };
const mod = (value, modulus = P) => ((value % modulus) + modulus) % modulus;

function pow(base, exponent, modulus = P) {
  let result = 1n;
  let value = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = result * value % modulus;
    value = value * value % modulus;
    e >>= 1n;
  }
  return result;
}

function liftX(bytes) {
  const x = BigInt(`0x${bytes.toString("hex")}`);
  if (x >= P) return null;
  const y = pow(mod(x * x * x + 7n), (P + 1n) >> 2n);
  if (mod(y * y) !== mod(x * x * x + 7n)) return null;
  return { x, y: y & 1n ? P - y : y, z: 1n };
}

function jdouble(point) {
  if (point.z === 0n || point.y === 0n) return INF;
  const a = mod(point.x * point.x);
  const b = mod(point.y * point.y);
  const c = mod(b * b);
  const d = mod(2n * (mod((point.x + b) * (point.x + b)) - a - c));
  const e = mod(3n * a);
  const f = mod(e * e);
  const x = mod(f - 2n * d);
  const y = mod(e * (d - x) - 8n * c);
  const z = mod(2n * point.y * point.z);
  return { x, y, z };
}

function jadd(a, b) {
  if (a.z === 0n) return b;
  if (b.z === 0n) return a;
  const z1z1 = mod(a.z * a.z);
  const z2z2 = mod(b.z * b.z);
  const u1 = mod(a.x * z2z2);
  const u2 = mod(b.x * z1z1);
  const s1 = mod(a.y * b.z * z2z2);
  const s2 = mod(b.y * a.z * z1z1);
  if (u1 === u2) return s1 === s2 ? jdouble(a) : INF;
  const h = mod(u2 - u1);
  const i = mod(4n * h * h);
  const j = mod(h * i);
  const r = mod(2n * (s2 - s1));
  const v = mod(u1 * i);
  const x = mod(r * r - j - 2n * v);
  const y = mod(r * (v - x) - 2n * s1 * j);
  const z = mod((mod((a.z + b.z) * (a.z + b.z)) - z1z1 - z2z2) * h);
  return { x, y, z };
}

function scalarPoint(scalar, point) {
  let result = INF;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = jadd(result, addend);
    addend = jdouble(addend);
    k >>= 1n;
  }
  return result;
}

function affine(point) {
  if (point.z === 0n) return null;
  const inverse = pow(point.z, P - 2n);
  const inverse2 = mod(inverse * inverse);
  return { x: mod(point.x * inverse2), y: mod(point.y * inverse2 * inverse), z: 1n };
}

function big32(value) {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

function taggedHash(tag, ...parts) {
  const tagHash = sha256(Buffer.from(tag));
  return sha256(tagHash, tagHash, ...parts);
}

function schnorrVerify(publicKey, message, signature) {
  if (publicKey.length !== 32 || message.length !== 32 || signature.length !== 64) return false;
  const point = liftX(publicKey);
  if (!point) return false;
  const r = BigInt(`0x${signature.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (r >= P || s >= N || s === 0n) return false;
  const e = BigInt(`0x${taggedHash("BIP0340/challenge", signature.subarray(0, 32), publicKey, message).toString("hex")}`) % N;
  const negativePoint = { x: point.x, y: mod(-point.y), z: 1n };
  const result = affine(jadd(scalarPoint(s, { ...G, z: 1n }), scalarPoint(e, negativePoint)));
  return result !== null && (result.y & 1n) === 0n && result.x === r;
}

function ecdhX(privateKey, publicKey) {
  const scalar = BigInt(`0x${privateKey.toString("hex")}`);
  const point = liftX(publicKey);
  assert(scalar > 0n && scalar < N && point);
  return big32(affine(scalarPoint(scalar, point)).x);
}

function edPublicKey(bytes) {
  return { key: concat(Buffer.from("302a300506032b6570032100", "hex"), bytes), format: "der", type: "spki" };
}

function edPrivateKey(seed) {
  return { key: concat(Buffer.from("302e020100300506032b657004220420", "hex"), seed), format: "der", type: "pkcs8" };
}

function edPublicFromSeed(seed) {
  return createPublicKey(edPrivateKey(seed)).export({ format: "der", type: "spki" }).subarray(-32);
}

function singleTag(tags, name) {
  const found = tags.filter((tag) => tag[0] === name);
  if (found.length > 1) fail("CredentialMalformed");
  return found.length ? found[0][1] ?? "" : null;
}

function decimalTimestamp(text) {
  if (!/^(?:0|[1-9][0-9]{0,15})$/.test(text)) fail("CredentialMalformed");
  const value = BigInt(text);
  if (value > MAX_SAFE) fail("CredentialMalformed");
  return value;
}

function credentialId(credential) {
  return sha256(Buffer.from(JSON.stringify([
    0,
    credential.pubkey.toString("hex"),
    Number(credential.createdAt),
    20460,
    credential.tags,
    credential.content,
  ])));
}

function verifyPersonCredential(credential, now, policy) {
  const id = credentialId(credential);
  if (!schnorrVerify(credential.pubkey, id, credential.sig)) fail("CredentialSignatureInvalid");
  const d = singleTag(credential.tags, "d");
  const scope = singleTag(credential.tags, "scope");
  if (d !== credential.pubkey.toString("hex") || scope !== "person") fail("CredentialNotPersonScoped");
  if (policy.expectedIdentity && !credential.pubkey.equals(policy.expectedIdentity)) {
    fail("CredentialWrongIdentity");
  }
  const deviceText = singleTag(credential.tags, "device");
  if (deviceText === null || !/^[0-9a-f]{64}$/.test(deviceText)) fail("CredentialMalformed");
  const expirationText = singleTag(credential.tags, "expiration");
  if (expirationText === null) fail("CredentialMalformed");
  const expiresAt = decimalTimestamp(expirationText);
  if (expiresAt <= now) fail("CredentialExpired");
  if (credential.createdAt > now + 600n) fail("CredentialNotYetValid");
  const lifetime = 30n * 86400n;
  if (expiresAt > credential.createdAt + lifetime || expiresAt > now + lifetime) {
    fail("CredentialLifetimeTooLong");
  }
  if (policy.revokedCredentials.some((revoked) => revoked.equals(id))) fail("CredentialRevoked");
  return { id, device: hex(deviceText), expiresAt };
}

function parseBinding(input) {
  if (input.length > 8192) fail("TooLarge");
  const r = new Reader(input);
  const bodyStart = r.at;
  r.map(8);
  r.key(1);
  if (r.uint() !== 1n) fail("UnsupportedVersion");
  r.key(2);
  const credentialIdentity = r.fixed(37);
  if (!credentialIdentity.subarray(0, 5).equals(Buffer.from("vmls1"))) fail("BadLeafIdentity");
  r.key(3);
  const signatureKey = r.fixed(32);
  r.key(4);
  r.map(5);
  r.key(1);
  const pubkey = r.fixed(32);
  r.key(2);
  const createdAt = r.timestamp();
  r.key(3);
  const tags = [];
  for (let i = r.array(16); i > 0; i -= 1) {
    const values = [];
    const length = r.array(8);
    if (length === 0) fail("Malformed");
    for (let j = 0; j < length; j += 1) values.push(r.text(512));
    tags.push(values);
  }
  r.key(4);
  const content = r.text(1024);
  r.key(5);
  const sig = r.fixed(64);
  const credential = { pubkey, createdAt, tags, content, sig };
  r.key(5);
  const device = r.fixed(32);
  r.key(6);
  const expiresAt = r.timestamp();
  r.key(7);
  const homeBox = r.fixed(32);
  const body = concat(Buffer.from([0xa7]), input.subarray(bodyStart + 1, r.at));
  r.key(8);
  const signature = r.fixed(64);
  r.finish();
  return {
    credentialIdentity,
    leafId: credentialIdentity.subarray(5),
    signatureKey,
    credential,
    device,
    expiresAt,
    homeBox,
    signature,
    body,
  };
}

function verifyBindingParsed(binding, now, leaf, policy) {
  if (!binding.credentialIdentity.equals(leaf.identity) || !binding.signatureKey.equals(leaf.signatureKey)) {
    fail("BindingLeafMismatch");
  }
  if (!liftX(binding.device)) fail("BadDeviceKey");
  const digest = sha256(Buffer.from("VMLS/1 leaf-binding"), binding.body);
  if (!schnorrVerify(binding.device, digest, binding.signature)) fail("BindingSignatureInvalid");
  const credential = verifyPersonCredential(binding.credential, now, policy);
  if (!credential.device.equals(binding.device)) fail("CredentialWrongDevice");
  if (binding.expiresAt <= now) fail("BindingExpired");
  if (binding.expiresAt > credential.expiresAt) fail("BindingOutlivesCredential");
  return {
    identity: binding.credential.pubkey,
    device: binding.device,
    leafId: binding.leafId,
    credentialId: credential.id,
    credentialExpiresAt: credential.expiresAt,
    expiresAt: binding.expiresAt,
    homeBox: binding.homeBox,
    signatureKey: binding.signatureKey,
  };
}

function verifyBinding(input, now, leaf, policy) {
  return verifyBindingParsed(parseBinding(input), now, leaf, policy);
}

function parseCapability(input) {
  if (input.length > 32768) fail("TooLarge");
  const r = new Reader(input);
  r.map(8);
  r.key(1);
  if (r.uint() !== 1n) fail("UnsupportedVersion");
  r.key(2);
  const packageId = r.fixed(32);
  r.key(3);
  const keyPackage = r.bytes(16384);
  if (keyPackage.length === 0) fail("Empty");
  r.key(4);
  const binding = parseBinding(r.bytes(8192));
  r.key(5);
  const welcomeMailbox = r.fixed(32);
  r.key(6);
  const welcomeTransport = r.fixed(32);
  r.key(7);
  const welcomeSecret = r.fixed(32);
  r.key(8);
  const expiresAt = r.timestamp();
  r.finish();
  return { packageId, keyPackage, binding, welcomeMailbox, welcomeTransport, welcomeSecret, expiresAt };
}

function verifyCapability(input, now, leaf, policy) {
  const capability = parseCapability(input);
  if (capability.expiresAt <= now) fail("CapabilityExpired");
  if (capability.expiresAt > now + 7n * 86400n) fail("CapabilityLifetimeTooLong");
  const binding = verifyBindingParsed(capability.binding, now, leaf, policy);
  if (capability.expiresAt > binding.expiresAt) fail("CapabilityOutlivesBinding");
  return { ...capability, binding };
}

function recordKeyNonce(recordSecret, recordId) {
  const prk = hkdfExtract(recordId, recordSecret);
  const okm = hkdfExpand(prk, Buffer.from("VMLS/1 record aead"), 28);
  return { key: okm.subarray(0, 16), nonce: okm.subarray(16) };
}

function bucketFor(contentLength) {
  return BUCKETS.find((bucket) => contentLength <= bucket - 48) ?? null;
}

function encodePlaintext(recordType, payload) {
  if (payload.length === 0) fail("Empty");
  if (payload.length > 1048519) fail("TooLarge");
  const plaintext = concat(cborMap(2), cborUint(1), cborUint(recordType), cborUint(2), cborBytes(payload));
  const bucket = bucketFor(plaintext.length);
  if (!bucket) fail("TooLarge");
  return concat(plaintext, Buffer.alloc(bucket - 48 - plaintext.length));
}

function decodePlaintext(padded) {
  if (!BUCKETS.some((bucket) => padded.length === bucket - 48)) fail("BadRecordLength");
  const r = new Reader(padded);
  r.map(2);
  r.key(1);
  const recordType = r.uint();
  r.key(2);
  const payload = r.bytes(1048519);
  const contentLength = r.at;
  if (![1n, 2n, 3n, 4n, 5n].includes(recordType)) fail("UnsupportedRecordType");
  if (payload.length === 0) fail("Empty");
  if (bucketFor(contentLength) !== padded.length + 48 || padded.subarray(contentLength).some((byte) => byte !== 0)) {
    fail("BadPadding");
  }
  return { recordType: Number(recordType), payload };
}

const KIND_TYPES = { leaf: 1, welcome: 2, introduction: 3, "commit-slot": 4, "fork-evidence": 5 };

function openRecord(recordSecret, mailbox, sealed, kind) {
  if (!BUCKETS.includes(sealed.length)) fail("BadRecordLength");
  const recordId = sealed.subarray(0, 32);
  const { key, nonce } = recordKeyNonce(recordSecret, recordId);
  const aad = concat(Buffer.from("VMLS/1 record"), mailbox, recordId);
  let padded;
  try {
    const decipher = createDecipheriv("aes-128-gcm", key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    padded = concat(decipher.update(sealed.subarray(32, sealed.length - 16)), decipher.final());
  } catch {
    fail("OuterSealFailed");
  }
  const record = decodePlaintext(padded);
  if (record.recordType !== KIND_TYPES[kind]) fail("UnexpectedRecordType");
  return { recordId, ...record };
}

function sealRecord(recordSecret, mailbox, recordId, recordType, payload) {
  const padded = encodePlaintext(recordType, payload);
  const { key, nonce } = recordKeyNonce(recordSecret, recordId);
  const aad = concat(Buffer.from("VMLS/1 record"), mailbox, recordId);
  const cipher = createCipheriv("aes-128-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return concat(recordId, cipher.update(padded), cipher.final(), cipher.getAuthTag());
}

function parseWitnessRequest(input, op) {
  if (input.length > 256) fail("TooLarge");
  const r = new Reader(input);
  r.map(op === "read" ? 3 : 6);
  r.key(1);
  if (r.uint() !== 1n) fail("UnsupportedVersion");
  r.key(2);
  const subject = r.fixed(32);
  let expectedSeq;
  let expectedDigest;
  let nextDigest;
  if (op === "advance") {
    r.key(3);
    expectedSeq = r.uint();
    if (expectedSeq >= MAX_SAFE) fail("Malformed");
    r.key(4);
    expectedDigest = r.fixed(32);
    r.key(5);
    nextDigest = r.fixed(32);
  }
  r.key(op === "read" ? 3 : 6);
  const challenge = r.fixed(32);
  r.finish();
  return { subject, expectedSeq, expectedDigest, nextDigest, challenge };
}

function encodeWitnessRequest(op, fields) {
  const parts = [cborMap(op === "read" ? 3 : 6), cborUint(1), cborUint(1), cborUint(2), cborBytes(fields.subject)];
  if (op === "advance") {
    parts.push(cborUint(3), cborUint(fields.expectedSeq), cborUint(4), cborBytes(fields.expectedDigest), cborUint(5), cborBytes(fields.nextDigest));
  }
  parts.push(cborUint(op === "read" ? 3 : 6), cborBytes(fields.challenge));
  return concat(...parts);
}

function decodeSlotReceipt(input) {
  if (input.length !== 197) fail("Malformed");
  if (input[0] !== 1) fail("UnsupportedVersion");
  const receipt = {
    node: input.subarray(1, 33),
    installation: input.subarray(33, 65),
    slot: input.subarray(65, 97),
    attempt: input.readUInt32BE(97),
    envelopeHash: input.subarray(101, 133),
    signature: input.subarray(133),
  };
  const digest = sha256(Buffer.from("VMLS/1 slot receipt"), receipt.installation, receipt.slot, u32be(receipt.attempt), receipt.envelopeHash);
  return { ...receipt, digest };
}

function parseSlotReceipt(input, pinnedNode) {
  const receipt = decodeSlotReceipt(input);
  if (!receipt.node.equals(pinnedNode)) fail("ReceiptWrongNode");
  if (!edVerify(null, receipt.digest, edPublicKey(receipt.node), receipt.signature)) fail("ReceiptSignatureInvalid");
  return receipt;
}

function verifyWitnessReceipt(input, pinnedNode, challenge) {
  if (input.length !== 170) fail("Malformed");
  if (input[0] !== 1) fail("UnsupportedVersion");
  if (input[1] > 2) fail("Malformed");
  if (input.readBigUInt64BE(34) > MAX_SAFE) fail("Malformed");
  if (!input.subarray(74, 106).equals(challenge)) fail("WitnessChallengeMismatch");
  const digest = sha256(Buffer.from("VMLS/1 witness receipt"), input.subarray(0, 106));
  if (!edVerify(null, digest, edPublicKey(pinnedNode), input.subarray(106))) fail("ReceiptSignatureInvalid");
  return { status: input[1], subject: input.subarray(2, 34), seq: input.readBigUInt64BE(34), stateDigest: input.subarray(42, 74), challenge };
}

function verifyEvidence(input, pinnedNode) {
  if (input.length < 10) fail("Malformed");
  if (input[0] !== 1) fail("UnsupportedVersion");
  const count = input[9];
  if (![1, 2].includes(count) || input.length !== 10 + count * 197) fail("Malformed");
  const receipts = [];
  for (let i = 0; i < count; i += 1) receipts.push(decodeSlotReceipt(input.subarray(10 + i * 197, 10 + (i + 1) * 197)));
  if (count === 2) {
    const [a, b] = receipts;
    const pairA = concat(u32be(a.attempt), a.envelopeHash);
    const pairB = concat(u32be(b.attempt), b.envelopeHash);
    if (!a.node.equals(b.node) || !a.installation.equals(b.installation) || !a.slot.equals(b.slot) || pairA.compare(pairB) >= 0) {
      fail("EvidenceNotEquivocation");
    }
  }
  for (let i = 0; i < count; i += 1) parseSlotReceipt(input.subarray(10 + i * 197, 10 + (i + 1) * 197), pinnedNode);
  return { preEpoch: input.readBigUInt64BE(1), receipts };
}

function encodeTyped(value) {
  if (value.t === "null") return Buffer.from([0xf6]);
  if (value.t === "int") {
    const integer = BigInt(value.v);
    return integer >= 0n ? cborUint(integer) : writeHead(1, -1n - integer);
  }
  if (value.t === "bytes") return cborBytes(hex(value.hex));
  if (value.t === "text") return cborText(value.v);
  if (value.t === "array") return concat(cborArray(value.items.length), ...value.items.map(encodeTyped));
  throw new Error(`unknown typed value ${value.t}`);
}

function manifestFor(test) {
  const entries = test.entries.map((entry) => {
    const key = concat(cborArray(1 + entry.key.length), cborText(entry.namespace), ...entry.key.map(encodeTyped));
    return { key, valueHash: sha256(encodeTyped(entry.value)) };
  });
  entries.sort((a, b) => a.key.compare(b.key));
  for (let i = 1; i < entries.length; i += 1) assert(!entries[i - 1].key.equals(entries[i].key));
  const rows = entries.map((entry) => concat(cborArray(2), cborBytes(entry.key), cborBytes(entry.valueHash)));
  return concat(cborArray(5), cborUint(1), cborBytes(hex(test.subjectHex)), cborBytes(hex(test.installationHex)), cborBytes(hex(test.schemaManifestHashHex)), cborArray(rows.length), ...rows);
}

function verifyAllocation(f, name, method) {
  const vector = f[name];
  const fields = {
    subject: hex(f.subjectHex),
    challenge: hex(f.challengeHex),
    expectedSeq: BigInt(f.expectedSeq),
    expectedDigest: hex(f.expectedDigestHex),
    nextDigest: hex(f.nextDigestHex),
  };
  const body = encodeWitnessRequest(name, fields);
  equal(body, hex(vector.requestHex), `allocation ${name}: request`);
  equal(body.length, vector.requestBytes, `allocation ${name}: request length`);
  const unsigned = concat(Buffer.from([1, method]), hex(f.writerHex), hex(f.courierTokenHex), (() => {
    const out = Buffer.alloc(2);
    out.writeUInt16BE(body.length);
    return out;
  })(), body);
  equal(unsigned, hex(vector.unsignedHex), `allocation ${name}: unsigned framing`);
  const digest = sha256(Buffer.from("VMLS/1 allocation witness request\0"), hex(f.witnessHex), unsigned);
  equal(digest, hex(vector.signatureMessageHex), `allocation ${name}: digest`);
  const signature = edSign(null, digest, edPrivateKey(hex(f.writerSeedHex)));
  equal(signature, hex(vector.signatureHex), `allocation ${name}: signature`);
  const envelope = concat(unsigned, signature);
  equal(envelope, hex(vector.envelopeHex), `allocation ${name}: envelope`);
  equal(envelope.length, vector.envelopeBytes, `allocation ${name}: envelope length`);
  ok(edVerify(null, digest, edPublicKey(hex(f.writerHex)), envelope.subarray(envelope.length - 64)), `allocation ${name}: verification`);
  equal(parseWitnessRequest(body, name).subject, fields.subject, `allocation ${name}: decoded request`);
}

function envelopeCiphertext(reader) {
  const first = reader.byte();
  let length;
  if (first >= 0x40 && first <= 0x57) length = first & 31;
  else if (first === 0x58) length = reader.byte();
  else if (first === 0x59) length = reader.take(2).readUInt16BE();
  else if (first === 0x5a) length = reader.take(4).readUInt32BE();
  else fail("NonCanonical");
  if ((length <= 23 && first !== (0x40 | length))
    || (length > 23 && length <= 0xff && first !== 0x58)
    || (length > 0xff && length <= 0xffff && first !== 0x59)
    || (length > 0xffff && first !== 0x5a)) fail("NonCanonical");
  if (length === 0) fail("EmptyCiphertext");
  if (length > 1048576) fail("TooLarge");
  return reader.take(length);
}

class Lcg {
  constructor(seed) {
    this.state = seed >>> 0;
  }

  byte() {
    this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0;
    return this.state >>> 24;
  }

  bytes(length) {
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i += 1) out[i] = this.byte();
    return out;
  }
}

function hostileInputs(file) {
  const base = hex(file.baseHex);
  const head = hex(file.randomHeadHex);
  const out = [];
  for (let length = 0; length < base.length; length += 1) out.push(base.subarray(0, length));
  for (let bit = 0; bit < base.length * 8; bit += 1) {
    const changed = Buffer.from(base);
    changed[Math.floor(bit / 8)] ^= 1 << (bit % 8);
    out.push(changed);
  }
  const lcg = new Lcg(file.seed);
  for (let i = 0; i < file.splices; i += 1) {
    const cut = Math.floor(lcg.byte() * base.length / 256);
    const resume = Math.floor(lcg.byte() * base.length / 256);
    out.push(concat(base.subarray(0, cut), base.subarray(resume)));
  }
  for (let i = 0; i < file.randoms; i += 1) {
    let input;
    if (file.randomLength === "base") {
      input = Buffer.alloc(base.length);
      const random = lcg.bytes(1 + i % 24);
      random.copy(input);
    } else {
      const length = ((lcg.byte() << 8) | lcg.byte()) % file.randomLength;
      input = lcg.bytes(length);
    }
    if (i % 2 === 0 && input.length >= head.length) head.copy(input);
    out.push(input);
  }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
suite("envelope", () => {
  const file = json("vmls-core/vectors/vmls-envelope-v1.json");
  for (const test of file.cases) {
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
      if (!mailbox.equals(hex(test.activeMailboxHex ?? file.mailboxHex))) fail("WrongMailbox");
      r.expect(3);
      const ciphertext = envelopeCiphertext(r);
      r.finish();
      return { ciphertext };
    });
    checkOutcome(`envelope ${test.name}`, actual, test.expect);
    if (test.expect.ok) equal(actual.value.ciphertext, hex(test.expect.ciphertextHex), `envelope ${test.name}: ciphertext`);
  }
});

suite("leaf bindings", () => {
  const file = json("vmls-core/vectors/vmls-binding-v1.json");
  const now = BigInt(file.now);
  const revokedCredentials = file.revokedCredentialIds.map(hex);
  for (const test of file.cases) {
    const leaf = {
      identity: hex(test.leafIdentityHex ?? file.leaf.identityHex),
      signatureKey: hex(test.leafSignatureKeyHex ?? file.leaf.signatureKeyHex),
    };
    const policy = {
      expectedIdentity: test.expectedIdentityHex ? hex(test.expectedIdentityHex) : null,
      revokedCredentials: test.revoked ? revokedCredentials : [],
    };
    const actual = outcome(() => verifyBinding(hex(test.bindingHex), now, leaf, policy));
    checkOutcome(`binding ${test.name}`, actual, test.expect);
    if (test.expect.ok) {
      for (const [field, expected] of [
        ["identity", test.expect.identityHex],
        ["device", test.expect.deviceHex],
        ["leafId", test.expect.leafIdHex],
        ["credentialId", test.expect.credentialIdHex],
        ["homeBox", test.expect.homeBoxHex],
      ]) equal(actual.value[field], hex(expected), `binding ${test.name}: ${field}`);
      equal(actual.value.expiresAt, BigInt(test.expect.expiresAt), `binding ${test.name}: expiry`);
    }
  }
});

suite("capabilities", () => {
  const file = json("vmls-core/vectors/vmls-capability-v1.json");
  const now = BigInt(file.now);
  const revokedCredentials = file.revokedCredentialIds.map(hex);
  for (const test of file.cases) {
    const leaf = {
      identity: hex(test.leafIdentityHex ?? file.leaf.identityHex),
      signatureKey: hex(test.leafSignatureKeyHex ?? file.leaf.signatureKeyHex),
    };
    const policy = {
      expectedIdentity: test.expectedIdentityHex ? hex(test.expectedIdentityHex) : null,
      revokedCredentials: test.revoked ? revokedCredentials : [],
    };
    const actual = outcome(() => verifyCapability(hex(test.capabilityHex), now, leaf, policy));
    checkOutcome(`capability ${test.name}`, actual, test.expect);
    if (test.expect.ok) {
      for (const [field, expected] of [
        ["packageId", test.expect.packageIdHex],
        ["keyPackage", test.expect.keyPackageHex],
        ["welcomeMailbox", test.expect.welcomeMailboxHex],
        ["welcomeTransport", test.expect.welcomeTransportHex],
        ["welcomeSecret", test.expect.welcomeSecretHex],
      ]) equal(actual.value[field], hex(expected), `capability ${test.name}: ${field}`);
      equal(actual.value.expiresAt, BigInt(test.expect.expiresAt), `capability ${test.name}: expiry`);
      equal(actual.value.binding.identity, hex(test.expect.identityHex), `capability ${test.name}: identity`);
      equal(actual.value.binding.leafId, hex(test.expect.leafIdHex), `capability ${test.name}: leaf`);
      equal(actual.value.binding.expiresAt, BigInt(test.expect.bindingExpiresAt), `capability ${test.name}: binding expiry`);
    }
  }
});

suite("derivations and sealed records", () => {
  const file = json("vmls-core/vectors/vmls-record-v1.json");
  equal(file.exporter.label, "VMLS/1 epoch", "exporter label");
  equal(hex(file.exporter.contextHex), Buffer.alloc(0), "exporter context");
  equal(file.exporter.length, 32, "exporter length");
  equal(file.buckets, BUCKETS, "record buckets");
  const d = file.derivations;
  const epoch = hex(d.epochSecretHex);
  for (const leaf of d.leaves) {
    const leafId = hex(leaf.leafIdHex);
    const mailbox = hkdfExpand(epoch, concat(Buffer.from("VMLS/1 mailbox"), leafId));
    equal(mailbox, hex(leaf.mailboxHex), "leaf mailbox");
    equal(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 record"), leafId, mailbox)), hex(leaf.recordSecretHex), "leaf record secret");
  }
  for (const slot of d.commitSlots) {
    const derived = hkdfExpand(epoch, concat(Buffer.from("VMLS/1 commit-slot"), u32be(slot.attempt)));
    equal(derived, hex(slot.slotHex), "commit slot");
    equal(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 slot record"), derived)), hex(slot.recordSecretHex), "slot record secret");
  }
  equal(sha256(Buffer.from("VMLS/1 commit"), hex(d.commitHash.messageHex)), hex(d.commitHash.hashHex), "commit hash");
  for (const record of d.recordKeys) {
    const { key, nonce } = recordKeyNonce(hex(record.recordSecretHex), hex(record.recordIdHex));
    equal(key, hex(record.keyHex), "record key");
    equal(nonce, hex(record.nonceHex), "record nonce");
  }
  const intro = d.introduction;
  const fromJoiner = ecdhX(hex(intro.testOnlyJoinerRzPrivHex), hex(intro.adderRzHex));
  const fromAdder = ecdhX(hex(intro.testOnlyAdderRzPrivHex), hex(intro.joinerRzHex));
  equal(fromJoiner, fromAdder, "ECDH agreement");
  equal(fromJoiner, hex(intro.ecdhXHex), "ECDH known answer");
  for (const test of intro.cases) {
    const prk = hkdfExtract(Buffer.from("VMLS/1 introduction"), fromJoiner);
    const suffix = concat(hex(test.recipientRzHex), u64be(test.counter));
    equal(hkdfExpand(prk, concat(Buffer.from("VMLS/1 introduction mailbox"), suffix)), hex(test.mailboxHex), "introduction mailbox");
    equal(hkdfExpand(prk, concat(Buffer.from("VMLS/1 introduction record"), suffix)), hex(test.recordSecretHex), "introduction record secret");
  }
  for (const test of file.records) {
    const secret = hex(test.recordSecretHex);
    const mailbox = hex(test.mailboxHex);
    const sealed = hex(test.sealedHex);
    const actual = outcome(() => openRecord(secret, mailbox, sealed, test.kind));
    checkOutcome(`record ${test.name}`, actual, test.expect);
    if (test.expect.ok) {
      equal(actual.value.recordId, hex(test.expect.recordIdHex), `record ${test.name}: id`);
      equal(actual.value.recordType, test.expect.type, `record ${test.name}: type`);
      equal(actual.value.payload, hex(test.expect.payloadHex), `record ${test.name}: payload`);
      equal(sealRecord(secret, mailbox, actual.value.recordId, actual.value.recordType, actual.value.payload), sealed, `record ${test.name}: deterministic seal`);
      if (actual.value.recordType === 3) parseCapability(actual.value.payload);
    }
  }
});

suite("send lanes", () => {
  const file = json("vmls-core/vectors/vmls-lane-v1.json");
  equal(file.cases.length, 48, "lane combination count");
  for (const test of file.cases) {
    const i = test.input;
    let decision;
    if (i.conversation === "public") {
      decision = ["send-nip17", "public", "public", false];
    } else if (i.choice === "start-public") {
      decision = ["start-public-conversation", "public", "public", false];
    } else if (i.conversation === "sheltered" && i.groupState === "needs-recovery") {
      decision = ["hold", "not-sent", "needs-recovery", true];
    } else if (i.conversation === "new" && !i.peerCapability) {
      decision = ["offer-public", "not-sent", "start-separate-public", true];
    } else if (!i.shelteredRoute) {
      decision = ["hold", "not-sent", "sheltered-unavailable", true];
    } else if (i.conversation === "new") {
      decision = ["create-sheltered-conversation", "sheltered", "sheltered", false];
    } else {
      decision = ["send-sheltered", "sheltered", "sheltered", false];
    }
    equal(decision, [test.expect.action, test.expect.indicator, test.expect.wording, test.expect.offerPublic], `lane ${JSON.stringify(i)}`);
  }
});

suite("device credentials", () => {
  const file = json("vectors/device-credential.json");
  const nostrId = (event) => sha256(Buffer.from(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content])));
  equal(nostrId(file.tombstone), hex(file.tombstone.id), "tombstone id");
  ok(schnorrVerify(hex(file.tombstone.pubkey), nostrId(file.tombstone), hex(file.tombstone.sig)), "tombstone signature");
  for (const test of file.cases) {
    const event = test.event;
    const id = nostrId(event);
    equal(id, hex(event.id), `credential ${test.name}: id`);
    ok(schnorrVerify(hex(event.pubkey), id, hex(event.sig)), `credential ${test.name}: signature`);
    const tags = (name) => event.tags.filter((tag) => tag[0] === name);
    const single = (name) => tags(name).length === 1 ? tags(name)[0][1] : null;
    const person = Object.hasOwn(test.expect, "identity");
    const target = person ? test.expect.identity : test.expect.roomId;
    const expiry = Number(single("expiration"));
    const accepted = single("d") === target
      && single("device") === file.testOnlyKeys.device
      && (person ? single("scope") === "person" : single("scope") === null)
      && event.created_at <= file.now + 600
      && expiry > file.now
      && expiry <= event.created_at + 30 * 86400
      && expiry <= file.now + 30 * 86400
      && !test.tombstoned;
    equal(accepted, test.ok, `credential ${test.name}: acceptance`);
    if (test.tombstoned) equal(file.tombstone.tags[0][1], event.id, "tombstone targets credential");
  }
});

suite("security design", () => {
  const d = json("vmls-core/vectors/vmls-security-design-v1.json");
  const node = hex(d.nodeHex);
  for (const [receiptName, envelopeName] of [["slotReceiptHex", "envelopeHex"], ["otherSlotReceiptHex", "otherEnvelopeHex"]]) {
    const receipt = parseSlotReceipt(hex(d[receiptName]), node);
    equal(receipt.envelopeHash, sha256(hex(d[envelopeName])), `${receiptName}: envelope hash`);
    equal(receipt.installation, hex(d.installationHex), `${receiptName}: installation`);
  }
  const first = parseSlotReceipt(hex(d.slotReceiptHex), node);
  equal(first.digest, hex(d.slotDigestHex), "slot digest");
  const relabelled = parseSlotReceipt(hex(d.relabelledSlotReceiptHex), node);
  equal(relabelled.envelopeHash, first.envelopeHash, "relabelled envelope hash");
  equal(relabelled.attempt, first.attempt + 1, "relabelled attempt");
  const foreign = parseSlotReceipt(hex(d.foreignSlotReceiptHex), node);
  equal(foreign.installation, hex(d.foreignInstallationHex), "foreign installation");
  for (const name of ["evidenceHex", "relabelledEvidenceHex", "attemptOrderEvidenceHex"]) {
    const evidence = verifyEvidence(hex(d[name]), node);
    equal(evidence.preEpoch, 7n, `${name}: epoch`);
    equal(evidence.receipts.length, 2, `${name}: pair`);
  }
  for (const test of d.precedence.cases) {
    const actual = outcome(() => verifyEvidence(hex(test.evidenceHex), node));
    checkOutcome(`evidence ${test.name}`, actual, test.expect);
  }
  const witness = verifyWitnessReceipt(hex(d.witnessHex), node, Buffer.alloc(32, 0x77));
  equal(witness.status, 0, "witness status");
  equal(witness.seq, 9n, "witness sequence");
  const epoch = hex(d.epochSecretHex);
  const leaf = hex(d.leafHex);
  const forkMailbox = hkdfExpand(epoch, concat(Buffer.from("VMLS/1 fork mailbox"), leaf));
  equal(forkMailbox, hex(d.forkMailboxHex), "fork mailbox");
  equal(hkdfExpand(epoch, concat(Buffer.from("VMLS/1 fork record"), leaf, forkMailbox)), hex(d.forkRecordSecretHex), "fork record secret");
});

suite("witness requests", () => {
  const file = json("vmls-core/vectors/vmls-witness-request-v1.json");
  for (const test of file.cases) {
    const actual = outcome(() => parseWitnessRequest(hex(test.bodyHex), test.op));
    checkOutcome(`witness ${test.name}`, actual, test.expect);
    if (test.expect.ok) {
      equal(actual.value.subject, hex(test.expect.subjectHex), `witness ${test.name}: subject`);
      equal(actual.value.challenge, hex(test.expect.challengeHex), `witness ${test.name}: challenge`);
      if (test.op === "advance") {
        equal(actual.value.expectedSeq, BigInt(test.expect.expectedSeq), `witness ${test.name}: sequence`);
        equal(actual.value.expectedDigest, hex(test.expect.expectedDigestHex), `witness ${test.name}: expected digest`);
        equal(actual.value.nextDigest, hex(test.expect.nextDigestHex), `witness ${test.name}: next digest`);
      }
      equal(encodeWitnessRequest(test.op, actual.value), hex(test.bodyHex), `witness ${test.name}: canonical encoding`);
    }
  }
});

suite("state manifests", () => {
  const file = jsonExactInts("vmls-core/vectors/vmls-manifest-v1.json");
  for (const test of file.cases) {
    const manifest = manifestFor(test);
    equal(manifest, hex(test.manifestHex), `manifest ${test.name}`);
    equal(sha256(Buffer.from("VMLS/1 state manifest"), manifest), hex(test.digestHex), `manifest ${test.name}: digest`);
    const reversed = manifestFor({ ...test, entries: [...test.entries].reverse() });
    equal(reversed, manifest, `manifest ${test.name}: insertion-order independence`);
  }
});

suite("allocation witness forwarding", () => {
  const file = json("vmls-core/vectors/signer-allocation-witness-v1.json");
  equal(edPublicFromSeed(hex(file.writerSeedHex)), hex(file.writerHex), "writer public key");
  equal(edPublicFromSeed(hex(file.witnessSeedHex)), hex(file.witnessHex), "witness public key");
  verifyAllocation(file, "read", 1);
  verifyAllocation(file, "advance", 2);
});

suite("hostile corpus", () => {
  const file = json("vmls-core/vectors/vmls-hostile-v1.json");
  const leaf = { identity: hex(file.leaf.identityHex), signatureKey: hex(file.leaf.signatureKeyHex) };
  const policy = { expectedIdentity: null, revokedCredentials: [] };
  for (const hostile of file.suites) {
    const inputs = hostileInputs(hostile);
    equal(inputs.length, hostile.codes.length, `${hostile.structure}: generated count`);
    inputs.forEach((input, index) => {
      const actual = outcome(() => {
        if (hostile.structure === "binding") return verifyBinding(input, BigInt(file.now), leaf, policy);
        if (hostile.structure === "capability") return verifyCapability(input, BigInt(file.now), leaf, policy);
        if (hostile.structure === "plaintext") return decodePlaintext(input);
        throw new Error(`unknown hostile structure ${hostile.structure}`);
      });
      if ((actual.ok ? 0 : ERROR_NUMBERS[actual.error]) !== hostile.codes[index]) console.error(actual.stack);
      equal(actual.ok ? 0 : ERROR_NUMBERS[actual.error], hostile.codes[index], `${hostile.structure} hostile input ${index}: ${actual.error ?? "success"}`);
    });
  }
});

console.log(`PASS ${suites} suites, ${assertions} independent assertions`);
}

export {
  ERROR_NUMBERS,
  Reader,
  concat,
  credentialId,
  decodePlaintext,
  decodeSlotReceipt,
  ecdhX,
  fail,
  edPrivateKey,
  edPublicFromSeed,
  edSign,
  encodeTyped,
  encodeWitnessRequest,
  envelopeCiphertext,
  hex,
  hkdfExpand,
  hkdfExtract,
  hostileInputs,
  json,
  jsonExactInts,
  manifestFor,
  openRecord,
  outcome,
  parseCapability,
  parseSlotReceipt,
  parseWitnessRequest,
  recordKeyNonce,
  sealRecord,
  schnorrVerify,
  sha256,
  verifyBinding,
  verifyCapability,
  verifyEvidence,
  verifyPersonCredential,
};
