// Unit tests for receiver/src/lib/crypto.ts — the envelope validator and
// the AES-256-GCM decryptor shared by /api/sync and /api/logs.
//
// Run: node --test tests/receiver/crypto.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, randomBytes, createHash } from "node:crypto";

process.env.KEYLOGGER_PSK = "deadbeef".repeat(8); // test PSK, 64 hex chars

const { isValidEnvelope, decryptEnvelope } = await import(
  "../../receiver/src/lib/crypto.ts"
);

// Same construction the keylogger uses (crypto.c) and the wire format the
// receiver expects: AES-256-GCM, 12-byte nonce, 16-byte tag, AAD = device id.
function seal(plaintext, devid, psk = process.env.KEYLOGGER_PSK) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(psk, "hex"), nonce);
  cipher.setAAD(Buffer.from(devid, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    v: 1,
    d: devid,
    ts: Math.floor(Date.now() / 1000),
    n: nonce.toString("base64"),
    c: ct.toString("base64"),
    t: cipher.getAuthTag().toString("base64"),
  };
}

const DEVID = createHash("sha256")
  .update("testmachine\\matt")
  .digest("hex")
  .slice(0, 16);

test("isValidEnvelope accepts a well-formed envelope", () => {
  assert.equal(isValidEnvelope(seal("hello", DEVID)), true);
});

test("isValidEnvelope rejects malformed envelopes", () => {
  const good = seal("hello", DEVID);
  assert.equal(isValidEnvelope({}), false);
  assert.equal(isValidEnvelope({ ...good, d: 5 }), false); // wrong type
  assert.equal(isValidEnvelope({ ...good, ts: "123" }), false);
  assert.equal(isValidEnvelope({ ...good, n: undefined }), false);
  assert.equal(isValidEnvelope({ ...good, c: undefined }), false);
  assert.equal(isValidEnvelope({ ...good, t: undefined }), false);
  // 11-byte nonce / 15-byte tag are rejected by length check
  assert.equal(
    isValidEnvelope({ ...good, n: Buffer.alloc(11).toString("base64") }),
    false
  );
  assert.equal(
    isValidEnvelope({ ...good, t: Buffer.alloc(15).toString("base64") }),
    false
  );
});

test("decryptEnvelope roundtrips a sealed batch", () => {
  const env = seal("héllo wörld 日本語\nsecond line", DEVID);
  assert.equal(decryptEnvelope(env), "héllo wörld 日本語\nsecond line");
});

test("decryptEnvelope rejects a tampered ciphertext", () => {
  const env = seal("attack at dawn", DEVID);
  const ct = Buffer.from(env.c, "base64");
  ct[0] ^= 0x01;
  env.c = ct.toString("base64");
  assert.throws(() => decryptEnvelope(env));
});

test("decryptEnvelope rejects a tampered tag", () => {
  const env = seal("attack at dawn", DEVID);
  const tag = Buffer.from(env.t, "base64");
  tag[15] ^= 0x01;
  env.t = tag.toString("base64");
  assert.throws(() => decryptEnvelope(env));
});

test("decryptEnvelope rejects the wrong AAD (device id)", () => {
  // Sealed for DEVID, presented as a different device.
  const env = seal("hello", DEVID);
  const other = seal("hello", "0123456789abcdef");
  const mixed = { ...other, n: env.n, c: env.c, t: env.t };
  assert.throws(() => decryptEnvelope(mixed));
});

test("decryptEnvelope rejects the wrong PSK", () => {
  const env = seal("hello", DEVID, "cafebabe".repeat(8));
  assert.throws(() => decryptEnvelope(env));
});

test("decryptEnvelope rejects an empty plaintext batch edge case", () => {
  // zero-length ciphertext is valid GCM; must decrypt to empty string
  const env = seal("", DEVID);
  assert.equal(decryptEnvelope(env), "");
});
