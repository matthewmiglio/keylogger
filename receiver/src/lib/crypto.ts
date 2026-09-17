import { createDecipheriv } from "node:crypto";

// Encrypted batch envelope as uploaded by the keylogger. This exact shape is
// what gets stored in the blob store — batches are kept encrypted at rest and
// only decrypted on demand when viewed.
export type Envelope = {
  v?: number;
  d?: string; // device id (16 hex chars)
  ts?: number; // unix seconds
  n?: string; // base64 12-byte nonce
  c?: string; // base64 ciphertext
  t?: string; // base64 16-byte tag
};

export function isValidEnvelope(env: Envelope): boolean {
  const { d, ts, n, c, t } = env;
  if (typeof d !== "string" || typeof ts !== "number")
    return false;
  if (typeof n !== "string" || typeof c !== "string" || typeof t !== "string")
    return false;
  return (
    Buffer.from(n, "base64").length === 12 &&
    Buffer.from(t, "base64").length === 16
  );
}

// Decrypts + authenticates an envelope. Throws on GCM auth failure or a
// malformed/missing PSK — callers map that to their error response.
export function decryptEnvelope(env: Envelope): string {
  const key = Buffer.from(process.env.KEYLOGGER_PSK!, "hex");
  if (key.length !== 32)
    throw new Error("bad psk");

  const nonce = Buffer.from(env.n!, "base64");
  const tag = Buffer.from(env.t!, "base64");
  const ciphertext = Buffer.from(env.c!, "base64");

  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(Buffer.from(env.d!, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}
