# Tests

Two suites covering the parts worth testing — the crypto/wire contract and the
receiver API behavior. Nothing here deploys, persists, or captures real
keystrokes; the `WH_KEYBOARD_LL` hook itself is covered by the manual
end-to-end checklist in the top-level `README.md`.

## Run everything

```
python tests/run_all.py
```

(Windows; needs MSYS2 MinGW-w64 `gcc` and Node 24+ on PATH. Missing tool = that
suite is skipped, not failed.)

## `keylogger/` — native C suite

`test_native.c` links the implant's platform-independent core (`buffer.c`,
`util.c`, `crypto.c`; `capture.c` is stubbed — it needs a real hook) and checks:

- **base64** against RFC 4648 vectors + all 256 byte values
- **wide ↔ UTF-8** roundtrips (ASCII, accents, CJK, emoji)
- **event buffer**: push/count/clear, flush gate (60 s oldest-event, 256-event
  threshold), 64 KiB text-cap eviction (oldest dropped, count preserved
  through serialization), serialization format (one header per title switch,
  events contiguous under one title, timestamp stamping)
- **device id**: 16-hex format, stability across calls
- **AES-256-GCM seal**: roundtrip decrypted via BCrypt with the exact envelope
  the receiver expects, plus rejection of tampered ciphertext / wrong AAD /
  wrong key, and nonce uniqueness across seals

## `receiver/` — Node test-runner suite

- **`crypto.test.mjs`** (unit, instant): `isValidEnvelope` field/length
  validation, `decryptEnvelope` roundtrip + rejection of tampered ciphertext,
  tampered tag, wrong AAD (device id), wrong PSK, empty-plaintext edge case.
- **`api.test.mjs`** (integration, ~1 min): boots `next dev` on port 3999
  with test env (no blob token → in-memory fallback store) and exercises the
  real HTTP surface: weather page, `/api/health`, `/api/sync` 400/401/200
  paths, `/api/logs` Bearer-header auth (query-string tokens rejected),
  listing, on-demand decrypt of the exact batch just synced, 404 for unknown
  pathnames.

Both receiver suites use the same envelope construction as
`receiver/scripts/test-sync.mjs` and the implant (`crypto.c`): AES-256-GCM,
12-byte nonce, 16-byte tag, AAD = device id — so a change to the wire format
on either side breaks these tests first.

## Notes

- `api.test.mjs` uses a **test PSK and LOGS_TOKEN** (`deadbeef…` /
  `test-logs-token-…`), injected via `process.env`; `BLOB_READ_WRITE_TOKEN` is
  emptied so your real `.env.local` blob store is never touched.
- Port 3999 is used because 3000 is commonly in use on this machine.
