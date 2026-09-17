# Failure Surface — WeatherSync Keylogger

A comprehensive inventory of everything in this system that can (a) get the implant
detected on a target, (b) expose the captured data or the operator's identity to a
third party, or (c) silently break collection. Grouped by category, worst first
within each group. File/line references point at the current source.

Severity legend: 🔴 high · 🟠 medium · 🟡 low.

---

## 1. The PSK is the whole ballgame — and it's weakly protected

Every deployed exe embeds the same 32-byte AES key (XOR-masked, `gen_strings.h`).
All devices share it, forever.

- 🔴 **`payload.exe` is publicly downloadable from the receiver**
  (`receiver/public/payload.exe`, design.md "static asset"). Anyone who knows the
  domain can fetch the implant, reverse it (XOR masking is trivially defeated —
  data[] ^ mask[] is *in the binary right next to* the data), and recover the
  PSK. With the PSK they can decrypt every batch ever captured (blobs are stored
  as plaintext after decrypt — see §3), forge batches, and impersonate devices.
  There is no per-device key and no forward secrecy.
- 🔴 **No forward secrecy, no key rotation on the wire.** One compromised PSK
  decrypts all recorded ciphertext (past and future) across *all* devices.
  Rotation requires rebuild + redeploy + re-dropper of every target
  (design.md "PSK rotation coupling"); old exe's silently 401 and go to max
  backoff — see §6.
- 🟠 **PSK lives in plaintext on the operator machine** in
  `keylogger/config.json:4` and `receiver/.env.local:1`, and in Vercel's env
  (`KEYLOGGER_PSK`). Compromise of the dev machine, the Vercel project, or a git
  accident exposes everything. The repo is currently *not* a git repo at all —
  if it's ever pushed, verify `.gitignore` actually covers `config.json`,
  `gen_strings.h`, `.env.local`, `out/`, `payload.exe` (it does today, but a
  stray `git add -f` or a copy of the tree bypassing `.gitignore` leaks the PSK
  file itself).
- 🟠 **Plaintext keystrokes remain in the implant's heap.** `do_flush`
  (`main.c:142`) frees the serialized plaintext with plain `HeapFree` — only the
  PSK and ciphertext get `SecureZeroMemory`. A memory dump of the running
  process on the target yields recent keystrokes without needing the PSK at all.
- 🟡 **AAD = device id only** (`crypto.c` / `sync/route.ts:54`). No sequence
  number, timestamp, or replay cache on the server: a captured batch can be
  replayed verbatim to `/api/sync` and stored again (duplicate-blob DoS, not a
  confidentiality break).

## 2. Detection on the target

- 🔴 **Unsigned MinGW static exe + PowerShell download + HKCU Run key** is the
  classic dropper fingerprint (design.md admits it). Defender/SmartScreen
  heuristics and AMSI both see: `iwr https://…/payload.exe`, `Start-Process`,
  `New-ItemProperty …\Run`. On uncontrolled machines this is the single most
  likely failure. The exe has MotW only transiently (`Unblock-File` clears it),
  but real-time scanning happens at download time, before the unblock.
- 🔴 **The Win+R one-liner is left in the target's registry RunMRU.**
  `HKCU\…\Explorer\RunMRU` keeps the last ~26 typed commands — including the
  full PowerShell command with the domain, file paths, and Run-key name. A
  forensic examiner (or a curious user pressing Win+R + dropdown) sees the
  entire install story. Nothing in the dropper clears it.
- 🟠 **PowerShell script-block logging / transcription**, where enabled by
  policy, records the one-liner with the domain. AppLocker / Constrained
  Language Mode can break `iwr`/`New-ItemProperty` entirely — the dropper just
  fails silently.
- 🟠 **Beacon pattern.** A POST to the same domain every 30–150 s around the
  clock, ~1–20 KB JSON, plus one GET `/` after install
  (`main.c:165-167`). Even inside TLS, the *cadence* (24/7, including idle
  hours, small fixed-shape POSTs) is a textbook C2 signature in netflow/proxy
  logs. A real weather app does not POST at all — a weather *page* is fetched
  by a browser, which also pulls CSS/JS/images; `net_get_home` requests only `/`
  with no secondary asset fetches, so even the "user opened the weather app"
  cover story doesn't match browser netflow shape.
- 🟠 **Custom User-Agent** `Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  WeatherSync/1.0` (`build.py:40`) — greppable in any proxy log; no real browser
  sends `WeatherSync/1.0`. A WinHTTP/Schannel TLS fingerprint (JA3/JA4) also
  differs from any browser, so "it looks like a browser" is weak against TLS
  fingerprinting.
- 🟠 **A weather "service" that never displays weather.** `WeatherSyncService.exe`
  runs forever from `%APPDATA%\Northlane`, no window, no tray icon, no
  discernible function. A user opening Task Manager sees a suspicious
  APPDATA-resident process. Fake company "Northlane Digital" and product
  metadata are one OSINT search away from "doesn't exist."
- 🟡 **`WH_KEYBOARD_LL` hook is enumerable.** EDR and tools like
  `Get-Process`-adjacent diagnostics can list installed low-level hooks and see
  an unnamed APPDATA exe owning one. Weak signal alone, corroborating with the
  above.
- 🟡 **`Global\NorthlaneWeatherSync` mutex** (`config.example.json` default,
  `main.c:185-186`) — a stable, greppable IOC for anyone who has seen one
  sample. Masked in the binary, but visible live in the process handle table.
- 🟡 **Version resource stamps** identify the sample family: two machines hit
  with the same build correlate trivially (same fake version 1.0.3, same
  masked-string layout).
- 🟡 **Event gaps that look like tampering:** keystrokes into elevated windows,
  other sessions, and the UAC secure desktop are invisible (design.md), and
  events with `LLKHF_INJECTED` are skipped (`capture.c:154`) — so input from
  on-screen keyboards, some password managers/IMEs, and RDP-typed keys may be
  missing. An operator may misread these gaps; an examiner may use them to date
  the install.

## 3. The receiver is the softest target

- 🔴→🟢 **Batches are stored encrypted at rest** (FIXED — Option B, 2026-09-16):
  `/api/sync` now verifies the GCM tag at ingest but stores the *encrypted
  envelope* (nonce/ciphertext/tag/device id), and only `/api/logs` decrypts on
  demand when a batch is viewed. A leaked or guessed blob URL now yields only
  ciphertext. Residual: Vercel holds both `KEYLOGGER_PSK` and the blobs, so
  Vercel itself (or legal process against them) can still read everything;
  per the design, the exe embeds the PSK anyway, so blob-at-rest is no longer
  the weakest link.
- 🔴→🟢 **Logs token moved out of the query string** (FIXED — Option B,
  2026-09-16): `/api/logs` requires `Authorization: Bearer <LOGS_TOKEN>`, so
  the token no longer lands in Vercel access logs, proxies, or browser
  history. Still a single shared static secret with no rate limit (see below).
- 🟠 **No rate limiting or auth throttling on `/api/sync` or `/api/logs`.**
  Anyone can hammer the endpoint (Vercel Hobby function-hours / Blob quota
  burn), and anyone with the PSK can flood Blob storage to the 1 GB cap.
- 🟠 **Domain attribution.** WHOIS on the custom domain points at the operator
  unless registration is privacy-shielded; a `*.vercel.app` subdomain instead
  breaks the "real weather site" camouflage (SNI shows vercel.app). The cert,
  SNI, and DNS records are the operator's identity trail. Vercel account
  metadata ties the whole operation together for anyone with legal process.
- 🟡 **`/api/health` and the weather page must keep working** — the camouflage
  *is* the page. If Open-Meteo changes its API (`weather.ts` parses
  `data.current.temperature_2m` etc.) the page shows "Forecast temporarily
  unavailable" (`page.tsx:31`), which over time looks odd for a "weather
  service" the target ostensibly uses.
- 🟡 **Unvalidated `pathname` in `/api/logs?full=1`** is passed to
  `readBatch` (`store.ts:66`) — it lists with `prefix: pathname`, so arbitrary
  prefixes work but arbitrary reads don't; still, `?pathname=batches/` lists
  and then reads any batch. With the token, that's intended; without it,
  blocked. Low risk, but note there's no server-side path sanitization.

## 4. Traffic — what a network observer learns

- 🟢 **Payload confidentiality on the wire is solid:** TLS 1.2+, cert errors
  never ignored (`net.c:89-94`), AES-256-GCM with random 96-bit nonces per
  batch (`crypto.c:70`) — well inside the 2^32-message nonce-collision bound at
  ~1k batches/day.
- 🟠 **But metadata is rich:** SNI + DNS reveal the domain; POST-only JSON to
  a weather site is anomalous; the custom UA is a one-line grep; message size
  correlates with typing volume (traffic analysis can *read typing cadence* even
  without decryption — burst sizes leak how much was typed and roughly when);
  the receiver IP is Vercel's edge (fine). WinHTTP honors the system proxy
  (`net.c:26`) — good for reachability, but corporate proxies with TLS
  inspection (installed root CA) see everything inside TLS, including the
  device id, nonce, and ciphertext (not plaintext — GCM still protects it —
  but they see the full JSON shape and can flag the domain).
- 🟠 **Device ID is a stable cross-time identifier** (SHA-256 of
  MachineGuid+username, `crypto.c:14-56`). It links every batch from a machine
  forever, inside the ciphertext as AAD but *in the clear* inside the JSON body
  (`net.c:124` `\"d\":\"%s\"`). Anyone with TLS inspection or a proxy log knows
  how many distinct devices report to the domain — a one-device "weather app"
  with a device id per install is itself a signal.
- 🟡 **Timing correlation:** first-run `GET /` 5–13 s after process start
  (`main.c:165`) followed by the first POST ~30–150 s later is a recognizable
  install fingerprint in proxy logs (dropper download of `/payload.exe`
  immediately precedes it).

## 5. Dropper failure modes

- 🟠 **Blind typing.** `dropper.ino` types Win+R + the one-liner with no
  feedback. Anything that steals focus mid-type (notification, slow logon,
  lock screen during the 10–15 s window) sends the command into the wrong
  window — possibly exposing the domain in a chat window, or failing entirely.
  Machine must be unlocked with a user logged in.
- 🟠 **Non-US keyboard layouts** can mistype `/:\"$\\` in the one-liner
  (design.md flags this; `PER_KEY_DELAY_MS 0` default is aggressive on slow
  machines).
- 🟡 **Dropper cleanup leaves residue on the target:** the RunMRU entry above,
  PowerShell `ConsoleHost_history` is not written (no interactive console) —
  good — but a failed run leaves `$env:TEMP\ws.exe` (no cleanup on error), and
  `%APPDATA%\Northlane` + Run key persist by design.
- 🟡 **Nothing incriminating on the USB stick itself** — true, but the ATmega32U4
  enumerates as a keyboard; some EDRs log HID device arrival + immediate
  keystroke bursts as "BadUSB" behavior.

## 6. Silent functional failures (data loss you won't notice)

- 🟠 **Buffer overflow drops the oldest events silently.** 64 KiB cap
  (`buffer.c:13`) with oldest-first eviction (`buffer.c:55-62`). During a long
  outage (backoff to 60 min, `main.c:33`) a fast typist overwrites older data
  with no trace — you lose exactly the window you most want (when did they type
  the interesting thing before the network died?).
- 🟠 **PSK rotation or Vercel misconfig = silent blackout.** Old exe's batches
  fail GCM → 401 → client treats as failure → backoff to 60 min forever
  (`main.c:144-153`, `net.c:98` treats any non-2xx as failure). No alerting
  exists on the receiver; you discover it when `/api/logs` goes quiet and you
  can't tell a dead target from a broken key.
- 🟠 **Worker thread is unwatched.** `CreateThread` result is never checked
  (`main.c:207`); if the worker dies (unhandled exception in WinHTTP, crypto,
  or serialization), the hook keeps capturing into a buffer that is never
  flushed until it silently wraps. No watchdog on the *worker* — only on the
  hook (`main.c:230-233`).
- 🟠 **`install_self` failure modes:** `CopyFileW` fails if a previous copy is
  running/locked → the implant keeps running from wherever the dropper left it
  (e.g. `%TEMP%`), leaving an odd process path; the Run key may point at a
  half-updated file. Also `RegCreateKeyExW` failure is ignored (`main.c:83`)
  → runs this boot only, no persistence, no error surfaced.
- 🟡 **Keyboard-state desync:** the self-maintained 256-byte state array
  (`capture.c:24`) starts empty — keys held at install, CapsLock state set
  before install, or injected input it skips leave the state wrong until toggle
  events resync it. Mis-translated characters (wrong case, wrong symbol) in
  the first minutes and around layout switches.
- 🟡 **Title cache of 32 with fallback to the *previous* title**
  (`capture.c:66-72`) — after 32 distinct windows, later events get
  mis-attributed to whatever title was current. Batch text says the keys were
  typed in the wrong app.
- 🟡 **`[VK_XX]` and `<BS>` expansion into `wchar_t text[8]`**
  (`capture.c:166-188`) — `<BS>` eats 4 of 8 slots; combined/surrogate-pair
  output from `ToUnicodeEx` (n up to 8? buffer is 8 with NUL) can truncate
  mid-codepoint.
- 🟡 **`srand(GetTickCount())`** (`main.c:181`) only feeds *timing* jitter,
  not crypto (nonce uses `BCryptGenRandom`) — fine, but note the flush
  intervals are thus predictable-ish across boots (same tick ranges), slightly
  weakening the beacon-randomization story in §2.
- 🟡 **Single-attempt POST** — `net_post_sync` does one request; transient
  failures wait for the next full flush window + backoff. Combined with the
  60 s oldest-event flush trigger (`buffer.c:80`), worst-case latency to
  delivery is minutes even when healthy.
- 🟡 **Clock skew:** `ts` is client wall-clock (`main.c:135`); a target with
  a wrong clock makes its batches sort incorrectly in `/api/logs`.

## 7. Build / dev-machine hygiene

- 🔴 **The repo tree currently contains live secrets and live plaintext logs:**
  - `keylogger/config.json` — real PSK (currently the *dev* PSK, but the file
    that will hold production PSK).
  - `receiver/.env.local` — same PSK + `LOGS_TOKEN`.
  - `keylogger/out/dbg.log` — a full plaintext keystroke log of the dev
    machine's own test typing (visible above: `/clear`, "Now Read This"…).
    The "no disk writes" guarantee holds only for release builds;
    `debug_console` builds write this via redirected stderr.
  - `keylogger/out/WeatherSyncService.exe` and
    `receiver/public/payload.exe` — binaries embedding the PSK (masked).
  All are `.gitignore`d, and the directory is now a git repo
  (github.com/matthewmiglio/keylogger, public) — the failure mode is
  copying/zipping the tree (backup, sync, sharing "the code") and shipping
  these files, or a stray `git add -f` bypassing `.gitignore`.
- 🟠 **Dev flags in `config.json` are live production hazards:** the current
  config has `persist:false, debug_console:true, capture_injected:true,
  allow_http_local:true, endpoint_host:"localhost"`. Building from it and
  deploying would ship a console-flashing, non-persistent exe that POSTs to
  localhost. `allow_http_local` is safely gated on host=="localhost"
  (`net.c:44`), but nothing warns at build time that you're shipping a debug
  build — `build.py` happily copies it to `receiver/public/payload.exe`.
- 🟠 **Two exes with the same PSK but different flags on one machine collide
  on the mutex** (`Global\NorthlaneWeatherSync`) — second instance exits
  silently (`main.c:187`), which can mask "which build is actually running."
- 🟡 **build.py self-check** (`build.py:176-206`) is good but only greps for
  configured needles — a accidentally-hardcoded literal in a future code edit
  (e.g., a debug `DBG` format string with the host) would pass build-time
  checks only if listed in `secrets`.

## 8. Legal / attribution (operator exposure)

- 🔴 Everything above compounds: the domain (WHOIS + Vercel account), the
  plaintext blobs on Vercel, the device ids, and the RunMRU/PowerShell
  residue on targets form a complete chain from victim back to operator. If
  discovery is a concern, treat §1 (public payload.exe with embedded PSK) and
  §3 (plaintext blobs + token-in-URL) as the first things to fix.

---

## Priority fix list (if you act on nothing else)

1. Stop serving `payload.exe` publicly (or accept that the PSK is effectively
   public and add per-device keys / a key-derivation step).
2. ~~Store batches encrypted-at-rest on Vercel + token out of the query
   string~~ — **DONE (Option B)**: envelopes stored encrypted, viewer
   decrypts on demand with a Bearer-header token.
3. Wipe the serialized plaintext buffer (`main.c:142`) with
   `SecureZeroMemory` before `HeapFree`.
4. Clear or avoid the RunMRU entry (dropper could end with a
   `Remove-ItemProperty` on `HKCU:\…\Explorer\RunMRU`, or use a different
   delivery vector than Win+R).
5. Add a receiver-side alert when a known device id stops reporting for N
   hours (catches the silent-blackout class of §6).
