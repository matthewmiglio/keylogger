// WinHTTP transport. All slow network work runs on the worker thread.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "gen_strings.h" // CFG_ALLOW_HTTP_LOCAL, CFG_LOCAL_PORT, CFG_DEBUG_CONSOLE
#include "net.h"
#include "util.h"

#if CFG_DEBUG_CONSOLE
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

static HINTERNET g_session;

bool net_init(void)
{
    wchar_t ua[160];
    cfg_get_str(CFG_UA, ua, 160);
    g_session = WinHttpOpen(ua,
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return g_session != NULL;
}

void net_shutdown(void)
{
    if (g_session)
        WinHttpCloseHandle(g_session);
}

// Local-test convenience: plain HTTP to localhost:CFG_LOCAL_PORT when the
// build was made with CFG_ALLOW_HTTP_LOCAL and the host is "localhost".
static bool local_http(INTERNET_PORT *port, DWORD *flags)
{
#if CFG_ALLOW_HTTP_LOCAL
    wchar_t host[128];
    cfg_get_str(CFG_HOST, host, 128);
    if (_wcsicmp(host, L"localhost") == 0) {
        *port = CFG_LOCAL_PORT;
        *flags = 0;
        return true;
    }
#else
    (void)port; (void)flags;
#endif
    return false;
}

static bool request(const wchar_t *verb, const wchar_t *path,
                   const wchar_t *extra_headers,
                   const void *body, DWORD body_len)
{
    wchar_t host[128];
    cfg_get_str(CFG_HOST, host, 128);

    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    DWORD secure = WINHTTP_FLAG_SECURE;
    local_http(&port, &secure);

    HINTERNET connect = WinHttpConnect(g_session, host, port, 0);
    if (!connect)
        return false;

    HINTERNET req = WinHttpOpenRequest(connect, verb, path, NULL,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      secure);
    if (!req) {
        WinHttpCloseHandle(connect);
        return false;
    }

    if (!WinHttpSendRequest(req, extra_headers,
                           extra_headers ? (DWORD)-1 : 0,
                           (LPVOID)body, body_len, body_len, 0) ||
        !WinHttpReceiveResponse(req, NULL)) {
        DBG("net: %ls %ls failed gle=%lu\n", verb, path, GetLastError());
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(connect);
        return false;
    }

    // Rejected certificate errors must fail the request; never ignore them.
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(req,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                        WINHTTP_NO_HEADER_INDEX);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(connect);
    return status >= 200 && status < 300;
}

bool net_post_sync(const char *device_id, uint64_t ts_ms,
                   const uint8_t nonce[12],
                   const uint8_t *ct, size_t ct_len,
                   const uint8_t tag[16])
{
    if (!g_session)
        return false;

    size_t b64_ct_len = 4 * ((ct_len + 2) / 3) + 1;
    char *b64_n  = (char *)HeapAlloc(GetProcessHeap(), 0, 32);
    char *b64_c  = (char *)HeapAlloc(GetProcessHeap(), 0, b64_ct_len);
    char *b64_t  = (char *)HeapAlloc(GetProcessHeap(), 0, 32);
    char *body   = (char *)HeapAlloc(GetProcessHeap(), 0, b64_ct_len + 256);
    bool ok = false;

    if (!b64_n || !b64_c || !b64_t || !body)
        goto done;

    b64_encode(nonce, 12, b64_n);
    b64_encode(ct, ct_len, b64_c);
    b64_encode(tag, 16, b64_t);

    int n = snprintf(body, b64_ct_len + 256,
                    "{\"v\":1,\"d\":\"%s\",\"ts\":%llu,"
                    "\"n\":\"%s\",\"c\":\"%s\",\"t\":\"%s\"}",
                    device_id, (unsigned long long)(ts_ms / 1000),
                    b64_n, b64_c, b64_t);
    if (n <= 0)
        goto done;

    wchar_t path[256];
    cfg_get_str(CFG_PATH, path, 256);

    ok = request(L"POST", path,
                 L"Content-Type: application/json\r\n"
                 L"Accept: application/json\r\n",
                 body, (DWORD)n);

done:
    if (b64_n) HeapFree(GetProcessHeap(), 0, b64_n);
    if (b64_c) HeapFree(GetProcessHeap(), 0, b64_c);
    if (b64_t) HeapFree(GetProcessHeap(), 0, b64_t);
    if (body) HeapFree(GetProcessHeap(), 0, body);
    return ok;
}

bool net_get_home(void)
{
    if (!g_session)
        return false;
    return request(L"GET", L"/", NULL, NULL, 0);
}
