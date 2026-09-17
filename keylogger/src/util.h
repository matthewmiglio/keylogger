#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

// Milliseconds since Unix epoch.
uint64_t now_ms(void);

// Base64 encode; out must hold 4*ceil(n/3)+1 bytes. Returns strlen(out).
size_t b64_encode(const uint8_t *in, size_t n, char *out);

// Heap-allocated conversions (caller frees).
char    *wide_to_utf8(const wchar_t *w);
wchar_t *utf8_to_wide(const char *s);

#endif
