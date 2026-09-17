// AES-256-GCM and SHA-256 via Windows CNG (BCrypt). No external crypto.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "config.h"
#include "util.h"

#define NT_OK(s) (((NTSTATUS)(s)) >= 0)

void crypto_device_id(char out[17])
{
    // MachineGuid (read-only) + current username -> SHA-256 -> 16 hex chars.
    strcpy(out, "0000000000000000");
    wchar_t guid[64] = L"";
    DWORD guid_len = sizeof(guid), guid_type = 0;
    RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                 L"MachineGuid", RRF_RT_REG_SZ, &guid_type, guid, &guid_len);

    wchar_t wuser[64] = L"";
    DWORD user_len = 64;
    GetUserNameW(wuser, &user_len);

    wchar_t wsrc[160];
    _snwprintf(wsrc, 160, L"%s\\%s", guid, wuser);
    char *src = wide_to_utf8(wsrc);
    if (!src)
        src = _strdup("unknown\\unknown");

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (NT_OK(st)) {
        st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
        if (NT_OK(st)) {
            BCryptHashData(hash, (PUCHAR)src, (ULONG)strlen(src), 0);
            BYTE digest[32] = {0};
            BCryptFinishHash(hash, digest, sizeof(digest), 0);
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 8; i++) {
                out[i * 2]     = hex[digest[i] >> 4];
                out[i * 2 + 1] = hex[digest[i] & 0xF];
            }
            out[16] = '\0';
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    size_t src_len = strlen(src);
    SecureZeroMemory(src, src_len);
    HeapFree(GetProcessHeap(), 0, src);
}

bool crypto_seal_batch(const uint8_t key[32],
                       const char *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t nonce[12],
                       uint8_t **ct_out, size_t *ct_len,
                       uint8_t tag[16])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    bool ok = false;

    // Random 96-bit nonce from the system RNG.
    NTSTATUS st = BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_OK(st))
        return false;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_OK(st))
        goto done;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_OK(st))
        goto done;
    st = BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
                                    (PUCHAR)key, 32, 0);
    if (!NT_OK(st))
        goto done;

    {
        uint8_t *ct = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, pt_len ? pt_len : 1);
        if (!ct)
            goto done;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = nonce;
        info.cbNonce = 12;
        info.pbAuthData = (PUCHAR)aad;
        info.cbAuthData = (ULONG)aad_len;
        info.pbTag = tag;
        info.cbTag = 16;

        ULONG done_len = 0;
        st = BCryptEncrypt(hkey, (PUCHAR)pt, (ULONG)pt_len, &info,
                           NULL, 0, ct, (ULONG)pt_len, &done_len, 0);
        if (NT_OK(st)) {
            *ct_out = ct;
            *ct_len = done_len;
            ok = true;
        } else {
            HeapFree(GetProcessHeap(), 0, ct);
        }
    }

done:
    if (hkey)
        BCryptDestroyKey(hkey);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
