#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Stable per-machine device id: 16 lowercase hex chars (2 x uint64 out).
// SHA-256(MachineGuid + "\\" + username), first 8 bytes, hex-encoded.
void crypto_device_id(char out[17]);

// AES-256-GCM seal. On success, *ct_out is a heap buffer (caller frees)
// of *ct_len bytes; nonce/tag are written to the caller's arrays.
bool crypto_seal_batch(const uint8_t key[32],
                        const char *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t nonce[12],
                        uint8_t **ct_out, size_t *ct_len,
                        uint8_t tag[16]);

#endif
