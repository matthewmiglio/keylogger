#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdbool.h>
#include <stdint.h>
#include <windows.h>

// Installs the WH_KEYBOARD_LL hook (message pump must run on this thread).
bool kbd_install(void);
void kbd_uninstall(void);
bool kbd_hook_ok(void);

// Called every 5 s by the main tick so idle periods still attribute events
// to the right window. The hook callback also refreshes on window change.
void kbd_refresh_foreground_title(void);

// UTF-8 title for a title index (interned by this module; stable while running).
const char *kbd_title_at(uint32_t idx);

#endif
