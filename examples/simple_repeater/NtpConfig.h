#pragma once

// NTP servers used to correct rtc_clock on boards with no battery-backed RTC
// (see AutoDiscoverRTCClock) once WiFi comes up -- see main.cpp. Overridable
// per-variant via build_flags (-D NTP_SERVER_1='"..."'), same pattern as
// FIRMWARE_BUILD_DATE/FIRMWARE_VERSION in MyMesh.h. Not a runtime/CLI
// setting (unlike wifi.ssid, ip.host, etc.) -- changing these requires a
// rebuild.

#ifndef NTP_SERVER_1
  #define NTP_SERVER_1   "pool.ntp.org"
#endif

#ifndef NTP_SERVER_2
  #define NTP_SERVER_2   "time.google.com"
#endif
