#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>

#include "MyMesh.h"

// WiFi STA for IpBridgeRadio's own mesh link -- runtime config only
// (wifi.ssid/wifi.pwd set via the CLI), same convention companion_radio's
// main.cpp uses for the same radio. No phone-pairing transport to juggle
// here (room server only ever speaks its text CLI over serial/Ethernet),
// so this is simpler than the companion's version of the same bring-up.
#if defined(ESP32) && defined(IP_BRIDGE_RADIO)
  #include <WiFi.h>
  #include <esp_wifi.h>
  #include <time.h>
  #include <esp_sntp.h>
  #include "NtpConfig.h"
  bool wifi_needs_reconnect = false;
  unsigned long last_wifi_reconnect_attempt = 0;
  // No battery-backed RTC on these boards, so rtc_clock resets to a bogus
  // default every boot until NTP corrects it -- re-applied periodically (see
  // NTP_RESYNC_INTERVAL_MS below) to bound long-run drift, not just once at
  // boot/reconnect. Same pattern as simple_repeater/main.cpp's NTP bring-up;
  // scoped to IP_BRIDGE_RADIO only -- ESP-NOW-bridged room servers already
  // get their clock from the host's periodic ESP-NOW time beacon
  // (ESPNowBridgeRadio.cpp's handleTimeBeacon()), and companion boards get
  // theirs pushed by the phone app, so neither needs this.
  bool ntp_synced = false;
  unsigned long last_ntp_sync_at = 0;
  #ifndef NTP_RESYNC_INTERVAL_MS
  #define NTP_RESYNC_INTERVAL_MS (12UL * 60 * 60 * 1000)  // 12h -- drift is slow, no need to be aggressive
  #endif
  #ifndef FIRMWARE_BUILD_EPOCH
  #define FIRMWARE_BUILD_EPOCH 1700000000UL  // ~Nov 2023, only if build.sh wasn't used
  #endif
#endif

#ifdef ETHERNET_ENABLED
  #define ETHERNET_CLI_BANNER "MeshCore Room Server CLI"
  #include <helpers/nrf52/EthernetCLI.h>
#endif

#ifdef DISPLAY_CLASS
  #include "UITask.h"
  static UITask ui_task(display);
#endif

StdRNG fast_rng;
SimpleMeshTables tables;
MyMesh the_mesh(board, radio_driver, *new ArduinoMillis(), fast_rng, rtc_clock, tables);

void halt() {
  while (1) ;
}

static char command[MAX_POST_TEXT_LEN+1];
#ifdef ETHERNET_ENABLED
static char ethernet_command[MAX_POST_TEXT_LEN+1];
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);

  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#ifdef DISPLAY_CLASS
  if (display.begin()) {
    display.startFrame();
    display.setCursor(0, 0);
    display.print("Please wait...");
    display.endFrame();
  }
#endif

  if (!radio_init()) { halt(); }

  fast_rng.begin(radio_driver.getRngSeed());

  FILESYSTEM* fs;
#if defined(NRF52_PLATFORM)
  InternalFS.begin();
  fs = &InternalFS;
  IdentityStore store(InternalFS, "");
#elif defined(RP2040_PLATFORM)
  LittleFS.begin();
  fs = &LittleFS;
  IdentityStore store(LittleFS, "/identity");
  store.begin();
#elif defined(ESP32)
  SPIFFS.begin(true);
  fs = &SPIFFS;
  IdentityStore store(SPIFFS, "/identity");
#else
  #error "need to define filesystem"
#endif
  if (!store.load("_main", the_mesh.self_id)) {
    the_mesh.self_id = radio_new_identity();   // create new random identity
    int count = 0;
    while (count < 10 && (the_mesh.self_id.pub_key[0] == 0x00 || the_mesh.self_id.pub_key[0] == 0xFF)) {  // reserved id hashes
      the_mesh.self_id = radio_new_identity(); count++;
    }
    store.save("_main", the_mesh.self_id);
  }

  Serial.print("Room ID: ");
  mesh::Utils::printHex(Serial, the_mesh.self_id.pub_key, PUB_KEY_SIZE); Serial.println();

  command[0] = 0;
#ifdef ETHERNET_ENABLED
  ethernet_command[0] = 0;
#endif

  sensors.begin();

  the_mesh.begin(fs);

#if defined(ESP32) && defined(IP_BRIDGE_RADIO)
  if (the_mesh.getNodePrefs()->wifi_ssid[0] != 0) {
    board.setInhibitSleep(true);   // prevent sleep when WiFi is active
    WiFi.setAutoReconnect(true);
    esp_wifi_set_ps(WIFI_PS_NONE);   // modem sleep adds latency/jitter, same reasoning as companion_radio's own WiFi paths
    #ifndef WIFI_TX_POWER
    #define WIFI_TX_POWER 20
    #endif
    esp_wifi_set_max_tx_power(WIFI_TX_POWER * 4);

    WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
        if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
            wifi_needs_reconnect = true;
        } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
            wifi_needs_reconnect = false;
            configTime(0, 0, NTP_SERVER_1, NTP_SERVER_2);   // UTC, matches rtc_clock's epoch semantics
        }
    });

    WiFi.begin(the_mesh.getNodePrefs()->wifi_ssid, the_mesh.getNodePrefs()->wifi_pwd);
  }
#endif

#ifdef DISPLAY_CLASS
  ui_task.begin(the_mesh.getNodePrefs(), FIRMWARE_BUILD_DATE, FIRMWARE_VERSION);
#endif

#ifdef ETHERNET_ENABLED
  ethernet_start_task();
#endif

  // send out initial zero hop Advertisement to the mesh
#if ENABLE_ADVERT_ON_BOOT == 1
  // +/- 10s random jitter around the 16s base delay -- several of these
  // boards sharing one ESP-NOW channel/hub all reboot at the same wall-clock
  // moment (e.g. a shared power cycle) and were otherwise guaranteed to
  // advert in the same instant every time.
  the_mesh.sendSelfAdvertisement(the_mesh.getRNG()->nextInt(6000, 26001), false);
#endif

  board.onBootComplete();
}

void loop() {
  int len = strlen(command);
  while (Serial.available() && len < sizeof(command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      command[len++] = c;
      command[len] = 0;
    }
    Serial.print(c);
  }
  if (len == sizeof(command)-1) {  // command buffer full
    command[sizeof(command)-1] = '\r';
  }

  if (len > 0 && command[len - 1] == '\r') {  // received complete line
    command[len - 1] = 0;  // replace newline with C string null terminator
    char reply[160];
    reply[0] = 0;
#ifdef ETHERNET_ENABLED
    if (!ethernet_handle_command(command, reply)) {
      the_mesh.handleCommand(0, command, reply);
    }
#else
    the_mesh.handleCommand(0, command, reply);  // NOTE: there is no sender_timestamp via serial!
#endif
    if (reply[0]) {
      Serial.print("  -> "); Serial.println(reply);
    }

    command[0] = 0;  // reset command buffer
  }

#ifdef ETHERNET_ENABLED
  ethernet_loop_maintain();
  if (ethernet_read_line(ethernet_command, sizeof(ethernet_command))) {
    char reply[160];
    reply[0] = 0;
    if (!ethernet_handle_command(ethernet_command, reply)) {
      the_mesh.handleCommand(0, ethernet_command, reply);
    }
    ethernet_send_reply(reply);
    ethernet_command[0] = 0;
  }
#endif

#if defined(ESP32) && defined(IP_BRIDGE_RADIO)
  if (wifi_needs_reconnect && (millis() - last_wifi_reconnect_attempt > 10000)) {
    WiFi.disconnect();
    WiFi.reconnect();
    last_wifi_reconnect_attempt = millis();
    ntp_synced = false;   // re-apply once the reconnect's SNTP query lands
  }
  if (!ntp_synced) {
    // sntp_get_sync_status() only reports COMPLETED once a real SNTP reply
    // has actually been processed -- unlike checking the epoch value alone,
    // this can't be fooled by the boot-time fallback clock, which sets a
    // hardcoded date that already looks "plausible" despite never having
    // talked to a real time server.
    if (sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
      time_t now = time(NULL);
      if (now > (time_t)FIRMWARE_BUILD_EPOCH) {   // sanity floor even on a genuine SNTP reply
        rtc_clock.setCurrentTime((uint32_t)now);
        ntp_synced = true;
        last_ntp_sync_at = millis();
        MESH_DEBUG_PRINTLN("Clock synced via NTP: %u", (uint32_t)now);
      }
    }
  } else if (the_mesh.getNodePrefs()->wifi_ssid[0] != 0 &&
             (millis() - last_ntp_sync_at > NTP_RESYNC_INTERVAL_MS)) {
    // Same guard as the initial sync: only re-triggered when WiFi is
    // actually configured. Periodic, not drift-critical -- see the field
    // comment on ntp_synced above.
    MESH_DEBUG_PRINTLN("Re-syncing clock via NTP...");
    configTime(0, 0, NTP_SERVER_1, NTP_SERVER_2);
    ntp_synced = false;   // re-applied once this new SNTP query lands, same as above
  }
#endif

  the_mesh.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();
#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif
}
