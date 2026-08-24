#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>

#include "MyMesh.h"

#ifdef DISPLAY_CLASS
  #include "UITask.h"
  static UITask ui_task(board, display);
#endif

#ifdef ETHERNET_ENABLED
  #define ETHERNET_CLI_BANNER "MeshCore Repeater CLI"
  #include <helpers/nrf52/EthernetCLI.h>
#endif

// WiFi STA uplink (IP-bridge groundwork -- see planning/ip-bridge-design.md).
// Plain IP connectivity only, not the companion TCP protocol -- this board still
// talks CLI over Serial/ESPNowBridgeRadio (or the normal LoRa radio) same as any other
// repeater. Credentials are runtime-configurable only (CommonCLI 'set wifi.ssid'/
// 'set wifi.pwd'), never build flags. Needed by ESPNOW_BRIDGE_RADIO boards (WiFi STA and
// ESP-NOW share one radio, so the channel-sync logic below matters) and, independently,
// by any board -- ESP-NOW-radio or real-LoRa -- that just wants WITH_IP_BRIDGE's WiFi
// uplink with no ESP-NOW side-channel involved at all.
#if defined(ESP32) && (defined(ESPNOW_BRIDGE_RADIO) || defined(WITH_IP_BRIDGE))
  #include <WiFi.h>
  #include <time.h>
  #include "NtpConfig.h"
  bool wifi_needs_reconnect = false;
  unsigned long last_wifi_reconnect_attempt = 0;
  // These boards have no battery-backed RTC (see AutoDiscoverRTCClock's
  // fallback), so rtc_clock resets to a bogus default every boot until
  // something sets it -- previously only GPS or a manual/companion-app
  // 'clock sync'. WiFi is already a hard requirement here, so a public NTP
  // pool is a free way to get a correct clock with no extra dependency.
  // Applied once: not continuous drift correction, just fixing the
  // stuck-at-boot-default case.
  bool ntp_synced = false;
#endif

StdRNG fast_rng;
SimpleMeshTables tables;

MyMesh the_mesh(board, radio_driver, *new ArduinoMillis(), fast_rng, rtc_clock, tables);

void halt() {
  while (1) ;
}

static char command[160];
#ifdef ETHERNET_ENABLED
static char ethernet_command[160];
#endif

// For power saving
unsigned long POWERSAVING_FIRSTSLEEP_SECS = 120; // The first sleep (if enabled) from boot

#if defined(PIN_USER_BTN) && defined(_SEEED_SENSECAP_SOLAR_H_)
static unsigned long userBtnDownAt = 0;
#define USER_BTN_HOLD_OFF_MILLIS 1500
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);

  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#if defined(MESH_DEBUG) && defined(NRF52_PLATFORM)
  // give some extra time for serial to settle so
  // boot debug messages can be seen on terminal
  delay(5000);
#endif

#ifdef DISPLAY_CLASS
  if (display.begin()) {
    display.startFrame();
    display.setCursor(0, 0);
    display.print("Please wait...");
    display.endFrame();
  }
#endif

  if (!radio_init()) {
    MESH_DEBUG_PRINTLN("Radio init failed!");
    halt();
  }

  fast_rng.begin(radio_driver.getRngSeed());

  FILESYSTEM* fs;
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  InternalFS.begin();
  fs = &InternalFS;
  IdentityStore store(InternalFS, "");
#elif defined(ESP32)
  SPIFFS.begin(true);
  fs = &SPIFFS;
  IdentityStore store(SPIFFS, "/identity");
#elif defined(RP2040_PLATFORM)
  LittleFS.begin();
  fs = &LittleFS;
  IdentityStore store(LittleFS, "/identity");
  store.begin();
#else
  #error "need to define filesystem"
#endif
  if (!store.load("_main", the_mesh.self_id)) {
    MESH_DEBUG_PRINTLN("Generating new keypair");
    the_mesh.self_id = radio_new_identity();   // create new random identity
    int count = 0;
    while (count < 10 && (the_mesh.self_id.pub_key[0] == 0x00 || the_mesh.self_id.pub_key[0] == 0xFF)) {  // reserved id hashes
      the_mesh.self_id = radio_new_identity(); count++;
    }
    store.save("_main", the_mesh.self_id);
  }

  Serial.print("Repeater ID: ");
  mesh::Utils::printHex(Serial, the_mesh.self_id.pub_key, PUB_KEY_SIZE); Serial.println();

  command[0] = 0;
#ifdef ETHERNET_ENABLED
  ethernet_command[0] = 0;
#endif

  sensors.begin();

#if defined(ESP32) && defined(WITH_IP_BRIDGE)
  // MUST happen before the_mesh.begin(fs) below: IpBridge::begin() (called
  // from within it) opens a listening UDP socket immediately whenever this
  // board is configured in server role (ip.port set, ip.host empty) --
  // completely independent of whether WiFi credentials have even been set
  // yet. That socket call needs WiFi's underlying netif/event-loop/lwIP task
  // to already exist, or it crashes outright with a lwIP tcpip-task assert
  // ("Invalid mbox"). On ESPNOW_BRIDGE_RADIO boards this already happens as
  // a side effect of the ESP-NOW radio's own init in radio_init() above --
  // harmless/idempotent to call again here. On a real-LoRa board there is no
  // ESP-NOW init to do it implicitly, so this is the only thing that does.
  WiFi.mode(WIFI_STA);
#endif

  the_mesh.begin(fs);

#if defined(ESP32) && (defined(ESPNOW_BRIDGE_RADIO) || defined(WITH_IP_BRIDGE))
  // wifi_ssid is only ever set via 'set wifi.ssid ...' over the CLI (CommonCLI) --
  // never a build flag. Empty means WiFi STA is simply not configured yet.
  if (the_mesh.getNodePrefs()->wifi_ssid[0] != 0) {
    board.setInhibitSleep(true);   // prevent sleep when WiFi is active
    WiFi.setAutoReconnect(true);

    WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
        if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
            MESH_DEBUG_PRINTLN("WiFi disconnected. Flagging for reconnect...");
            wifi_needs_reconnect = true;
        } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
            MESH_DEBUG_PRINTLN("WiFi connected successfully!");
            wifi_needs_reconnect = false;
            configTime(0, 0, NTP_SERVER_1, NTP_SERVER_2);   // UTC, matches rtc_clock's epoch semantics
        }
    });

    WiFi.begin(the_mesh.getNodePrefs()->wifi_ssid, the_mesh.getNodePrefs()->wifi_pwd);
#ifdef ESPNOW_BRIDGE_RADIO
    // WiFi STA and ESP-NOW share one radio and MUST be on the same channel.
    // Deliberately NOT auto-synced to whatever WiFi negotiates: that would
    // let the live channel silently diverge from the 'bridge.channel' CLI
    // setting (a config value that lies), and wouldn't propagate to any
    // paired ESP-NOW mini boards either, since each configures its own
    // channel independently. Instead, the access point's channel must be
    // static and known at config time, with 'bridge.channel' set to match
    // it by hand -- see planning/ip-bridge-design.md for the operational
    // requirement this implies. relockChannel() here only recovers from the
    // transient PHY reset BLE causes at association time -- it re-asserts
    // whatever channel 'bridge.channel' already configured (applied earlier
    // in MyMesh::begin()), it does not read anything back from WiFi.
    radio_driver.relockChannel();
#endif
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
  the_mesh.sendSelfAdvertisement(16000, false);
#endif

  board.onBootComplete();
}

void loop() {
  // Handle Serial CLI
  int len = strlen(command);
  while (Serial.available() && len < sizeof(command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      command[len++] = c;
      command[len] = 0;
      Serial.print(c);
    }
    if (c == '\r') break;
  }
  if (len == sizeof(command)-1) {  // command buffer full
    command[sizeof(command)-1] = '\r';
  }

  if (len > 0 && command[len - 1] == '\r') {  // received complete line
    Serial.print('\n');
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

#if defined(PIN_USER_BTN) && defined(_SEEED_SENSECAP_SOLAR_H_) && !defined(DISPLAY_CLASS)
  // Hold the user button to power off the SenseCAP Solar repeater.
  int btnState = digitalRead(PIN_USER_BTN);
  if (btnState == LOW) {
    if (userBtnDownAt == 0) {
      userBtnDownAt = millis();
    } else if ((unsigned long)(millis() - userBtnDownAt) >= USER_BTN_HOLD_OFF_MILLIS) {
      Serial.println("Powering off...");
      board.powerOff();  // does not return
    }
  } else {
    userBtnDownAt = 0;
  }
#endif

  the_mesh.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif

#if defined(ESP32) && (defined(ESPNOW_BRIDGE_RADIO) || defined(WITH_IP_BRIDGE))
  if (wifi_needs_reconnect && (millis() - last_wifi_reconnect_attempt > 10000)) {
    MESH_DEBUG_PRINTLN("Attempting manual WiFi reconnect...");
    WiFi.disconnect();
    WiFi.reconnect();
    last_wifi_reconnect_attempt = millis();
    ntp_synced = false;   // re-apply once the reconnect's SNTP query lands
  }
  if (!ntp_synced) {
    time_t now = time(NULL);
    if (now > 1700000000) {   // plausible real UTC time, ie. SNTP has actually landed
      rtc_clock.setCurrentTime((uint32_t)now);
      ntp_synced = true;
      MESH_DEBUG_PRINTLN("Clock synced via NTP: %u", (uint32_t)now);
    }
  }
#endif

  rtc_clock.tick();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif
  if (the_mesh.getNodePrefs()->powersaving_enabled && !the_mesh.hasPendingWork()) {
#if defined(NRF52_PLATFORM)
    board.sleep(0); // nrf ignores seconds param, sleeps whenever possible
#else
    if (the_mesh.millisHasNowPassed(POWERSAVING_FIRSTSLEEP_SECS * 1000)) { // To check if it is time to sleep
      board.sleep(30); // Sleep. Wake up after a while or when receiving a LoRa packet
    }
#endif
  }
}
