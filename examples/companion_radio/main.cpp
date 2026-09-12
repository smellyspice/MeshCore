#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>
#include "MyMesh.h"

// Believe it or not, this std C function is busted on some platforms!
static uint32_t _atoi(const char* sp) {
  uint32_t n = 0;
  while (*sp && *sp >= '0' && *sp <= '9') {
    n *= 10;
    n += (*sp++ - '0');
  }
  return n;
}

// interface manager
#include <helpers/MultiSerialInterface.h>
MultiSerialInterface interface_manager;

// include bluetooth interface
#if defined(BLE_PIN_CODE)
  #ifdef ESP32
    // include esp32 bluetooth interface
    #include <helpers/esp32/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #elif defined(NRF52_PLATFORM)
    // include nrf52 bluetooth interface
    #include <helpers/nrf52/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #else
    #error "SerialBLEInterface is not defined for this platform"
  #endif
#endif

// include wifi interface
#ifdef WIFI_SSID
  #ifndef TCP_PORT
    #define TCP_PORT 5000
  #endif
  #ifdef ESP32
    // include esp32 wifi interface
    #include <helpers/esp32/SerialWifiInterface.h>
    #include <esp_wifi.h>
    SerialWifiInterface wifi_interface;

    // Boot-time default max power for this board's WiFi radio (see
    // src/helpers/esp32/ESPNOWRadio.cpp -- shared convention so ESP-NOW and
    // plain WiFi use on the same board agree).
    #ifndef WIFI_TX_POWER
    #define WIFI_TX_POWER 20
    #endif
  #else
    #error "SerialWifiInterface is not defined for this platform"
  #endif
#endif

// WiFi STA for IpBridgeRadio's own mesh link (see the setup()/loop() blocks
// below) -- needed even when WIFI_SSID (the phone-transport path above) is
// NOT defined, e.g. a BLE/USB companion that still reaches its repeater over
// IP instead of ESP-NOW.
#if defined(ESP32) && defined(IP_BRIDGE_RADIO) && !defined(WIFI_SSID)
  #include <WiFi.h>
  #include <esp_wifi.h>
#endif

// include usb interface
#if defined(ENABLE_USB_INTERFACE)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface usb_serial_interface;
#endif

// include ethernet interface
#if defined(ETHERNET_ENABLED)
  #include <helpers/ethernet/EthernetInterface.h>
  ETHERNET_CLASS ethernet_interface;
#endif

// include hardware serial interface
#if defined(SERIAL_RX)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface hardware_serial_interface;
  HardwareSerial companion_serial(1);
#endif

// platform file system
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
  #if defined(QSPIFLASH)
    #include <CustomLFS_QSPIFlash.h>
    DataStore store(InternalFS, QSPIFlash, rtc_clock);
  #else
    #if defined(EXTRAFS)
      #include <CustomLFS.h>
      CustomLFS ExtraFS(0xD4000, 0x19000, 128);
      DataStore store(InternalFS, ExtraFS, rtc_clock);
    #else
      DataStore store(InternalFS, rtc_clock);
    #endif
  #endif
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
  DataStore store(LittleFS, rtc_clock);
#elif defined(ESP32)
  #include <SPIFFS.h>
  DataStore store(SPIFFS, rtc_clock);
#endif

/* GLOBAL OBJECTS */
#ifdef DISPLAY_CLASS
  #include "UITask.h"
  UITask ui_task(&board, &interface_manager);
#endif

StdRNG fast_rng;
SimpleMeshTables tables;
MyMesh the_mesh(radio_driver, fast_rng, rtc_clock, tables, store
   #ifdef DISPLAY_CLASS
      , &ui_task
   #endif
);

/* END GLOBAL OBJECTS */

void halt() {
  while (1) ;
}

/* WIFI RECONNECT TRACKERS */
#if defined(ESP32) && (defined(WIFI_SSID) || defined(IP_BRIDGE_RADIO))
  bool wifi_needs_reconnect = false;
  unsigned long last_wifi_reconnect_attempt = 0;
#endif

void setup() {
  Serial.begin(115200);
  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#ifdef DISPLAY_CLASS
  DisplayDriver* disp = NULL;
  if (display.begin()) {
    disp = &display;
    disp->startFrame();
  #ifdef ST7789
    disp->setTextSize(2);
  #endif
    disp->drawTextCentered(disp->width() / 2, 28, "Loading...");
    disp->endFrame();
  }
#endif

  if (!radio_init()) { halt(); }

  fast_rng.begin(radio_driver.getRngSeed());

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  InternalFS.begin();
  #if defined(QSPIFLASH)
    if (!QSPIFlash.begin()) {
      // debug output might not be available at this point, might be too early. maybe should fall back to InternalFS here?
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: failed to initialize");
    } else {
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: initialized successfully");
    }
  #else
  #if defined(EXTRAFS)
      ExtraFS.begin();
  #endif
  #endif
  store.begin();
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
  );
#elif defined(RP2040_PLATFORM)
  LittleFS.begin();
  store.begin();
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
  );
#elif defined(ESP32)
  SPIFFS.begin(true);
  store.begin();
  the_mesh.begin(
    #ifdef DISPLAY_CLASS
        disp != NULL
    #else
        false
    #endif
  );
#else
  #error "need to define filesystem"
#endif

// add bluetooth interface
#if defined(BLE_PIN_CODE)
  bluetooth_interface.begin(BLE_NAME_PREFIX, the_mesh.getNodePrefs()->node_name, the_mesh.getBLEPin());
  interface_manager.addInterface(InterfaceType::Bluetooth, &bluetooth_interface);
  #ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.relockChannel();  // BLE init can reset the WiFi PHY, desyncing it from the configured bridge channel
  #endif
#endif

// add wifi interface
#ifdef WIFI_SSID
  #if !defined(IP_BRIDGE_RADIO)
  // Standalone WIFI_SSID path (e.g. ESPNOW_BRIDGE_RADIO's own _wifi env) --
  // real compile-time credentials, so this is the only WiFi.begin() call at
  // all. Skipped entirely when IP_BRIDGE_RADIO is also defined: that combo
  // env uses WIFI_SSID purely to compile in SerialWifiInterface below, with
  // the actual (single) WiFi.begin() call issued later using real runtime
  // credentials -- calling WiFi.begin() here too, with throwaway placeholder
  // creds, would tear down and recreate the STA netif a second time once the
  // real call happens, which orphans the WiFiServer socket wifi_interface.begin()
  // below already bound (confirmed live 2026-09-12: WiFi itself connected fine,
  // but nothing ever answered on the phone-pairing TCP port again after the
  // second WiFi.begin()).
  board.setInhibitSleep(true);   // prevent sleep when WiFi is active
  WiFi.setAutoReconnect(true);
  esp_wifi_set_ps(WIFI_PS_NONE);   // modem sleep adds latency/jitter to WiFi/ESP-NOW RX
  esp_wifi_set_max_tx_power(WIFI_TX_POWER * 4);

  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
      if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
          WIFI_DEBUG_PRINTLN("WiFi disconnected. Flagging for reconnect...");
          wifi_needs_reconnect = true;
      } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
          WIFI_DEBUG_PRINTLN("WiFi connected successfully!");
          wifi_needs_reconnect = false;
      }
  });

  WiFi.begin(WIFI_SSID, WIFI_PWD);
  wifi_interface.begin(TCP_PORT);
  interface_manager.addInterface(InterfaceType::WiFi, &wifi_interface);
  #endif
  // IP_BRIDGE_RADIO combo case: wifi_interface.begin() is deferred to the
  // first ARDUINO_EVENT_WIFI_STA_GOT_IP in the block below instead of being
  // called here immediately -- confirmed live (2026-09-12) that starting the
  // WiFiServer before the STA interface has ever actually associated leaves
  // it refusing every connection permanently (TCP RST, not just slow to
  // answer), even though the *later* real WiFi.begin() goes on to succeed.
#endif

// bring up WiFi STA for IpBridgeRadio's own mesh link -- independent of
// whatever transport talks to the phone app (USB/BLE/WiFi above). Runtime
// config only (wifi.ssid/wifi.pwd set via CMD_SET_WIFI_PARAMS), same
// convention simple_repeater's own WITH_IP_BRIDGE WiFi STA bring-up uses --
// never a compile-time default.
#if defined(ESP32) && defined(IP_BRIDGE_RADIO)
  if (the_mesh.getNodePrefs()->wifi_ssid[0] != 0) {
    board.setInhibitSleep(true);   // prevent sleep when WiFi is active
    WiFi.setAutoReconnect(true);
    esp_wifi_set_ps(WIFI_PS_NONE);   // modem sleep adds latency/jitter, same reasoning as WIFI_SSID path
    #ifndef WIFI_TX_POWER
    #define WIFI_TX_POWER 20
    #endif
    esp_wifi_set_max_tx_power(WIFI_TX_POWER * 4);
    int8_t actual_power = 0;
    esp_wifi_get_max_tx_power(&actual_power);
    MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: tx_power set to %d (readback: %d quarter-dBm)", WIFI_TX_POWER, (int)actual_power);

    WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
        if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
            MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: disconnected, reason=%d", (int)info.wifi_sta_disconnected.reason);
            wifi_needs_reconnect = true;
        } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
            MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: got IP: %s", WiFi.localIP().toString().c_str());
            wifi_needs_reconnect = false;
            #ifdef WIFI_SSID
            // First real IP -- safe now to start the phone-pairing WiFiServer
            // (see the comment on the skipped immediate wifi_interface.begin()
            // above for why this can't happen any earlier). Guarded to once:
            // GOT_IP can fire again on a later reconnect.
            static bool wifi_interface_started = false;
            if (!wifi_interface_started) {
              wifi_interface_started = true;
              wifi_interface.begin(TCP_PORT);
              interface_manager.addInterface(InterfaceType::WiFi, &wifi_interface);
              // addInterface() here happens well after MyMesh::startInterface()'s
              // one-time interface_manager.enable() sweep in setup() already ran
              // (this whole block only runs once WiFi has an IP, i.e. mid-loop()),
              // so this interface's own _isEnabled flag was never set by that sweep --
              // MultiSerialInterface::checkRecvFrame()/writeFrame() silently skip any
              // interface where isEnabled() is false, which is why the phone app could
              // open the TCP socket (plain WiFiServer::accept(), unrelated to this flag)
              // but never got a device-info response. Enable it explicitly.
              wifi_interface.enable();
            }
            #endif
        } else if (event == ARDUINO_EVENT_WIFI_STA_CONNECTED) {
            MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: associated to AP");
        } else if (event == ARDUINO_EVENT_WIFI_STA_START) {
            MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: STA start");
        }
    });

    MESH_DEBUG_PRINTLN("IpBridgeRadio WiFi: begin(ssid=%s)", the_mesh.getNodePrefs()->wifi_ssid);
    WiFi.begin(the_mesh.getNodePrefs()->wifi_ssid, the_mesh.getNodePrefs()->wifi_pwd);
  }
#endif

// add usb interface
#if defined(ENABLE_USB_INTERFACE)
  usb_serial_interface.begin(Serial);
  interface_manager.addInterface(InterfaceType::USB, &usb_serial_interface);
#endif

// add ethernet interface
#if defined(ETHERNET_ENABLED)
  ethernet_interface.begin();
  interface_manager.addInterface(InterfaceType::Ethernet, &ethernet_interface);
#endif

// add hardware serial interface
#if defined(SERIAL_RX)
  companion_serial.setPins(SERIAL_RX, SERIAL_TX);
  companion_serial.begin(115200);
  hardware_serial_interface.begin(companion_serial);
  interface_manager.addInterface(InterfaceType::HardwareSerial, &hardware_serial_interface);
#endif

  the_mesh.startInterface(interface_manager);
  sensors.begin();

#if ENV_INCLUDE_GPS == 1
  the_mesh.applyGpsPrefs();
#endif

#ifdef DISPLAY_CLASS
  ui_task.begin(disp, &sensors, the_mesh.getNodePrefs());  // still want to pass this in as dependency, as prefs might be moved
#endif

  board.onBootComplete();
}

void loop() {
  the_mesh.loop();
  interface_manager.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();
#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif

  if (!the_mesh.hasPendingWork()) {
#if defined(NRF52_PLATFORM)
    board.sleep(0); // nrf ignores seconds param, sleeps whenever possible
#endif
  }

#if defined(ESP32) && (defined(WIFI_SSID) || defined(IP_BRIDGE_RADIO))
  // Safely attempt to reconnect every 10 seconds if flagged. MESH_DEBUG_PRINTLN
  // (not WIFI_DEBUG_PRINTLN) -- the latter is only ever defined when WIFI_SSID
  // pulls in SerialWifiInterface.h, which an IP_BRIDGE_RADIO-only build (BLE/
  // USB for the phone, WiFi only for the mesh link) never does.
  if (wifi_needs_reconnect && (millis() - last_wifi_reconnect_attempt > 10000)) {
    MESH_DEBUG_PRINTLN("Attempting manual WiFi reconnect...");
    WiFi.disconnect();
    WiFi.reconnect();
    last_wifi_reconnect_attempt = millis();
  }
#endif
}
