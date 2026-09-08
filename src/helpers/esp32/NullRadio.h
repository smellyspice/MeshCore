#pragma once

#include <Mesh.h>
#include <esp_system.h>

/**
 * A Radio implementation with no real hardware behind it at all -- not even
 * ESP-NOW. For simple_repeater builds where the board has no LoRa chip and
 * the actual mesh transport is WITH_ESPNOW_BRIDGE's own ESPNowBridge (the
 * multi-peer ESP-NOW bridge HOST, src/helpers/bridges/ESPNowBridge.cpp,
 * which does its own independent esp_now_init()/WiFi setup). Dispatcher
 * still needs a working Radio object to drive its TX-completion loop (see
 * Dispatcher::loop()) and MyMesh's stats/config calls, so this exists purely
 * to satisfy that contract: sends complete instantly, nothing is ever
 * received "over radio".
 *
 * Deliberately NOT ESPNowBridgeRadio -- that class is a genuine ESP-NOW
 * *client* radio (single-peer spoke joining someone else's bridge) and
 * would double up on WiFi/ESP-NOW init, fighting ESPNowBridge for the same
 * peripheral/callbacks. This class touches no WiFi/ESP-NOW APIs whatsoever.
 *
 * Also implements the same IpBridge LED-status hooks (indicateServerMode/
 * setLinkConnected/indicateIpPing/indicatePongReceived) that
 * ESPNowBridgeRadio provides, so IpBridge.cpp's existing calls to
 * radio_driver.<these> light up here too -- see the guard note on
 * HAS_RADIO_STATUS_LED below for how that's wired in without needing
 * ESPNOW_BRIDGE_RADIO to be (wrongly) defined for a board using this class.
 * No boot-flash coordination needed here (unlike ESPNowBridgeRadio) --
 * BOOT_LED_DOUBLE_FLASH is a feature only that class ever implements; a
 * board using NullRadio has no boot flash to avoid stomping.
 */
class NullRadio : public mesh::Radio {
  bool _server_led_on = false;
  unsigned long _server_led_off_at = 0;
  bool _ip_ping_led_on = false;
  unsigned long _ip_ping_led_off_at = 0;
  bool _ip_pong_led_on = false;
  unsigned long _ip_pong_led_off_at = 0;
  bool _disconnect_blink_active = false;
  bool _disconnect_led_on = false;
  unsigned long _disconnect_next_toggle_at = 0;

public:
  NullRadio() { }

  uint32_t getRngSeed() { return esp_random(); }

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) { /* no-op, no real radio */ }
  void setTxPower(int8_t dbm) { /* no-op */ }
  void powerOff() { /* no-op */ }

  void init() { /* no-op */ }
  void loop() override;

  int recvRaw(uint8_t* bytes, int sz) override { return 0; }  // nothing ever received "over radio"
  uint32_t getEstAirtimeFor(int len_bytes) override { return 1; }  // never actually sent, cost is moot
  bool startSendRaw(const uint8_t* bytes, int len) override { return true; }  // pretend it started fine
  bool isSendComplete() override { return true; }  // instantly "done" -- nothing was really sent
  void onSendFinished() override { /* no-op */ }
  bool isInRecvMode() const override { return true; }

  float packetScore(float snr, int packet_len) override { return 0; }

  uint32_t getPacketsRecv() const { return 0; }
  uint32_t getPacketsSent() const { return 0; }
  uint32_t getPacketsRecvErrors() const { return 0; }
  void resetStats() { /* no-op, nothing tracked */ }

  virtual float getLastRSSI() const override { return 0; }
  virtual float getLastSNR() const override { return 0; }

  virtual bool setRxBoostedGainMode(bool) { return false; }
  virtual bool getRxBoostedGainMode() const { return false; }

  // Same behavior/timings as ESPNowBridgeRadio's own (see that class for the
  // original), minus boot-flash-collision handling, which doesn't apply here.
  void indicateServerMode();
  void indicateIpPing();
  void indicatePongReceived();
  void setLinkConnected(bool connected);
};
