#pragma once

#include <Mesh.h>

#ifndef BRIDGE_CHANNEL
  #define BRIDGE_CHANNEL 1
#endif
#ifndef BRIDGE_SECRET
  #define BRIDGE_SECRET "changeme"
#endif

/**
 * Radio driver for ESP32 boards with no LoRa chip that need to join an
 * existing MeshCore repeater's ESPNowBridge network (src/helpers/bridges/ESPNowBridge.cpp)
 * as if they were another bridge-enabled repeater -- rather than forming a
 * separate, incompatible ESP-NOW mesh like plain ESPNOWRadio does.
 *
 * Wire format matches ESPNowBridge exactly (magic header + Fletcher-16 checksum +
 * XOR "encryption" keyed by BRIDGE_SECRET, on channel BRIDGE_CHANNEL) so an
 * unmodified repeater running the bridge needs no firmware changes to talk to this.
 */
class ESPNowBridgeRadio : public mesh::Radio {
protected:
  uint32_t n_recv, n_sent, n_recv_errors;
  mesh::MainBoard* _board;
  bool _tx_led_on = false;
  uint32_t _tx_led_off_at = 0;
  bool _rx_led_on = false;
  uint32_t _rx_led_off_at = 0;
  bool _boot_led_on = false;
  uint32_t _boot_led_off_at = 0;

public:
  // board is used to drive the existing onBeforeTransmit()/onAfterTransmit()
  // TX-LED hook (see src/helpers/ESP32Board.h) -- the same mechanism RadioLib-based
  // LoRa radios use, since ESP-NOW doesn't go through that wrapper.
  ESPNowBridgeRadio(mesh::MainBoard& board) : _board(&board) { n_recv = n_sent = n_recv_errors = 0; }

  uint32_t getRngSeed();

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) {
    // no-op
  }
  void powerOff() { /* no-op */ }

  void init();
  void loop() override;
  int recvRaw(uint8_t* bytes, int sz) override;
  uint32_t getEstAirtimeFor(int len_bytes) override;
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override;
  void onSendFinished() override;
  bool isInRecvMode() const override;

  uint32_t getPacketsRecv() const { return n_recv; }
  uint32_t getPacketsSent() const { return n_sent; }
  uint32_t getPacketsRecvErrors() const { return n_recv_errors; }
  void resetStats() { n_recv = n_sent = n_recv_errors = 0; }

  virtual float getLastRSSI() const override;
  virtual float getLastSNR() const override;

  float packetScore(float snr, int packet_len) override { return 0; }

  /**
   * These two functions do nothing for ESP-NOW, but are needed for the
   * Radio interface.
   */
  virtual bool setRxBoostedGainMode(bool) { return false; }
  virtual bool getRxBoostedGainMode() const { return false; }

  uint32_t intID();
  void setTxPower(uint8_t dbm);

  /**
   * Re-applies the WiFi channel. BLE init on ESP32 can reset the WiFi PHY
   * and desync it from the configured channel, so callers must invoke this
   * again after starting BLE.
   */
  void relockChannel();

  /**
   * Overrides the boot-time BRIDGE_CHANNEL/BRIDGE_SECRET defaults with
   * persisted prefs values, and re-applies the channel immediately. Call
   * after prefs have been loaded from flash (radio_driver.init() itself runs
   * before that, so it always starts from the compile-time defaults).
   * secret is copied/truncated the same way StrHelper::strncpy does (max 15
   * chars + null), matching the char[16] field it's meant to be loaded from.
   */
  void setBridgeParams(uint8_t channel, const char* secret);
};

#if ESPNOW_DEBUG_LOGGING && ARDUINO
  #include <Arduino.h>
  #define ESPNOW_DEBUG_PRINT(F, ...) Serial.printf("ESP-Now-Bridge: " F, ##__VA_ARGS__)
  #define ESPNOW_DEBUG_PRINTLN(F, ...) Serial.printf("ESP-Now-Bridge: " F "\n", ##__VA_ARGS__)
#else
  #define ESPNOW_DEBUG_PRINT(...) {}
  #define ESPNOW_DEBUG_PRINTLN(...) {}
#endif
