#pragma once

#include <Mesh.h>

/**
 * Radio driver for ESP32 boards with no LoRa chip that need to join an
 * existing MeshCore repeater's ESPNowBridge network (src/helpers/bridges/ESPNowBridge.cpp)
 * as if they were another bridge-enabled repeater -- rather than forming a
 * separate, incompatible ESP-NOW mesh like plain ESPNOWRadio does.
 *
 * Wire format matches ESPNowBridge exactly (magic header + Fletcher-16 checksum +
 * XOR "encryption" keyed by the configured bridge secret, on the configured bridge
 * channel) so an unmodified repeater running the bridge needs no firmware changes
 * to talk to this.
 *
 * There is no compile-time channel/secret default. Both are CLI/persisted-config
 * only ('set bridge.channel'/'set bridge.secret', see CommonCLI) -- the board
 * stays inert (no ESP-NOW peer registered, so no TX/RX at all) until both have
 * actually been set at least once. See setBridgeParams() below.
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
  uint8_t _boot_led_phase = 0;  // only used when BOOT_LED_DOUBLE_FLASH is defined
  bool _server_led_on = false;
  uint32_t _server_led_off_at = 0;
  uint8_t _server_led_phase = 0;  // 0,2,4 = on (flash N), 1,3 = gap; 5 = done, same style as _boot_led_phase
  bool _ip_ping_led_on = false;
  uint32_t _ip_ping_led_off_at = 0;
  bool _ip_pong_led_on = false;
  uint32_t _ip_pong_led_off_at = 0;
  bool _disconnect_blink_active = false;  // repeating, unlike the one-shot flashes above
  bool _disconnect_led_on = false;
  uint32_t _disconnect_next_toggle_at = 0;

  // Deferred-start flags: the shared LED has no arbitration between indicators
  // (whoever writes last wins), so a call arriving while the boot flash (or,
  // for the link indicator, the boot flash OR the one-shot server-mode flash)
  // is still showing would otherwise stomp it invisibly. Rather than starting
  // it right away, indicateServerMode()/setLinkConnected(false) set one of
  // these and return; loop() replays the call once the thing it would have
  // clobbered has finished. See indicateServerMode()/setLinkConnected() below.
  bool _server_mode_pending = false;
  bool _link_disconnect_pending = false;

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
   * Applies persisted bridge.channel/bridge.secret CLI config, registering the
   * ESP-NOW broadcast peer (first time or re-registering) and applying the
   * channel immediately. init() itself never registers a peer -- there's no
   * compile-time channel/secret to fall back to -- so the board has no TX/RX
   * at all until this has been called at least once with real values, either
   * from MyMesh::begin() (once persisted prefs are loaded, if both were
   * already set) or a live 'set bridge.channel'/'set bridge.secret'.
   * secret is copied/truncated the same way StrHelper::strncpy does (max 15
   * chars + null), matching the char[16] field it's meant to be loaded from.
   */
  void setBridgeParams(uint8_t channel, const char* secret);

  /**
   * One-shot pattern indicating this board is running as an IpBridge
   * server/hub (listening for a peer) rather than a spoke (dialing out): 3
   * quick blue flashes (150ms on/off each), same phase-counter style as the
   * boot double-flash. A single flash (the original design) was too easy to
   * miss or lose to a stray interruption (RX/TX flicker, a stray CLI
   * moment) -- 3 quick blinks reads as deliberate even if briefly glanced
   * at. Non-blocking, same timer-poll mechanism as the TX/RX/boot LEDs. Not
   * tied to the boot-green sequence -- called separately, whenever IpBridge
   * actually knows its role (after prefs load, well after boot; deferred via
   * _server_mode_pending if boot's own flash is still showing, see below).
   */
  void indicateServerMode();

  /**
   * IpBridge heartbeat indicators, both shorter than indicateServerMode()'s
   * 1s so they read as a quick blink rather than a flash (30/50ms was tried
   * first and was imperceptible -- too close to the human flicker-perception
   * threshold at this LED's brightness):
   * - indicateIpPing(): blue, ~120ms. Spoke calls this when it sends a ping;
   *   hub calls this when it receives one -- same event, same color, seen
   *   from each side of the wire.
   * - indicatePongReceived(): green, ~180ms, noticeably longer than the ping
   *   flash so it reads as distinct. Only ever called by the spoke, on
   *   receiving the hub's pong -- confirms the round trip actually completed.
   */
  void indicateIpPing();
  void indicatePongReceived();

  /**
   * Persistent (not one-shot) state indicator, both roles: slow red/off blink
   * (500ms each) whenever this board is actively running IpBridge but has no
   * connected peer -- hub listening with nobody there, or spoke dialing
   * out/reconnecting. Called on every state transition that changes
   * connectedness (listen/connect start, handshake success, peer timeout).
   * Solid off once connected -- the one-shot ping/pong/server-mode flashes
   * above can still briefly interrupt this (shared physical LED, no
   * arbitration), same accepted tradeoff as the boot-LED interruption case.
   * Never called at all for an unconfigured board -- IpBridge::begin() only
   * reaches the call site once it's confirmed ip.host/ip.port/ip.secret are
   * actually set (see IpBridge.cpp), so an unconfigured spoke shows no light.
   */
  void setLinkConnected(bool connected);
};

#if ESPNOW_DEBUG_LOGGING && ARDUINO
  #include <Arduino.h>
  #define ESPNOW_DEBUG_PRINT(F, ...) Serial.printf("ESP-Now-Bridge: " F, ##__VA_ARGS__)
  #define ESPNOW_DEBUG_PRINTLN(F, ...) Serial.printf("ESP-Now-Bridge: " F "\n", ##__VA_ARGS__)
#else
  #define ESPNOW_DEBUG_PRINT(...) {}
  #define ESPNOW_DEBUG_PRINTLN(...) {}
#endif
