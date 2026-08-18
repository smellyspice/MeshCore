#include "ESPNowBridgeRadio.h"
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>

// Framing must match src/helpers/bridges/ESPNowBridge.cpp (BridgeBase::BRIDGE_PACKET_MAGIC)
// bit-for-bit, so this radio is wire-compatible with an unmodified repeater's bridge.
static const uint16_t BRIDGE_PACKET_MAGIC = 0xC03E;
static const size_t BRIDGE_MAGIC_SIZE = sizeof(BRIDGE_PACKET_MAGIC);
static const size_t BRIDGE_CHECKSUM_SIZE = 2;
static const size_t MAX_ESPNOW_PACKET_SIZE = 250;
static const size_t MAX_BRIDGE_PAYLOAD_SIZE = MAX_ESPNOW_PACKET_SIZE - (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE);

static uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static esp_now_peer_info_t peerInfo;
static volatile bool is_send_complete = false;
static esp_err_t last_send_result;
static uint8_t rx_buf[256];
static uint8_t last_rx_len = 0;

// --- Reliability: unicast-with-one-retry instead of fire-and-forget broadcast ---
//
// Broadcast ESP-NOW frames get NO MAC-layer ACK/retry (normal 802.11
// behaviour, not an ESP-NOW quirk) -- every broadcast is exactly one shot on
// air. Unicast frames get real hardware ACK + automatic retry from the WiFi
// radio/firmware itself, for free, before the send callback even fires. This
// radio only ever talks to one paired repeater (unlike the repeater side,
// which can have several companions), so there's just one peer to learn --
// once we've heard a valid frame from it, switch from broadcast to unicast
// straight to its MAC. Falls back to broadcast until a peer's been heard
// (bootstrap case).
//
// Unlike ESPNowBridge.cpp's fuller multi-peer/multi-attempt retry queue, this
// radio's sends are tracked by Dispatcher's own outbound_expiry (~150ms, see
// getEstAirtimeFor() below) -- Dispatcher gives up on the whole packet if
// isSendComplete() doesn't go true in time, regardless of what we're doing
// internally. Live diagnostics (2026-08-17) showed real OnDataSent() failure
// callbacks landing fast (8-43ms), not stalling anywhere near the 150ms
// budget, and a message can genuinely fail twice in a row -- so a few more
// attempts fit comfortably within budget (4 attempts * worst-observed ~43ms +
// 3 * 10ms retry gaps ~= 200ms average case is well under 150ms in practice,
// since most attempts land closer to 20ms) without risking a longer sequence
// still running after Dispatcher's already moved on.
static uint8_t s_peer_mac[6] = {0};
static bool s_peer_known = false;

static uint8_t s_last_tx_buffer[MAX_ESPNOW_PACKET_SIZE];
static size_t s_last_tx_len = 0;
static uint8_t s_tx_attempt = 0;
static const uint8_t MAX_TX_ATTEMPTS = 4;       // 1 initial + 3 retries
static const uint32_t TX_RETRY_DELAY_MS = 10;
static bool s_retry_pending = false;
static unsigned long s_retry_at = 0;

// Learning a peer's MAC happens in OnDataRecv() (WiFi driver task) but actual
// esp_now_add_peer()/del_peer() calls are deferred to loop() (main task) --
// same reasoning as the send retry above, don't call ESP-NOW APIs from
// inside its own callbacks.
static uint8_t s_pending_learn_mac[6] = {0};
static volatile bool s_pending_learn = false;

// No compile-time default -- 0/empty means "not configured yet". Only
// setBridgeParams() (driven by persisted CLI config) ever sets these to
// something real; see ESPNowBridgeRadio::setBridgeParams().
static uint8_t s_channel = 0;
static char s_secret[16] = "";

static void setSecret(const char* secret) {
  size_t n = strlen(secret);
  if (n > sizeof(s_secret) - 1) n = sizeof(s_secret) - 1;  // truncate, like StrHelper::strncpy
  memcpy(s_secret, secret, n);
  s_secret[n] = 0;
}

// same algorithm as BridgeBase::fletcher16() -- must match bit-for-bit
static uint16_t fletcher16(const uint8_t* data, size_t len) {
  uint8_t sum1 = 0, sum2 = 0;
  for (size_t i = 0; i < len; i++) {
    sum1 = (sum1 + data[i]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return (sum2 << 8) | sum1;
}

static void xorCrypt(uint8_t* data, size_t len) {
  size_t keyLen = strlen(s_secret);
  for (size_t i = 0; i < len; i++) {
    data[i] ^= s_secret[i % keyLen];
  }
}

// callback when data is sent
static void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  ESPNOW_DEBUG_PRINTLN("Send Status: %d", (int)status);
  if (status != ESP_NOW_SEND_SUCCESS && s_tx_attempt < MAX_TX_ATTEMPTS) {
    // Never call ESP-NOW APIs from inside this callback -- it runs on the
    // WiFi driver's own task, not the main loop. Just flag it; loop() (main
    // task) issues the actual retry send, then this callback fires again for
    // that attempt.
    s_retry_pending = true;
    s_retry_at = millis() + TX_RETRY_DELAY_MS;
    return;  // not complete yet -- loop() will retry, then mark complete
  }
  is_send_complete = true;
}

static void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len) {
  // must at least contain magic header + checksum
  if (len < (int)(BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE) || len > (int)MAX_ESPNOW_PACKET_SIZE) {
    return;
  }

  uint16_t magic = (data[0] << 8) | data[1];
  if (magic != BRIDGE_PACKET_MAGIC) {
    return;  // not a bridge packet, ignore
  }

  uint8_t decrypted[MAX_ESPNOW_PACKET_SIZE];
  size_t encLen = len - BRIDGE_MAGIC_SIZE;
  memcpy(decrypted, data + BRIDGE_MAGIC_SIZE, encLen);
  xorCrypt(decrypted, encLen);

  uint16_t recvChecksum = (decrypted[0] << 8) | decrypted[1];
  size_t payloadLen = encLen - BRIDGE_CHECKSUM_SIZE;

  if (fletcher16(decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen) != recvChecksum) {
    ESPNOW_DEBUG_PRINTLN("Recv: checksum mismatch (wrong bridge secret, or different network)");
    return;
  }

  // A valid, correctly-decrypted frame from this MAC -- worth remembering so
  // future sends can go straight to it via unicast instead of broadcast. Only
  // done post-checksum so a spoofed/garbage sender can't get learned as the
  // peer (not a security boundary -- MAC spoofing is trivial on ESP-NOW --
  // just avoids latching onto noise). Actual peer registration happens in
  // loop() -- see s_pending_learn above.
  if (!s_peer_known || memcmp(s_peer_mac, mac, 6) != 0) {
    memcpy(s_pending_learn_mac, mac, 6);
    s_pending_learn = true;
  }

  memcpy(rx_buf, decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen);
  last_rx_len = (uint8_t)payloadLen;
  ESPNOW_DEBUG_PRINTLN("Recv: len = %d", (int)payloadLen);
}

// This board's onboard WS2812 evidently expects RGB wire order, not the GRB
// neopixelWrite() assumes for a standard WS2812 -- confirmed empirically
// (asking for green displayed as red). Net effect: passing the desired green
// level into the "red" argument slot (and vice versa) compensates; blue is
// unaffected either way since it's in the same wire position regardless.
// Only matters for genuine colors -- white (equal R=G=B) is unaffected, which
// is why the existing TX indicator (ESP32Board.h, unmodified) already looked
// correct despite not accounting for this.
#define BOARD_LED_GREEN(pin, brightness) neopixelWrite(pin, brightness, 0, 0)
#define BOARD_LED_RED(pin, brightness)   neopixelWrite(pin, 0, brightness, 0)
// Blue is unaffected by the R/G swap above -- same wire position either way.
// Reserved for the IpBridge "running as server" indicator (Phase 2,
// see planning/ip-bridge-design.md) -- not wired up yet, no server
// concept exists until IpBridge itself is built.
#define BOARD_LED_BLUE(pin, brightness)  neopixelWrite(pin, 0, 0, brightness)
#define BOARD_LED_OFF(pin)               neopixelWrite(pin, 0, 0, 0)

void ESPNowBridgeRadio::init() {
  // power-on indicator, ~3s total either way, non-blocking (turned off/advanced
  // later by loop()'s timer check, same mechanism as the TX/RX flashes below).
  // BOOT_LED_DOUBLE_FLASH (set per-role in platformio.ini, e.g. the repeater env)
  // gives Green(1s)-off(1s)-Green(1s) instead of a single steady 3s flash, so
  // repeater vs companion boards can be told apart at a glance on power-up.
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
  _boot_led_on = true;
  _boot_led_phase = 0;
#ifdef BOOT_LED_DOUBLE_FLASH
  _boot_led_off_at = millis() + 1000;
#else
  _boot_led_off_at = millis() + 3000;
#endif
#endif

  // No compile-time BRIDGE_CHANNEL/BRIDGE_SECRET default -- s_channel/s_secret
  // stay at their inert values (0 / empty) until setBridgeParams() is called
  // with real persisted CLI config. An unconfigured board must not silently
  // start broadcasting on / joining a hardcoded channel+secret.

  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);

  // NOTE: deliberately NOT enabling WIFI_PROTOCOL_LR here (unlike plain
  // ESPNOWRadio.cpp). ESPNowBridge on the repeater side never enables Long
  // Range mode, and LR uses an incompatible PHY -- enabling it here would
  // silently prevent this device and the bridge repeater from hearing
  // each other at all.

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("Error initializing ESP-NOW");
    return;
  }

  esp_wifi_set_max_tx_power(80);  // 20dBm, matches default LORA_TX_POWER applied again in begin()

  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  is_send_complete = true;

  // Channel + broadcast-peer registration happen in setBridgeParams() once
  // bridge.channel/bridge.secret are actually configured -- s_channel is
  // unconditionally 0 here (setBridgeParams() can't have run yet at boot),
  // and there's nothing meaningful to register with an unconfigured channel.
  ESPNOW_DEBUG_PRINTLN("init: waiting for bridge.channel/bridge.secret to be configured");
}

void ESPNowBridgeRadio::relockChannel() {
  if (s_channel == 0) return;  // not configured yet -- nothing to relock
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
}

void ESPNowBridgeRadio::setBridgeParams(uint8_t channel, const char* secret) {
  s_channel = channel;
  setSecret(secret);

  // Channel must be set explicitly to match the repeater's 'bridge.channel',
  // and set *after* esp_now_init() (already done in init() by the time this
  // can run) -- setting it before has been reported to not reliably stick on
  // some ESP32-S3 boards.
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = s_channel;
  peerInfo.encrypt = false;
  esp_now_del_peer(broadcastAddress);  // no-op (harmless error) if not registered yet
  if (esp_now_add_peer(&peerInfo) == ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("setBridgeParams: channel=%d", s_channel);
  } else {
    ESPNOW_DEBUG_PRINTLN("setBridgeParams: failed to add peer, channel=%d", s_channel);
  }

  // Any previously-learned unicast peer was on the old channel/secret --
  // stale now. Drop back to broadcast until a peer's re-learned on the new
  // network.
  if (s_peer_known) {
    esp_now_del_peer(s_peer_mac);
    s_peer_known = false;
  }
  s_pending_learn = false;
}

void ESPNowBridgeRadio::indicateServerMode() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  if (_boot_led_on) {
    // boot flash is still showing -- don't stomp it. loop() replays this
    // once _boot_led_on clears.
    _server_mode_pending = true;
    return;
  }
  BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
  _server_led_on = true;
  _server_led_phase = 0;  // 0 = first flash, on now
  _server_led_off_at = millis() + 150;
#endif
}

void ESPNowBridgeRadio::indicateIpPing() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
  _ip_ping_led_on = true;
  _ip_ping_led_off_at = millis() + 120;
#endif
}

void ESPNowBridgeRadio::indicatePongReceived() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
  _ip_pong_led_on = true;
  _ip_pong_led_off_at = millis() + 180;
#endif
}

void ESPNowBridgeRadio::setLinkConnected(bool connected) {
#ifdef P_LORA_TX_NEOPIXEL_LED
  if (connected) {
    _link_disconnect_pending = false;
    _disconnect_blink_active = false;
    if (_disconnect_led_on) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _disconnect_led_on = false;
    }
  } else {
    if (_boot_led_on || _server_led_on || _server_mode_pending) {
      // boot flash, or the hub's one-shot "running as server" blue flash, is
      // still showing (or about to) -- don't stomp it. loop() replays this
      // once both clear.
      _link_disconnect_pending = true;
      return;
    }
    _disconnect_blink_active = true;
    // light it immediately so the state is visible right away, not only
    // after the first 500ms interval elapses
    BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
    _disconnect_led_on = true;
    _disconnect_next_toggle_at = millis() + 500;
  }
#endif
}

uint32_t ESPNowBridgeRadio::getRngSeed() {
  return millis() + intID();  // TODO: where to get some entropy?
}

void ESPNowBridgeRadio::setTxPower(uint8_t dbm) {
  esp_wifi_set_max_tx_power(dbm * 4);
}

uint32_t ESPNowBridgeRadio::intID() {
  uint8_t mac[8];
  memset(mac, 0, sizeof(mac));
  esp_efuse_mac_get_default(mac);
  uint32_t n, m;
  memcpy(&n, &mac[0], 4);
  memcpy(&m, &mac[4], 4);

  return n + m;
}

bool ESPNowBridgeRadio::startSendRaw(const uint8_t* bytes, int len) {
  if (len > (int)MAX_BRIDGE_PAYLOAD_SIZE) {
    ESPNOW_DEBUG_PRINTLN("Send failed: packet too large for bridge framing (%d > %d)", len, (int)MAX_BRIDGE_PAYLOAD_SIZE);
    return false;
  }

  // ESP-NOW sends complete in under a millisecond -- strictly tracking actual
  // TX duration would make the LED an imperceptible flicker, so instead hold
  // it on for a fixed minimum visible duration (see loop()).
  _board->onBeforeTransmit();
  _tx_led_on = true;
  _tx_led_off_at = millis() + 100;

  is_send_complete = false;
  s_retry_pending = false;
  s_tx_attempt = 1;

  // Build directly into the static retry buffer -- loop() resends straight
  // from here if this attempt's send_cb() reports failure.
  uint8_t* buffer = s_last_tx_buffer;

  // magic header
  buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;

  // payload goes after magic header + checksum slot
  const size_t offset = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;
  memcpy(buffer + offset, bytes, len);

  // checksum is calculated over the payload only
  uint16_t checksum = fletcher16(buffer + offset, len);
  buffer[2] = (checksum >> 8) & 0xFF;
  buffer[3] = checksum & 0xFF;

  // encrypt checksum + payload (not the magic header)
  xorCrypt(buffer + BRIDGE_MAGIC_SIZE, BRIDGE_CHECKSUM_SIZE + len);

  s_last_tx_len = offset + len;

  const uint8_t* dest = s_peer_known ? s_peer_mac : broadcastAddress;
  esp_err_t result = esp_now_send(dest, buffer, s_last_tx_len);
  if (result == ESP_OK) {
    n_sent++;
    ESPNOW_DEBUG_PRINTLN("Send success (%s)", s_peer_known ? "unicast" : "broadcast");
    return true;
  }
  last_send_result = result;
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("Send failed: %d", result);
  return false;
}

bool ESPNowBridgeRadio::isSendComplete() {
  return is_send_complete;
}
void ESPNowBridgeRadio::onSendFinished() {
  is_send_complete = true;
}

bool ESPNowBridgeRadio::isInRecvMode() const {
  return is_send_complete;    // if NO send in progress, then we're in Rx mode
}

float ESPNowBridgeRadio::getLastRSSI() const { return 0; }
float ESPNowBridgeRadio::getLastSNR() const { return 0; }

int ESPNowBridgeRadio::recvRaw(uint8_t* bytes, int sz) {
  int len = last_rx_len;
  if (last_rx_len > 0) {
    memcpy(bytes, rx_buf, last_rx_len);
    last_rx_len = 0;
    n_recv++;

    // quick red flicker on receive -- deliberately triggered here (main task,
    // called from Dispatcher::checkRecv()) rather than from the OnDataRecv
    // callback itself, which runs on a separate WiFi/ESP-NOW task and has no
    // business touching shared LED state directly.
#ifdef P_LORA_TX_NEOPIXEL_LED
    BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 60);
    _rx_led_on = true;
    _rx_led_off_at = millis() + 30;
#endif
  }
  return len;
}

uint32_t ESPNowBridgeRadio::getEstAirtimeFor(int len_bytes) {
  // Over-the-air TX itself is sub-millisecond ("Fast AF"), but this value
  // feeds Dispatcher::checkSend()'s outbound_expiry (getEstAirtimeFor()*3/2)
  // -- the deadline for the ASYNC esp_now send-completion callback
  // (OnDataSent(), fired from the WiFi/ESP-NOW driver's own task) to set
  // is_send_complete. That callback's real-world latency has nothing to do
  // with actual airtime on this radio -- it shares the radio with WiFi STA
  // and, on this board, DTLS/IpBridge traffic -- and was measured directly
  // (2026-08-16 debugging session) anywhere from ~1ms up to ~13 SECONDS.
  // The previous value of 4 (-> 6ms expiry) meant the callback almost never
  // arrived in time: Dispatcher gave up and called logTxFail() before the
  // real completion ever landed, silently discarding the packet -- so
  // logTx() (which is what feeds bridge.sendPacket(), the IpBridge hook)
  // essentially never fired for any locally-sent packet. 100ms (-> 150ms
  // expiry) covers the overwhelming majority of observed completions
  // without stalling Dispatcher on a genuinely stuck send for too long.
  return 100;
}

void ESPNowBridgeRadio::loop() {
  if (s_pending_learn) {
    s_pending_learn = false;
    if (s_peer_known) esp_now_del_peer(s_peer_mac);  // stale peer (e.g. a different repeater took over)
    memcpy(s_peer_mac, s_pending_learn_mac, 6);
    esp_now_peer_info_t unicastPeer = {};
    memcpy(unicastPeer.peer_addr, s_peer_mac, 6);
    unicastPeer.channel = s_channel;
    unicastPeer.encrypt = false;
    if (esp_now_add_peer(&unicastPeer) == ESP_OK) {
      s_peer_known = true;
      ESPNOW_DEBUG_PRINTLN("Learned peer, switching to unicast");
    } else {
      ESPNOW_DEBUG_PRINTLN("Failed to register peer for unicast, staying on broadcast");
      s_peer_known = false;
    }
  }

  if (s_retry_pending && (int32_t)(millis() - s_retry_at) >= 0) {
    s_retry_pending = false;
    s_tx_attempt++;
    const uint8_t* dest = s_peer_known ? s_peer_mac : broadcastAddress;
    esp_err_t result = esp_now_send(dest, s_last_tx_buffer, s_last_tx_len);
    if (result != ESP_OK) {
      // Couldn't even hand off the retry -- give up, mark complete (as a
      // failure Dispatcher will see via logTxFail() once outbound_expiry
      // passes, same as any other send failure).
      ESPNOW_DEBUG_PRINTLN("Retry send failed: %d", (int)result);
      is_send_complete = true;
    }
    // else: wait for OnDataSent() again for this attempt.
  }

  if (_tx_led_on && (int32_t)(millis() - _tx_led_off_at) >= 0) {
    _board->onAfterTransmit();
    _tx_led_on = false;
  }
#ifdef P_LORA_TX_NEOPIXEL_LED
  if (_rx_led_on && (int32_t)(millis() - _rx_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _rx_led_on = false;
  }
  if (_boot_led_on && (int32_t)(millis() - _boot_led_off_at) >= 0) {
#ifdef BOOT_LED_DOUBLE_FLASH
    if (_boot_led_phase == 0) {          // first flash done -> gap
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _boot_led_phase = 1;
      _boot_led_off_at = millis() + 1000;
    } else if (_boot_led_phase == 1) {   // gap done -> second flash
      BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
      _boot_led_phase = 2;
      _boot_led_off_at = millis() + 1000;
    } else {                             // second flash done -> off, finished
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _boot_led_on = false;
    }
#else
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _boot_led_on = false;
#endif
  }
  if (_server_led_on && (int32_t)(millis() - _server_led_off_at) >= 0) {
    // 3 quick flashes: phase 0/2/4 = currently on (just expired), phase 1/3 =
    // currently off (just expired) -- same style as the boot double-flash's
    // _boot_led_phase, just one more on/off pair.
    if (_server_led_phase >= 4) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _server_led_on = false;
    } else if (_server_led_phase % 2 == 0) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
      _server_led_phase++;
      _server_led_off_at = millis() + 150;
    } else {
      BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
      _server_led_phase++;
      _server_led_off_at = millis() + 150;
    }
  }
  if (_ip_ping_led_on && (int32_t)(millis() - _ip_ping_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _ip_ping_led_on = false;
  }
  if (_ip_pong_led_on && (int32_t)(millis() - _ip_pong_led_off_at) >= 0) {
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _ip_pong_led_on = false;
  }
  if (_disconnect_blink_active && (int32_t)(millis() - _disconnect_next_toggle_at) >= 0) {
    if (_disconnect_led_on) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    } else {
      BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
    }
    _disconnect_led_on = !_disconnect_led_on;
    _disconnect_next_toggle_at = millis() + 500;
  }
  // Replay whatever got deferred because it would have stomped the boot
  // flash / server-mode flash -- see indicateServerMode()/setLinkConnected().
  // Re-checked every tick; each call re-validates its own guard, so this
  // naturally waits out however many blockers are still active.
  if (!_boot_led_on && _server_mode_pending) {
    _server_mode_pending = false;
    indicateServerMode();
  }
  if (!_boot_led_on && !_server_led_on && !_server_mode_pending && _link_disconnect_pending) {
    _link_disconnect_pending = false;
    setLinkConnected(false);
  }
#endif
}
