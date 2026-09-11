#include "ESPNowBridgeRadio.h"
#include "target.h"  // for the board variant's global rtc_clock -- see handleTimeBeacon() below
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>

// Boot-time default max power for this board's WiFi radio (see ESPNOWRadio.cpp --
// shared convention so ESP-NOW and plain WiFi use on the same board agree).
#ifndef WIFI_TX_POWER
#define WIFI_TX_POWER 20
#endif

// Framing must match src/helpers/bridges/ESPNowBridge.cpp (BridgeBase::BRIDGE_PACKET_MAGIC/
// BRIDGE_TIME_MAGIC) bit-for-bit, so this radio is wire-compatible with an unmodified
// repeater's bridge.
static const uint16_t BRIDGE_PACKET_MAGIC = 0xC03E;
static const uint16_t BRIDGE_TIME_MAGIC = 0xC03F;
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

// Broadcast ESP-NOW frames get no MAC-layer ACK/retry; unicast gets hardware
// ACK + retry for free. This board can have MULTIPLE peers talking to it at
// once (e.g. this radio also backs a hub like EchoGate, fielding several
// room-server/companion boards on the same ESP-NOW segment, not just a
// single spoke's one paired repeater as originally assumed) -- so instead of
// remembering just one MAC and overwriting it every time a different peer is
// heard from (which silently made every other peer unreachable the moment
// any one of them talked), a small table of known peers is kept, mirroring
// src/helpers/bridges/ESPNowBridge.cpp's own MAX_KNOWN_PEERS design for the
// same reason. Sending fans out: unicast-with-retry to every known peer in
// turn, then (FLOOD/zero-hop-advert only) one extra broadcast pass to reach
// anyone not yet individually learned -- same fan-out shape as
// ESPNowBridge::advanceToNextPeerOrFinish(), just reimplemented here since
// this class drives the mesh::Radio interface (one send at a time, polled via
// isSendComplete()) rather than ESPNowBridge's own queued-bridge loop().
//
// Table sized for a real EchoBoard-style hub (5-10 peers), not
// ESPNowBridge's 19 -- keeps per-packet worst-case fan-out time bounded (see
// getEstAirtimeFor()) rather than scaling for a case this radio doesn't need
// to support.
static const uint8_t MAX_KNOWN_PEERS = 10;
static uint8_t s_known_peers[MAX_KNOWN_PEERS][6];
static uint8_t s_known_peer_count = 0;

// Sentinel for "currently sending the broadcast pass" in the fan-out below,
// distinct from any real index into s_known_peers.
static const uint8_t PEER_IDX_BROADCAST = 0xFF;
static uint8_t s_active_peer_idx = PEER_IDX_BROADCAST;
static bool s_is_flood = false;
static bool s_flood_broadcast_done = false;
static bool s_advance_pending = false;  // deferred to loop(), see OnDataSent()

// Retries are bounded by Dispatcher's own outbound_expiry (see
// getEstAirtimeFor()) -- it gives up on the whole packet if isSendComplete()
// doesn't go true in time. Live-measured (2026-08-26, real hardware, real
// failures against a paired repeater): a failed attempt's own OnDataSent()
// callback lands in ~16-21ms, consistently -- not the old, unreconciled
// "up to 13s" claim (see getEstAirtimeFor()). At ~21ms/attempt worst case,
// 12 attempts costs roughly 12*21 + 11*TX_RETRY_DELAY_MS =~ 362ms worst
// case per peer, within budget below. Bumped 4 -> 6 -> 12 (a plain
// user-facing win: retries are cheap and fast, so a lot more of them beats a
// visible timeout error on a marginal link) -- observed live that some
// exchanges only succeeded on attempt 3, and 4/4 failures were common enough
// to be the primary complaint driving this whole investigation. The real
// root cause looks like antenna/RF margin between this board and its paired
// repeater (confirmed live: failures dropped sharply at close range), not
// something fixable here -- this is a pragmatic mitigation for marginal
// links, not a fix for the underlying link budget. This ceiling applies
// per-peer in the fan-out above, same as it always did for the single-peer
// case.
static uint8_t s_last_tx_buffer[MAX_ESPNOW_PACKET_SIZE];
static size_t s_last_tx_len = 0;
static uint8_t s_tx_attempt = 0;
static const uint8_t MAX_TX_ATTEMPTS = 12;      // 1 initial + 11 retries, per peer
static const uint32_t TX_RETRY_DELAY_MS = 10;
static bool s_retry_pending = false;
static unsigned long s_retry_at = 0;

// Learning a peer's MAC happens in OnDataRecv() (WiFi driver task) but actual
// esp_now_add_peer()/del_peer() calls are deferred to loop() (main task) --
// same reasoning as the send retry above, don't call ESP-NOW APIs from
// inside its own callbacks. Only one MAC can be "pending learn" at a time,
// which is fine -- two never-before-seen peers transmitting in the same
// handful of milliseconds is not a real scenario here.
static uint8_t s_pending_learn_mac[6] = {0};
static volatile bool s_pending_learn = false;

static bool isKnownPeer(const uint8_t* mac) {
  for (uint8_t i = 0; i < s_known_peer_count; i++) {
    if (memcmp(s_known_peers[i], mac, 6) == 0) return true;
  }
  return false;
}

// Timing instrumentation for OnDataSent() latency -- added to actually
// measure this instead of relying on old, unreconciled numbers in
// getEstAirtimeFor()'s comment (one debugging session claimed up to 13s
// stalls, the very next day's diagnostics showed 8-43ms; never resolved).
// s_attempt_started_at resets each retry; s_send_started_at stays fixed
// across all attempts of one packet, so both per-attempt and cumulative
// latency are visible against Dispatcher's ~150ms outbound_expiry budget.
static unsigned long s_send_started_at = 0;
static unsigned long s_attempt_started_at = 0;

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

// --- Time-sync beacon (see ESPNowBridge::broadcastTime() for the repeater side) ---
// Trust boundary is bridge.secret alone: a frame that decrypts and
// checksum-validates against it came from something on this same private
// ESP-NOW network, which is exactly the same guarantee the packet path below
// relies on for RX. No comparison against this board's own current time --
// just a plausibility floor and a cooldown so a steady stream of beacons
// only actually moves the clock about twice a day.
//
// The floor is this board's own firmware build date, not a fixed historical
// date -- no board should ever accept a time older than when its own
// firmware was built, and unlike a hardcoded constant this doesn't need
// bumping every release. Falls back to a fixed date only for a raw `pio run`
// build that skipped build.sh's flag injection (FIRMWARE_BUILD_EPOCH unset).
#ifndef FIRMWARE_BUILD_EPOCH
#define FIRMWARE_BUILD_EPOCH 1700000000UL  // ~Nov 2023, only if build.sh wasn't used
#endif
static const uint32_t TIME_BEACON_MIN_PLAUSIBLE = FIRMWARE_BUILD_EPOCH;
static const uint32_t TIME_APPLY_COOLDOWN_MS = 12UL * 60 * 60 * 1000;  // 12h
static unsigned long s_last_time_applied_at = 0;  // millis(), 0 = never applied yet

static void issueSendAttempt();  // defined near loop(), used by startSendRaw() above it

static void handleTimeBeacon(const uint8_t* data, int len) {
  static const size_t TIME_PAYLOAD_SIZE = 4;
  if (len != (int)(BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + TIME_PAYLOAD_SIZE)) return;
  if (s_secret[0] == 0) return;  // unconfigured -- xorCrypt()'s keyLen would be 0

  uint8_t decrypted[BRIDGE_CHECKSUM_SIZE + TIME_PAYLOAD_SIZE];
  memcpy(decrypted, data + BRIDGE_MAGIC_SIZE, sizeof(decrypted));
  xorCrypt(decrypted, sizeof(decrypted));

  uint16_t recvChecksum = (decrypted[0] << 8) | decrypted[1];
  if (fletcher16(decrypted + BRIDGE_CHECKSUM_SIZE, TIME_PAYLOAD_SIZE) != recvChecksum) {
    return;  // wrong bridge secret, or different network
  }

  const uint8_t* p = decrypted + BRIDGE_CHECKSUM_SIZE;
  uint32_t t = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
  if (t < TIME_BEACON_MIN_PLAUSIBLE) return;

  unsigned long now = millis();
  if (s_last_time_applied_at != 0 && (now - s_last_time_applied_at) < TIME_APPLY_COOLDOWN_MS) {
    return;  // applied one recently enough -- wait out the cooldown
  }
  rtc_clock.setCurrentTime(t);
  s_last_time_applied_at = now;
  ESPNOW_DEBUG_PRINTLN("Time beacon applied: %u", t);
}

// callback when data is sent
static void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  unsigned long now = millis();
  ESPNOW_DEBUG_PRINTLN("Send Status: %d (peer_idx=%d, attempt %d, +%lums this attempt, +%lums total)",
                       (int)status, (int)s_active_peer_idx, (int)s_tx_attempt,
                       now - s_attempt_started_at, now - s_send_started_at);
  if (status != ESP_NOW_SEND_SUCCESS && s_tx_attempt < MAX_TX_ATTEMPTS) {
    // Never call ESP-NOW APIs from inside this callback -- it runs on the
    // WiFi driver's own task, not the main loop. Just flag it; loop() (main
    // task) issues the actual retry send, then this callback fires again for
    // that attempt.
    s_retry_pending = true;
    s_retry_at = millis() + TX_RETRY_DELAY_MS;
    return;  // not complete yet -- loop() will retry, then mark complete
  }
  // This peer is done (succeeded, or exhausted its retries) -- move on to the
  // next known peer (or the flood broadcast pass, or finish) in loop(), same
  // "don't call ESP-NOW APIs from inside this callback" rule as the retry
  // path above.
  s_advance_pending = true;
}

static void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len) {
  // must at least contain magic header + checksum
  if (len < (int)(BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE) || len > (int)MAX_ESPNOW_PACKET_SIZE) {
    return;
  }

  uint16_t magic = (data[0] << 8) | data[1];
  if (magic == BRIDGE_TIME_MAGIC) {
    handleTimeBeacon(data, len);
    return;
  }
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
  if (!s_pending_learn && !isKnownPeer(mac)) {
    memcpy(s_pending_learn_mac, mac, 6);
    s_pending_learn = true;
  }

  memcpy(rx_buf, decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen);
  last_rx_len = (uint8_t)payloadLen;
  ESPNOW_DEBUG_PRINTLN("Recv: len = %d", (int)payloadLen);
}

// This board's onboard WS2812 expects RGB wire order, not the GRB
// neopixelWrite() assumes -- confirmed empirically (green displayed as red).
// R/G are swapped to compensate; blue is in the same wire position either way.
#define BOARD_LED_GREEN(pin, brightness) neopixelWrite(pin, brightness, 0, 0)
#define BOARD_LED_RED(pin, brightness)   neopixelWrite(pin, 0, brightness, 0)
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
  // Modem sleep adds latency/jitter to every RX window -- off for ESP-NOW.
  esp_wifi_set_ps(WIFI_PS_NONE);

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

  esp_wifi_set_max_tx_power(WIFI_TX_POWER * 4);

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

  // Any previously-learned unicast peers were on the old channel/secret --
  // stale now. Drop back to broadcast-only until peers are re-learned on the
  // new network.
  for (uint8_t i = 0; i < s_known_peer_count; i++) {
    esp_now_del_peer(s_known_peers[i]);
  }
  s_known_peer_count = 0;
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
  if (s_secret[0] == 0) {
    // Unconfigured board (bridge.secret never set) -- xorCrypt()'s keyLen
    // would be 0, causing a divide-by-zero (i % keyLen) crash. The mesh
    // dispatcher doesn't know this radio is unconfigured and will still try
    // to send a self-advert on boot regardless, so this has to be enforced
    // here, not just left to the "stays inert" comment in init() above.
    ESPNOW_DEBUG_PRINTLN("Send failed: bridge.secret not configured yet");
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
  s_send_started_at = millis();
  s_attempt_started_at = s_send_started_at;

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

  // A zero-hop advert (DIRECT route, no path) has no real destination --
  // it means "whoever's nearby, take note", the same as its inherently-
  // broadcast behaviour on LoRa's RF layer. It skips the known-peer fan-out
  // entirely and goes straight to one broadcast, same as when no peers are
  // known yet at all. Detected directly off the still-unencrypted header/
  // path-len bytes -- see Packet::writeTo() for the wire layout this
  // mirrors (byte 0 = header, byte 1 = path_len when route type isn't
  // one of the TRANSPORT_* variants, which a zero-hop advert never is).
  bool zero_hop_advert = (((bytes[0] >> PH_TYPE_SHIFT) & PH_TYPE_MASK) == PAYLOAD_TYPE_ADVERT)
                       && ((bytes[0] & PH_ROUTE_MASK) == ROUTE_TYPE_DIRECT)
                       && (bytes[1] == 0);
  // Any FLOOD-route packet (route type 0 or 1 -- see PH_ROUTE_MASK) is
  // inherently "for anyone listening", same as an advert -- not just this
  // one remembered peer. This is the actual fix: previously only zero-hop
  // adverts got broadcast, so a relayed FLOOD packet (e.g. a login request)
  // silently reached only whichever peer happened to be "known" at the time,
  // never the others.
  uint8_t route = bytes[0] & PH_ROUTE_MASK;
  s_is_flood = (route == ROUTE_TYPE_FLOOD || route == ROUTE_TYPE_TRANSPORT_FLOOD);

  s_flood_broadcast_done = false;
  s_active_peer_idx = (s_known_peer_count == 0 || zero_hop_advert) ? PEER_IDX_BROADCAST : 0;
  issueSendAttempt();
  if (is_send_complete) {
    // issueSendAttempt() hit a hard esp_now_send() failure and gave up
    // immediately -- report failure the same way the old code path did.
    ESPNOW_DEBUG_PRINTLN("Send failed");
    return false;
  }
  n_sent++;
  ESPNOW_DEBUG_PRINTLN("Send started (%s)", (s_active_peer_idx == PEER_IDX_BROADCAST) ? "broadcast" : "unicast");
  return true;
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
  // is_send_complete, covering every attempt in MAX_TX_ATTEMPTS's retry
  // loop above, not just the first. An earlier value here (4, -> 6ms
  // expiry) meant the callback almost never arrived in time at all --
  // Dispatcher gave up before the real completion landed, so logTx() (what
  // feeds bridge.sendPacket(), the IpBridge hook) essentially never fired
  // for any locally-sent packet. A later value (100, -> 150ms) was based on
  // a debugging session that claimed up to 13-SECOND completions -- that
  // claim was never reconciled with same-day live measurements showing
  // 8-43ms, and turned out to be unfounded once actually checked (see
  // MAX_TX_ATTEMPTS's comment above). 290 (-> 435ms expiry) was sized for
  // MAX_TX_ATTEMPTS=12's real single-peer worst case (~362ms, live-measured
  // math above), with margin.
  //
  // Now that a send can fan out to every known peer in turn (see
  // s_known_peers above), that per-peer worst case has to be multiplied by
  // how many peers a single logical send might actually visit -- otherwise
  // Dispatcher gives up and logs a failure while the fan-out is still
  // legitimately working through peers 2, 3, 4... A FLOOD packet visits
  // every known peer plus one extra broadcast pass; a DIRECT packet visits
  // every known peer (no extra pass) -- so "known peers + 1" covers both,
  // without needing to know here which kind of packet is in flight.
  return 290 * ((uint32_t)s_known_peer_count + 1);
}

// Issues one esp_now_send() for whichever peer s_active_peer_idx currently
// points at (a real known-peer slot, or the PEER_IDX_BROADCAST sentinel),
// resetting the per-peer retry-attempt counter. Shared by startSendRaw()
// (first peer of a new packet) and advanceOrFinish() (moving on to the next
// one). On a hard failure to even hand off to the driver, marks complete
// immediately -- same fallback OnDataSent() itself never gets a chance to
// fire for.
static void issueSendAttempt() {
  s_tx_attempt = 1;
  s_attempt_started_at = millis();
  const uint8_t* dest = (s_active_peer_idx == PEER_IDX_BROADCAST)
                       ? broadcastAddress : s_known_peers[s_active_peer_idx];
  esp_err_t result = esp_now_send(dest, s_last_tx_buffer, s_last_tx_len);
  if (result != ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("esp_now_send() call failed, err=%d", (int)result);
    is_send_complete = true;
  }
}

// Called once the current peer's send has either succeeded or exhausted its
// retries (see OnDataSent()'s s_advance_pending). Mirrors
// ESPNowBridge::advanceToNextPeerOrFinish()'s fan-out shape: unicast to every
// known peer in turn, then (FLOOD/zero-hop-advert only) one extra broadcast
// pass to reach anyone not yet individually learned, then done.
static void advanceOrFinish() {
  bool wasBroadcast = (s_active_peer_idx == PEER_IDX_BROADCAST);
  uint8_t nextPeerIdx = wasBroadcast ? 0 : (uint8_t)(s_active_peer_idx + 1);

  if (!wasBroadcast && s_known_peer_count > 0 && nextPeerIdx < s_known_peer_count) {
    s_active_peer_idx = nextPeerIdx;
    issueSendAttempt();
    return;
  }

  // Unicast fan-out to every known peer is done (or there were none). FLOOD
  // traffic still needs to reach whoever hasn't been individually learned
  // yet -- a purely passive listener would otherwise never be reachable once
  // ANY other peer becomes known. DIRECT traffic skips this: unicast to
  // every known peer, or the sole bootstrap broadcast if none are known yet,
  // is already correct for it.
  if (!wasBroadcast && !s_flood_broadcast_done && s_known_peer_count > 0 && s_is_flood) {
    s_flood_broadcast_done = true;
    s_active_peer_idx = PEER_IDX_BROADCAST;
    issueSendAttempt();
    return;
  }

  is_send_complete = true;
}

void ESPNowBridgeRadio::loop() {
  if (s_pending_learn) {
    s_pending_learn = false;
    if (s_known_peer_count < MAX_KNOWN_PEERS && !isKnownPeer(s_pending_learn_mac)) {
      esp_now_peer_info_t unicastPeer = {};
      memcpy(unicastPeer.peer_addr, s_pending_learn_mac, 6);
      unicastPeer.channel = s_channel;
      unicastPeer.encrypt = false;
      if (esp_now_add_peer(&unicastPeer) == ESP_OK) {
        memcpy(s_known_peers[s_known_peer_count], s_pending_learn_mac, 6);
        s_known_peer_count++;
        ESPNOW_DEBUG_PRINTLN("Learned peer, now tracking %d for unicast", (int)s_known_peer_count);
      } else {
        ESPNOW_DEBUG_PRINTLN("Failed to register peer for unicast, staying on broadcast for it");
      }
    }
    // else: already known, or table full -- that peer just stays reachable
    // only via the FLOOD broadcast pass, same as ESPNowBridge's "table full"
    // case.
  }

  if (s_retry_pending && (int32_t)(millis() - s_retry_at) >= 0) {
    s_retry_pending = false;
    s_tx_attempt++;
    s_attempt_started_at = millis();
    const uint8_t* dest = (s_active_peer_idx == PEER_IDX_BROADCAST)
                         ? broadcastAddress : s_known_peers[s_active_peer_idx];
    esp_err_t result = esp_now_send(dest, s_last_tx_buffer, s_last_tx_len);
    if (result != ESP_OK) {
      // Couldn't even hand off the retry -- give up on this peer and move on,
      // same as exhausting MAX_TX_ATTEMPTS (see advanceOrFinish()).
      ESPNOW_DEBUG_PRINTLN("Retry send failed: %d", (int)result);
      s_advance_pending = true;
    }
    // else: wait for OnDataSent() again for this attempt.
  }

  if (s_advance_pending) {
    s_advance_pending = false;
    advanceOrFinish();
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
