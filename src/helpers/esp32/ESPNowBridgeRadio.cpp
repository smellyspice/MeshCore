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

// runtime-overridable copies of the boot-time BRIDGE_CHANNEL/BRIDGE_SECRET
// defaults -- see ESPNowBridgeRadio::setBridgeParams().
static uint8_t s_channel = BRIDGE_CHANNEL;
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
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("Send Status: %d", (int)status);
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
#define BOARD_LED_OFF(pin)               neopixelWrite(pin, 0, 0, 0)

void ESPNowBridgeRadio::init() {
  // power-on indicator: steady green for 3s. Non-blocking -- turned off later
  // by loop()'s timer check (same mechanism as the TX/RX flashes below),
  // rather than a blocking delay() here.
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
  _boot_led_on = true;
  _boot_led_off_at = millis() + 3000;
#endif

  setSecret(BRIDGE_SECRET);  // boot-time default; setBridgeParams() may override later once prefs load

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

  // Channel must be set explicitly to match the repeater's 'bridge.channel',
  // and set *after* esp_now_init() -- setting it before has been reported to
  // not reliably stick on some ESP32-S3 boards.
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

  esp_wifi_set_max_tx_power(80);  // 20dBm, matches default LORA_TX_POWER applied again in begin()

  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = s_channel;
  peerInfo.encrypt = false;

  is_send_complete = true;

  // Add peer
  if (esp_now_add_peer(&peerInfo) == ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("init success, channel=%d", s_channel);
  } else {
    ESPNOW_DEBUG_PRINTLN("Failed to add peer");
  }
}

void ESPNowBridgeRadio::relockChannel() {
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
}

void ESPNowBridgeRadio::setBridgeParams(uint8_t channel, const char* secret) {
  s_channel = channel;
  setSecret(secret);

  // re-apply immediately: channel via WiFi, and the broadcast peer's channel field
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
  peerInfo.channel = s_channel;
  esp_now_del_peer(broadcastAddress);
  esp_now_add_peer(&peerInfo);

  ESPNOW_DEBUG_PRINTLN("setBridgeParams: channel=%d", s_channel);
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

  uint8_t buffer[MAX_ESPNOW_PACKET_SIZE];

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

  const size_t totalLen = offset + len;
  esp_err_t result = esp_now_send(broadcastAddress, buffer, totalLen);
  if (result == ESP_OK) {
    n_sent++;
    ESPNOW_DEBUG_PRINTLN("Send success");
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
  return 4;  // Fast AF
}

void ESPNowBridgeRadio::loop() {
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
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    _boot_led_on = false;
  }
#endif
}
