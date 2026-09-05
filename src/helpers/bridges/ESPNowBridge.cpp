#include "ESPNowBridge.h"

#include <WiFi.h>
#include <esp_wifi.h>

// Boot-time default max power for this board's WiFi radio (see
// src/helpers/esp32/ESPNOWRadio.cpp -- shared convention so ESP-NOW and
// plain WiFi use on the same board agree).
#ifndef WIFI_TX_POWER
#define WIFI_TX_POWER 20
#endif

#ifdef WITH_ESPNOW_BRIDGE

// Static member to handle callbacks
ESPNowBridge *ESPNowBridge::_instance = nullptr;

// Static callback wrappers
void ESPNowBridge::recv_cb(const uint8_t *mac, const uint8_t *data, int32_t len) {
  if (_instance) {
    _instance->onDataRecv(mac, data, len);
  }
}

void ESPNowBridge::send_cb(const uint8_t *mac, esp_now_send_status_t status) {
  if (_instance) {
    _instance->onDataSent(mac, status);
  }
}

ESPNowBridge::ESPNowBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc), _rx_buffer_pos(0) {
  _instance = this;
}

void ESPNowBridge::learnPeer(const uint8_t *mac) {
  for (uint8_t i = 0; i < _known_peer_count; i++) {
    if (memcmp(_known_peers[i], mac, 6) == 0) return;  // already known
  }
  if (_known_peer_count >= MAX_KNOWN_PEERS) return;  // table full -- stays on broadcast for this one

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, mac, 6);
  peerInfo.channel = _prefs->bridge_channel;
  peerInfo.encrypt = false;
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Failed to register peer for unicast\n");
    return;
  }

  memcpy(_known_peers[_known_peer_count], mac, 6);
  _known_peer_count++;
  BRIDGE_DEBUG_PRINTLN("Learned peer, now tracking %d for unicast\n", (int)_known_peer_count);
}

void ESPNowBridge::begin() {
  BRIDGE_DEBUG_PRINTLN("Initializing...\n");

  // Initialize WiFi in station mode
  WiFi.mode(WIFI_STA);

  esp_wifi_set_max_tx_power(WIFI_TX_POWER * 4);

  // Set Wi-Fi channel
  if (esp_wifi_set_channel(_prefs->bridge_channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Error setting WIFI channel to %d\n", _prefs->bridge_channel);
    return;
  }

  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Error initializing ESP-NOW\n");
    return;
  }

  // Register callbacks
  esp_now_register_recv_cb(recv_cb);
  esp_now_register_send_cb(send_cb);

  // Add broadcast peer
  esp_now_peer_info_t peerInfo = {};
  memset(&peerInfo, 0, sizeof(peerInfo));
  memset(peerInfo.peer_addr, 0xFF, ESP_NOW_ETH_ALEN); // Broadcast address
  peerInfo.channel = _prefs->bridge_channel;
  peerInfo.encrypt = false;

  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Failed to add broadcast peer\n");
    return;
  }

  // Reset unicast/retry/queue state -- begin() can be called again after end()
  // (e.g. bridge.enabled toggled off/on), so this can't just rely on
  // constructor-time initializers.
  _known_peer_count = 0;
  for (uint8_t i = 0; i < MAX_QUEUED_SENDS; i++) _send_queue[i].in_use = false;
  _active_queue_idx = -1;
  _active_peer_idx = 0;
  _send_attempt = 0;
  _send_in_flight = false;
  _send_awaiting_retry = false;

  // Update bridge state
  _initialized = true;
}

void ESPNowBridge::end() {
  BRIDGE_DEBUG_PRINTLN("Stopping...\n");

  // Remove broadcast peer
  uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  if (esp_now_del_peer(broadcastAddress) != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Error removing broadcast peer\n");
  }

  // esp_now_deinit() below frees all peers regardless, but remove them
  // explicitly first for clarity/symmetry with begin()'s registration.
  for (uint8_t i = 0; i < _known_peer_count; i++) {
    esp_now_del_peer(_known_peers[i]);
  }
  _known_peer_count = 0;

  // Unregister callbacks
  esp_now_register_recv_cb(nullptr);
  esp_now_register_send_cb(nullptr);

  // Deinitialize ESP-NOW
  if (esp_now_deinit() != ESP_OK) {
    BRIDGE_DEBUG_PRINTLN("Error deinitializing ESP-NOW\n");
  }

  // Turn off WiFi
  WiFi.mode(WIFI_OFF);

  // Update bridge state
  _initialized = false;
}

void ESPNowBridge::loop() {
  if (_send_awaiting_retry && (int32_t)(millis() - _send_retry_at) >= 0) {
    _send_awaiting_retry = false;
    issueSend();
  }
}

void ESPNowBridge::xorCrypt(uint8_t *data, size_t len) {
  size_t keyLen = strlen(_prefs->bridge_secret);
  for (size_t i = 0; i < len; i++) {
    data[i] ^= _prefs->bridge_secret[i % keyLen];
  }
}

void ESPNowBridge::onDataRecv(const uint8_t *mac, const uint8_t *data, int32_t len) {
  // Ignore packets that are too small to contain header + checksum
  if (len < (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE)) {
    BRIDGE_DEBUG_PRINTLN("RX packet too small, len=%d\n", len);
    return;
  }

  // Validate total packet size
  if (len > MAX_ESPNOW_PACKET_SIZE) {
    BRIDGE_DEBUG_PRINTLN("RX packet too large, len=%d\n", len);
    return;
  }

  // Check packet header magic
  uint16_t received_magic = (data[0] << 8) | data[1];
  if (received_magic != BRIDGE_PACKET_MAGIC) {
    BRIDGE_DEBUG_PRINTLN("RX invalid magic 0x%04X\n", received_magic);
    return;
  }

  // Make a copy we can decrypt
  uint8_t decrypted[MAX_ESPNOW_PACKET_SIZE];
  const size_t encryptedDataLen = len - BRIDGE_MAGIC_SIZE;
  memcpy(decrypted, data + BRIDGE_MAGIC_SIZE, encryptedDataLen);

  // Try to decrypt (checksum + payload)
  xorCrypt(decrypted, encryptedDataLen);

  // Validate checksum
  uint16_t received_checksum = (decrypted[0] << 8) | decrypted[1];
  const size_t payloadLen = encryptedDataLen - BRIDGE_CHECKSUM_SIZE;

  if (!validateChecksum(decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen, received_checksum)) {
    // Failed to decrypt - likely from a different network
    BRIDGE_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04X\n", received_checksum);
    return;
  }

  // A valid, correctly-decrypted frame from this MAC -- worth remembering so
  // future sends to it can use unicast (real ACK+retry) instead of broadcast.
  // Only done post-checksum so a spoofed/garbage sender can't pollute the
  // peer table (not a security boundary -- MAC spoofing is trivial on
  // ESP-NOW -- just avoids wasting a table slot on noise).
  _instance->learnPeer(mac);
  _instance->_last_activity_at = millis();

  BRIDGE_DEBUG_PRINTLN("RX, payload_len=%d\n", payloadLen);

  // Create mesh packet
  mesh::Packet *pkt = _instance->_mgr->allocNew();
  if (!pkt) return;

  if (pkt->readFrom(decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen)) {
    _instance->onPacketReceived(pkt);
  } else {
    _instance->_mgr->free(pkt);
  }
}

void ESPNowBridge::onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  onSendResult(status == ESP_NOW_SEND_SUCCESS);
}

void ESPNowBridge::onSendResult(bool ok) {
  _send_in_flight = false;
  _last_activity_at = millis();

  if (_time_beacon_pending) {
    _time_beacon_pending = false;
    BRIDGE_DEBUG_PRINTLN("Time beacon %s\n", ok ? "sent" : "send failed");
    progressSend();  // in case a real packet got queued while the beacon was in flight
    return;
  }

  if (_active_queue_idx < 0) return;  // stray/late callback after a reset -- nothing to do

  unsigned long dt = millis() - _send_issued_at;
  if (ok) {
    BRIDGE_DEBUG_PRINTLN("TX ok, peer_idx=%d attempt=%d, +%lums since issueSend()\n",
                         (int)_active_peer_idx, (int)_send_attempt, dt);
    advanceToNextPeerOrFinish();
  } else if (_send_attempt < MAX_SEND_ATTEMPTS) {
    BRIDGE_DEBUG_PRINTLN("TX failed, will retry (attempt %d of %d), +%lums since issueSend()\n",
                         (int)_send_attempt, (int)MAX_SEND_ATTEMPTS, dt);
    _send_awaiting_retry = true;
    _send_retry_at = millis() + SEND_RETRY_DELAY_MS;
  } else {
    BRIDGE_DEBUG_PRINTLN("TX failed after %d attempts, giving up on this peer, +%lums since issueSend()\n",
                         (int)_send_attempt, dt);
    advanceToNextPeerOrFinish();
  }
}

void ESPNowBridge::advanceToNextPeerOrFinish() {
  bool wasBroadcast = (_active_peer_idx == PEER_IDX_BROADCAST);
  uint8_t nextPeerIdx = wasBroadcast ? 0 : (uint8_t)(_active_peer_idx + 1);

  if (!wasBroadcast && _known_peer_count > 0 && nextPeerIdx < _known_peer_count) {
    _active_peer_idx = nextPeerIdx;
    _send_attempt = 0;
    issueSend();
    return;
  }

  // Unicast fan-out to every known peer is done (or there were none). FLOOD
  // traffic still needs to reach whoever we haven't individually learned yet
  // -- a purely passive listener (e.g. a room server that never transmits)
  // would otherwise never be reachable once ANY other peer becomes known,
  // since the branch above only ever unicasts to the known-peers list. One
  // extra broadcast covers that, without giving up the unicast-with-retry
  // reliability benefit for peers we do know. DIRECT traffic (a single real
  // destination) skips this -- unicast-with-retry to a known peer, or the
  // sole bootstrap broadcast if none are known yet, is already correct for it.
  if (!wasBroadcast && !_flood_broadcast_done && _known_peer_count > 0 &&
      _send_queue[_active_queue_idx].is_flood) {
    _flood_broadcast_done = true;
    _active_peer_idx = PEER_IDX_BROADCAST;
    _send_attempt = 0;
    issueSend();
    return;
  }

  // Done -- free this queue slot and pick up whatever's next.
  _send_queue[_active_queue_idx].in_use = false;
  _active_queue_idx = -1;
  progressSend();
}

void ESPNowBridge::issueSend() {
  if (_active_queue_idx < 0) return;
  QueuedSend &q = _send_queue[_active_queue_idx];

  uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  const uint8_t *dest = (_active_peer_idx == PEER_IDX_BROADCAST)
                             ? broadcastAddress
                             : _known_peers[_active_peer_idx];

  _send_attempt++;
  _send_in_flight = true;
  _send_issued_at = millis();
  esp_err_t result = esp_now_send(dest, q.buffer, q.len);
  if (result != ESP_OK) {
    // Couldn't even hand this off to the driver -- treat like an immediate
    // send failure so it still gets the same retry/give-up handling.
    BRIDGE_DEBUG_PRINTLN("esp_now_send() call failed, err=%d\n", (int)result);
    onSendResult(false);
  }
}

void ESPNowBridge::progressSend() {
  if (_active_queue_idx >= 0 || _send_in_flight || _send_awaiting_retry) return;  // already busy

  for (uint8_t i = 0; i < MAX_QUEUED_SENDS; i++) {
    if (_send_queue[i].in_use) {
      _active_queue_idx = i;
      // Zero-hop adverts skip the known-peer unicast fan-out entirely --
      // one broadcast is the whole point (see QueuedSend::is_zero_hop_advert)
      // -- same as when no peers are known yet at all.
      _active_peer_idx = (_known_peer_count == 0 || _send_queue[i].is_zero_hop_advert)
                        ? PEER_IDX_BROADCAST : 0;
      _send_attempt = 0;
      _flood_broadcast_done = false;
      issueSend();
      return;
    }
  }
}

void ESPNowBridge::sendPacket(mesh::Packet *packet) {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  // First validate the packet pointer
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }

  if (_tx_seen.wasSeen(packet)) return;
  _tx_seen.markSeen(packet);

  // Create a temporary buffer just for size calculation and reuse for actual writing
  uint8_t sizingBuffer[MAX_PAYLOAD_SIZE];
  uint16_t meshPacketLen = packet->writeTo(sizingBuffer);

  // Check if packet fits within our maximum payload size
  if (meshPacketLen > MAX_PAYLOAD_SIZE) {
    BRIDGE_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", meshPacketLen,
                         MAX_PAYLOAD_SIZE);
    return;
  }

  int8_t slot = -1;
  for (uint8_t i = 0; i < MAX_QUEUED_SENDS; i++) {
    if (!_send_queue[i].in_use) { slot = (int8_t)i; break; }
  }
  if (slot < 0) {
    // Fanning out a previous packet to several peers (with retries) is
    // taking a while and the queue's backed up -- drop rather than block,
    // same tradeoff BridgeBase's own dedup/queueing already makes elsewhere.
    BRIDGE_DEBUG_PRINTLN("TX send queue full, dropping packet\n");
    return;
  }

  QueuedSend &q = _send_queue[slot];
  q.is_flood = packet->isRouteFlood();
  q.is_zero_hop_advert = packet->getPayloadType() == PAYLOAD_TYPE_ADVERT
                       && packet->getRouteType() == ROUTE_TYPE_DIRECT
                       && packet->path_len == 0;

  // Write magic header (2 bytes)
  q.buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  q.buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;

  // Write packet payload starting after magic header and checksum
  const size_t packetOffset = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;
  memcpy(q.buffer + packetOffset, sizingBuffer, meshPacketLen);

  // Calculate and add checksum (only of the payload)
  uint16_t checksum = fletcher16(q.buffer + packetOffset, meshPacketLen);
  q.buffer[2] = (checksum >> 8) & 0xFF; // High byte
  q.buffer[3] = checksum & 0xFF;        // Low byte

  // Encrypt payload and checksum (not including magic header)
  xorCrypt(q.buffer + BRIDGE_MAGIC_SIZE, meshPacketLen + BRIDGE_CHECKSUM_SIZE);

  // Total packet size: magic header + checksum + payload
  q.len = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + meshPacketLen;
  q.in_use = true;

  BRIDGE_DEBUG_PRINTLN("TX queued, len=%d, known_peers=%d\n", meshPacketLen, (int)_known_peer_count);
  progressSend();
}

bool ESPNowBridge::broadcastTime(uint32_t timestamp) {
  if (!_initialized) return false;
  // Same single-send-in-flight rule as the queue machinery -- don't stomp a
  // real packet's send (or a previous beacon still completing). Skipping this
  // round is fine; the caller broadcasts again in a few minutes regardless.
  if (_active_queue_idx >= 0 || _send_in_flight || _send_awaiting_retry) return false;

  static const size_t TIME_PAYLOAD_SIZE = 4;
  uint8_t buf[BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + TIME_PAYLOAD_SIZE];

  buf[0] = (BRIDGE_TIME_MAGIC >> 8) & 0xFF;
  buf[1] = BRIDGE_TIME_MAGIC & 0xFF;

  uint8_t *payload = buf + BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;
  payload[0] = (timestamp >> 24) & 0xFF;
  payload[1] = (timestamp >> 16) & 0xFF;
  payload[2] = (timestamp >> 8) & 0xFF;
  payload[3] = timestamp & 0xFF;

  uint16_t checksum = fletcher16(payload, TIME_PAYLOAD_SIZE);
  buf[2] = (checksum >> 8) & 0xFF;
  buf[3] = checksum & 0xFF;

  xorCrypt(buf + BRIDGE_MAGIC_SIZE, BRIDGE_CHECKSUM_SIZE + TIME_PAYLOAD_SIZE);

  uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  _send_in_flight = true;
  _time_beacon_pending = true;
  esp_err_t result = esp_now_send(broadcastAddress, buf, sizeof(buf));
  if (result != ESP_OK) {
    _send_in_flight = false;
    _time_beacon_pending = false;
    BRIDGE_DEBUG_PRINTLN("Time beacon: esp_now_send() failed, err=%d\n", (int)result);
    return false;
  }
  BRIDGE_DEBUG_PRINTLN("Time beacon: broadcasting t=%u\n", timestamp);
  return true;
}

void ESPNowBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

#endif
