#pragma once

#include "MeshCore.h"
#include "esp_now.h"
#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_ESPNOW_BRIDGE

/**
 * @brief Bridge implementation using ESP-NOW protocol for packet transport
 *
 * This bridge enables mesh packet transport over ESP-NOW, a connectionless communication
 * protocol provided by Espressif that allows ESP32 devices to communicate directly
 * without WiFi router infrastructure.
 *
 * Features:
 * - Broadcast-based communication (all bridges receive all packets)
 * - Network isolation using XOR encryption with shared secret
 * - Duplicate packet detection using SimpleMeshTables tracking
 * - Maximum packet size of 250 bytes (ESP-NOW limitation)
 *
 * Packet Structure:
 * [2 bytes] Magic Header - Used to identify ESPNowBridge packets
 * [2 bytes] Fletcher-16 checksum of encrypted payload (calculated over payload only)
 * [246 bytes max] Encrypted payload containing the mesh packet
 *
 * The Fletcher-16 checksum is used to validate packet integrity and detect
 * corrupted or tampered packets. It's calculated over the encrypted payload
 * and provides a simple but effective way to verify packets are both
 * uncorrupted and from the same network (since the checksum is calculated
 * after encryption).
 *
 * Configuration:
 * - Define WITH_ESPNOW_BRIDGE to enable this bridge
 * - Define _prefs->bridge_secret with a string to set the network encryption key
 *
 * Network Isolation:
 * Multiple independent mesh networks can coexist by using different
 * _prefs->bridge_secret values. Packets encrypted with a different key will
 * fail the checksum validation and be discarded.
 */
class ESPNowBridge : public BridgeBase {
private:
  static ESPNowBridge *_instance;
  static void recv_cb(const uint8_t *mac, const uint8_t *data, int32_t len);
  static void send_cb(const uint8_t *mac, esp_now_send_status_t status);

  /**
   * ESP-NOW Protocol Structure:
   * - ESP-NOW header: 20 bytes (handled by ESP-NOW protocol)
   * - ESP-NOW payload: 250 bytes maximum
   * Total ESP-NOW packet: 270 bytes
   *
   * Our Bridge Packet Structure (must fit in ESP-NOW payload):
   * - Magic header: 2 bytes
   * - Checksum: 2 bytes
   * - Available payload: 246 bytes
   */
  static const size_t MAX_ESPNOW_PACKET_SIZE = 250;

  /**
   * Size constants for packet parsing
   */
  static const size_t MAX_PAYLOAD_SIZE = MAX_ESPNOW_PACKET_SIZE - (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE);

  /** Buffer for receiving ESP-NOW packets */
  uint8_t _rx_buffer[MAX_ESPNOW_PACKET_SIZE];

  /** Current position in receive buffer */
  size_t _rx_buffer_pos;

  // BridgeBase's inherited _seen_packets is shared between RX and TX -- a
  // packet that arrived FROM this bridge (e.g. a companion/room-server-role
  // peer on the same ESP-NOW segment) is already marked seen by the time
  // logTx()'s mirror-back call reaches sendPacket() below, so it gets
  // silently dropped instead of relayed to any other peer on this same
  // bridge -- a real, 100%-reproducible failure for any peer-to-peer
  // relay through this bridge, not an RF/reliability issue. Same class of
  // bug IpBridge already fixed the same way (see IpBridge.h's _tx_seen);
  // ESPNowBridge just hadn't been given the equivalent fix yet.
  SimpleMeshTables _tx_seen;

  // --- Reliability: unicast-with-retry instead of fire-and-forget broadcast ---
  //
  // Broadcast ESP-NOW frames get NO MAC-layer ACK/retry at all (that's normal
  // 802.11 behaviour, not an ESP-NOW quirk) -- every broadcast is exactly one
  // shot on air. Unicast frames, by contrast, get real hardware-level ACK +
  // automatic retry from the WiFi radio/firmware itself, for free, before
  // send_cb() even fires. So instead of always broadcasting, we learn the MAC
  // of every peer we've actually heard from (companions/repeaters we're
  // bridged with) and unicast to each of them individually, falling back to
  // broadcast only for peers we haven't heard from yet (bootstrap case).
  //
  // A single outbound mesh packet can therefore fan out to multiple unicast
  // sends (one per known peer) -- these are deliberately serialized (wait for
  // each send_cb() before starting the next), matching ESP-NOW's own guidance
  // that sending again before the previous send's callback has returned can
  // cause "disorder" of the callback. A small bounded queue absorbs bursts
  // that arrive while a previous packet's fan-out/retries are still in flight.
  // ESP-NOW's own hard limit is ESP_NOW_MAX_TOTAL_PEER_NUM=20 total
  // registered peers (esp_now.h) -- NOT ESP_NOW_MAX_ENCRYPT_PEER_NUM=6,
  // which only applies to encrypted peers and this bridge always registers
  // with encrypt=false. One of the 20 slots is permanently used by the
  // broadcast address (also registered via esp_now_add_peer(), see begin()),
  // leaving 19 as the real max for individually-tracked unicast peers.
  // Previously hardcoded to 6 with no documented reason -- raised to the
  // actual safe maximum 2026-09-01 to support more than a handful of
  // ESP-NOW peers on one repeater.
  static const uint8_t MAX_KNOWN_PEERS = 19;
  static const uint8_t MAX_QUEUED_SENDS = 4;
  // Matches ESPNowBridgeRadio.cpp's MAX_TX_ATTEMPTS (raised 4->12 in beta 4 for
  // the exact same reason): the client->bridge direction and this bridge->client
  // direction cross the same physical, sometimes-marginal ESP-NOW link -- there's
  // no reason retries would help one direction and not the other. This constant
  // was never raised alongside the client-side one, leaving replies/relays back
  // out to a peer meaningfully less reliable than requests coming in.
  static const uint8_t MAX_SEND_ATTEMPTS = 12;     // 1 initial + 11 retries, per peer
  static const uint32_t SEND_RETRY_DELAY_MS = 30;  // backoff before re-trying a failed unicast

  uint8_t _known_peers[MAX_KNOWN_PEERS][6];
  uint8_t _known_peer_count = 0;

  struct QueuedSend {
    uint8_t buffer[MAX_ESPNOW_PACKET_SIZE];
    size_t len = 0;
    bool in_use = false;
    // FLOOD-route traffic (group channel messages, adverts, etc.) is meant
    // to reach everyone, not just peers we've individually heard from --
    // unlike DIRECT traffic, which has one real destination and benefits
    // from unicast-with-retry to it specifically. See advanceToNextPeerOrFinish().
    bool is_flood = false;
    // A zero-hop advert (DIRECT route, no path) is the one DIRECT-route
    // exception to that rule -- it has no real destination either, just
    // "whoever's nearby", the same as its inherently-broadcast behaviour
    // on LoRa's RF layer. Unicasting it to only the peers we already know
    // about would leave any other peer on this same ESP-NOW segment (e.g.
    // one that's never transmitted, so we've never learned its MAC)
    // completely unaware of it. See progressSend().
    bool is_zero_hop_advert = false;
  };
  QueuedSend _send_queue[MAX_QUEUED_SENDS];

  // State for whichever queued send is currently being fanned out to peers.
  int8_t _active_queue_idx = -1;   // -1 = nothing in flight
  uint8_t _active_peer_idx = 0;    // index into _known_peers (or "broadcast" sentinel below)
  uint8_t _send_attempt = 0;
  bool _send_in_flight = false;
  bool _send_awaiting_retry = false;
  // Set once the extra post-unicast-fan-out broadcast (FLOOD traffic only,
  // see advanceToNextPeerOrFinish()) has been done for the current queued
  // send, so it fires at most once per packet, not every time advance is called.
  bool _flood_broadcast_done = false;
  unsigned long _send_retry_at = 0;
  unsigned long _send_issued_at = 0;  // millis() at issueSend() -- timing instrumentation, see onSendResult()

  // --- Time-sync beacon (see broadcastTime()) ---
  // A one-shot broadcast, not routed through the queue/fan-out machinery
  // above (it has no mesh::Packet, no peer-specific destination, and no
  // retry -- missing one is fine, another follows in a few minutes). It
  // still shares the single esp_now_send()-in-flight-at-a-time constraint
  // everything else here respects, so it's gated by (and sets) the same
  // _send_in_flight flag; this flag tells onSendResult() the completing
  // callback belongs to the beacon, not the queue.
  bool _time_beacon_pending = false;

  // millis() of the last completed send (success or final failure) or
  // received frame -- see shouldDeferHeartbeat().
  unsigned long _last_activity_at = 0;
  // Observed live: a companion's reply, sent within ~20ms of receiving
  // something from this bridge, can arrive right as this bridge itself was
  // just active -- covers that whole round-trip window, not just "literally
  // mid-send right now".
  static const uint32_t ACTIVITY_GRACE_MS = 50;
  static const uint8_t PEER_IDX_BROADCAST = 0xFF;  // sentinel: no known peers yet, use broadcast

  /**
   * Remembers a peer's MAC (from an incoming frame) so future sends to it can
   * use unicast instead of broadcast. Registers it as a real ESP-NOW peer.
   * No-op if already known or the table is full.
   */
  void learnPeer(const uint8_t *mac);

  /**
   * Starts fanning out _send_queue[_active_queue_idx] to peers if nothing is
   * currently in flight for it. Called both when a new packet is queued and
   * after each send completes/retries.
   */
  void progressSend();

  /**
   * Actually issues one esp_now_send() for the currently active queued send,
   * to either _known_peers[_active_peer_idx] or the broadcast address if
   * _active_peer_idx == PEER_IDX_BROADCAST.
   */
  void issueSend();

  /**
   * Handles the outcome of one send attempt (from either the async send_cb()
   * or an immediate esp_now_send() failure): on success or attempts
   * exhausted, moves on; on failure with attempts remaining, schedules a
   * retry via loop().
   */
  void onSendResult(bool ok);

  /**
   * Advances to the next known peer for the current queued send, or -- if
   * that was the last one (or the sole broadcast attempt) -- marks the
   * queued send done and picks up whatever's next in the queue.
   */
  void advanceToNextPeerOrFinish();

  /**
   * Performs XOR encryption/decryption of data
   * Used to isolate different mesh networks
   *
   * Uses _prefs->bridge_secret as the key in a simple XOR operation.
   * The same operation is used for both encryption and decryption.
   * While not cryptographically secure, it provides basic network isolation.
   *
   * @param data Pointer to data to encrypt/decrypt
   * @param len Length of data in bytes
   */
  void xorCrypt(uint8_t *data, size_t len);

  /**
   * ESP-NOW receive callback
   * Called by ESP-NOW when a packet is received
   *
   * @param mac Source MAC address
   * @param data Received data
   * @param len Length of received data
   */
  void onDataRecv(const uint8_t *mac, const uint8_t *data, int32_t len);

  /**
   * ESP-NOW send callback
   * Called by ESP-NOW after a transmission attempt
   *
   * @param mac_addr Destination MAC address
   * @param status Transmission status
   */
  void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status);

public:
  /**
   * Constructs an ESPNowBridge instance
   *
   * @param prefs Node preferences for configuration settings
   * @param mgr PacketManager for allocating and queuing packets
   * @param rtc RTCClock for timestamping debug messages
   */
  ESPNowBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc);

  /**
   * Initializes the ESP-NOW bridge
   *
   * - Configures WiFi in station mode
   * - Initializes ESP-NOW protocol
   * - Registers callbacks
   * - Sets up broadcast peer
   */
  void begin() override;

  /**
   * Stops the ESP-NOW bridge
   *
   * - Removes broadcast peer
   * - Unregisters callbacks
   * - Deinitializes ESP-NOW protocol
   * - Turns off WiFi to release radio resources
   */
  void end() override;

  /**
   * Drives the send queue/retry state machine: advances to the next peer or
   * retry attempt once a send has completed or its retry backoff has
   * elapsed. Actual ESP-NOW TX/RX itself stays callback-based.
   */
  void loop() override;

  /**
   * Called when a packet is received via ESP-NOW
   * Queues the packet for mesh processing if not seen before
   *
   * @param packet The received mesh packet
   */
  void onPacketReceived(mesh::Packet *packet) override;

  /**
   * Called when a packet needs to be transmitted via ESP-NOW
   * Encrypts and broadcasts the packet if not seen before
   *
   * @param packet The mesh packet to transmit
   */
  void sendPacket(mesh::Packet *packet) override;

  /**
   * Broadcasts a 4-byte UTC timestamp to every board on this ESP-NOW segment,
   * framed/encrypted the same way as everything else here (magic + Fletcher-16
   * checksum + XOR keyed by bridge.secret) but with BRIDGE_TIME_MAGIC instead
   * of BRIDGE_PACKET_MAGIC, so ESPNowBridgeRadio clients can tell it apart from
   * a wrapped mesh::Packet without attempting to parse it as one. Caller
   * (simple_repeater's main.cpp/MyMesh) is responsible for only calling this
   * with a real NTP-sourced timestamp, and for pacing the calls -- this makes
   * no attempt to rate-limit itself. Returns false (and sends nothing) if the
   * bridge isn't initialized or a send is already in flight -- safe to just
   * skip that round and try again on the next scheduled call.
   */
  bool broadcastTime(uint32_t timestamp);

  /**
   * True while a send is in flight, or briefly after any send/receive
   * activity (see ACTIVITY_GRACE_MS) -- covers not just "literally mid-send"
   * but the short window right after, where a peer's own reply is likely
   * still in flight back to us. Lets a dual-bridge board (WITH_IP_BRIDGE
   * alongside this) hold off IpBridge's heartbeat ping for a tick rather
   * than risk it competing with an inbound ESP-NOW frame's MAC-ACK timing
   * for the radio -- see IpBridge::setDeferHeartbeat(). Confirmed live: a
   * companion's reply repeatedly failed 4/4 retries specifically when this
   * bridge's own heartbeat ping landed in the same window as the companion's
   * round trip.
   */
  bool shouldDeferHeartbeat() const {
    return _active_queue_idx >= 0 || _send_in_flight || _send_awaiting_retry ||
           (millis() - _last_activity_at < ACTIVITY_GRACE_MS);
  }
};

#endif
