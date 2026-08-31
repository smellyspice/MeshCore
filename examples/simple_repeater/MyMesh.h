#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include <RTClib.h>
#include <target.h>

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
#elif defined(ESP32)
  #include <SPIFFS.h>
  using File = fs::File;
#endif

#ifdef WITH_RS232_BRIDGE
#include "helpers/bridges/RS232Bridge.h"
#define WITH_BRIDGE
#endif

#ifdef WITH_ESPNOW_BRIDGE
#include "helpers/bridges/ESPNowBridge.h"
#define WITH_BRIDGE
#endif

#ifdef WITH_IP_BRIDGE
#include "helpers/bridges/IpBridge.h"
#define WITH_BRIDGE
#endif

#include <helpers/AdvertDataHelpers.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/ClientACL.h>
#include <helpers/CommonCLI.h>
#include <helpers/IdentityStore.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/StatsFormatHelper.h>
#include <helpers/TxtDataHelpers.h>
#include <helpers/RegionMap.h>
#include <helpers/RoutingPolicy.h>
#include "RateLimiter.h"

#ifndef FLOOD_ADVERT_JITTER_MS
  // +/- N ms applied to flood_advert_interval each time the timer
  // reschedules, so identically-configured boards don't all flood-advert
  // in lockstep (e.g. several repeaters bench-tested/provisioned together).
  #define FLOOD_ADVERT_JITTER_MS   (10UL * 60 * 1000) // +/- 10 minutes
#endif

#ifndef LOCAL_ADVERT_JITTER_MS
  // Same idea as FLOOD_ADVERT_JITTER_MS but scaled down -- advert_interval's
  // minimum is 60 minutes (vs. flood_advert_interval's 3 hours), so a smaller
  // window is used to avoid meaningfully changing the configured cadence.
  #define LOCAL_ADVERT_JITTER_MS   (2UL * 60 * 1000) // +/- 2 minutes
#endif

struct RepeaterStats {
  uint16_t batt_milli_volts;
  uint16_t curr_tx_queue_len;
  int16_t  noise_floor;
  int16_t  last_rssi;
  uint32_t n_packets_recv;
  uint32_t n_packets_sent;
  uint32_t total_air_time_secs;
  uint32_t total_up_time_secs;
  uint32_t n_sent_flood, n_sent_direct;
  uint32_t n_recv_flood, n_recv_direct;
  uint16_t err_events;                // was 'n_full_events'
  int16_t  last_snr;   // x 4
  uint16_t n_direct_dups, n_flood_dups;
  uint32_t total_rx_air_time_secs;
  uint32_t n_recv_errors;
};

struct NeighbourInfo {
  mesh::Identity id;
  uint32_t advert_timestamp;
  uint32_t heard_timestamp;
  int8_t snr; // multiplied by 4, user should divide to get float value
};

#ifndef MAX_BRIDGE_NEIGHBOURS
  // Sized to match MAX_NEIGHBOURS -- same population source (adverts heard
  // at 0 hops), so no reason for a smaller cap. Falls back to a small
  // default on a board where MAX_NEIGHBOURS isn't set at all.
  #if defined(MAX_NEIGHBOURS) && MAX_NEIGHBOURS > 0
    #define MAX_BRIDGE_NEIGHBOURS   MAX_NEIGHBOURS
  #else
    #define MAX_BRIDGE_NEIGHBOURS   8
  #endif
#endif

// Kept separate from neighbours[] so the RF-awareness check in
// getRetransmitDelay() isn't contaminated by bridge-heard identities. Merged
// only at display time (formatAllNeighborsReply()), with a 'via' column.
struct BridgeNeighbourInfo {
  mesh::Identity id;
  uint32_t heard_timestamp;
  int8_t snr;   // meaningful for ESPNOW (real RF), not for IP -- 'via' tells the reader which
  uint8_t via;  // BRIDGE_VIA_* below
};

#define BRIDGE_VIA_UNKNOWN  0
#define BRIDGE_VIA_RS232    1
#define BRIDGE_VIA_ESPNOW   2
#define BRIDGE_VIA_IP       3

// How long a bridge_neighbours[] entry stays trusted for
// findBridgeOnlyNextHop() to redirect on. Generous on purpose: a stale entry
// just costs one unnecessary bridge send, but a too-eager one could misroute.
#define BRIDGE_NEIGHBOUR_FRESHNESS_SECS   (30 * 60)

// Max age for recv_pkt_source_bridge to still be trusted by trySendViaBridge().
// Same-turn reply generation is synchronous, so this should always be near-
// instant in practice; the bound exists to stop a stale flag from applying to
// an unrelated later send.
#define RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS   1000

#ifdef WITH_IP_BRIDGE
// A PATH-return crossing the IP bridge is what decides whether a contact
// ends up using RF or IP. When a live RF neighbour exists, logTx() holds the
// packet briefly instead of mirroring it immediately, giving a genuine RF
// path a head start -- if it completes in time, the held IP copy just
// arrives as a harmless duplicate (existing dedup absorbs it) instead of
// racing ahead of it. Only PAYLOAD_TYPE_PATH packets are delayed.

// "Live" = heard directly within this window. Generous on purpose: erring
// toward "still live" only costs some held-back latency, never correctness.
#define RF_AWARENESS_WINDOW_SECS   (30 * 60)

// One PATH-return per re-established route, not per message -- low volume,
// so a handful of slots is ample.
#define MAX_PENDING_IP_SENDS   4

struct PendingIpSend {
  mesh::Packet* packet;        // NULL = empty slot
  unsigned long release_at;    // millis() timestamp; send once passed
};
#endif

#ifndef FIRMWARE_BUILD_DATE
  #define FIRMWARE_BUILD_DATE   "14 Aug 2026"
#endif

#ifndef FIRMWARE_VERSION
  #define FIRMWARE_VERSION   "v1.17.1"
#endif

#define FIRMWARE_ROLE "repeater"

#define PACKET_LOG_FILE  "/packet_log"

class MyMesh : public mesh::Mesh, public CommonCLICallbacks {
  FILESYSTEM* _fs;
  uint32_t last_millis;
  uint64_t uptime_millis;
  unsigned long next_local_advert, next_flood_advert;
  bool _logging;
  NodePrefs _prefs;
  ClientACL  acl;
  CommonCLI _cli;
  uint8_t reply_data[MAX_PACKET_PAYLOAD];
  uint8_t reply_path[MAX_PATH_SIZE];
  uint8_t reply_path_len;
  TransportKeyStore key_store;
  RegionMap region_map, temp_map;
  RegionEntry* load_stack[8];
  RegionEntry* recv_pkt_region;
  // Which bridge (if any) delivered the packet currently being processed --
  // copied from Packet::_src_bridge, read back in trySendViaBridge() to
  // route a reply directly back out that same bridge. void* rather than
  // AbstractBridge* to avoid a new #include; cast at point of use.
  void* recv_pkt_source_bridge;
  // millis() timestamp recv_pkt_source_bridge was last set. "Consume-once"
  // only guarantees it clears on the next sendPacket() call, not that one
  // happens soon (bridge heartbeat pongs don't go through sendPacket() at
  // all) -- trySendViaBridge() ignores the flag once it's older than
  // RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS, so a stale flag can't misroute an
  // unrelated later send.
  unsigned long recv_pkt_source_bridge_set_at;
  TransportKey default_scope;
  RateLimiter discover_limiter, anon_limiter;
  uint32_t pending_discover_tag;
  unsigned long pending_discover_until;
  bool region_load_active;
  unsigned long dirty_contacts_expiry;
#if MAX_NEIGHBOURS
  NeighbourInfo neighbours[MAX_NEIGHBOURS];
#endif
#ifdef WITH_BRIDGE
  BridgeNeighbourInfo bridge_neighbours[MAX_BRIDGE_NEIGHBOURS];
#endif
#ifdef WITH_IP_BRIDGE
  PendingIpSend pending_ip_sends[MAX_PENDING_IP_SENDS];
#endif
  CayenneLPP telemetry;
  unsigned long set_radio_at, revert_radio_at;
  float pending_freq;
  float pending_bw;
  uint8_t pending_sf;
  uint8_t pending_cr;
  int  matching_peer_indexes[MAX_CLIENTS];
  // Independently gated (not an #elif chain) so more than one can be active
  // at once, e.g. ESP-NOW + IP together on a real-LoRa repeater.
#ifdef WITH_RS232_BRIDGE
  RS232Bridge rs232_bridge;
#endif
#ifdef WITH_ESPNOW_BRIDGE
  ESPNowBridge espnow_bridge;
#if defined(WITH_IP_BRIDGE)
  unsigned long _last_time_broadcast_at = 0;  // millis(), 0 = never yet -- see maybeBroadcastTime()
  static const uint32_t TIME_BROADCAST_INTERVAL_MS = 5UL * 60 * 1000;  // 5 min
#endif
#endif
#ifdef WITH_IP_BRIDGE
  IpBridge ip_bridge;
#endif

  void putNeighbour(const mesh::Identity& id, uint32_t timestamp, float snr);
#ifdef WITH_BRIDGE
  void putBridgeNeighbour(const mesh::Identity& id, uint32_t timestamp, float snr, const void* src_bridge);
  void formatAllNeighborsReply(char* reply);
  // Looks up a DIRECT packet's next hop (path[0]) against the neighbour
  // tables. Returns the specific bridge if that identity has only ever been
  // heard via one bridge and never over local RF; otherwise NULL, the safe
  // default. Used to redirect sends whose next hop is provably bridge-only.
  void* findBridgeOnlyNextHop(const uint8_t* hash, uint8_t hash_size) const;
#endif
#ifdef WITH_IP_BRIDGE
  bool hasLiveRfNeighbour() const;
  void queueDelayedIpSend(mesh::Packet* pkt);
  void flushPendingIpSends();
#endif
  uint8_t handleLoginReq(const mesh::Identity& sender, const uint8_t* secret, uint32_t sender_timestamp, const uint8_t* data, bool is_flood);
  uint8_t handleAnonRegionsReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  uint8_t handleAnonOwnerReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  uint8_t handleAnonClockReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data);
  int handleRequest(ClientInfo* sender, uint32_t sender_timestamp, uint8_t* payload, size_t payload_len);
  mesh::Packet* createSelfAdvert();

  File openAppend(const char* fname);
  bool isLooped(const mesh::Packet* packet, const uint8_t max_counters[]);

protected:
  float getAirtimeBudgetFactor() const override {
    return _prefs.airtime_factor;
  }

  bool allowPacketForward(const mesh::Packet* packet) override;
  const char* getLogDateTime() override;
  void logRxRaw(float snr, float rssi, const uint8_t raw[], int len) override;

  void logRx(mesh::Packet* pkt, int len, float score) override;
  void logTx(mesh::Packet* pkt, int len) override;
  void logTxFail(mesh::Packet* pkt, int len) override;
  int calcRxDelay(float score, uint32_t air_time) const override;

  uint32_t getRetransmitDelay(const mesh::Packet* packet) override;
  uint32_t getDirectRetransmitDelay(const mesh::Packet* packet) override;

  int getInterferenceThreshold() const override {
    return _prefs.interference_threshold;
  }
  bool getCADEnabled() const override {
    return _prefs.cad_enabled;
  }
  int getAGCResetInterval() const override {
    return ((int)_prefs.agc_reset_interval) * 4000;   // milliseconds
  }
  uint8_t getExtraAckTransmitCount() const override {
    return _prefs.multi_acks;
  }

#if ENV_INCLUDE_GPS == 1
  void applyGpsPrefs() {
    sensors.setSettingValue("gps", _prefs.gps_enabled?"1":"0");
  }
#endif

  mesh::DispatcherAction onRecvPacket(mesh::Packet* pkt) override;
#ifdef WITH_BRIDGE
  bool trySendViaBridge(mesh::Packet* packet) override;
  // Relay-forwarding counterpart to trySendViaBridge() -- covers ordinary
  // pass-through traffic (a packet not addressed to this node), which never
  // goes through sendPacket() at all.
  bool tryRelayViaBridge(mesh::Packet* packet) override;
#endif

  void onAnonDataRecv(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender, uint8_t* data, size_t len) override;
  int searchPeersByHash(const uint8_t* hash) override;
  void getPeerSharedSecret(uint8_t* dest_secret, int peer_idx) override;
  void onAdvertRecv(mesh::Packet* packet, const mesh::Identity& id, uint32_t timestamp, const uint8_t* app_data, size_t app_data_len);
  void onPeerDataRecv(mesh::Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) override;
  bool onPeerPathRecv(mesh::Packet* packet, int sender_idx, const uint8_t* secret, uint8_t* path, uint8_t path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) override;
  void onControlDataRecv(mesh::Packet* packet) override;

  void sendFloodReply(mesh::Packet* packet, unsigned long delay_millis, uint8_t path_hash_size);

public:
  MyMesh(mesh::MainBoard& board, mesh::Radio& radio, mesh::MillisecondClock& ms, mesh::RNG& rng, mesh::RTCClock& rtc, mesh::MeshTables& tables);

  void begin(FILESYSTEM* fs);
  void sendNodeDiscoverReq();
  const char* getFirmwareVer() override { return FIRMWARE_VERSION; }
  const char* getBuildDate() override { return FIRMWARE_BUILD_DATE; }
  const char* getRole() override { return FIRMWARE_ROLE; }
  const char* getNodeName() { return _prefs.node_name; }
  NodePrefs* getNodePrefs() {
    return &_prefs;
  }

  void savePrefs() override {
    _cli.savePrefs(_fs);
  }

  void sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size);

  // CommonCLICallbacks
  void applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins) override;
  bool formatFileSystem() override;
  void sendSelfAdvertisement(int delay_millis, bool flood) override;
  void updateAdvertTimer() override;
  void updateFloodAdvertTimer() override;

  void setLoggingOn(bool enable) override { _logging = enable; }

  void eraseLogFile() override {
    _fs->remove(PACKET_LOG_FILE);
  }

  void dumpLogFile() override;
  void setTxPower(int8_t power_dbm) override;
  void formatNeighborsReply(char *reply) override;
  void removeNeighbor(const uint8_t* pubkey, int key_len) override;
  void formatStatsReply(char *reply) override;
  void formatRadioStatsReply(char *reply) override;
  void formatPacketStatsReply(char *reply) override;
  void startRegionsLoad() override;
  bool saveRegions() override;
  void onDefaultRegionChanged(const RegionEntry* r) override;

  mesh::LocalIdentity& getSelfId() override { return self_id; }

  void saveIdentity(const mesh::LocalIdentity& new_id) override;
  void clearStats() override;

  void handleCommand(uint32_t sender_timestamp, char* command, char* reply);
  void loop();

#if defined(WITH_ESPNOW_BRIDGE) && defined(WITH_IP_BRIDGE)
  /**
   * Broadcasts this repeater's current time to the ESP-NOW segment
   * (ESPNowBridge::broadcastTime()) every TIME_BROADCAST_INTERVAL_MS, but
   * only while time_valid is true -- callers (main.cpp) should pass their own
   * "has NTP actually landed" flag, since a fresh boot's default clock must
   * never get broadcast as if it were real. Call every loop() tick; internally
   * a no-op except right at the interval boundary. Only compiled in for a
   * dual-bridge repeater (WITH_IP_BRIDGE is where NTP time actually comes
   * from -- WITH_ESPNOW_BRIDGE alone has no time source to broadcast).
   */
  void maybeBroadcastTime(bool time_valid);
#endif

#if defined(WITH_BRIDGE)
  void setBridgeState(bool enable) override {
    // Toggled independently per bridge -- with more than one compiled in,
    // each can already be in a different running state.
#ifdef WITH_RS232_BRIDGE
    if (enable != rs232_bridge.isRunning()) {
      if (enable) rs232_bridge.begin(); else rs232_bridge.end();
    }
#endif
#ifdef WITH_ESPNOW_BRIDGE
    if (enable != espnow_bridge.isRunning()) {
      if (enable) espnow_bridge.begin(); else espnow_bridge.end();
    }
#endif
#ifdef WITH_IP_BRIDGE
    if (enable != ip_bridge.isRunning()) {
      if (enable) ip_bridge.begin(); else ip_bridge.end();
    }
#endif
  }

  void restartBridge() override {
    // Always end()+begin(), not just when already running: begin() is a safe
    // no-op on incomplete config, but a board configured one CLI field at a
    // time would otherwise never start until a reboot (isRunning() stays
    // false until begin() has already succeeded once).
#ifdef WITH_RS232_BRIDGE
    rs232_bridge.end();
    rs232_bridge.begin();
#endif
#ifdef WITH_ESPNOW_BRIDGE
    espnow_bridge.end();
    espnow_bridge.begin();
#endif
#ifdef WITH_IP_BRIDGE
    ip_bridge.end();
    ip_bridge.begin();
#endif
#ifdef ESPNOW_BRIDGE_RADIO
    // bridge.channel/bridge.secret here are ESPNowBridgeRadio's own, separate
    // from the IpBridge/etc member above despite the similar naming. Applying
    // them here (not just at boot) is what makes them CLI-settable. Requires
    // both set -- an empty secret would divide-by-zero in xorCrypt().
    if (_prefs.bridge_channel != 0 && _prefs.bridge_secret[0] != 0) {
      radio_driver.setBridgeParams(_prefs.bridge_channel, _prefs.bridge_secret);
    }
#endif
  }
#endif
#ifdef WITH_IP_BRIDGE
  bool formatIpStatus(char *reply) override {
    ip_bridge.formatStatus(reply);
    return true;
  }
#endif
#if !defined(WITH_BRIDGE) && defined(ESPNOW_BRIDGE_RADIO)
  void restartBridge() override {
    if (_prefs.bridge_channel != 0 && _prefs.bridge_secret[0] != 0) {
      radio_driver.setBridgeParams(_prefs.bridge_channel, _prefs.bridge_secret);
    }
  }
#endif

  // To check if there is pending work
  bool hasPendingWork() const;

  bool setRxBoostedGain(bool enable) override;

  #if defined(USE_LR2021)
  virtual bool configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) override;
  #endif

};
