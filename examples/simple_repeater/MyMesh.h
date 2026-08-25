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
  #define MAX_BRIDGE_NEIGHBOURS   8
#endif

// Kept as a separate table from NeighbourInfo/neighbours[] (not merged in)
// because neighbours[] represents identities heard directly over this
// repeater's own radio and is consumed as-is by the RF-awareness check in
// getRetransmitDelay() -- that check must stay uncontaminated by bridge
// traffic. The two tables are merged only at display time, in
// formatNeighborsReply(), with a 'via' column added to every row.
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

// How long a bridge_neighbours[] entry stays trusted enough for
// findBridgeOnlyNextHop() to redirect on it -- same generous-on-purpose
// reasoning as RF_AWARENESS_WINDOW_SECS below (a stale-but-still-used entry
// only costs an unnecessary bridge send attempt; a too-eager entry could
// misroute). Defined unconditionally (not just under WITH_IP_BRIDGE) since
// findBridgeOnlyNextHop() applies to any bridge type.
#define BRIDGE_NEIGHBOUR_FRESHNESS_SECS   (30 * 60)

// Max age for recv_pkt_source_bridge to still be trusted by trySendViaBridge()
// -- generous for genuine same-turn reply processing (which is synchronous,
// same millis() tick in practice) but far too short for it to still be "the
// same request" after other unrelated activity. See recv_pkt_source_bridge's
// declaration above.
#define RECV_PKT_SOURCE_BRIDGE_MAX_AGE_MS   1000

#ifdef WITH_IP_BRIDGE
// A PATH-return crossing the IP bridge is the packet that decides which
// route (RF or IP) a contact ends up using -- see
// planning/ip-bridge-mesh-safety.md. Holding it back briefly, only when
// this repeater currently has a live RF neighbour to defer to, gives a
// genuine RF path a head start; if one exists and completes in time, the
// held IP copy arrives as a harmless duplicate (existing dedup absorbs it)
// instead of racing ahead of it. Only ever delays PAYLOAD_TYPE_PATH
// packets -- see logTx().

// "Live" RF neighbour = heard directly within this window. Generous on
// purpose -- advert cadence isn't tightly bounded, and erring toward
// "still consider it live" only costs a bit of held-back latency, never
// correctness (see planning doc).
#define RF_AWARENESS_WINDOW_SECS   (30 * 60)

// PATH-return traffic is low-volume by nature (one per contact per
// re-established route, not per message) -- a handful of slots is ample.
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
  // copied from Packet::_src_bridge at the same point recv_pkt_region is
  // set, read back in sendFloodReply() to route the reply directly back out
  // that same bridge instead of requiring a local radio broadcast first.
  // void* (not AbstractBridge*) to avoid a new #include here; cast back to
  // AbstractBridge* at the point it's actually used.
  void* recv_pkt_source_bridge;
  // millis() timestamp recv_pkt_source_bridge was last set -- "consume-once"
  // only guarantees it's cleared by the NEXT sendPacket() call, not that one
  // happens soon. If nothing gets sent for a while after a bridge-sourced
  // receive (plausible -- bridge heartbeat pongs don't go through
  // Mesh::sendPacket() at all), the stale flag can misfire on some later,
  // completely unrelated locally-initiated send. trySendViaBridge() checks
  // this age and ignores the flag once it's too old. See
  // planning/ip-bridge-mesh-safety.md gap #4 (staleness bug found live
  // 2026-08-24 via discover.neighbors's own probe getting misrouted).
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
  // Each bridge type is independently gated (not an #elif chain) so a board
  // can have more than one active at once -- e.g. WITH_ESPNOW_BRIDGE +
  // WITH_IP_BRIDGE together on a real-LoRa repeater. Any code that needs to
  // act on "all active bridges" must touch each member explicitly; there's
  // no shared base-class array/loop here deliberately, to keep each bridge
  // trivially optional at compile time with zero cost when not selected.
#ifdef WITH_RS232_BRIDGE
  RS232Bridge rs232_bridge;
#endif
#ifdef WITH_ESPNOW_BRIDGE
  ESPNowBridge espnow_bridge;
#endif
#ifdef WITH_IP_BRIDGE
  IpBridge ip_bridge;
#endif

  void putNeighbour(const mesh::Identity& id, uint32_t timestamp, float snr);
#ifdef WITH_BRIDGE
  void putBridgeNeighbour(const mesh::Identity& id, uint32_t timestamp, float snr, const void* src_bridge);
  void formatAllNeighborsReply(char* reply);
  // Looks up a DIRECT packet's next hop (path[0], truncated identity hash)
  // against the neighbour tables: returns the specific bridge instance if
  // that identity has ONLY ever been heard via one bridge and NEVER over
  // local RF (within RF_AWARENESS_WINDOW_SECS-ish confidence -- see .cpp),
  // else NULL (unknown or RF-reachable -- always the safe default). Used by
  // trySendViaBridge() to redirect DIRECT-route sends whose true next hop
  // is provably bridge-only, without guessing from how the *triggering*
  // packet happened to arrive (see planning/ip-bridge-mesh-safety.md gap #4).
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
  // pass-through traffic (REQ/RESPONSE/TXT_MSG/PATH being relayed, not
  // addressed to this node), which never goes through sendPacket() at all.
  // See planning/ip-bridge-mesh-safety.md gap #4, "relay-forwarding" follow-up.
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

#if defined(WITH_BRIDGE)
  void setBridgeState(bool enable) override {
    // Each active bridge is checked/toggled independently -- with more than
    // one compiled in, they can each already be in a different running
    // state, so there's no single isRunning() to gate on up front the way a
    // lone bridge could.
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
    // Always end()+begin(), not just when already running -- begin()
    // re-validates config and is a safe no-op if still incomplete, but if we
    // only reset an already-running bridge, a board configured entirely via
    // CLI (ip.host/ip.port/ip.secret set one at a time, each triggering this
    // callback) would never actually start until a reboot, since isRunning()
    // stays false until begin() has already succeeded once. Applies to every
    // active bridge independently -- CommonCLI's 'set ip.*'/'set bridge.*'
    // handlers all funnel through this same callback regardless of which
    // bridge's setting actually changed.
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
    // bridge.channel/bridge.secret (FR11) are the ESPNowBridgeRadio's own
    // channel/secret, unrelated to the `bridge` (IpBridge/etc) member above
    // despite the similar naming -- both happen to route through this same
    // callback since CommonCLI's 'set bridge.channel'/'set bridge.secret'
    // handlers call restartBridge() either way. Applying this here (rather
    // than only at boot in begin()) is what makes the channel/secret
    // actually CLI-settable instead of compile-time only. Gated the same way
    // begin() gates its own initial call -- setting only one of the two via
    // CLI must leave the radio inert, not armed with an empty secret (which
    // would divide-by-zero in ESPNowBridgeRadio's xorCrypt() on the next
    // received frame).
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
