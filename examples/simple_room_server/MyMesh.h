#pragma once

#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>

#if defined(NRF52_PLATFORM)
  #include <InternalFileSystem.h>
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
#elif defined(ESP32)
  #include <SPIFFS.h>
#endif

#include <helpers/ArduinoHelpers.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/IdentityStore.h>
#include <helpers/AdvertDataHelpers.h>
#include <helpers/TxtDataHelpers.h>
#include <helpers/CommonCLI.h>
#include <helpers/StatsFormatHelper.h>
#include <helpers/ClientACL.h>
#include <helpers/RegionMap.h>
#include <helpers/RoutingPolicy.h>
#include <RTClib.h>
#include <target.h>

/* ------------------------------ Config -------------------------------- */

#ifndef FIRMWARE_BUILD_DATE
  #define FIRMWARE_BUILD_DATE   "14 Aug 2026"
#endif

#ifndef FIRMWARE_VERSION
  #define FIRMWARE_VERSION   "v1.17.1"
#endif

#ifndef LORA_FREQ
  #define LORA_FREQ   915.0
#endif
#ifndef LORA_BW
  #define LORA_BW     250
#endif
#ifndef LORA_SF
  #define LORA_SF     10
#endif
#ifndef LORA_CR
  #define LORA_CR      5
#endif
#ifndef LORA_TX_POWER
  #define LORA_TX_POWER  20
#endif

#ifndef ADVERT_NAME
  #define  ADVERT_NAME   "Test BBS"
#endif
#ifndef ADVERT_LAT
  #define  ADVERT_LAT  0.0
#endif
#ifndef ADVERT_LON
  #define  ADVERT_LON  0.0
#endif

#ifndef ADMIN_PASSWORD
  #define  ADMIN_PASSWORD  "password"
#endif

#ifndef MAX_UNSYNCED_POSTS
  #define MAX_UNSYNCED_POSTS    32
#endif

#ifndef SERVER_RESPONSE_DELAY
  #define SERVER_RESPONSE_DELAY   300
#endif

#ifndef TXT_ACK_DELAY
  #define TXT_ACK_DELAY     200
#endif

#define FIRMWARE_ROLE "room_server"

#define PACKET_LOG_FILE  "/packet_log"

#define MAX_POST_TEXT_LEN    (160-9)

struct PostInfo {
  mesh::Identity author;
  uint32_t post_timestamp;   // by OUR clock
  char text[MAX_POST_TEXT_LEN+1];
};

#ifdef WITH_ROOM_CHANNEL_BRIDGE
// One public group channel this room server passively listens on, feeding
// its text messages into the post feed as if an admin had typed them via
// 'room.post'. Deliberately single-channel (one board == one #hashtag) --
// this board's own identity already IS the channel's identity, so there's
// no need to tag posts with a channel name the way a multi-channel design
// would (see planning notes) -- posts just keep the channel's own embedded
// "sender: text" as-is, preserving the full MAX_POST_TEXT_LEN budget.
#define ROOM_CHANNEL_FILE   "/room_channel"
#define ROOM_CHANNEL_NAME_LEN   32
#endif

class MyMesh : public mesh::Mesh, public CommonCLICallbacks {
  FILESYSTEM* _fs;
  uint32_t last_millis;
  uint64_t uptime_millis;
  unsigned long next_local_advert, next_flood_advert;
  bool _logging;
  bool region_load_active;
  NodePrefs _prefs;
  TransportKeyStore key_store;
  RegionMap region_map, temp_map;
  ClientACL acl;
  CommonCLI _cli;
  unsigned long dirty_contacts_expiry;
  uint8_t reply_data[MAX_PACKET_PAYLOAD];
  unsigned long next_push;
  uint16_t _num_posted, _num_post_pushes;
  int next_client_idx;  // for round-robin polling
  int next_post_idx;
  PostInfo posts[MAX_UNSYNCED_POSTS];   // cyclic queue
  CayenneLPP telemetry;
  RegionEntry* load_stack[8];
  RegionEntry* recv_pkt_region;
  TransportKey default_scope;
  unsigned long set_radio_at, revert_radio_at;
  float pending_freq;
  float pending_bw;
  uint8_t pending_sf;
  uint8_t pending_cr;
  int  matching_peer_indexes[MAX_CLIENTS];

#ifdef WITH_ROOM_CHANNEL_BRIDGE
  char _room_channel_name[ROOM_CHANNEL_NAME_LEN];
  char _room_channel_psk[65];  // longest accepted form: hex of a 32-byte key (64 chars) +null -- stored verbatim (whichever format was typed in) so 'get room.channel' can echo it back
  mesh::GroupChannel _room_channel;
  bool _room_channel_set = false;

  void loadRoomChannel();
#endif

  void addPost(ClientInfo* client, const char* postData);
  void storePost(const mesh::Identity& author, const char* postData);
  void pushPostToClient(ClientInfo* client, PostInfo& post);
  uint8_t getUnsyncedCount(ClientInfo* client);
  bool processAck(const uint8_t *data);
  mesh::Packet* createSelfAdvert();
  File openAppend(const char* fname);
  int handleRequest(ClientInfo* sender, uint32_t sender_timestamp, uint8_t* payload, size_t payload_len);

protected:
  float getAirtimeBudgetFactor() const override {
    return _prefs.airtime_factor;
  }

  void logRxRaw(float snr, float rssi, const uint8_t raw[], int len) override;
  void logRx(mesh::Packet* pkt, int len, float score) override;
  void logTx(mesh::Packet* pkt, int len) override;
  void logTxFail(mesh::Packet* pkt, int len) override;

  int calcRxDelay(float score, uint32_t air_time) const override;
  const char* getLogDateTime() override;
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

  mesh::DispatcherAction onRecvPacket(mesh::Packet* pkt) override;

  bool allowPacketForward(const mesh::Packet* packet) override;
  void onAnonDataRecv(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender, uint8_t* data, size_t len) override;
  int searchPeersByHash(const uint8_t* hash) override ;
  void getPeerSharedSecret(uint8_t* dest_secret, int peer_idx) override;
  void onPeerDataRecv(mesh::Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) override;
  bool onPeerPathRecv(mesh::Packet* packet, int sender_idx, const uint8_t* secret, uint8_t* path, uint8_t path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) override;
  void onAckRecv(mesh::Packet* packet, uint32_t ack_crc) override;

#ifdef WITH_ROOM_CHANNEL_BRIDGE
  int searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel channels[], int max_matches) override;
  void onGroupDataRecv(mesh::Packet* packet, uint8_t type, const mesh::GroupChannel& channel, uint8_t* data, size_t len) override;
#endif

#if ENV_INCLUDE_GPS == 1
  void applyGpsPrefs() {
    sensors.setSettingValue("gps", _prefs.gps_enabled?"1":"0");
  }
#endif

  void sendFloodReply(mesh::Packet* packet, unsigned long delay_millis, uint8_t path_hash_size);

public:
  MyMesh(mesh::MainBoard& board, mesh::Radio& radio, mesh::MillisecondClock& ms, mesh::RNG& rng, mesh::RTCClock& rtc, mesh::MeshTables& tables);

  void begin(FILESYSTEM* fs);
  void addSystemPost(const char* postData);

#ifdef WITH_ROOM_CHANNEL_BRIDGE
  // Persists name + PSK (base64) to flash and immediately activates it
  // (recomputes hash+secret, no reboot needed). Returns false if the PSK
  // doesn't decode to a valid 16 or 32 byte key.
  bool setRoomChannel(const char* name, const char* psk_base64);
  const char* getRoomChannelName() const { return _room_channel_set ? _room_channel_name : ""; }
  const char* getRoomChannelPsk() const { return _room_channel_set ? _room_channel_psk : ""; }
#endif

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
  bool setRxBoostedGain(bool enable) override;

#ifdef ESPNOW_BRIDGE_RADIO
  void restartBridge() override {
    if (_prefs.bridge_channel != 0 && _prefs.bridge_secret[0] != 0) {
      radio_driver.setBridgeParams(_prefs.bridge_channel, _prefs.bridge_secret);
    }
  }
#endif

  void formatNeighborsReply(char *reply) override {
    strcpy(reply, "not supported");
  }
  void formatStatsReply(char *reply) override;
  void formatRadioStatsReply(char *reply) override;
  void formatPacketStatsReply(char *reply) override;
  void startRegionsLoad() override;
  bool saveRegions() override;
  void onDefaultRegionChanged(const RegionEntry* r) override;

  mesh::LocalIdentity& getSelfId() override { return self_id; }

  static bool saveFilter(ClientInfo* client);

  void saveIdentity(const mesh::LocalIdentity& new_id) override;
  void clearStats() override;
  void handleCommand(uint32_t sender_timestamp, char* command, char* reply);
  void loop();
};
