#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_MQTT_BRIDGE

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <Identity.h>

/**
 * @brief Passive MQTT publisher: uplinks decoded packet/status telemetry to
 * an MQTT broker you run yourself. Observer only -- publish-only, no
 * subscribe, nothing can come back from the broker and be injected onto the
 * mesh.
 *
 * Wire-compatible with the `meshcore/{iata}/{device_pubkey}/{status|packets}`
 * topic and JSON schema used by an existing, independently-run fork
 * (agessaman/MeshCore, observer-firmware branch) -- not a bespoke schema, so
 * this feed drops straight into a self-hosted CoreScope instance (which
 * ingests that exact schema) unmodified. See planning/mqtt-fork-research-notes.md
 * and planning/mqtt-bridge-design.md.
 *
 * Deliberately does NOT reuse that fork's transport (esp-mqtt/PsychicMqttClient,
 * which runs its own FreeRTOS task -- their own MQTT_OWNERSHIP.md documents a
 * still-open cross-core UAF risk from exactly that). Instead this hand-rolls
 * the small slice of MQTT 3.1.1 + WebSocket framing actually needed (CONNECT/
 * CONNACK/PUBLISH/PINGREQ/PINGRESP, no subscribe), polled synchronously from
 * loop() over the same non-blocking raw-socket + mbedTLS pattern IpBridge
 * already uses -- single-threaded, no FreeRTOS task, no thread-safety surface.
 *
 * One broker, configured via mqtt.server (any mqtt://, mqtts://, ws://, or
 * wss:// URL) + optional mqtt.username/mqtt.password. No built-in community
 * broker presets and no JWT auth -- this is scoped to a broker you run and
 * trust yourself (e.g. your own self-hosted CoreScope, which bundles its own
 * Mosquitto broker), not the public community MQTT ecosystem, so the
 * machinery those need (curated broker presets, Ed25519-signed JWT to
 * satisfy a shared community auth scheme, cert pinning against a specific
 * public CA) doesn't apply here and was deliberately left out -- decided
 * 2026-08-31 after concluding that publishing bridge-relayed (non-RF)
 * traffic to a *shared* community aggregator risked distorting other
 * people's RF propagation analytics (see planning/mqtt-bridge-design.md).
 * TLS, if used, is NOT certificate-verified (MBEDTLS_SSL_VERIFY_NONE) --
 * there's no CLI surface for pasting in a CA cert. Fine for a broker on your
 * own LAN/VPN; not meant for an arbitrary broker across the open internet.
 *
 * QoS 0 only, no retain -- this is a best-effort telemetry feed, not a
 * guaranteed-delivery channel; a dropped status/packet message is expected
 * to be superseded by the next one shortly after. Simpler than tracking
 * PUBACKs/retransmits for a feed where occasional loss doesn't matter.
 *
 * Only the "status" and "packets" topics are implemented (the two that
 * matter for actually viewing mesh activity). The fork's separate "raw" and
 * "neighbors" topics are not -- "packets" already carries the raw hex dump
 * plus RF metadata, covering the useful case; explicitly deferred, not an
 * oversight.
 *
 * Publishes both RF-received and bridge-received traffic, but NOT under the
 * same label. publishRx() (RF, called from MyMesh::logRx()) includes real
 * SNR/RSSI/score and uses "direction":"rx". publishRxBridge() (called from
 * MyMesh::logRxBridge(), which fires once per bridge-sourced packet via
 * Packet::_src_bridge -- see Dispatcher::loop()'s inbound-queue drain) has no
 * RF metrics and deliberately uses a distinct "direction":"bridge" rather
 * than reusing "rx" -- the fork's own schema only ever defines "rx"/"tx", so
 * this is an intentional, documented deviation: mislabeling a bridge hop as
 * "rx" would look exactly like a real (if oddly incomplete) radio reception
 * to any consumer, which is the same class of problem the fork's own PR #13
 * ("Omit SNR/RSSI instead of publishing hardcoded 12.5/-65 when no radio
 * data") ran into and fixed by omitting rather than fabricating. Since this
 * bridge only ever talks to a broker you run yourself, a non-standard third
 * value is fine here -- there's no shared community consumer whose fixed
 * two-value assumption this could quietly break.
 */
class MQTTBridge : public BridgeBase {
public:
  // 'identity' is used only for its public key (the topic device-id
  // segment) -- no signing, no JWT.
  MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, mesh::LocalIdentity *identity);

  void begin() override;
  void end() override;
  void loop() override;

  // Unused: this bridge never forwards a packet onto another physical medium
  // (sendPacket()) and has no inbound medium of its own to receive from
  // (onPacketReceived()) -- AbstractBridge's bidirectional-bridge interface
  // doesn't fit an outbound-only observer, so both are no-ops. Real
  // publishing happens via publishRx()/publishRxBridge()/publishTx() below,
  // called directly from MyMesh's logging hooks (see those for why: this
  // needs SNR/RSSI/score and RX-vs-TX-vs-bridge direction, none of which
  // AbstractBridge's generic sendPacket(Packet*) signature carries).
  void sendPacket(mesh::Packet *packet) override {}
  void onPacketReceived(mesh::Packet *packet) override {}

  void publishRx(const mesh::Packet *pkt, int len, float score, float snr, float rssi);
  void publishRxBridge(const mesh::Packet *pkt, int len);
  void publishTx(const mesh::Packet *pkt, int len);

  // For 'get mqtt.status' -- see IpBridge::formatStatus() for the convention
  // (caller-owned buffer, no size param).
  void formatStatus(char *reply) const;

private:
  enum class State : uint8_t {
    IDLE,             // not initialized / stopped / not enabled
    TCP_CONNECTING,   // non-blocking connect() in progress
    TLS_HANDSHAKING,  // TLS handshake in progress (skipped for mqtt://, ws://)
    WS_HANDSHAKING,   // HTTP Upgrade request sent, waiting for 101 response (skipped for mqtt://, mqtts://)
    MQTT_CONNECTING,  // MQTT CONNECT sent, waiting for CONNACK
    CONNECTED,        // ready to publish
    RECONNECT_WAIT,   // waiting before retrying
  };

  NodePrefs *_prefs;
  mesh::LocalIdentity *_identity;

  State _state = State::IDLE;
  unsigned long _next_action_at = 0;

  // Parsed once per (re)connect attempt from mqtt.server.
  bool _use_tls = false;
  bool _use_ws = false;
  char _host[64] = {0};
  uint16_t _port = 0;
  char _ws_path[64] = {0};

  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  mbedtls_net_context _conn_fd;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  bool _tls_conf_ready = false;

  unsigned long _handshake_started_at = 0;
  unsigned long _last_rx_at = 0;
  unsigned long _next_ping_at = 0;
  bool _ping_outstanding = false;

  // WebSocket handshake: random Sec-WebSocket-Key sent, expected accept value
  // computed locally to validate the server's response.
  char _ws_expected_accept[32] = {0};
  char _ws_http_buf[256] = {0};
  size_t _ws_http_buf_len = 0;

  // Small inbound scratch buffer -- this bridge never subscribes, so the only
  // inbound MQTT traffic is CONNACK (once) and PINGRESP (periodically); a WS
  // control frame (ping/close) from the broker is also handled here. Sized
  // generously above the largest of those, not for arbitrary inbound PUBLISH.
  uint8_t _rx_buf[64];
  size_t _rx_buf_len = 0;

  // Inline WS frame-unwrap state, persisted across loop() ticks (a frame
  // header/payload can arrive split across many non-blocking reads). Reset
  // to header-parsing on every fresh connection via pollConnectedIO()'s
  // caller (startWsHandshake()/teardownConnection() implicitly restart this
  // by re-entering CONNECTED fresh next time).
  uint8_t _ws_frame_hdr[2];
  uint8_t _ws_frame_hdr_len = 0;
  uint8_t _ws_frame_opcode = 0;
  uint8_t _ws_len_bytes_needed = 0;
  uint8_t _ws_len_buf[8];
  uint8_t _ws_len_buf_pos = 0;
  uint64_t _ws_frame_payload_len = 0;
  uint64_t _ws_frame_payload_read = 0;

  // Device pubkey as uppercase hex, computed once in begin() -- used as the
  // topic device-id segment.
  char _pubkey_hex[65] = {0};

  bool parseBrokerConfig();       // fills _host/_port/_use_tls/_use_ws/_ws_path from mqtt.server

  void startConnect();
  void pollTcpConnecting();
  bool setupTlsConfig();
  void pollTlsHandshake();
  void startWsHandshake();
  void pollWsHandshake();
  void startMqttConnect();
  void pollMqttConnecting();
  void pollConnectedIO();
  void checkPing();
  void teardownConnection(bool reconnect);
  void scheduleReconnect();

  // Transport-agnostic I/O: transparently goes through TLS (if _use_tls) and
  // WS framing (if _use_ws) so everything above this layer just deals in
  // plain MQTT control-packet bytes.
  int transportWrite(const uint8_t *buf, size_t len);   // returns bytes written, <0 on hard error
  int transportReadByte(uint8_t *out);                  // returns 1 (byte read), 0 (nothing available), <0 on hard error

  bool sendMqttConnect();
  bool sendMqttPublish(const char *topic, const char *payload, size_t payload_len);
  bool sendMqttPingreq();
  void handleMqttControlByte(uint8_t b);

  // JSON payload builders, matching the fork's field layout where applicable
  // -- see class doc comment for the "bridge" direction deviation.
  size_t buildStatusPayload(char *out, size_t out_size);
  size_t buildPacketPayload(char *out, size_t out_size, const mesh::Packet *pkt, int len,
                             const char *direction, float score, float snr, float rssi);
};

#endif
