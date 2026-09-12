#pragma once

#include <Mesh.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

/**
 * Radio driver for ESP32 companion boards with no LoRa chip that need to
 * reach a MeshCore repeater's IpBridge server (src/helpers/bridges/IpBridge.cpp)
 * directly over WiFi/IP -- TCP + TLS-PSK, same wire framing/handshake IpBridge
 * itself uses -- instead of needing an ESP-NOW hop through a bridging
 * repeater/hub (see ESPNowBridgeRadio for that alternative).
 *
 * Client role only: a companion has exactly one upstream repeater, so unlike
 * IpBridge itself there's no listen socket, no multi-peer table, no
 * challenger-slot eviction dance -- just the single connect/handshake/
 * reconnect state machine IpBridge's own client role (_peers[0]) already
 * uses. Ported to work in raw bytes (this class's recvRaw()/startSendRaw()
 * are what Dispatcher polls directly) rather than mesh::Packet objects --
 * simpler than IpBridge, not just a reshaping of it, since there's no
 * multi-peer fan-out or loop-dedup to replicate for a single point-to-point
 * link (the Mesh/Dispatcher layer above already does its own dedup).
 *
 * No compile-time host/port/secret default -- all three are set at runtime
 * via setIpParams() (see its own comment) once persisted config is loaded.
 * An unconfigured board stays inert (no socket, no traffic at all).
 */
class IpBridgeRadio : public mesh::Radio {
public:
  IpBridgeRadio(mesh::MainBoard& board) : _board(&board) { }

  uint32_t getRngSeed();

  void setParams(float freq, float bw, uint8_t sf, uint8_t cr) {
    // no-op -- not a PHY radio
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

  uint32_t getPacketsRecv() const { return _n_recv; }
  uint32_t getPacketsSent() const { return _n_sent; }
  uint32_t getPacketsRecvErrors() const { return _n_recv_errors; }
  void resetStats() { _n_recv = _n_sent = _n_recv_errors = 0; }

  float getLastRSSI() const override { return 0; }
  float getLastSNR() const override { return 0; }
  float packetScore(float snr, int packet_len) override { return 0; }

  /**
   * These do nothing for a TCP/IP link, but are needed for the same
   * radio_driver.* surface companion_radio's MyMesh.cpp calls unconditionally
   * (see ESPNowBridgeRadio's own identical stubs).
   */
  bool setRxBoostedGainMode(bool) { return false; }
  bool getRxBoostedGainMode() const { return false; }
  void setTxPower(uint8_t dbm) { /* no-op */ }

  /**
   * Applies persisted ip.host/ip.port/ip.secret plus this node's own public
   * key (used to derive the PSK client identity presented during the TLS
   * handshake, same 8-hex-char convention IpBridge's client role uses) and
   * (re)starts the connection state machine. Called once, after both prefs
   * and this node's identity have been loaded (see companion_radio's
   * MyMesh::begin()) -- host/secret are copied/truncated the same way
   * StrHelper::strncpy does, matching the char[] fields they're loaded from.
   * Safe to call again later (e.g. a live config change) -- tears down any
   * existing connection first.
   */
  void setIpParams(const char* host, uint16_t port, const char* secret, const uint8_t* self_pub_key);

  // Lightweight human-readable status string, same convention as
  // IpBridge::formatStatus() -- caller-owned buffer, no size param.
  void formatStatus(char* reply) const;

  /**
   * LED status hooks -- same behavior/timings as NullRadio's own (see that
   * class), which itself mirrors ESPNowBridgeRadio's IpBridge indicators
   * minus the boot-flash-collision handling that doesn't apply here. No-ops
   * unless P_LORA_TX_NEOPIXEL_LED is defined by the board.
   */
  void indicateIpPing();
  void indicatePongReceived();
  void setLinkConnected(bool connected);

private:
  bool _ip_ping_led_on = false;
  unsigned long _ip_ping_led_off_at = 0;
  bool _ip_pong_led_on = false;
  unsigned long _ip_pong_led_off_at = 0;
  bool _disconnect_blink_active = false;
  bool _disconnect_led_on = false;
  unsigned long _disconnect_next_toggle_at = 0;

  enum class State : uint8_t {
    IDLE,           // not configured yet, or explicitly torn down
    TCP_CONNECTING, // non-blocking connect() in progress
    HANDSHAKING,    // TLS handshake in progress
    CONNECTED,      // TLS session up, ready for framed packets
    RECONNECT_WAIT, // waiting before retrying
  };

  mesh::MainBoard* _board;

  uint32_t _n_recv = 0, _n_sent = 0, _n_recv_errors = 0;

  char _host[64] = {0};
  uint16_t _port = 0;
  char _secret[32] = {0};
  char _own_identity[9] = {0};  // 8 hex chars + NUL, derived from self_pub_key
  bool _configured = false;

  State _state = State::IDLE;
  mbedtls_net_context _conn_fd;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  bool _tls_conf_ready = false;

  unsigned long _handshake_started_at = 0;
  unsigned long _next_handshake_poll_at = 0;
  unsigned long _next_action_at = 0;  // TCP_CONNECTING timeout, or RECONNECT_WAIT retry-at

  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  // Diagnostics for formatStatus() -- last mbedtls_ssl_setup() failure (0 if
  // never failed this way), and free heap at that moment. Added 2026-09-12
  // after a live RECONNECT_WAIT loop turned out to be MBEDTLS_ERR_SSL_ALLOC_FAILED
  // (heap exhaustion on a BLE+USB dual companion build), not visible any other
  // way without a debug-logging reflash.
  int _last_ssl_setup_err = 0;
  uint32_t _last_ssl_setup_free_heap = 0;

  unsigned long _last_rx_at = 0;
  unsigned long _next_ping_at = 0;

  // Matches IpBridge.h's own MAX_PACKET_SIZE formula exactly -- same framing,
  // same peer (an unmodified IpBridge server) on the other end.
  static constexpr uint16_t MAX_PACKET_SIZE = (MAX_TRANS_UNIT + 1) + 6 /*framing overhead*/;
  uint8_t _rx_frame_buffer[MAX_PACKET_SIZE];
  uint16_t _rx_frame_buffer_pos = 0;

  // One complete decoded frame waiting to be handed out via recvRaw() --
  // single-slot, not a queue, same convention ESPNowBridgeRadio's own
  // last_rx_len/rx_buf uses. Draining stops the moment this fills (see
  // loop()); nothing is lost since TCP keeps the rest buffered until the
  // next poll.
  uint8_t _pending_rx[MAX_PACKET_SIZE];
  uint16_t _pending_rx_len = 0;

  bool _send_complete = true;

  bool setupTlsConfig();
  bool setupSslContext();
  void startConnect();
  void pollTcpConnecting();
  void pollHandshake();
  void pollConnectedIO();
  void checkHeartbeat();
  void processFramedByte(uint8_t b);
  void sendFramed(const uint8_t* payload, uint16_t len);
  void teardownConnection(bool reconnect);
  void scheduleReconnect();
};
