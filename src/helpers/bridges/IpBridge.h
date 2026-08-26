#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_IP_BRIDGE

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

/**
 * @brief Bridge over UDP + DTLS-PSK, for a point-to-point IP link between
 * exactly two paired MeshCore nodes.
 *
 * - UDP, not TCP: mbedtls_net_connect() has no non-blocking TCP variant.
 *   Keeps the bridge a synchronous, single-threaded state machine like
 *   RS232Bridge/ESPNowBridge, with no FreeRTOS task or thread-safety surface.
 * - Best-effort, fire-and-forget: no bridge-level packet retry, consistent
 *   with ESPNowBridge.
 * - Role is inferred from config, not a build-time choice:
 *     _prefs->ip_host set -> CLIENT: dials out to ip_host:ip_port.
 *     _prefs->ip_host empty, ip_port set -> SERVER: listens on ip_port,
 *       accepts the first peer to complete a DTLS-PSK handshake, then locks
 *       the socket to that address. Implements mbedTLS's HelloVerifyRequest/
 *       cookie exchange (_cookie_ctx below) as return-routability proof
 *       against source-address spoofing, closing off reflection/
 *       amplification abuse -- not for its usual multi-client purpose, since
 *       there's exactly one peer here by design.
 * - Dead-link detection is app-level (ping/pong heartbeat, N consecutive
 *   misses), since UDP/DTLS gives no OS-level disconnect signal.
 * - DNS (client side only) is failure-triggered: reconnect retries the last
 *   known-good IP first, only re-resolving after consecutive failures.
 *
 * Wire framing (once the DTLS session is up) mirrors RS232Bridge:
 * [2 bytes] Magic Header (0xC03E)
 * [2 bytes] Payload Length
 * [n bytes] Mesh Packet Payload
 * [2 bytes] Fletcher-16 Checksum
 * (DTLS already gives real integrity/authentication; this framing is purely for
 * message-boundary delimiting and reuses the existing pattern rather than
 * inventing a new one.)
 */
class IpBridge : public BridgeBase {
public:
  IpBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc);

  void begin() override;
  void end() override;
  void loop() override;
  void sendPacket(mesh::Packet *packet) override;
  void onPacketReceived(mesh::Packet *packet) override;

  // Dual-bridge boards only (WITH_ESPNOW_BRIDGE alongside WITH_IP_BRIDGE):
  // MyMesh calls this every loop() tick, just before ip_bridge.loop(), with
  // whether ESPNowBridge currently has a send in flight. Both bridges share
  // one physical WiFi radio, and the heartbeat ping fires on its own
  // independent 15s timer, completely decoupled from any specific packet --
  // unlike logTx()'s same-packet dual-bridge mirror (already staggered),
  // there's no single packet to stagger against here. Skipping the ping for
  // one tick when ESP-NOW is mid-transaction is cheap (checkHeartbeat() just
  // tries again next tick, at most a few ms later) and avoids a real,
  // observed collision: an inbound ESP-NOW unicast frame needs its MAC-layer
  // ACK sent within a very tight hardware timing window, and a concurrent
  // heartbeat TX competing for the same radio can make that ACK late enough
  // for the sender to see a failed send, even though this repeater did
  // receive the frame. Does not affect dead-link timeout detection, which
  // stays live every tick regardless.
  void setDeferHeartbeat(bool defer) { _defer_heartbeat = defer; }

  // Lightweight live-state query for 'get ip.status' -- doesn't need
  // BRIDGE_DEBUG=1 the way the full handshake/heartbeat tracing does. Writes
  // a short human-readable summary into 'reply' (caller-owned buffer, same
  // convention as CommonCLICallbacks::formatStatsReply() etc -- no size
  // param, caller's buffer is trusted to be large enough).
  void formatStatus(char *reply) const;

private:
  enum class State : uint8_t {
    IDLE,           // not initialized / stopped
    LISTENING,      // server mode, waiting for a peer to complete a handshake
    HANDSHAKING,    // DTLS handshake in progress (either role)
    CONNECTED,      // DTLS session up, ready for framed packets
    RECONNECT_WAIT, // client mode only, waiting before retrying
  };

  bool _is_server = false;
  State _state = State::IDLE;
  unsigned long _next_action_at = 0;

  // BridgeBase's inherited _seen_packets is shared between RX and TX; a
  // packet needing to cross in one direction could be silently dropped
  // because identical content already crossed the other way. Separate TX
  // table removes that false-positive for this bridge only.
  SimpleMeshTables _tx_seen;

  // Throttles how often HANDSHAKING polls mbedtls_ssl_handshake(). Without
  // this, each poll blocks up to 1ms in mbedtls_net_recv_timeout() when the
  // peer is unreachable, capping the whole main loop at ~1kHz and starving
  // CLI/mesh dispatch/LEDs -- confirmed live against an unreachable peer.
  unsigned long _next_handshake_poll_at = 0;

  // millis() when the current HANDSHAKING attempt started -- set at every
  // entry into that state (startConnect(), pollListening()'s accept, and
  // the same-source-port CLIENT_RECONNECT case in pollConnectedIO()). Bounds
  // how long a handshake is allowed to sit unresolved: WANT_READ/WANT_WRITE/
  // TIMEOUT from mbedtls_ssl_handshake() just means "keep polling, mbedTLS's
  // own DTLS retransmit is handling it" -- correct behavior for a live peer,
  // but with no outer bound at all, a peer that disappears mid-handshake
  // (network switch, IP change, dead) leaves this stuck in HANDSHAKING
  // forever: the server's listening socket won't accept a new connection
  // until this one resolves, and nothing ever made it resolve, and observed
  // live requiring a manual reboot to recover. See checkHeartbeat() for
  // the equivalent watchdog once actually CONNECTED -- this covers the gap
  // before that point.
  unsigned long _handshake_started_at = 0;

  // Last known-good IP for the client role, so most reconnects skip DNS.
  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  // Heartbeat / dead-link detection -- the only way to know the link is down,
  // since UDP/DTLS gives no OS-level disconnect signal. Only the client
  // pings on its own initiative; the server never sends pings, so both
  // roles instead watch _last_rx_at, updated on any valid received frame
  // (ping, pong, or a real mesh packet). If too long has passed since
  // anything was heard, the link is dead -- a simple time-since-last-rx
  // check rather than a per-ping miss counter.
  unsigned long _last_rx_at = 0;
  unsigned long _next_ping_at = 0;
  bool _defer_heartbeat = false;  // see setDeferHeartbeat()

  struct Timer {
    unsigned long int_at = 0;
    unsigned long fin_at = 0;
    bool active = false;
  };

  mbedtls_net_context _listen_fd;

  mbedtls_net_context _conn_fd_slot;
  mbedtls_ssl_context _ssl_slot;
  Timer _timer_slot;
  mbedtls_net_context *_conn_fd = &_conn_fd_slot;
  mbedtls_ssl_context *_ssl = &_ssl_slot;
  Timer *_timer = &_timer_slot;

  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  mbedtls_ssl_cookie_ctx _cookie_ctx;  // server-only, harmless to init/free as client too
  bool _tls_conf_ready = false;

  // Source address of the peer currently mid-handshake (server role only) --
  // needed by mbedtls_ssl_set_client_transport_id(), including re-asserting it
  // after MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED resets the SSL context (see
  // pollHandshake()).
  unsigned char _client_ip[16];
  size_t _client_ip_len = 0;

  static constexpr uint16_t OVERHEAD = BRIDGE_MAGIC_SIZE + BRIDGE_LENGTH_SIZE + BRIDGE_CHECKSUM_SIZE;
  static constexpr uint16_t MAX_PACKET_SIZE = (MAX_TRANS_UNIT + 1) + OVERHEAD;
  uint8_t _rx_buffer[MAX_PACKET_SIZE];
  uint16_t _rx_buffer_pos = 0;

  // Heartbeat ping/pong are sent through the exact same magic+length+checksum
  // framing as real mesh packets (single-byte payload holding one of these
  // markers) rather than as special raw out-of-band bytes -- one framing/parsing
  // code path for everything, and it's how a 1-byte "packet" is unambiguously
  // told apart from a real (much larger) mesh packet payload on receipt.
  static constexpr uint8_t HEARTBEAT_PING = 0xF1;
  static constexpr uint8_t HEARTBEAT_PONG = 0xF2;

  bool setupTlsConfig();
  void teardownConnection(bool reconnect);
  void startListen();         // server: open+bind the listening socket
  void startConnect();        // client: kick off a new attempt (cached IP first)
  void pollListening();
  void pollHandshake();
  void pollConnectedIO();
  void checkHeartbeat();      // send ping if due; teardown if pong overdue
  void processFramedByte(uint8_t b);
  void sendFramed(const uint8_t *payload, uint16_t len);  // shared: packets + heartbeat
  static int timerGetDelay(void *ctx);
  static void timerSetDelay(void *ctx, uint32_t int_ms, uint32_t fin_ms);
};

#endif
