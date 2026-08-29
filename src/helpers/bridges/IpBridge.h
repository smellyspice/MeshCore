#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_IP_BRIDGE

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

/**
 * @brief Bridge over TCP + TLS-PSK, for a point-to-point IP link between
 * exactly two paired MeshCore nodes.
 *
 * - TCP, not UDP: the OS's own retransmit/ordering/flow-control replaces
 *   what would otherwise need to be a hand-rolled ACK+retry layer on top of
 *   UDP. mbedtls_net_connect() has no non-blocking TCP variant, so the
 *   connect step is done manually -- a raw non-blocking socket() + connect(),
 *   polled to completion -- rather than via that call; see startConnect()/
 *   pollTcpConnecting(). Keeps the bridge a synchronous, single-threaded
 *   state machine like RS232Bridge/ESPNowBridge, with no FreeRTOS task or
 *   thread-safety surface.
 * - Role is inferred from config, not a build-time choice:
 *     _prefs->ip_host set -> CLIENT: dials out to ip_host:ip_port.
 *     _prefs->ip_host empty, ip_port set -> SERVER: listens on ip_port,
 *       accepts connections, and requires each to complete a TLS-PSK
 *       handshake before it's trusted with anything.
 * - A new incoming connection while already CONNECTED to a peer is accepted
 *   into a separate "challenger" slot and must complete its own TLS-PSK
 *   handshake before it's allowed to replace the active session -- a bare
 *   TCP accept() proves nothing (a port scanner or any random connect()
 *   could otherwise knock out a live tunnel), so the swap only happens once
 *   the challenger has proven it holds the real secret. See
 *   pollChallengerHandshake(). This is what lets a legitimately reconnecting
 *   peer (e.g. after an IP change) get back in without the other side needing
 *   a manual reboot, while an unauthenticated connection attempt can't touch
 *   the existing tunnel at all.
 * - Dead-link detection is still app-level (ping/pong heartbeat, timeout):
 *   a peer that silently disappears (power loss, cable pull) gives no clean
 *   TCP close -- only a graceful FIN or an active RST would be caught by the
 *   OS, and this needs to catch the silent case too.
 * - DNS (client side only) is failure-triggered: reconnect retries the last
 *   known-good IP first, only re-resolving after consecutive failures.
 *
 * Wire framing (once the TLS session is up) mirrors RS232Bridge:
 * [2 bytes] Magic Header (0xC03E)
 * [2 bytes] Payload Length
 * [n bytes] Mesh Packet Payload
 * [2 bytes] Fletcher-16 Checksum
 * (TLS already gives real integrity/authentication; this framing is purely for
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
    TCP_CONNECTING, // client mode only, non-blocking connect() in progress
    HANDSHAKING,    // TLS handshake in progress (either role)
    CONNECTED,      // TLS session up, ready for framed packets
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
  // entry into that state (pollTcpConnecting() on success, pollListening()'s
  // accept). Bounds how long a handshake is allowed to sit unresolved: a
  // peer that stops responding mid-handshake would otherwise leave this
  // stuck in HANDSHAKING forever -- the server's listening socket still
  // accepts other connections independently (see the challenger slot below),
  // but a client-side stall like this needs its own bound to ever recover.
  // See checkHeartbeat() for the equivalent watchdog once actually
  // CONNECTED -- this covers the gap before that point.
  unsigned long _handshake_started_at = 0;

  // Last known-good IP for the client role, so most reconnects skip DNS.
  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  // Heartbeat / dead-link detection -- the only way to know the link is down
  // when the peer disappears silently rather than closing cleanly. Only the
  // client pings on its own initiative; the server never sends pings, so both
  // roles instead watch _last_rx_at, updated on any valid received frame
  // (ping, pong, or a real mesh packet). If too long has passed since
  // anything was heard, the link is dead -- a simple time-since-last-rx
  // check rather than a per-ping miss counter.
  unsigned long _last_rx_at = 0;
  unsigned long _next_ping_at = 0;
  bool _defer_heartbeat = false;  // see setDeferHeartbeat()

  mbedtls_net_context _listen_fd;

  mbedtls_net_context _conn_fd_slot;
  mbedtls_ssl_context _ssl_slot;
  mbedtls_net_context *_conn_fd = &_conn_fd_slot;
  mbedtls_ssl_context *_ssl = &_ssl_slot;

  // "Challenger" slot: a second, fully separate connection accepted while
  // already CONNECTED to a peer. Held only transiently while it proves
  // itself via its own TLS-PSK handshake -- see pollChallengerHandshake().
  // Never touches the active session's _conn_fd/_ssl above unless/until the
  // challenger's handshake actually succeeds, at which point it's promoted
  // and the old active session is torn down.
  bool _challenger_active = false;
  mbedtls_net_context _challenger_fd;
  mbedtls_ssl_context _challenger_ssl;
  unsigned long _challenger_handshake_started_at = 0;
  unsigned char _challenger_ip[16];
  size_t _challenger_ip_len = 0;

  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  bool _tls_conf_ready = false;

  // Source address of the currently-active peer (server role only) -- purely
  // for formatStatus()'s "connected to peer X.X.X.X" display.
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
  void scheduleReconnect();        // client-only: bump failure count, compute+log backoff, enter RECONNECT_WAIT
  void startListen();              // server: open+bind+listen the listening socket
  void startConnect();             // client: kick off a new non-blocking connect() (cached IP first)
  void pollTcpConnecting();        // client: poll the in-progress connect() for completion
  void pollListening();            // server: accept new connections (primary or challenger)
  void pollHandshake();            // poll the active session's TLS handshake
  void pollChallengerHandshake();  // server: poll a pending challenger's TLS handshake
  void pollConnectedIO();
  void checkHeartbeat();           // send ping if due; teardown if pong overdue
  void processFramedByte(uint8_t b);
  void sendFramed(const uint8_t *payload, uint16_t len);  // shared: packets + heartbeat
  bool setupSslContext(mbedtls_ssl_context *ssl, mbedtls_net_context *fd);  // shared: ssl_setup + set_bio
};

#endif
