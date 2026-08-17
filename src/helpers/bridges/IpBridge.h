#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_IP_BRIDGE

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

/**
 * @brief Bridge implementation over UDP + DTLS-PSK, for a single point-to-point
 * point-to-point IP link between exactly two paired MeshCore nodes.
 *
 * See planning/ip-bridge-design.md for the full design rationale. Summary
 * of the decisions that shape this class:
 *
 * - UDP, not TCP: mbedtls_net_connect() has no non-blocking variant for TCP (it
 *   performs a blocking DNS resolution and TCP handshake). A UDP socket's connect()
 *   is local-only bookkeeping, and DTLS's handshake is explicitly designed to be
 *   timer-driven from an external loop rather than requiring a blocking thread --
 *   see mbedtls_ssl_set_timer_cb() below. This keeps the bridge a synchronous,
 *   single-threaded state machine like RS232Bridge/ESPNowBridge, with no FreeRTOS
 *   task and no thread-safety surface.
 * - Best-effort, fire-and-forget: no bridge-level packet retry, consistent with
 *   ESPNowBridge (esp_now_send() is one-shot; there's no ack/retry anywhere in the
 *   mesh/repeater layer for relay traffic).
 * - Role is inferred from config, not a build-time choice:
 *     _prefs->ip_host set   -> CLIENT: dials out to ip_host:ip_port.
 *     _prefs->ip_host empty, ip_port set -> SERVER: listens on ip_port,
 *       accepts datagrams from the first peer that completes a valid DTLS-PSK
 *       handshake, then locks (connects) the socket to that one peer address.
 *       Deliberately NOT implementing mbedTLS's HelloVerifyRequest/cookie
 *       multi-client-tracking mechanism -- that exists to let one bind socket
 *       serve many simultaneous clients, which doesn't apply here (exactly one
 *       peer, ever, by design -- see planning doc). Accepted tradeoff: a
 *       malicious remote host could send us garbage ClientHellos and cost us a
 *       little CPU on failed handshakes, but without the correct PSK they can
 *       never complete a handshake or read/write mesh traffic -- worst case is a
 *       minor CPU nuisance, not a confidentiality/integrity risk.
 * - Dead-link detection is app-level (ping/pong heartbeat, N consecutive misses),
 *   because UDP/DTLS gives no OS-level "connection dropped" signal at all.
 * - DNS (client/spoke side only) is failure-triggered, not proactive: on
 *   reconnect, retries the last known-good IP first; only re-resolves via
 *   WiFi.hostByName() (bounded ~15s worst case, not mbedTLS's fully blocking
 *   resolver) after a couple of consecutive failures against the cached IP.
 *
 * Wire framing (once the DTLS session is up) mirrors RS232Bridge exactly, since a
 * DTLS record stream, like serial, needs explicit message framing:
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

  // Throttles how often HANDSHAKING polls mbedtls_ssl_handshake(), independent
  // of mbedTLS's own DTLS retransmit backoff (which only paces re-sending the
  // flight, not how often we call in to check). Without this, loop() calls
  // pollHandshake() on every single tick -- and each call blocks for up to
  // mbedtls_ssl_conf_read_timeout()'s 1ms via a real select() inside
  // mbedtls_net_recv_timeout() when no reply is available (e.g. peer
  // unreachable). That capped the whole main loop at ~1kHz and starved
  // everything else sharing it (CLI serial reads, mesh dispatch, LEDs) --
  // confirmed live via a spoke pointed at an unreachable hub. See
  // planning/ip-bridge-design.md.
  unsigned long _next_handshake_poll_at = 0;

  // last known-good IP for the client role, so most reconnects skip DNS entirely
  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  // heartbeat / dead-link detection (the only way to know the link is down at all,
  // since UDP/DTLS gives no OS-level disconnect signal -- see class comment).
  // Only the client/spoke sends pings on its own initiative (_next_ping_at);
  // the server/hub never independently pings -- it has nothing useful to say
  // unprompted, and doing so would need its own peer to still be listening,
  // which is exactly what's in question. Both roles use the SAME passive
  // watchdog though: _last_rx_at updates on ANY valid received frame (ping,
  // pong, or a real mesh packet), not just pongs specifically -- if it only
  // tracked pongs, the hub (which never sends pings, so never receives a pong)
  // would immediately think the link was dead. Simple time-since-last-rx
  // watchdog rather than a per-ping miss counter: if too long has passed since
  // anything was heard, the link is dead, full stop -- equivalent to "N
  // consecutive misses" without needing to track N separately.
  unsigned long _last_rx_at = 0;
  unsigned long _next_ping_at = 0;

  struct Timer {
    unsigned long int_at = 0;
    unsigned long fin_at = 0;
    bool active = false;
  };

  mbedtls_net_context _listen_fd;

  // Two fixed-address slots for the connection contexts, so a peer-restart
  // reconnect (see checkForReconnectAttempt()/pollTentativeHandshake()) can
  // verify a challenger on a SEPARATE tentative context without disturbing
  // the live one -- an unauthenticated sender (scanner, garbage UDP) can
  // never affect the live session, only cost a bounded amount of CPU/RAM on
  // its own doomed attempt (same accepted tradeoff as the no-HelloVerify
  // decision above, extended to cover this path too). _ssl/_conn_fd/_timer
  // are pointers into whichever slot is currently "live"; promoting a
  // verified tentative attempt just flips which slot each pointer targets --
  // deliberately NOT a struct copy/swap, since mbedtls_ssl_context stores
  // pointers (via mbedtls_ssl_set_bio()/set_timer_cb()) back to &_conn_fd/
  // &_timer by address, and copying the struct's bytes elsewhere would leave
  // those internal pointers referencing the old (soon-to-be-reused) address.
  // Swapping the indirection layer instead means the underlying structs
  // never move, so nothing needs re-pointing.
  mbedtls_net_context _conn_fd_slot[2];
  mbedtls_ssl_context _ssl_slot[2];
  Timer _timer_slot[2];
  mbedtls_net_context *_conn_fd = &_conn_fd_slot[0];
  mbedtls_ssl_context *_ssl = &_ssl_slot[0];
  Timer *_timer = &_timer_slot[0];
  mbedtls_net_context *_tentative_conn_fd = &_conn_fd_slot[1];
  mbedtls_ssl_context *_tentative_ssl = &_ssl_slot[1];
  Timer *_tentative_timer = &_timer_slot[1];

  // Bounded to exactly one tentative attempt at a time (no pool/queue) --
  // caps worst-case extra RAM at one additional mbedtls_ssl_context
  // (~32KB, same MBEDTLS_SSL_MAX_CONTENT_LEN cost as the live session, see
  // NFR6 in planning/ip-bridge-design.md) no matter how many stray
  // packets/scanners hit the listen port. Has its own timeout, shorter than
  // and independent of the main heartbeat timeout, so a stalled or
  // intentionally-incomplete attempt can't camp the slot indefinitely.
  bool _tentative_active = false;
  unsigned long _tentative_started_at = 0;

  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  bool _tls_conf_ready = false;

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

  void checkForReconnectAttempt();  // server only: watch _listen_fd while CONNECTED
  void pollTentativeHandshake();    // advance/timeout/promote the tentative attempt
  void discardTentative();
};

#endif
