#pragma once

#include "helpers/bridges/BridgeBase.h"

#ifdef WITH_IP_BRIDGE

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#ifndef MAX_IP_PEERS
// How many simultaneous server-side connections this bridge can hold open at
// once. Covers e.g. a genuinely remote "friends-house" repeater plus a local
// LAN gateway repeater, both connected to the same hub at the same time, with
// some headroom. Each live peer costs a real mbedtls_ssl_context (a few KB of
// heap) plus a small per-peer receive buffer -- raise this only after
// confirming free-heap headroom on the actual board, not blindly.
#define MAX_IP_PEERS 4
#endif

/**
 * @brief Bridge over TCP + TLS-PSK, for IP links between MeshCore nodes.
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
 *     _prefs->ip_host set -> CLIENT: dials out to ip_host:ip_port. A client
 *       only ever needs one relationship (to its one configured hub), so it
 *       always uses _peers[0] and never touches any other slot.
 *     _prefs->ip_host empty, ip_port set -> SERVER: listens on ip_port,
 *       accepts up to MAX_IP_PEERS connections, and requires each to
 *       complete a TLS-PSK handshake before it's trusted with anything.
 *       Every peer authenticates with the same shared ip.secret -- same
 *       convention as ESPNowBridge's one shared bridge.secret for its whole
 *       segment, not a distinct identity per peer.
 * - A new incoming connection while every slot is already in use is accepted
 *   into a separate "challenger" slot and must complete its own TLS-PSK
 *   handshake before it's allowed to evict an existing peer -- a bare TCP
 *   accept() proves nothing (a port scanner or any random connect() could
 *   otherwise knock a live tunnel out), so the swap only happens once the
 *   challenger has proven it holds the real secret. See
 *   pollChallengerHandshake(). On success it evicts whichever slot has gone
 *   longest without hearing anything (oldest last_rx_at), not a fixed slot.
 *   This is what lets a legitimately reconnecting peer (e.g. after an IP
 *   change) get back in without a manual reboot, while an unauthenticated
 *   connection attempt can't touch any existing tunnel at all.
 * - Every CONNECTED peer gets the exact same outbound traffic (both FLOOD and
 *   DIRECT packets) -- see sendPacket(). Mesh-layer encryption already
 *   protects DIRECT payload content from a peer it wasn't addressed to, so
 *   this is a bandwidth tradeoff, not a plaintext leak; it also means no
 *   per-peer destination routing/bookkeeping is needed here at all.
 * - Dead-link detection is still app-level (ping/pong heartbeat, timeout),
 *   tracked per peer: a peer that silently disappears (power loss, cable
 *   pull) gives no clean TCP close -- only a graceful FIN or an active RST
 *   would be caught by the OS, and this needs to catch the silent case too,
 *   without one dead peer affecting any other peer's session.
 * - DNS (client side only) is failure-triggered: reconnect retries the last
 *   known-good IP first, only re-resolving after consecutive failures.
 *
 * Wire framing (once a peer's TLS session is up) mirrors RS232Bridge:
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
  // self_id: this node's own identity. Used two ways:
  //  - Client role: presented as this connection's PSK identity (so the
  //    server can look up which registered peer credential applies).
  //  - Server role: not needed for auth (each connecting peer presents its
  //    own identity instead), kept only for symmetry/future use.
  IpBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, const mesh::LocalIdentity *self_id);

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
  // param, caller's buffer is trusted to be large enough). Lists every
  // non-idle peer slot on the server; single-session summary on the client.
  void formatStatus(char *reply) const;

  // Server role only: the resolved identity (8 hex chars, or empty if not
  // yet/no longer known) of whichever peer is CONNECTED on a given slot --
  // lets callers (MyMesh's bridge_neighbours[] tracking) know exactly who is
  // live on this bridge right now, instead of inferring it from adverts.
  // Returns NULL if idx is out of range or that slot isn't CONNECTED.
  const char* connectedPeerIdentity(int idx) const;
  int peerCount() const { return MAX_IP_PEERS; }

private:
  enum class State : uint8_t {
    IDLE,           // slot empty / not initialized
    TCP_CONNECTING, // client (_peers[0]) only: non-blocking connect() in progress
    HANDSHAKING,    // TLS handshake in progress (either role)
    CONNECTED,      // TLS session up, ready for framed packets
    RECONNECT_WAIT, // client (_peers[0]) only: waiting before retrying
  };

  static constexpr uint16_t OVERHEAD = BRIDGE_MAGIC_SIZE + BRIDGE_LENGTH_SIZE + BRIDGE_CHECKSUM_SIZE;
  static constexpr uint16_t MAX_PACKET_SIZE = (MAX_TRANS_UNIT + 1) + OVERHEAD;

  // Everything that used to be a single scalar connection's worth of state on
  // IpBridge itself, now one per slot. A client only ever populates _peers[0];
  // a server uses as many as it has live connections, up to MAX_IP_PEERS.
  struct PeerSlot {
    State state = State::IDLE;
    mbedtls_net_context conn_fd;
    mbedtls_ssl_context ssl;

    // millis() when the current HANDSHAKING attempt started -- bounds how
    // long a handshake is allowed to sit unresolved (see class doc comment).
    unsigned long handshake_started_at = 0;
    // Throttles how often HANDSHAKING polls mbedtls_ssl_handshake() for this
    // slot -- without it, each poll can block briefly in mbedtls_net_recv()
    // when the peer is slow, and with several slots that adds up.
    unsigned long next_handshake_poll_at = 0;

    // Client (_peers[0]) only: TCP_CONNECTING timeout deadline, or
    // RECONNECT_WAIT retry-at time. Unused on server slots.
    unsigned long next_action_at = 0;

    // Peer's source address (server role only) -- for formatStatus().
    unsigned char client_ip[16] = {0};
    size_t client_ip_len = 0;

    // Server role only: which registered peer identity (8 hex chars)
    // resolved during this slot's handshake -- set by the PSK callback,
    // cleared on teardown. Empty on the client role (a client's one
    // relationship is already known from ip_host, not looked up).
    char identity[9] = {0};

    // Heartbeat / dead-link detection, tracked independently per peer so one
    // silent peer's timeout can't affect any other peer's session.
    unsigned long last_rx_at = 0;
    unsigned long next_ping_at = 0;

    // Per-peer framing/parse state -- two peers can each be mid-frame at once.
    uint8_t rx_buffer[MAX_PACKET_SIZE];
    uint16_t rx_buffer_pos = 0;
  };

  bool _is_server = false;
  bool _server_listening = false;  // instance-wide: is the listen socket bound and up
  PeerSlot _peers[MAX_IP_PEERS];

  // BridgeBase's inherited _seen_packets is shared between RX and TX; a
  // packet needing to cross in one direction could be silently dropped
  // because identical content already crossed the other way. Separate TX
  // table removes that false-positive for this bridge only. Shared across
  // every peer -- "have I already sent this exact packet on this bridge",
  // not per-peer, same convention ESPNowBridge already uses for its whole
  // multi-peer segment.
  SimpleMeshTables _tx_seen;

  // Last known-good IP for the client role, so most reconnects skip DNS.
  char _resolved_ip[16] = {0};
  uint8_t _consecutive_connect_failures = 0;

  bool _defer_heartbeat = false;  // see setDeferHeartbeat()

  mbedtls_net_context _listen_fd;

  // "Challenger" slot: a connection accepted while every real slot is
  // already in use. Held only transiently while it proves itself via its own
  // TLS-PSK handshake -- see pollChallengerHandshake(). Never touches any
  // active session unless/until the challenger's handshake actually
  // succeeds, at which point it's promoted into whichever slot has gone
  // longest without hearing anything, and that old session is torn down.
  bool _challenger_active = false;
  mbedtls_net_context _challenger_fd;
  mbedtls_ssl_context _challenger_ssl;
  unsigned long _challenger_handshake_started_at = 0;
  unsigned char _challenger_ip[16];
  size_t _challenger_ip_len = 0;
  // Resolved by the PSK callback during the challenger's handshake, same as
  // a regular slot's 'identity' field -- copied onto whichever slot the
  // challenger is promoted into on success (see pollChallengerHandshake()).
  char _challenger_identity[9] = {0};

  const mesh::LocalIdentity *_self_id;

  mbedtls_ssl_config _ssl_conf;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_entropy_context _entropy;
  bool _tls_conf_ready = false;

  // Heartbeat ping/pong are sent through the exact same magic+length+checksum
  // framing as real mesh packets (single-byte payload holding one of these
  // markers) rather than as special raw out-of-band bytes -- one framing/parsing
  // code path for everything, and it's how a 1-byte "packet" is unambiguously
  // told apart from a real (much larger) mesh packet payload on receipt.
  static constexpr uint8_t HEARTBEAT_PING = 0xF1;
  static constexpr uint8_t HEARTBEAT_PONG = 0xF2;

  bool anyPeerConnected() const;
  int findFreeSlot();          // -1 if none
  int findStalestSlot();       // for challenger eviction when table is full
  // For debug logging only -- with MAX_IP_PEERS>1, log lines that don't say
  // which peer they're about have no way to be told apart (this bit us: a
  // checksum-mismatch investigation couldn't rule out "two different peers,
  // coincidentally matching checksum" until this existed).
  int peerIndex(const PeerSlot &peer) const { return (int)(&peer - _peers); }

  bool setupTlsConfig();
  // Server role: mbedTLS calls this during a handshake with whatever
  // identity string the connecting client presented. Looks it up against
  // _prefs->ip_peers[], and on a match calls mbedtls_ssl_set_hs_psk() with
  // that peer's own secret and stashes the resolved identity (see
  // rememberResolvedIdentity()) so the eventual PeerSlot/challenger knows
  // who it belongs to. Returns non-zero (handshake fails) on no match --
  // this is the actual access-control check now, not a single shared secret.
  static int pskLookupTrampoline(void *ctx, mbedtls_ssl_context *ssl, const unsigned char *identity, size_t identity_len);
  int resolvePsk(mbedtls_ssl_context *ssl, const unsigned char *identity, size_t identity_len);
  void rememberResolvedIdentity(mbedtls_ssl_context *ssl, const char *identity);
  void teardownConnection(PeerSlot &peer, bool reconnect);
  void scheduleReconnect();        // client-only: bump failure count, compute+log backoff, enter RECONNECT_WAIT
  void startListen();              // server: open+bind+listen the listening socket
  void startConnect();             // client: kick off a new non-blocking connect() (cached IP first) against _peers[0]
  void pollTcpConnecting();        // client: poll the in-progress connect() for completion, against _peers[0]
  void pollListening();            // server: accept new connections (into a free slot, or the challenger)
  void pollHandshake(PeerSlot &peer);            // poll one slot's TLS handshake
  void pollChallengerHandshake();  // server: poll a pending challenger's TLS handshake
  void pollConnectedIO(PeerSlot &peer);
  void checkHeartbeat(PeerSlot &peer);           // send ping if due (client); teardown if pong overdue (both)
  void processFramedByte(PeerSlot &peer, uint8_t b);
  void sendFramed(PeerSlot &peer, const uint8_t *payload, uint16_t len);  // shared: packets + heartbeat
  bool setupSslContext(mbedtls_ssl_context *ssl, mbedtls_net_context *fd);  // shared: ssl_setup + set_bio
};

#endif
