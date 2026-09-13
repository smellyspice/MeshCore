#include "IpBridge.h"

#ifdef WITH_IP_BRIDGE

#include <WiFi.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>

// Optional cross-cutting hook: boards whose radio_driver knows how to show
// connect/disconnect/ping/pong status on an LED get that status lit up here.
// Two concrete radio_driver types currently implement it -- ESPNowBridgeRadio
// (a board that pairs IpBridge with it as its no-LoRa client radio, e.g. the
// esp32_s3_zero companion/room-server envs) and NullRadio (a board that
// pairs IpBridge with WITH_ESPNOW_BRIDGE's real host class instead, e.g. a
// LoRa-less gateway repeater, which has no radio hardware at all). Only one
// of these is ever compiled in for a given board. IP_BRIDGE_HAS_STATUS_LED
// is what every call site below actually checks, so adding a third
// LED-capable radio_driver later only means adding a branch here, not
// touching every call site. Gated the same way main.cpp already gates
// relockChannel() -- keeps IpBridge itself portable, not hard-dependent on
// any one radio driver.
#if defined(ESPNOW_BRIDGE_RADIO)
#include <helpers/esp32/ESPNowBridgeRadio.h>
extern ESPNowBridgeRadio radio_driver;
#define IP_BRIDGE_HAS_STATUS_LED 1
#elif defined(NULLRADIO_STATUS_LED)
#include <helpers/esp32/NullRadio.h>
extern NullRadio radio_driver;
#define IP_BRIDGE_HAS_STATUS_LED 1
#endif

#ifndef IP_BRIDGE_PING_INTERVAL_MS
#define IP_BRIDGE_PING_INTERVAL_MS   15000   // how often the client pings
#endif
#ifndef IP_BRIDGE_PONG_TIMEOUT_MS
#define IP_BRIDGE_PONG_TIMEOUT_MS    45000   // ~3 missed pings -> dead link
#endif
#ifndef IP_BRIDGE_RECONNECT_DELAY_MS
#define IP_BRIDGE_RECONNECT_DELAY_MS 5000    // base delay -- see reconnectDelayFor()
#endif
#ifndef IP_BRIDGE_RECONNECT_MAX_MS
#define IP_BRIDGE_RECONNECT_MAX_MS   60000   // cap backoff at 60s -- a client only
                                              // ever has one peer, no shared server to
                                              // be gentle on, so bias toward noticing
                                              // the peer come back over minimizing retries
#endif
#ifndef IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS
#define IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS 50  // see next_handshake_poll_at in IpBridge.h
#endif
#ifndef IP_BRIDGE_HANDSHAKE_TIMEOUT_MS
// Bounds how long a TLS handshake (any peer slot, or the challenger) is
// allowed to sit unresolved before being given up on -- see
// handshake_started_at in IpBridge.h for what this guards against.
#define IP_BRIDGE_HANDSHAKE_TIMEOUT_MS 30000
#endif
#ifndef IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS
// Bounds the manual non-blocking connect() (see startConnect()/
// pollTcpConnecting()) -- an unreachable host would otherwise only fail via
// the OS's own SYN retry timeout, which can be tens of seconds.
#define IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS 5000
#endif
#ifndef IP_BRIDGE_KEEPALIVE_IDLE_SECS
#define IP_BRIDGE_KEEPALIVE_IDLE_SECS  30   // start probing after this long idle
#endif
#ifndef IP_BRIDGE_KEEPALIVE_INTVL_SECS
#define IP_BRIDGE_KEEPALIVE_INTVL_SECS 10   // gap between unanswered probes
#endif
#ifndef IP_BRIDGE_KEEPALIVE_COUNT
#define IP_BRIDGE_KEEPALIVE_COUNT      3    // probes before the kernel declares the link dead
#endif

// TCP-level keepalive -- a defense-in-depth backstop alongside the app-level
// ping/pong heartbeat below. Kept as a supplement, not a replacement: a
// keepalive-triggered failure surfaces as a generic OS-mapped error code on
// the next mbedtls_ssl_read()/write(), indistinguishable in BRIDGE_DEBUG
// output from any other transport error, whereas the app-level heartbeat
// logs an explicit "Heartbeat timeout" line -- valuable while this bridge is
// still being actively debugged. Also incidentally keeps NAT/router
// connection-tracking state alive on a port-forwarded path, independent of
// app-level traffic.
static void applyTcpKeepalive(int fd) {
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  int idle = IP_BRIDGE_KEEPALIVE_IDLE_SECS;
  int intvl = IP_BRIDGE_KEEPALIVE_INTVL_SECS;
  int cnt = IP_BRIDGE_KEEPALIVE_COUNT;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

// Client-only concept -- the server has no "reconnect", a freed slot just
// goes back to IDLE (a fresh peer is always welcome, no backoff needed there).
// Doubles the base delay per consecutive failure, capped at
// IP_BRIDGE_RECONNECT_MAX_MS, so a peer that's down for an extended stretch
// (not just a transient blip) gets retried less aggressively over time
// instead of a flat 5s forever. Shift is clamped well before it could push
// the value past the cap anyway, just to keep the math trivially safe.
static uint32_t reconnectDelayFor(uint8_t consecutive_failures) {
  uint8_t shift = consecutive_failures > 6 ? 6 : consecutive_failures;
  uint32_t delay = (uint32_t)IP_BRIDGE_RECONNECT_DELAY_MS << shift;
  return delay > IP_BRIDGE_RECONNECT_MAX_MS ? IP_BRIDGE_RECONNECT_MAX_MS : delay;
}

IpBridge::IpBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, const mesh::LocalIdentity *self_id)
    : BridgeBase(prefs, mgr, rtc), _self_id(self_id) {
  mbedtls_net_init(&_listen_fd);
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    mbedtls_net_init(&_peers[i].conn_fd);
    mbedtls_ssl_init(&_peers[i].ssl);
  }
  mbedtls_net_init(&_challenger_fd);
  mbedtls_ssl_init(&_challenger_ssl);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);
}

bool IpBridge::setupTlsConfig() {
  if (_tls_conf_ready) return true;

  const char *pers = "IpBridge";
  if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                             (const unsigned char *)pers, strlen(pers)) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ctr_drbg_seed failed\n");
    return false;
  }

  int endpoint = _is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;
  if (mbedtls_ssl_config_defaults(&_ssl_conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_config_defaults failed\n");
    return false;
  }

  // PSK-only: no certificates, so nothing to verify via authmode.
  mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

  // mbedtls_ssl_config_defaults()'s default ciphersuite list includes cert-based
  // suites we never configure (no certs at all -- PSK only). Restricting explicitly
  // to PSK suites matches mbedTLS's own official PSK example programs and avoids
  // relying on negotiation happening to fall back to PSK correctly on its own.
  static const int psk_ciphersuites[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
  };
  mbedtls_ssl_conf_ciphersuites(&_ssl_conf, psk_ciphersuites);

  if (_is_server) {
    // Per-peer credentials: mbedTLS calls resolvePsk() once per handshake
    // with whatever identity the connecting client presented, and it's
    // resolvePsk()'s job to look that up against _prefs->ip_peers[] and set
    // the matching secret -- see pskLookupTrampoline()/resolvePsk() below.
    // A client presenting an identity with no registered credential simply
    // fails the handshake (real access control, not "anyone holding the one
    // shared secret gets in").
    mbedtls_ssl_conf_psk_cb(&_ssl_conf, IpBridge::pskLookupTrampoline, this);
  } else {
    // Client role: present this node's own identity (so the server can look
    // up the matching credential) and this node's own secret, registered
    // against that identity on whichever server it dials.
    char own_identity[9];
    mesh::Utils::toHex(own_identity, _self_id->pub_key, 4);
    size_t secret_len = strlen(_prefs->ip_secret);
    if (mbedtls_ssl_conf_psk(&_ssl_conf, (const unsigned char *)_prefs->ip_secret, secret_len,
                              (const unsigned char *)own_identity, strlen(own_identity)) != 0) {
      BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_conf_psk failed\n");
      return false;
    }
  }

  _tls_conf_ready = true;
  return true;
}

int IpBridge::pskLookupTrampoline(void *ctx, mbedtls_ssl_context *ssl, const unsigned char *identity, size_t identity_len) {
  return ((IpBridge *)ctx)->resolvePsk(ssl, identity, identity_len);
}

int IpBridge::resolvePsk(mbedtls_ssl_context *ssl, const unsigned char *identity, size_t identity_len) {
  char id[9];
  size_t n = identity_len < 8 ? identity_len : 8;
  memcpy(id, identity, n);
  id[n] = 0;

  for (int i = 0; i < MAX_IP_PEER_CREDENTIALS; i++) {
    const NodePrefs::IpPeerCredential &cred = _prefs->ip_peers[i];
    if (cred.identity[0] != 0 && strcasecmp(cred.identity, id) == 0) {
      size_t secret_len = strlen(cred.secret);
      if (mbedtls_ssl_set_hs_psk(ssl, (const unsigned char *)cred.secret, secret_len) != 0) {
        BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_set_hs_psk failed for peer %s\n", id);
        return -1;
      }
      rememberResolvedIdentity(ssl, id);
      return 0;
    }
  }
  BRIDGE_DEBUG_PRINTLN("PSK lookup: no registered credential for identity %s, rejecting\n", id);
  return -1;
}

void IpBridge::rememberResolvedIdentity(mbedtls_ssl_context *ssl, const char *identity) {
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (&_peers[i].ssl == ssl) {
      memcpy(_peers[i].identity, identity, sizeof(_peers[i].identity));
      return;
    }
  }
  if (&_challenger_ssl == ssl) {
    memcpy(_challenger_identity, identity, sizeof(_challenger_identity));
  }
}

const char* IpBridge::connectedPeerIdentity(int idx) const {
  if (idx < 0 || idx >= MAX_IP_PEERS) return NULL;
  const PeerSlot &peer = _peers[idx];
  if (peer.state != State::CONNECTED || peer.identity[0] == 0) return NULL;
  return peer.identity;
}

void IpBridge::disconnectPeerByIdentity(const char *identity) {
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    PeerSlot &peer = _peers[i];
    if (peer.state == State::CONNECTED && strcasecmp(peer.identity, identity) == 0) {
      BRIDGE_DEBUG_PRINTLN("[peer %d] Revoked, disconnecting\n", i);
      teardownConnection(peer, false);
      return;
    }
  }
}

// Shared setup for any slot (a real peer slot, or the challenger): a fresh
// mbedtls_ssl_context bound to an already-non-blocking fd. f_recv_timeout is
// deliberately NULL -- this makes mbedTLS fall back to the plain non-blocking
// mbedtls_net_recv() (the fd is already non-blocking via
// mbedtls_net_set_nonblock() below), which returns MBEDTLS_ERR_SSL_WANT_READ
// immediately instead of ever blocking the caller -- mbedTLS's own documented
// pattern for externally-polled I/O.
bool IpBridge::setupSslContext(mbedtls_ssl_context *ssl, mbedtls_net_context *fd) {
  mbedtls_net_set_nonblock(fd);
  mbedtls_ssl_free(ssl);
  mbedtls_ssl_init(ssl);
  int setup_ret = mbedtls_ssl_setup(ssl, &_ssl_conf);
  if (setup_ret != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_setup failed, ret=-0x%04x, free_heap=%u\n",
                         (unsigned)(-setup_ret), (unsigned)ESP.getFreeHeap());
    return false;
  }
  mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  return true;
}

bool IpBridge::anyPeerConnected() const {
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (_peers[i].state == State::CONNECTED) return true;
  }
  return false;
}

int IpBridge::findFreeSlot() {
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (_peers[i].state == State::IDLE) return i;
  }
  return -1;
}

// Picks which peer to evict for a challenger that's just proven itself, once
// every slot is already in use. Prefers the CONNECTED slot that's gone
// longest without hearing anything (oldest last_rx_at) over disturbing a slot
// that's still (rarely) mid-handshake itself -- falls back to slot 0 only in
// the degenerate case where every slot is somehow HANDSHAKING at once.
int IpBridge::findStalestSlot() {
  int stalest = -1;
  unsigned long oldest_rx = 0;
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (_peers[i].state == State::CONNECTED) {
      if (stalest < 0 || _peers[i].last_rx_at < oldest_rx) {
        stalest = i;
        oldest_rx = _peers[i].last_rx_at;
      }
    }
  }
  return stalest >= 0 ? stalest : 0;
}

void IpBridge::begin() {
  BRIDGE_DEBUG_PRINTLN("Initializing...\n");

  _is_server = (_prefs->ip_host[0] == 0);
  if (_is_server && _prefs->ip_port == 0) {
    BRIDGE_DEBUG_PRINTLN("No ip.host or ip.port configured, not starting\n");
    return;
  }
  if (strlen(_prefs->ip_secret) == 0) {
    BRIDGE_DEBUG_PRINTLN("No ip.secret configured, not starting\n");
    return;
  }

  if (!setupTlsConfig()) return;

  for (int i = 0; i < MAX_IP_PEERS; i++) {
    _peers[i].state = State::IDLE;
    _peers[i].rx_buffer_pos = 0;
  }
  _consecutive_connect_failures = 0;

  if (_is_server) {
    startListen();
#ifdef IP_BRIDGE_HAS_STATUS_LED
    if (_server_listening) radio_driver.indicateServerMode();
#endif
#ifdef IP_BRIDGE_HAS_STATUS_LED
    // Not-connected indicator: hub listening with nobody there yet. Only
    // reached once begin() has confirmed the bridge is actually configured
    // and startListen() didn't fail, so an unconfigured board never lights
    // this at all.
    if (_server_listening) radio_driver.setLinkConnected(false);
#endif
  } else {
    startConnect();
#ifdef IP_BRIDGE_HAS_STATUS_LED
    if (_peers[0].state != State::IDLE) radio_driver.setLinkConnected(false);
#endif
  }

  _initialized = true;
}

void IpBridge::end() {
  BRIDGE_DEBUG_PRINTLN("Stopping...\n");

  for (int i = 0; i < MAX_IP_PEERS; i++) {
    mbedtls_ssl_free(&_peers[i].ssl);
    mbedtls_net_free(&_peers[i].conn_fd);
    mbedtls_ssl_init(&_peers[i].ssl);
    mbedtls_net_init(&_peers[i].conn_fd);
    _peers[i].state = State::IDLE;
    _peers[i].rx_buffer_pos = 0;
  }
  mbedtls_net_free(&_listen_fd);
  mbedtls_ssl_free(&_challenger_ssl);
  mbedtls_net_free(&_challenger_fd);
  mbedtls_ssl_config_free(&_ssl_conf);
  mbedtls_ctr_drbg_free(&_ctr_drbg);
  mbedtls_entropy_free(&_entropy);
  _tls_conf_ready = false;

  mbedtls_net_init(&_listen_fd);
  mbedtls_ssl_init(&_challenger_ssl);
  mbedtls_net_init(&_challenger_fd);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);

  _server_listening = false;
  _challenger_active = false;
  _initialized = false;
}

// Formats a peer address (raw bytes from mbedtls_net_accept()) as
// dotted-decimal. IPv4 only -- this bridge is built on
// WiFi.hostByName()/IPAddress throughout, never IPv6.
static void formatPeerIp(const unsigned char *ip, size_t len, char *out) {
  if (len == 4) {
    sprintf(out, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  } else {
    strcpy(out, "?");
  }
}

void IpBridge::formatStatus(char *reply) const {
  char peer_ip[20];
  const char *challenger_note = _challenger_active ? " (+ challenger authenticating)" : "";

  if (_is_server) {
    if (!_server_listening) {
      sprintf(reply, "idle (not started)");
      return;
    }

    // Caller's buffer is a fixed 'char reply[160]' (see examples/*/main.cpp),
    // and this is invoked as formatIpStatus(&reply[2]) -- 158 bytes usable.
    // With MAX_IP_PEERS=4, four fully-populated peer segments alone can run
    // past 260 bytes, so every segment below is length-checked against what
    // actually remains rather than appended unconditionally -- this used to
    // be unbounded sprintf() and overflowed the caller's stack buffer with
    // as few as 3 connected peers (stack-smashing crash/reboot, previously
    // mistaken for the multi-peer CLI-responsiveness issue itself -- see
    // planning/firmware-env-consolidation.md).
    const size_t budget = 158;
    char *dp = reply;
    size_t used = 0;
    char segment[80];

#define APPEND_SEGMENT() do { \
      size_t seg_len = strlen(segment); \
      if (used + seg_len + 1 > budget) { \
        if (used + 6 <= budget) strcpy(dp + used, "; ..."); \
        used = strlen(reply); \
        goto format_status_done; \
      } \
      strcpy(dp + used, segment); \
      used += seg_len; \
    } while (0)

    used = (size_t)snprintf(reply, budget, "listening on port %u", (unsigned)_prefs->ip_port);

    int connected_count = 0;
    for (int i = 0; i < MAX_IP_PEERS; i++) {
      const PeerSlot &peer = _peers[i];
      if (peer.state == State::IDLE) continue;
      connected_count++;
      formatPeerIp(peer.client_ip, peer.client_ip_len, peer_ip);
      unsigned long since_rx_secs = peer.last_rx_at == 0 ? 0 : (millis() - peer.last_rx_at) / 1000;
      if (peer.state == State::HANDSHAKING) {
        snprintf(segment, sizeof(segment), "; peer %s attempting handshake...", peer_ip);
      } else if (peer.state == State::CONNECTED) {
        const char *id = peer.identity[0] != 0 ? peer.identity : "?";
        if (peer.last_rx_at == 0) {
          snprintf(segment, sizeof(segment), "; peer %s [%s] connected, nothing received yet", peer_ip, id);
        } else {
          snprintf(segment, sizeof(segment), "; peer %s [%s] connected, last heard %lus ago", peer_ip, id, since_rx_secs);
        }
      } else {
        continue;
      }
      APPEND_SEGMENT();
    }
    if (connected_count == 0) {
      snprintf(segment, sizeof(segment), ", no peers yet");
      APPEND_SEGMENT();
    }
    snprintf(segment, sizeof(segment), "%s", challenger_note);
    APPEND_SEGMENT();
format_status_done:
    dp[used] = 0;
#undef APPEND_SEGMENT
  } else {  // client, always _peers[0]
    const PeerSlot &peer = _peers[0];
    unsigned long since_rx_secs = peer.last_rx_at == 0 ? 0 : (millis() - peer.last_rx_at) / 1000;
    switch (peer.state) {
      case State::IDLE:
        sprintf(reply, "idle (not started)");
        break;
      case State::TCP_CONNECTING:
        sprintf(reply, "connecting to %s (resolved: %s)...", _prefs->ip_host, _resolved_ip);
        break;
      case State::HANDSHAKING:
        sprintf(reply, "authenticating with %s (resolved: %s)...", _prefs->ip_host, _resolved_ip);
        break;
      case State::CONNECTED:
        if (peer.last_rx_at == 0) {
          sprintf(reply, "connected to %s (%s), nothing received yet", _prefs->ip_host, _resolved_ip);
        } else {
          sprintf(reply, "connected to %s (%s), last heard %lus ago", _prefs->ip_host, _resolved_ip, since_rx_secs);
        }
        break;
      case State::RECONNECT_WAIT:
        if (_resolved_ip[0] == 0) {
          sprintf(reply, "DNS lookup failed for %s, retrying...", _prefs->ip_host);
        } else {
          sprintf(reply, "reconnecting to %s (%s), %u failed attempt%s so far", _prefs->ip_host, _resolved_ip,
                  (unsigned)_consecutive_connect_failures, _consecutive_connect_failures == 1 ? "" : "s");
        }
        break;
      default:
        sprintf(reply, "unknown state");
        break;
    }
  }
}

void IpBridge::scheduleReconnect() {
  PeerSlot &peer = _peers[0];
  peer.state = State::RECONNECT_WAIT;

  if (WiFi.status() != WL_CONNECTED) {
    // No network at all right now -- this isn't "the peer is unreachable",
    // it's "there's nothing to even try over yet". Don't let this pile onto
    // the backoff: keep polling at the short base interval instead, so once
    // WiFi actually comes back (it has its own independent reconnect logic,
    // see main.cpp's wifi_needs_reconnect handling) the very next attempt
    // happens quickly rather than waiting out a multi-minute backoff window
    // that had nothing to do with the peer at all. If the peer genuinely
    // isn't answering once WiFi IS up, the real backoff below starts fresh.
    _consecutive_connect_failures = 0;
    peer.next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    BRIDGE_DEBUG_PRINTLN("No WiFi yet, retrying in %us\n", (unsigned)(IP_BRIDGE_RECONNECT_DELAY_MS / 1000));
    return;
  }

  _consecutive_connect_failures++;
  uint32_t delay = reconnectDelayFor(_consecutive_connect_failures);
  peer.next_action_at = millis() + delay;
  BRIDGE_DEBUG_PRINTLN("Reconnecting in %us (%u consecutive failure%s)\n",
                        (unsigned)(delay / 1000), (unsigned)_consecutive_connect_failures,
                        _consecutive_connect_failures == 1 ? "" : "s");
}

void IpBridge::startListen() {
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", (unsigned)_prefs->ip_port);

  mbedtls_net_free(&_listen_fd);
  mbedtls_net_init(&_listen_fd);
  if (mbedtls_net_bind(&_listen_fd, NULL, port_str, MBEDTLS_NET_PROTO_TCP) != 0) {
    BRIDGE_DEBUG_PRINTLN("Failed to bind TCP port %s\n", port_str);
    return;
  }
  mbedtls_net_set_nonblock(&_listen_fd);
  _server_listening = true;
  BRIDGE_DEBUG_PRINTLN("Listening on TCP %s\n", port_str);
}

void IpBridge::startConnect() {
  PeerSlot &peer = _peers[0];

  // Only re-resolve after a couple of consecutive failures against the cached IP --
  // most reconnects are transient blips, not an actual home IP change, so this
  // skips DNS on the first attempt or two. Since _consecutive_connect_failures
  // is no longer reset on a successful resolve (see below), every attempt once
  // past this threshold re-resolves -- deliberate, not a regression: during a
  // real extended outage this keeps picking up a genuinely changed DDNS IP
  // instead of only checking once and then giving up on ever re-checking.
  if (_resolved_ip[0] == 0 || _consecutive_connect_failures >= 2) {
    IPAddress ip;
    if (!WiFi.hostByName(_prefs->ip_host, ip)) {
      BRIDGE_DEBUG_PRINTLN("DNS lookup failed for %s\n", _prefs->ip_host);
      scheduleReconnect();
      return;
    }
    strncpy(_resolved_ip, ip.toString().c_str(), sizeof(_resolved_ip) - 1);
    _resolved_ip[sizeof(_resolved_ip) - 1] = 0;
    // Deliberately NOT resetting _consecutive_connect_failures here -- a
    // successful DNS lookup says nothing about whether the peer is actually
    // reachable, and zeroing the counter on it was undoing the backoff every
    // time this re-resolve threshold was hit, capping it at 20s forever
    // instead of ever climbing higher. The counter only resets on an actual
    // successful connection (see pollHandshake()).
    BRIDGE_DEBUG_PRINTLN("Resolved %s -> %s\n", _prefs->ip_host, _resolved_ip);
  }

  mbedtls_net_free(&peer.conn_fd);
  mbedtls_net_init(&peer.conn_fd);

  // mbedtls_net_connect() has no non-blocking TCP variant (see class doc
  // comment) -- it performs a real, blocking connect() for TCP, which would
  // freeze this whole single-threaded loop() for as long as it takes to
  // resolve. Done manually instead: create the socket, mark it non-blocking
  // *before* connect() so it returns immediately with EINPROGRESS, then poll
  // for completion in pollTcpConnecting().
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    BRIDGE_DEBUG_PRINTLN("TCP socket() failed, errno=%d\n", errno);
    scheduleReconnect();
    return;
  }

  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)_prefs->ip_port);
  // _resolved_ip is always a numeric dotted-decimal string here, never the raw
  // hostname -- resolution already happened above via WiFi.hostByName().
  addr.sin_addr.s_addr = inet_addr(_resolved_ip);

  int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    BRIDGE_DEBUG_PRINTLN("TCP connect() failed immediately, errno=%d\n", errno);
    close(fd);
    scheduleReconnect();
    return;
  }

  applyTcpKeepalive(fd);

  // mbedtls_net_context is just {int fd} -- trivial to populate directly,
  // bypassing mbedtls_net_connect() entirely for this step. Everything
  // downstream (mbedtls_net_set_nonblock(), mbedtls_ssl_set_bio(), etc.)
  // operates purely on ctx->fd and doesn't care how it got there.
  peer.conn_fd.fd = fd;
  peer.state = State::TCP_CONNECTING;
  peer.next_action_at = millis() + IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS;
  BRIDGE_DEBUG_PRINTLN("TCP connect in progress to %s:%u\n", _resolved_ip, (unsigned)_prefs->ip_port);
}

void IpBridge::pollTcpConnecting() {
  PeerSlot &peer = _peers[0];

  if ((int32_t)(millis() - peer.next_action_at) > 0) {
    BRIDGE_DEBUG_PRINTLN("TCP connect timed out\n");
    mbedtls_net_free(&peer.conn_fd);
    scheduleReconnect();
    return;
  }

  // Standard non-blocking-connect completion check: once the socket is
  // writable, the connect attempt has resolved one way or the other --
  // SO_ERROR distinguishes success (0) from a real failure.
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(peer.conn_fd.fd, &wfds);
  struct timeval tv = {0, 0};
  int sel = select(peer.conn_fd.fd + 1, NULL, &wfds, NULL, &tv);
  if (sel <= 0) return;  // not resolved yet, keep waiting

  int sock_err = 0;
  socklen_t err_len = sizeof(sock_err);
  getsockopt(peer.conn_fd.fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
  if (sock_err != 0) {
    BRIDGE_DEBUG_PRINTLN("TCP connect failed, err=%d\n", sock_err);
    mbedtls_net_free(&peer.conn_fd);
    scheduleReconnect();
    return;
  }

  if (!setupSslContext(&peer.ssl, &peer.conn_fd)) {
    mbedtls_net_free(&peer.conn_fd);
    scheduleReconnect();
    return;
  }

  peer.rx_buffer_pos = 0;
  peer.state = State::HANDSHAKING;
  peer.next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
  peer.handshake_started_at = millis();
  BRIDGE_DEBUG_PRINTLN("TCP connected, starting TLS handshake\n");
}

void IpBridge::pollListening() {
  mbedtls_net_context new_conn;
  mbedtls_net_init(&new_conn);

  unsigned char peer_ip[16];
  size_t peer_ip_len = 0;
  int ret = mbedtls_net_accept(&_listen_fd, &new_conn, peer_ip, sizeof(peer_ip), &peer_ip_len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    mbedtls_net_free(&new_conn);
    return;  // no pending connection
  }
  if (ret != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_net_accept error %d\n", ret);
    mbedtls_net_free(&new_conn);
    return;  // try again next loop()
  }

  applyTcpKeepalive(new_conn.fd);

  int free_idx = findFreeSlot();
  if (free_idx >= 0) {
    // A free slot exists -- this becomes that slot's session, same as
    // always. A bare accept() doesn't need extra scrutiny here: nothing
    // valuable exists yet in an empty slot to protect.
    PeerSlot &peer = _peers[free_idx];
    mbedtls_net_free(&peer.conn_fd);
    peer.conn_fd = new_conn;
    memcpy(peer.client_ip, peer_ip, peer_ip_len);
    peer.client_ip_len = peer_ip_len;

    if (!setupSslContext(&peer.ssl, &peer.conn_fd)) {
      mbedtls_net_free(&peer.conn_fd);
      return;  // slot stays IDLE
    }

    peer.rx_buffer_pos = 0;
    peer.identity[0] = 0;  // resolved by the PSK callback during the handshake below
    peer.state = State::HANDSHAKING;
    peer.next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
    peer.handshake_started_at = millis();
    BRIDGE_DEBUG_PRINTLN("Peer connecting (slot %d), starting TLS handshake\n", free_idx);
    return;
  }

  // Every slot is already in use (HANDSHAKING or CONNECTED) -- a bare TCP
  // accept() proves nothing yet (see class doc comment), so this must NOT
  // touch any existing session. Land it in the challenger slot and let it
  // prove itself via its own handshake first. Only one challenger at a
  // time -- reject a second simultaneous attempt outright rather than
  // letting an unauthenticated flood tie up unbounded resources.
  if (_challenger_active) {
    BRIDGE_DEBUG_PRINTLN("Rejecting extra connection attempt, a challenger is already mid-handshake\n");
    mbedtls_net_free(&new_conn);
    return;
  }

  mbedtls_net_free(&_challenger_fd);
  _challenger_fd = new_conn;
  memcpy(_challenger_ip, peer_ip, peer_ip_len);
  _challenger_ip_len = peer_ip_len;

  if (!setupSslContext(&_challenger_ssl, &_challenger_fd)) {
    mbedtls_net_free(&_challenger_fd);
    return;
  }

  _challenger_active = true;
  _challenger_handshake_started_at = millis();
  BRIDGE_DEBUG_PRINTLN("New connection while all %d slots full -- challenger handshake starting\n", MAX_IP_PEERS);
}

void IpBridge::pollHandshake(PeerSlot &peer) {
  if ((int32_t)(millis() - peer.handshake_started_at) > (int32_t)IP_BRIDGE_HANDSHAKE_TIMEOUT_MS) {
    // A peer that stops responding mid-handshake would otherwise leave this
    // stuck here forever. Same recovery path as any other handshake
    // failure: teardownConnection() already knows how to free the slot (or
    // put the client into RECONNECT_WAIT).
    BRIDGE_DEBUG_PRINTLN("[peer %d] TLS handshake timed out after %ums, giving up\n",
                         peerIndex(peer), (unsigned)IP_BRIDGE_HANDSHAKE_TIMEOUT_MS);
    teardownConnection(peer, true);
    return;
  }

  int ret = mbedtls_ssl_handshake(&peer.ssl);
  if (ret == 0) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] TLS session established\n", peerIndex(peer));
    peer.state = State::CONNECTED;
    peer.last_rx_at = millis();
    peer.next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
    _consecutive_connect_failures = 0;
#ifdef IP_BRIDGE_HAS_STATUS_LED
    radio_driver.setLinkConnected(true);
#endif
    return;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;  // keep polling
  }

  BRIDGE_DEBUG_PRINTLN("[peer %d] TLS handshake failed, err=%d\n", peerIndex(peer), ret);
  teardownConnection(peer, true);
}

void IpBridge::pollChallengerHandshake() {
  if ((int32_t)(millis() - _challenger_handshake_started_at) > (int32_t)IP_BRIDGE_HANDSHAKE_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("Challenger handshake timed out, discarding\n");
    mbedtls_ssl_free(&_challenger_ssl);
    mbedtls_net_free(&_challenger_fd);
    _challenger_active = false;
    return;
  }

  int ret = mbedtls_ssl_handshake(&_challenger_ssl);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;  // keep polling
  }
  if (ret != 0) {
    BRIDGE_DEBUG_PRINTLN("Challenger handshake failed, err=%d, discarding\n", ret);
    mbedtls_ssl_free(&_challenger_ssl);
    mbedtls_net_free(&_challenger_fd);
    _challenger_active = false;
    return;
  }

  // Challenger just proved it holds the real PSK -- promote it into whichever
  // slot has gone longest without hearing anything, tearing down whatever was
  // active there before. This is what lets a legitimately reconnecting peer
  // (e.g. after an IP change) take back over without needing anything
  // rebooted, even when every slot was already in use.
  int target_idx = findStalestSlot();
  PeerSlot &peer = _peers[target_idx];
  BRIDGE_DEBUG_PRINTLN("Challenger authenticated, replacing slot %d\n", target_idx);
  mbedtls_ssl_free(&peer.ssl);
  mbedtls_net_free(&peer.conn_fd);

  peer.ssl = _challenger_ssl;
  peer.conn_fd = _challenger_fd;
  memcpy(peer.client_ip, _challenger_ip, _challenger_ip_len);
  peer.client_ip_len = _challenger_ip_len;
  memcpy(peer.identity, _challenger_identity, sizeof(peer.identity));

  // Struct contents were moved into peer.ssl/peer.conn_fd above -- reset the
  // challenger slot to a fresh empty state without freeing (ownership of
  // the underlying fd/TLS session already transferred).
  mbedtls_ssl_init(&_challenger_ssl);
  mbedtls_net_init(&_challenger_fd);
  _challenger_active = false;
  _challenger_identity[0] = 0;

  // peer.ssl's bio was bound against &_challenger_fd's address; retarget it
  // to the now-promoted peer.conn_fd (same fd value, different storage
  // location).
  mbedtls_ssl_set_bio(&peer.ssl, &peer.conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  peer.rx_buffer_pos = 0;
  peer.state = State::CONNECTED;
  peer.last_rx_at = millis();
  peer.next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
  _consecutive_connect_failures = 0;
#ifdef IP_BRIDGE_HAS_STATUS_LED
  radio_driver.setLinkConnected(true);
#endif
}

void IpBridge::teardownConnection(PeerSlot &peer, bool reconnect) {
  mbedtls_ssl_free(&peer.ssl);
  mbedtls_ssl_init(&peer.ssl);
  mbedtls_net_free(&peer.conn_fd);
  mbedtls_net_init(&peer.conn_fd);
  peer.rx_buffer_pos = 0;
  peer.identity[0] = 0;

  if (_is_server) {
    // Free the slot -- it goes straight back to IDLE, ready for
    // findFreeSlot() to hand it to a fresh accept(). The listening socket
    // was never touched by accept()/teardown with real TCP, so it stays
    // live and accepting the whole time regardless.
    peer.state = State::IDLE;
#ifdef IP_BRIDGE_HAS_STATUS_LED
    if (!anyPeerConnected()) radio_driver.setLinkConnected(false);
#endif
  } else if (reconnect) {
    scheduleReconnect();
#ifdef IP_BRIDGE_HAS_STATUS_LED
    radio_driver.setLinkConnected(false);
#endif
  } else {
    peer.state = State::IDLE;
  }
}

void IpBridge::checkHeartbeat(PeerSlot &peer) {
  unsigned long now = millis();

  // Both roles watch for staleness -- the only way either side learns the
  // link is dead when the peer disappears silently instead of closing
  // cleanly. Tracked per peer, so one dead peer can't affect any other.
  if ((int32_t)(now - peer.last_rx_at) > IP_BRIDGE_PONG_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] Heartbeat timeout, link considered dead\n", peerIndex(peer));
    teardownConnection(peer, true);
    return;
  }

  // Only the client/spoke pings on its own initiative -- see the field comment
  // on last_rx_at in IpBridge.h for why the server/hub doesn't. _defer_heartbeat
  // (see setDeferHeartbeat()) postpones just this send by a tick or two when
  // ESP-NOW is mid-transaction -- next_ping_at is deliberately left alone so
  // it's retried again next loop() instead of being pushed a full interval out.
  if (!_is_server && !_defer_heartbeat && (int32_t)(now - peer.next_ping_at) >= 0) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] Sending heartbeat ping\n", peerIndex(peer));
    uint8_t ping = HEARTBEAT_PING;
    sendFramed(peer, &ping, 1);
#ifdef IP_BRIDGE_HAS_STATUS_LED
    radio_driver.indicateIpPing();
#endif
    peer.next_ping_at = now + IP_BRIDGE_PING_INTERVAL_MS;
  }
}

void IpBridge::pollConnectedIO(PeerSlot &peer) {
  checkHeartbeat(peer);

  // checkHeartbeat() can call teardownConnection() internally (dead-link
  // timeout), which frees peer.ssl and changes peer.state. Must not fall
  // through to using peer.ssl below in that case.
  if (peer.state != State::CONNECTED) return;

  // bounded drain per loop() call -- responsive without hogging the main loop
  // if a burst of traffic arrives all at once
  for (int i = 0; i < 4; i++) {
    uint8_t buf[64];
    int n = mbedtls_ssl_read(&peer.ssl, buf, sizeof(buf));
    if (n > 0) {
      for (int j = 0; j < n; j++) processFramedByte(peer, buf[j]);
      // processFramedByte() can itself call sendFramed() (replying to a ping
      // with a pong), which tears down the connection on write failure --
      // same stale-context hazard as above, just reached a different way.
      if (peer.state != State::CONNECTED) return;
      if (n < (int)sizeof(buf)) break;  // drained what was available
      continue;
    }
    if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      teardownConnection(peer, true);
      return;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ) {
      break;  // nothing more available right now, normal
    }
    // any other return value is a real error
    BRIDGE_DEBUG_PRINTLN("[peer %d] mbedtls_ssl_read error %d\n", peerIndex(peer), n);
    teardownConnection(peer, true);
    return;
  }
}

void IpBridge::processFramedByte(PeerSlot &peer, uint8_t b) {
  if (peer.rx_buffer_pos < 2) {
    // waiting for magic word
    if ((peer.rx_buffer_pos == 0 && b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) ||
        (peer.rx_buffer_pos == 1 && b == (BRIDGE_PACKET_MAGIC & 0xFF))) {
      peer.rx_buffer[peer.rx_buffer_pos++] = b;
    } else {
      peer.rx_buffer_pos = 0;
      if (b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) {
        peer.rx_buffer[peer.rx_buffer_pos++] = b;
      }
    }
    return;
  }

  peer.rx_buffer[peer.rx_buffer_pos++] = b;
  if (peer.rx_buffer_pos < 4) return;

  uint16_t len = (peer.rx_buffer[2] << 8) | peer.rx_buffer[3];
  if (len > (MAX_TRANS_UNIT + 1)) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] RX invalid length %d, resetting\n", peerIndex(peer), len);
    peer.rx_buffer_pos = 0;
    return;
  }

  if (peer.rx_buffer_pos != len + OVERHEAD) return;  // still accumulating

  uint16_t received_checksum = (peer.rx_buffer[4 + len] << 8) | peer.rx_buffer[5 + len];
  if (!validateChecksum(peer.rx_buffer + 4, len, received_checksum)) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] RX checksum mismatch, len=%d, rcv=0x%04x\n", peerIndex(peer), len, received_checksum);
    peer.rx_buffer_pos = 0;
    return;
  }

  // Any valid frame at all -- ping, pong, or a real packet -- proves this
  // peer is alive.
  peer.last_rx_at = millis();

  // Client only: this receipt already proves the link is alive in both
  // directions (we sent/received *something*), so push the next scheduled
  // ping back out rather than firing a redundant one right after. Note this
  // is keyed off RECEIVING, not sending -- resetting on send would let a
  // busy one-way traffic burst (spoke sending, hub with nothing to relay
  // back and no ping to reply to) go a full 45s without ever confirming the
  // hub is actually there, risking a false dead-link declaration. Resetting
  // on receive can't cause that: it only skips a ping when we've already
  // heard from the peer recently, which is exactly when skipping is safe.
  if (!_is_server) {
    peer.next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
  }

  if (len == 1 && peer.rx_buffer[4] == HEARTBEAT_PING) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] Received heartbeat ping, replying with pong\n", peerIndex(peer));
#ifdef IP_BRIDGE_HAS_STATUS_LED
    radio_driver.indicateIpPing();
#endif
    uint8_t pong = HEARTBEAT_PONG;
    sendFramed(peer, &pong, 1);
  } else if (len == 1 && peer.rx_buffer[4] == HEARTBEAT_PONG) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] Received heartbeat pong\n", peerIndex(peer));
#ifdef IP_BRIDGE_HAS_STATUS_LED
    radio_driver.indicatePongReceived();
#endif
  } else {
    BRIDGE_DEBUG_PRINTLN("[peer %d] RX, len=%d crc=0x%04x\n", peerIndex(peer), len, received_checksum);
    mesh::Packet *pkt = _mgr->allocNew();
    if (pkt) {
      if (pkt->readFrom(peer.rx_buffer + 4, len)) {
        onPacketReceived(pkt);
      } else {
        BRIDGE_DEBUG_PRINTLN("[peer %d] RX failed to parse packet\n", peerIndex(peer));
        _mgr->free(pkt);
      }
    } else {
      BRIDGE_DEBUG_PRINTLN("[peer %d] RX failed to allocate packet\n", peerIndex(peer));
    }
  }

  peer.rx_buffer_pos = 0;
}

void IpBridge::sendFramed(PeerSlot &peer, const uint8_t *payload, uint16_t len) {
  if (peer.state != State::CONNECTED) return;

  uint8_t buffer[MAX_PACKET_SIZE];
  buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;
  buffer[2] = (len >> 8) & 0xFF;
  buffer[3] = len & 0xFF;
  memcpy(buffer + 4, payload, len);

  uint16_t checksum = fletcher16(buffer + 4, len);
  buffer[4 + len] = (checksum >> 8) & 0xFF;
  buffer[5 + len] = checksum & 0xFF;

  // Timing instrumentation: how long does this call itself actually hold
  // the CPU/radio, on a board that also runs ESPNowBridge on the same
  // physical WiFi radio (dual-bridge repeater). mbedtls_ssl_write() is
  // non-blocking at the socket level (see setupSslContext()'s comment on
  // mbedtls_net_set_nonblock()), but AES/GCM encryption plus the actual
  // send() syscall still take real wall-clock time worth measuring
  // directly rather than assuming "non-blocking" means "instant".
  unsigned long t0 = millis();
  int ret = mbedtls_ssl_write(&peer.ssl, buffer, len + OVERHEAD);
  unsigned long dt = millis() - t0;
  BRIDGE_DEBUG_PRINTLN("[peer %d] sendFramed: len=%d crc=0x%04x, mbedtls_ssl_write took %lums (ret=%d)\n",
                       peerIndex(peer), len, checksum, dt, ret);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    BRIDGE_DEBUG_PRINTLN("[peer %d] mbedtls_ssl_write error %d\n", peerIndex(peer), ret);
    teardownConnection(peer, true);
  }
}

void IpBridge::sendPacket(mesh::Packet *packet) {
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }
  if (!anyPeerConnected()) return;

  if (_tx_seen.wasSeen(packet)) {
    BRIDGE_DEBUG_PRINTLN("TX suppressed (already seen), len=%d\n", packet->getRawLength());
    return;
  }
  _tx_seen.markSeen(packet);

  uint8_t sizing_buffer[MAX_TRANS_UNIT + 1];
  uint16_t len = packet->writeTo(sizing_buffer);
  if (len > (MAX_TRANS_UNIT + 1)) {
    BRIDGE_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", len, MAX_TRANS_UNIT + 1);
    return;
  }

  BRIDGE_DEBUG_PRINTLN("TX, len=%d crc=0x%04x\n", len, fletcher16(sizing_buffer, len));

  // Every connected peer gets the same packet -- both FLOOD and DIRECT
  // traffic. See class doc comment: mesh-layer encryption already protects
  // DIRECT payload content from a peer it wasn't addressed to, so this is a
  // bandwidth tradeoff, not a plaintext leak, and needs no per-destination
  // routing here.
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (_peers[i].state == State::CONNECTED) {
      sendFramed(_peers[i], sizing_buffer, len);
    }
  }
}

void IpBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

#ifdef BRIDGE_DEBUG
// R42 multi-peer investigation only -- see IpBridge.h. Prints a per-peer
// average/max tick cost every ~5s, then resets the window. Deliberately not
// printed every tick: Serial.printf() itself costs real time on this same
// core, and printing on every loop() would swamp the very thing being
// measured.
void IpBridge::profileTick(uint32_t loop_us) {
  if (loop_us > _prof_loop_us_max) _prof_loop_us_max = loop_us;

  uint32_t now = millis();
  if (_prof_window_start_at == 0) _prof_window_start_at = now;
  if ((int32_t)(now - _prof_window_start_at) < 5000) return;

  BRIDGE_DEBUG_PRINTLN("PROFILE loop_us_max=%u window_ms=%u free_heap=%u\n",
                        (unsigned)_prof_loop_us_max, (unsigned)(now - _prof_window_start_at),
                        (unsigned)ESP.getFreeHeap());
  for (int i = 0; i < MAX_IP_PEERS; i++) {
    if (_prof_peer_calls[i] == 0) continue;
    BRIDGE_DEBUG_PRINTLN("PROFILE peer[%d] state=%d calls=%u avg_us=%u\n",
                          i, (int)_peers[i].state, (unsigned)_prof_peer_calls[i],
                          (unsigned)(_prof_peer_us[i] / _prof_peer_calls[i]));
    _prof_peer_us[i] = 0;
    _prof_peer_calls[i] = 0;
  }
  _prof_loop_us_max = 0;
  _prof_window_start_at = now;
}
#endif

void IpBridge::loop() {
  if (!_initialized) return;

#ifdef BRIDGE_DEBUG
  uint32_t _prof_loop_start = micros();
#endif

  // Server: always check for a new incoming connection, regardless of any
  // slot's current state -- the listening socket stays live the whole time
  // (real TCP accept() never touches it), which is what lets a fresh,
  // legitimately re-authenticating peer get in via the challenger path even
  // while every slot is still (stale but) technically CONNECTED. See
  // pollListening().
  if (_is_server) {
    pollListening();
    if (_challenger_active) pollChallengerHandshake();
  }

  for (int i = 0; i < MAX_IP_PEERS; i++) {
    PeerSlot &peer = _peers[i];
    switch (peer.state) {
      case State::TCP_CONNECTING:
        pollTcpConnecting();  // client (_peers[0]) only
        break;
      case State::HANDSHAKING:
        // Throttled: calling mbedtls_ssl_handshake() on every single loop()
        // tick is unnecessary overhead when nothing new has arrived. See
        // next_handshake_poll_at in IpBridge.h.
        if ((int32_t)(millis() - peer.next_handshake_poll_at) >= 0) {
          pollHandshake(peer);
          peer.next_handshake_poll_at = millis() + IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS;
        }
        break;
      case State::CONNECTED: {
#ifdef BRIDGE_DEBUG
        uint32_t _prof_peer_start = micros();
        pollConnectedIO(peer);
        _prof_peer_us[i] += micros() - _prof_peer_start;
        _prof_peer_calls[i]++;
#else
        pollConnectedIO(peer);
#endif
        break;
      }
      case State::RECONNECT_WAIT:
        if ((int32_t)(millis() - peer.next_action_at) >= 0) startConnect();  // client (_peers[0]) only
        break;
      default:
        break;
    }
  }

#ifdef BRIDGE_DEBUG
  profileTick(micros() - _prof_loop_start);
#endif
}

#endif
