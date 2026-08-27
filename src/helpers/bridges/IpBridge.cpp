#include "IpBridge.h"

#ifdef WITH_IP_BRIDGE

#include <WiFi.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Optional cross-cutting hook: boards that pair IpBridge with ESPNowBridgeRadio
// (e.g. esp32_s3_zero) get a distinct blue LED flash when running in server/hub
// mode. Gated the same way main.cpp already gates relockChannel() -- keeps
// IpBridge itself portable, not hard-dependent on this one radio driver.
#ifdef ESPNOW_BRIDGE_RADIO
#include <helpers/esp32/ESPNowBridgeRadio.h>
extern ESPNowBridgeRadio radio_driver;
#endif

#ifndef IP_BRIDGE_PING_INTERVAL_MS
#define IP_BRIDGE_PING_INTERVAL_MS   15000   // how often the client pings
#endif
#ifndef IP_BRIDGE_PONG_TIMEOUT_MS
#define IP_BRIDGE_PONG_TIMEOUT_MS    45000   // ~3 missed pings -> dead link
#endif
#ifndef IP_BRIDGE_RECONNECT_DELAY_MS
#define IP_BRIDGE_RECONNECT_DELAY_MS 5000    // short, capped -- no exponential backoff
#endif
#ifndef IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS
#define IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS 50  // see _next_handshake_poll_at in IpBridge.h
#endif
#ifndef IP_BRIDGE_HANDSHAKE_TIMEOUT_MS
// Bounds how long a TLS handshake (primary or challenger) is allowed to sit
// unresolved before being given up on -- see _handshake_started_at in
// IpBridge.h for what this guards against.
#define IP_BRIDGE_HANDSHAKE_TIMEOUT_MS 30000
#endif
#ifndef IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS
// Bounds the manual non-blocking connect() (see startConnect()/
// pollTcpConnecting()) -- an unreachable host would otherwise only fail via
// the OS's own SYN retry timeout, which can be tens of seconds.
#define IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS 5000
#endif
#ifndef IP_BRIDGE_PSK_IDENTITY
#define IP_BRIDGE_PSK_IDENTITY       "meshcore-bridge"  // not secret, just an identifier
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

IpBridge::IpBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc) {
  mbedtls_net_init(&_listen_fd);
  mbedtls_net_init(&_conn_fd_slot);
  mbedtls_ssl_init(&_ssl_slot);
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

  size_t secret_len = strlen(_prefs->ip_secret);
  if (mbedtls_ssl_conf_psk(&_ssl_conf, (const unsigned char *)_prefs->ip_secret, secret_len,
                            (const unsigned char *)IP_BRIDGE_PSK_IDENTITY,
                            strlen(IP_BRIDGE_PSK_IDENTITY)) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_conf_psk failed\n");
    return false;
  }

  _tls_conf_ready = true;
  return true;
}

// Shared setup for both roles and for the challenger slot: a fresh
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
  if (mbedtls_ssl_setup(ssl, &_ssl_conf) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_setup failed\n");
    return false;
  }
  mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  return true;
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

  _rx_buffer_pos = 0;
  _consecutive_connect_failures = 0;

  if (_is_server) {
    startListen();
#ifdef ESPNOW_BRIDGE_RADIO
    if (_state == State::LISTENING) radio_driver.indicateServerMode();
#endif
  } else {
    startConnect();
  }

#ifdef ESPNOW_BRIDGE_RADIO
  // Not-connected indicator applies to both roles: hub listening with nobody
  // there, or spoke dialing out/reconnecting. Only reached once begin() has
  // confirmed the bridge is actually configured (both early-returns above
  // already passed) and the start attempt didn't fail straight into IDLE, so
  // an unconfigured board never lights this at all.
  if (_state != State::IDLE) radio_driver.setLinkConnected(false);
#endif

  _initialized = true;
}

void IpBridge::end() {
  BRIDGE_DEBUG_PRINTLN("Stopping...\n");

  mbedtls_ssl_free(_ssl);
  mbedtls_net_free(_conn_fd);
  mbedtls_net_free(&_listen_fd);
  mbedtls_ssl_free(&_challenger_ssl);
  mbedtls_net_free(&_challenger_fd);
  mbedtls_ssl_config_free(&_ssl_conf);
  mbedtls_ctr_drbg_free(&_ctr_drbg);
  mbedtls_entropy_free(&_entropy);
  _tls_conf_ready = false;

  mbedtls_ssl_init(_ssl);
  mbedtls_net_init(_conn_fd);
  mbedtls_net_init(&_listen_fd);
  mbedtls_ssl_init(&_challenger_ssl);
  mbedtls_net_init(&_challenger_fd);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);

  _state = State::IDLE;
  _rx_buffer_pos = 0;
  _challenger_active = false;
  _initialized = false;
}

// Formats the server-side peer address (_client_ip/_client_ip_len, raw bytes
// from mbedtls_net_accept()) as dotted-decimal. IPv4 only -- this bridge is
// built on WiFi.hostByName()/IPAddress throughout, never IPv6.
static void formatPeerIp(const unsigned char *ip, size_t len, char *out) {
  if (len == 4) {
    sprintf(out, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  } else {
    strcpy(out, "?");
  }
}

void IpBridge::formatStatus(char *reply) const {
  unsigned long since_rx_secs = _last_rx_at == 0 ? 0 : (millis() - _last_rx_at) / 1000;
  char peer_ip[20];
  const char *challenger_note = _challenger_active ? " (+ challenger authenticating)" : "";

  if (_is_server) {
    switch (_state) {
      case State::IDLE:
        sprintf(reply, "idle (not started)");
        break;
      case State::LISTENING:
        sprintf(reply, "listening on port %u, no peer yet%s", (unsigned)_prefs->ip_port, challenger_note);
        break;
      case State::HANDSHAKING:
        formatPeerIp(_client_ip, _client_ip_len, peer_ip);
        sprintf(reply, "peer %s attempting handshake...%s", peer_ip, challenger_note);
        break;
      case State::CONNECTED:
        formatPeerIp(_client_ip, _client_ip_len, peer_ip);
        if (_last_rx_at == 0) {
          sprintf(reply, "connected to peer %s, nothing received yet%s", peer_ip, challenger_note);
        } else {
          sprintf(reply, "connected to peer %s, last heard %lus ago%s", peer_ip, since_rx_secs, challenger_note);
        }
        break;
      default:
        sprintf(reply, "unknown state");
        break;
    }
  } else {  // client
    switch (_state) {
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
        if (_last_rx_at == 0) {
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
  _state = State::LISTENING;
  BRIDGE_DEBUG_PRINTLN("Listening on TCP %s\n", port_str);
}

void IpBridge::startConnect() {
  // Only re-resolve after a couple of consecutive failures against the cached IP --
  // most reconnects are transient blips, not an actual home IP change, so this
  // keeps DNS lookups rare rather than happening on every reconnect attempt.
  if (_resolved_ip[0] == 0 || _consecutive_connect_failures >= 2) {
    IPAddress ip;
    if (!WiFi.hostByName(_prefs->ip_host, ip)) {
      BRIDGE_DEBUG_PRINTLN("DNS lookup failed for %s\n", _prefs->ip_host);
      _state = State::RECONNECT_WAIT;
      _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
      return;
    }
    strncpy(_resolved_ip, ip.toString().c_str(), sizeof(_resolved_ip) - 1);
    _resolved_ip[sizeof(_resolved_ip) - 1] = 0;
    _consecutive_connect_failures = 0;
    BRIDGE_DEBUG_PRINTLN("Resolved %s -> %s\n", _prefs->ip_host, _resolved_ip);
  }

  mbedtls_net_free(_conn_fd);
  mbedtls_net_init(_conn_fd);

  // mbedtls_net_connect() has no non-blocking TCP variant (see class doc
  // comment) -- it performs a real, blocking connect() for TCP, which would
  // freeze this whole single-threaded loop() for as long as it takes to
  // resolve. Done manually instead: create the socket, mark it non-blocking
  // *before* connect() so it returns immediately with EINPROGRESS, then poll
  // for completion in pollTcpConnecting().
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    BRIDGE_DEBUG_PRINTLN("TCP socket() failed, errno=%d\n", errno);
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
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
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }

  applyTcpKeepalive(fd);

  // mbedtls_net_context is just {int fd} -- trivial to populate directly,
  // bypassing mbedtls_net_connect() entirely for this step. Everything
  // downstream (mbedtls_net_set_nonblock(), mbedtls_ssl_set_bio(), etc.)
  // operates purely on ctx->fd and doesn't care how it got there.
  _conn_fd->fd = fd;
  _state = State::TCP_CONNECTING;
  _next_action_at = millis() + IP_BRIDGE_TCP_CONNECT_TIMEOUT_MS;
  BRIDGE_DEBUG_PRINTLN("TCP connect in progress to %s:%u\n", _resolved_ip, (unsigned)_prefs->ip_port);
}

void IpBridge::pollTcpConnecting() {
  if ((int32_t)(millis() - _next_action_at) > 0) {
    BRIDGE_DEBUG_PRINTLN("TCP connect timed out\n");
    mbedtls_net_free(_conn_fd);
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }

  // Standard non-blocking-connect completion check: once the socket is
  // writable, the connect attempt has resolved one way or the other --
  // SO_ERROR distinguishes success (0) from a real failure.
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(_conn_fd->fd, &wfds);
  struct timeval tv = {0, 0};
  int sel = select(_conn_fd->fd + 1, NULL, &wfds, NULL, &tv);
  if (sel <= 0) return;  // not resolved yet, keep waiting

  int sock_err = 0;
  socklen_t err_len = sizeof(sock_err);
  getsockopt(_conn_fd->fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
  if (sock_err != 0) {
    BRIDGE_DEBUG_PRINTLN("TCP connect failed, err=%d\n", sock_err);
    mbedtls_net_free(_conn_fd);
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }

  if (!setupSslContext(_ssl, _conn_fd)) {
    mbedtls_net_free(_conn_fd);
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }

  _rx_buffer_pos = 0;
  _state = State::HANDSHAKING;
  _next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
  _handshake_started_at = millis();
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

  if (_state == State::LISTENING) {
    // No active peer yet -- this becomes the primary session, same as
    // always. A bare accept() doesn't need extra scrutiny here: nothing
    // valuable exists yet to protect.
    mbedtls_net_free(_conn_fd);
    *_conn_fd = new_conn;
    memcpy(_client_ip, peer_ip, peer_ip_len);
    _client_ip_len = peer_ip_len;

    if (!setupSslContext(_ssl, _conn_fd)) {
      mbedtls_net_free(_conn_fd);
      return;  // stay LISTENING
    }

    _rx_buffer_pos = 0;
    _state = State::HANDSHAKING;
    _next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
    _handshake_started_at = millis();
    BRIDGE_DEBUG_PRINTLN("Peer connecting, starting TLS handshake\n");
    return;
  }

  // Already have an active/pending session (HANDSHAKING or CONNECTED) -- a
  // bare TCP accept() proves nothing yet (see class doc comment), so this
  // must NOT touch the existing session. Land it in the challenger slot and
  // let it prove itself via its own handshake first. Only one challenger at
  // a time -- reject a second simultaneous attempt outright rather than
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
  BRIDGE_DEBUG_PRINTLN("New connection while already connected -- challenger handshake starting\n");
}

void IpBridge::pollHandshake() {
  if ((int32_t)(millis() - _handshake_started_at) > (int32_t)IP_BRIDGE_HANDSHAKE_TIMEOUT_MS) {
    // A peer that stops responding mid-handshake would otherwise leave this
    // stuck here forever. Same recovery path as any other handshake
    // failure: teardownConnection() already knows how to get the server
    // back to LISTENING or the client back to RECONNECT_WAIT.
    BRIDGE_DEBUG_PRINTLN("TLS handshake timed out after %ums, giving up\n", (unsigned)IP_BRIDGE_HANDSHAKE_TIMEOUT_MS);
    teardownConnection(true);
    return;
  }

  int ret = mbedtls_ssl_handshake(_ssl);
  if (ret == 0) {
    BRIDGE_DEBUG_PRINTLN("TLS session established\n");
    _state = State::CONNECTED;
    _last_rx_at = millis();
    _next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
    _consecutive_connect_failures = 0;
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.setLinkConnected(true);
#endif
    return;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;  // keep polling
  }

  BRIDGE_DEBUG_PRINTLN("TLS handshake failed, err=%d\n", ret);
  teardownConnection(true);
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

  // Challenger just proved it holds the real PSK -- promote it, tearing
  // down whatever was active before (a stale session, or a still-unproven
  // handshake attempt). This is what lets a legitimately reconnecting peer
  // (e.g. after an IP change) take back over without needing the other side
  // rebooted.
  BRIDGE_DEBUG_PRINTLN("Challenger authenticated, replacing active session\n");
  mbedtls_ssl_free(_ssl);
  mbedtls_net_free(_conn_fd);

  *_ssl = _challenger_ssl;
  *_conn_fd = _challenger_fd;
  memcpy(_client_ip, _challenger_ip, _challenger_ip_len);
  _client_ip_len = _challenger_ip_len;

  // Struct contents were moved into _ssl/_conn_fd above -- reset the
  // challenger slot to a fresh empty state without freeing (ownership of
  // the underlying fd/TLS session already transferred).
  mbedtls_ssl_init(&_challenger_ssl);
  mbedtls_net_init(&_challenger_fd);
  _challenger_active = false;

  // _ssl's bio was bound against &_challenger_fd's address; retarget it to
  // the now-promoted _conn_fd (same fd value, different storage location).
  mbedtls_ssl_set_bio(_ssl, _conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  _rx_buffer_pos = 0;
  _state = State::CONNECTED;
  _last_rx_at = millis();
  _next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
  _consecutive_connect_failures = 0;
#ifdef ESPNOW_BRIDGE_RADIO
  radio_driver.setLinkConnected(true);
#endif
}

void IpBridge::teardownConnection(bool reconnect) {
  mbedtls_ssl_free(_ssl);
  mbedtls_ssl_init(_ssl);
  mbedtls_net_free(_conn_fd);
  mbedtls_net_init(_conn_fd);
  _rx_buffer_pos = 0;

  if (_is_server) {
    // Just go back to waiting for a (possibly new) peer -- the listening
    // socket was never touched by accept()/teardown with real TCP, so it
    // stays live and accepting the whole time regardless.
    _state = State::LISTENING;
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.setLinkConnected(false);
#endif
  } else if (reconnect) {
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.setLinkConnected(false);
#endif
  } else {
    _state = State::IDLE;
  }
}

void IpBridge::checkHeartbeat() {
  unsigned long now = millis();

  // Both roles watch for staleness -- the only way either side learns the
  // link is dead when the peer disappears silently instead of closing
  // cleanly.
  if ((int32_t)(now - _last_rx_at) > IP_BRIDGE_PONG_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("Heartbeat timeout, link considered dead\n");
    teardownConnection(true);
    return;
  }

  // Only the client/spoke pings on its own initiative -- see the field comment
  // on _last_rx_at in IpBridge.h for why the server/hub doesn't. _defer_heartbeat
  // (see setDeferHeartbeat()) postpones just this send by a tick or two when
  // ESP-NOW is mid-transaction -- _next_ping_at is deliberately left alone so
  // it's retried again next loop() instead of being pushed a full interval out.
  if (!_is_server && !_defer_heartbeat && (int32_t)(now - _next_ping_at) >= 0) {
    BRIDGE_DEBUG_PRINTLN("Sending heartbeat ping\n");
    uint8_t ping = HEARTBEAT_PING;
    sendFramed(&ping, 1);
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.indicateIpPing();
#endif
    _next_ping_at = now + IP_BRIDGE_PING_INTERVAL_MS;
  }
}

void IpBridge::pollConnectedIO() {
  checkHeartbeat();

  // checkHeartbeat() can call teardownConnection() internally (dead-link
  // timeout), which frees _ssl and changes _state. Must not fall through to
  // using _ssl below in that case.
  if (_state != State::CONNECTED) return;

  // bounded drain per loop() call -- responsive without hogging the main loop
  // if a burst of traffic arrives all at once
  for (int i = 0; i < 4; i++) {
    uint8_t buf[64];
    int n = mbedtls_ssl_read(_ssl, buf, sizeof(buf));
    if (n > 0) {
      for (int j = 0; j < n; j++) processFramedByte(buf[j]);
      // processFramedByte() can itself call sendFramed() (replying to a ping
      // with a pong), which tears down the connection on write failure --
      // same stale-context hazard as above, just reached a different way.
      if (_state != State::CONNECTED) return;
      if (n < (int)sizeof(buf)) break;  // drained what was available
      continue;
    }
    if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      teardownConnection(true);
      return;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ) {
      break;  // nothing more available right now, normal
    }
    // any other return value is a real error
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_read error %d\n", n);
    teardownConnection(true);
    return;
  }
}

void IpBridge::processFramedByte(uint8_t b) {
  if (_rx_buffer_pos < 2) {
    // waiting for magic word
    if ((_rx_buffer_pos == 0 && b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) ||
        (_rx_buffer_pos == 1 && b == (BRIDGE_PACKET_MAGIC & 0xFF))) {
      _rx_buffer[_rx_buffer_pos++] = b;
    } else {
      _rx_buffer_pos = 0;
      if (b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) {
        _rx_buffer[_rx_buffer_pos++] = b;
      }
    }
    return;
  }

  _rx_buffer[_rx_buffer_pos++] = b;
  if (_rx_buffer_pos < 4) return;

  uint16_t len = (_rx_buffer[2] << 8) | _rx_buffer[3];
  if (len > (MAX_TRANS_UNIT + 1)) {
    BRIDGE_DEBUG_PRINTLN("RX invalid length %d, resetting\n", len);
    _rx_buffer_pos = 0;
    return;
  }

  if (_rx_buffer_pos != len + OVERHEAD) return;  // still accumulating

  uint16_t received_checksum = (_rx_buffer[4 + len] << 8) | _rx_buffer[5 + len];
  if (!validateChecksum(_rx_buffer + 4, len, received_checksum)) {
    BRIDGE_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04x\n", received_checksum);
    _rx_buffer_pos = 0;
    return;
  }

  // Any valid frame at all -- ping, pong, or a real packet -- proves the peer
  // is alive. See the _last_rx_at field comment in IpBridge.h for why this
  // isn't scoped to pongs specifically.
  _last_rx_at = millis();

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
    _next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
  }

  if (len == 1 && _rx_buffer[4] == HEARTBEAT_PING) {
    BRIDGE_DEBUG_PRINTLN("Received heartbeat ping, replying with pong\n");
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.indicateIpPing();
#endif
    uint8_t pong = HEARTBEAT_PONG;
    sendFramed(&pong, 1);
  } else if (len == 1 && _rx_buffer[4] == HEARTBEAT_PONG) {
    BRIDGE_DEBUG_PRINTLN("Received heartbeat pong\n");
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.indicatePongReceived();
#endif
  } else {
    BRIDGE_DEBUG_PRINTLN("RX, len=%d crc=0x%04x\n", len, received_checksum);
    mesh::Packet *pkt = _mgr->allocNew();
    if (pkt) {
      if (pkt->readFrom(_rx_buffer + 4, len)) {
        onPacketReceived(pkt);
      } else {
        BRIDGE_DEBUG_PRINTLN("RX failed to parse packet\n");
        _mgr->free(pkt);
      }
    } else {
      BRIDGE_DEBUG_PRINTLN("RX failed to allocate packet\n");
    }
  }

  _rx_buffer_pos = 0;
}

void IpBridge::sendFramed(const uint8_t *payload, uint16_t len) {
  if (_state != State::CONNECTED) return;

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
  int ret = mbedtls_ssl_write(_ssl, buffer, len + OVERHEAD);
  unsigned long dt = millis() - t0;
  BRIDGE_DEBUG_PRINTLN("sendFramed: mbedtls_ssl_write took %lums (ret=%d)\n", dt, ret);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_write error %d\n", ret);
    teardownConnection(true);
  }
}

void IpBridge::sendPacket(mesh::Packet *packet) {
  if (_state != State::CONNECTED) return;
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }

  if (!_tx_seen.wasSeen(packet)) {
    _tx_seen.markSeen(packet);

    uint8_t sizing_buffer[MAX_TRANS_UNIT + 1];
    uint16_t len = packet->writeTo(sizing_buffer);
    if (len > (MAX_TRANS_UNIT + 1)) {
      BRIDGE_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", len, MAX_TRANS_UNIT + 1);
      return;
    }

    BRIDGE_DEBUG_PRINTLN("TX, len=%d crc=0x%04x\n", len, fletcher16(sizing_buffer, len));
    sendFramed(sizing_buffer, len);
  } else {
    BRIDGE_DEBUG_PRINTLN("TX suppressed (already seen), len=%d\n", packet->getRawLength());
  }
}

void IpBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

void IpBridge::loop() {
  if (!_initialized) return;

  // Server: always check for a new incoming connection, regardless of
  // current state -- the listening socket stays live the whole time (real
  // TCP accept() never touches it), which is what lets a fresh, legitimately
  // re-authenticating peer get in via the challenger path even while an old
  // session is still (stale but) technically CONNECTED. See pollListening().
  if (_is_server) {
    pollListening();
    if (_challenger_active) pollChallengerHandshake();
  }

  switch (_state) {
    case State::TCP_CONNECTING:
      pollTcpConnecting();
      break;
    case State::HANDSHAKING:
      // Throttled: calling mbedtls_ssl_handshake() on every single loop()
      // tick is unnecessary overhead when nothing new has arrived. See
      // _next_handshake_poll_at in IpBridge.h.
      if ((int32_t)(millis() - _next_handshake_poll_at) >= 0) {
        pollHandshake();
        _next_handshake_poll_at = millis() + IP_BRIDGE_HANDSHAKE_POLL_INTERVAL_MS;
      }
      break;
    case State::CONNECTED:
      pollConnectedIO();
      break;
    case State::RECONNECT_WAIT:
      if ((int32_t)(millis() - _next_action_at) >= 0) startConnect();
      break;
    default:
      break;
  }
}

#endif
