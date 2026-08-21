#include "IpBridge.h"

#ifdef WITH_IP_BRIDGE

#include <WiFi.h>

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
#ifndef IP_BRIDGE_PSK_IDENTITY
#define IP_BRIDGE_PSK_IDENTITY       "meshcore-bridge"  // not secret, just an identifier
#endif

IpBridge::IpBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc)
    : BridgeBase(prefs, mgr, rtc) {
  mbedtls_net_init(&_listen_fd);
  mbedtls_net_init(&_conn_fd_slot);
  mbedtls_ssl_init(&_ssl_slot);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);
  mbedtls_ssl_cookie_init(&_cookie_ctx);
}

// mbedtls_ssl_set_timer_cb callbacks -- millis()-based rather than mbedtls_timing's
// POSIX-oriented helpers, to avoid depending on timing primitives that aren't
// guaranteed to behave the same way on this FreeRTOS/Arduino target.
void IpBridge::timerSetDelay(void *ctx, uint32_t int_ms, uint32_t fin_ms) {
  Timer *t = (Timer *)ctx;
  if (fin_ms == 0) {
    t->active = false;
  } else {
    t->active = true;
    t->int_at = millis() + int_ms;
    t->fin_at = millis() + fin_ms;
  }
}

int IpBridge::timerGetDelay(void *ctx) {
  Timer *t = (Timer *)ctx;
  if (!t->active) return -1;
  unsigned long now = millis();
  if ((int32_t)(now - t->fin_at) >= 0) return 2;   // final delay expired
  if ((int32_t)(now - t->int_at) >= 0) return 1;   // intermediate delay expired
  return 0;                                        // no delay expired yet
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
  if (mbedtls_ssl_config_defaults(&_ssl_conf, endpoint, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_config_defaults failed\n");
    return false;
  }

  // PSK-only: no certificates of any kind are used, so there is nothing to verify
  // via authmode -- see planning/ip-bridge-design.md for why PSK was chosen.
  mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

  // mbedtls_ssl_conf_dtls_cookies()'s DEFAULT is dummy callbacks that always
  // FAIL, specifically to force an explicit choice -- real cookie callbacks, or
  // NULL to disable HelloVerifyRequest outright. Real callbacks are used here:
  // even though this bridge only ever has one fixed peer (so the "let one bind
  // socket serve many simultaneous clients" use case for cookies doesn't
  // apply), the cookie round trip also proves the ClientHello's source address
  // is real (return-routability) before the larger ServerHello/
  // ServerKeyExchange/ServerHelloDone flight is ever sent there -- without it,
  // an attacker could spoof another host's IP as the datagram source and use
  // this bridge to reflect/amplify traffic at that host. Server-only API,
  // harmless to call as client too.
  if (mbedtls_ssl_cookie_setup(&_cookie_ctx, mbedtls_ctr_drbg_random, &_ctr_drbg) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_cookie_setup failed\n");
    return false;
  }
  mbedtls_ssl_conf_dtls_cookies(&_ssl_conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &_cookie_ctx);

  // CRITICAL: mbedtls_ssl_set_bio() below passes NULL for f_recv_timeout, not
  // mbedtls_net_recv_timeout(). This was originally wired up with a 1ms
  // mbedtls_ssl_conf_read_timeout() to fix a permanent post-handshake freeze
  // (0 timeout there means "block forever", confirmed in mbedTLS's own doc
  // comment) -- but that only ever covered mbedtls_ssl_read() after the
  // handshake completes. During the handshake itself, mbedTLS's internal
  // wait-for-reply logic ignores read_timeout entirely and instead calls
  // f_recv_timeout with a duration taken from ITS OWN DTLS retransmission
  // timer (the one driven by mbedtls_ssl_set_timer_cb below) -- which grows
  // 1s, 2s, 4s, 8s, 16s... up to a 60s cap. Confirmed live: a spoke handshaking
  // against an unreachable hub blocked mbedtls_ssl_handshake() -- and with it
  // the entire Arduino main loop, CLI included -- for exactly that doubling
  // sequence, one full block per retransmit. Passing NULL instead of
  // mbedtls_net_recv_timeout makes mbedTLS fall back to the plain non-blocking
  // mbedtls_net_recv() (the socket is already non-blocking via
  // mbedtls_net_set_nonblock()), which returns MBEDTLS_ERR_SSL_WANT_READ
  // immediately instead of blocking -- mbedTLS's own documented pattern for
  // externally-polled/non-blocking DTLS. The retransmission timer callback
  // still paces actual retransmits correctly; only the blocking wait is gone.

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
  mbedtls_ssl_config_free(&_ssl_conf);
  mbedtls_ctr_drbg_free(&_ctr_drbg);
  mbedtls_entropy_free(&_entropy);
  mbedtls_ssl_cookie_free(&_cookie_ctx);
  _tls_conf_ready = false;

  mbedtls_ssl_init(_ssl);
  mbedtls_net_init(_conn_fd);
  mbedtls_net_init(&_listen_fd);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);
  mbedtls_ssl_cookie_init(&_cookie_ctx);

  _state = State::IDLE;
  _rx_buffer_pos = 0;
  _initialized = false;
}

void IpBridge::formatStatus(char *reply) const {
  const char *role = _is_server ? "server" : "client";
  unsigned long since_rx_secs = _last_rx_at == 0 ? 0 : (millis() - _last_rx_at) / 1000;

  switch (_state) {
    case State::IDLE:
      sprintf(reply, "idle (not started)");
      break;
    case State::LISTENING:
      sprintf(reply, "listening (%s), no peer yet", role);
      break;
    case State::HANDSHAKING:
      sprintf(reply, "handshaking (%s)...", role);
      break;
    case State::CONNECTED:
      if (_last_rx_at == 0) {
        sprintf(reply, "connected (%s), nothing received yet", role);
      } else {
        sprintf(reply, "connected (%s), last heard %lus ago", role, since_rx_secs);
      }
      break;
    case State::RECONNECT_WAIT:
      sprintf(reply, "reconnecting (%s), %u failed attempt%s so far", role,
              (unsigned)_consecutive_connect_failures, _consecutive_connect_failures == 1 ? "" : "s");
      break;
    default:
      sprintf(reply, "unknown state");
      break;
  }
}

void IpBridge::startListen() {
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", (unsigned)_prefs->ip_port);

  mbedtls_net_free(&_listen_fd);
  mbedtls_net_init(&_listen_fd);
  if (mbedtls_net_bind(&_listen_fd, NULL, port_str, MBEDTLS_NET_PROTO_UDP) != 0) {
    BRIDGE_DEBUG_PRINTLN("Failed to bind UDP port %s\n", port_str);
    return;
  }
  mbedtls_net_set_nonblock(&_listen_fd);
  _state = State::LISTENING;
  BRIDGE_DEBUG_PRINTLN("Listening on UDP %s\n", port_str);
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

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", (unsigned)_prefs->ip_port);

  mbedtls_net_free(_conn_fd);
  mbedtls_net_init(_conn_fd);
  // _resolved_ip is always a numeric dotted-decimal string here, never the raw
  // hostname -- mbedtls_net_connect()'s internal getaddrinfo() resolves a numeric
  // IP locally/instantly rather than issuing a real DNS query, so this doesn't
  // reintroduce the blocking-DNS problem this design deliberately avoids.
  if (mbedtls_net_connect(_conn_fd, _resolved_ip, port_str, MBEDTLS_NET_PROTO_UDP) != 0) {
    BRIDGE_DEBUG_PRINTLN("UDP connect failed to %s:%s\n", _resolved_ip, port_str);
    _consecutive_connect_failures++;
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }
  mbedtls_net_set_nonblock(_conn_fd);

  mbedtls_ssl_free(_ssl);
  mbedtls_ssl_init(_ssl);
  if (mbedtls_ssl_setup(_ssl, &_ssl_conf) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_setup failed\n");
    _state = State::RECONNECT_WAIT;
    _next_action_at = millis() + IP_BRIDGE_RECONNECT_DELAY_MS;
    return;
  }
  mbedtls_ssl_set_bio(_ssl, _conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  mbedtls_ssl_set_timer_cb(_ssl, _timer, timerSetDelay, timerGetDelay);

  _rx_buffer_pos = 0;
  _state = State::HANDSHAKING;
  _next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
}

void IpBridge::pollListening() {
  mbedtls_net_context new_conn;
  mbedtls_net_init(&new_conn);

  unsigned char client_ip[16];
  size_t client_ip_len = 0;
  int ret = mbedtls_net_accept(&_listen_fd, &new_conn, client_ip, sizeof(client_ip), &client_ip_len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    mbedtls_net_free(&new_conn);
    return;  // no pending connection, stay LISTENING
  }
  if (ret != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_net_accept error %d\n", ret);
    mbedtls_net_free(&new_conn);
    return;  // stay LISTENING, try again next loop()
  }

  mbedtls_net_free(_conn_fd);
  *_conn_fd = new_conn;
  mbedtls_net_set_nonblock(_conn_fd);

  // Saved so it can be re-asserted after MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED
  // resets the SSL context in pollHandshake() -- the cookie is bound to this
  // address, so mbedTLS needs it again on the second (post-cookie) attempt.
  memcpy(_client_ip, client_ip, client_ip_len);
  _client_ip_len = client_ip_len;

  mbedtls_ssl_free(_ssl);
  mbedtls_ssl_init(_ssl);
  if (mbedtls_ssl_setup(_ssl, &_ssl_conf) != 0) {
    BRIDGE_DEBUG_PRINTLN("mbedtls_ssl_setup failed (server)\n");
    mbedtls_net_free(_conn_fd);
    mbedtls_net_init(_conn_fd);
    return;  // stay LISTENING
  }
  mbedtls_ssl_set_client_transport_id(_ssl, _client_ip, _client_ip_len);
  mbedtls_ssl_set_bio(_ssl, _conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  mbedtls_ssl_set_timer_cb(_ssl, _timer, timerSetDelay, timerGetDelay);

  _rx_buffer_pos = 0;
  _state = State::HANDSHAKING;
  _next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
  BRIDGE_DEBUG_PRINTLN("Peer connecting, starting DTLS handshake\n");
}

void IpBridge::pollHandshake() {
  int ret = mbedtls_ssl_handshake(_ssl);
  if (ret == 0) {
    BRIDGE_DEBUG_PRINTLN("DTLS session established\n");
    _state = State::CONNECTED;
    _last_rx_at = millis();
    _next_ping_at = millis() + IP_BRIDGE_PING_INTERVAL_MS;
    _consecutive_connect_failures = 0;
#ifdef ESPNOW_BRIDGE_RADIO
    radio_driver.setLinkConnected(true);
#endif
    return;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
      ret == MBEDTLS_ERR_SSL_TIMEOUT) {
    return;  // keep polling; mbedTLS handles DTLS retransmit internally
  }
  if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
    // Normal step in the cookie exchange (server only): mbedTLS already sent
    // the HelloVerifyRequest itself as part of this call. Reset the session
    // and keep polling on the same socket for the client's cookie-bearing
    // resend -- this is mbedTLS's documented pattern (see e.g. its own
    // programs/ssl/dtls_server.c), not a failure.
    mbedtls_ssl_session_reset(_ssl);
    mbedtls_ssl_set_client_transport_id(_ssl, _client_ip, _client_ip_len);
    return;
  }

  BRIDGE_DEBUG_PRINTLN("DTLS handshake failed, err=%d\n", ret);
  teardownConnection(true);
}

void IpBridge::teardownConnection(bool reconnect) {
  mbedtls_ssl_free(_ssl);
  mbedtls_ssl_init(_ssl);
  mbedtls_net_free(_conn_fd);
  mbedtls_net_init(_conn_fd);
  _rx_buffer_pos = 0;

  if (_is_server) {
    // just go back to waiting for a (possibly new) peer -- server side never
    // "reconnects" in the client sense, it just keeps listening
    //
    // IMPORTANT: mbedtls_net_accept() on a UDP bind socket silently replaces
    // _listen_fd's underlying fd with a freshly created (blocking) socket
    // once it has accepted a peer -- non-blocking mode set at boot in
    // startListen() does NOT carry over. Without re-asserting it here, the
    // next mbedtls_net_accept() call in pollListening() blocks forever on an
    // idle socket and freezes the whole main loop.
    mbedtls_net_set_nonblock(&_listen_fd);
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

  // Both roles watch for staleness -- this is the only way either side learns
  // the link is dead, since UDP/DTLS gives no OS-level disconnect signal.
  if ((int32_t)(now - _last_rx_at) > IP_BRIDGE_PONG_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("Heartbeat timeout, link considered dead\n");
    teardownConnection(true);
    return;
  }

  // Only the client/spoke pings on its own initiative -- see the field comment
  // on _last_rx_at in IpBridge.h for why the server/hub doesn't.
  if (!_is_server && (int32_t)(now - _next_ping_at) >= 0) {
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
  // using _ssl below in that case -- confirmed via live testing this was
  // happening (produced a stale mbedtls_ssl_read error immediately after a
  // teardown log line), which is exactly the kind of "use a freed/reset
  // mbedTLS context" hazard that could plausibly hang rather than cleanly
  // error under different timing, particularly on the write path.
  if (_state != State::CONNECTED) return;

  // A peer restarting from a new source port (rather than the same one) won't
  // be detected until the existing session's own heartbeat timeout expires --
  // no separate parallel-accept/reconnect-detection path while CONNECTED. An
  // earlier version of this attempted that (accepting a second, tentative
  // connection on _listen_fd while already CONNECTED, verifying it on its own
  // context, then promoting it) but hung the hub solid on real hardware and
  // was removed rather than carried forward disabled; see git history and
  // planning/ip-bridge-design.md for the investigation if this is revisited.

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
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_TIMEOUT) {
      break;  // nothing more available right now, normal
    }
    if (n == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
      // Peer (server-side only, per mbedTLS docs) is starting a fresh
      // handshake from the same source port -- almost always means it just
      // rebooted. mbedTLS has already reset the session internally, so the
      // ClientHello that triggered this is still usable right now -- picking
      // the handshake back up on this SAME context (not tearing it down)
      // avoids discarding it and having to wait out the peer's own DTLS
      // retransmit backoff (1s,2s,4s,8s,16s...) for a resend. That wait is
      // exactly the "couple of 15-second cycles" stall seen live when a
      // rebooted peer's first reconnect attempt got silently dropped by the
      // old teardownConnection()-on-any-error handling here.
      BRIDGE_DEBUG_PRINTLN("Peer reconnecting (same source port), resuming handshake\n");
      _rx_buffer_pos = 0;
      _state = State::HANDSHAKING;
      _next_handshake_poll_at = 0;  // poll immediately on the next loop() tick
#ifdef ESPNOW_BRIDGE_RADIO
      radio_driver.setLinkConnected(false);
#endif
      return;
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

  int ret = mbedtls_ssl_write(_ssl, buffer, len + OVERHEAD);
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

  if (!_seen_packets.wasSeen(packet)) {
    _seen_packets.markSeen(packet);

    uint8_t sizing_buffer[MAX_TRANS_UNIT + 1];
    uint16_t len = packet->writeTo(sizing_buffer);
    if (len > (MAX_TRANS_UNIT + 1)) {
      BRIDGE_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", len, MAX_TRANS_UNIT + 1);
      return;
    }

    sendFramed(sizing_buffer, len);
  }
}

void IpBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

void IpBridge::loop() {
  if (!_initialized) return;

  switch (_state) {
    case State::LISTENING:
      pollListening();
      break;
    case State::HANDSHAKING:
      // Throttled: mbedtls_ssl_handshake() blocks for up to
      // mbedtls_ssl_conf_read_timeout()'s 1ms (real select() syscall inside
      // mbedtls_net_recv_timeout()) whenever no reply is waiting -- calling it
      // on every loop() tick caps the whole main loop at ~1kHz and starves
      // everything else sharing it. See _next_handshake_poll_at in IpBridge.h.
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
