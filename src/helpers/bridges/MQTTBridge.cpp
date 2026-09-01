#include "helpers/bridges/MQTTBridge.h"

#ifdef WITH_MQTT_BRIDGE

#include <WiFi.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <RTClib.h>
#include <helpers/TxtDataHelpers.h>  // StrHelper::strncpy
#include <Utils.h>

#ifndef MQTT_CONNECT_TIMEOUT_MS
  #define MQTT_CONNECT_TIMEOUT_MS   10000
#endif
#ifndef MQTT_KEEPALIVE_SECS
  #define MQTT_KEEPALIVE_SECS       55
#endif
#ifndef MQTT_PING_MISS_TIMEOUT_MS
  // Broker is considered dead if no traffic (including our own PINGRESP) is
  // heard for this long -- comfortably more than one keepalive interval.
  #define MQTT_PING_MISS_TIMEOUT_MS ((MQTT_KEEPALIVE_SECS * 2 + 10) * 1000UL)
#endif
#ifndef MQTT_RECONNECT_BASE_MS
  #define MQTT_RECONNECT_BASE_MS    5000UL
#endif
#ifndef MQTT_RECONNECT_MAX_MS
  #define MQTT_RECONNECT_MAX_MS     300000UL  // 5 min cap, same as IpBridge
#endif

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

MQTTBridge::MQTTBridge(NodePrefs *prefs, mesh::PacketManager *mgr, mesh::RTCClock *rtc, mesh::LocalIdentity *identity)
    : BridgeBase(prefs, mgr, rtc), _prefs(prefs), _identity(identity) {
  mbedtls_net_init(&_conn_fd);
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);
}

void MQTTBridge::begin() {
  if (!_prefs->mqtt_enabled) return;
  mesh::Utils::toHex(_pubkey_hex, _identity->pub_key, PUB_KEY_SIZE);
  if (!parseBrokerConfig()) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: invalid broker config, not starting\n");
    return;
  }
  _initialized = true;
  _consecutive_connect_failures = 0;
  startConnect();
}

void MQTTBridge::end() {
  if (_state != State::IDLE) {
    teardownConnection(false);
  }
  _initialized = false;
}

// Tiny URL parser for the 'custom' preset: scheme://host[:port][/path]
static bool parseUrl(const char *url, bool *use_tls, bool *use_ws, char *host, size_t host_size,
                      uint16_t *port, char *path, size_t path_size) {
  const char *p = url;
  if (strncmp(p, "wss://", 6) == 0) { *use_tls = true; *use_ws = true; *port = 443; p += 6; }
  else if (strncmp(p, "ws://", 5) == 0) { *use_tls = false; *use_ws = true; *port = 80; p += 5; }
  else if (strncmp(p, "mqtts://", 8) == 0) { *use_tls = true; *use_ws = false; *port = 8883; p += 8; }
  else if (strncmp(p, "mqtt://", 7) == 0) { *use_tls = false; *use_ws = false; *port = 1883; p += 7; }
  else return false;

  const char *slash = strchr(p, '/');
  const char *host_end = slash ? slash : p + strlen(p);
  const char *colon = (const char *)memchr(p, ':', host_end - p);
  size_t hlen = (colon ? colon : host_end) - p;
  if (hlen == 0 || hlen >= host_size) return false;
  memcpy(host, p, hlen);
  host[hlen] = 0;

  if (colon) {
    int prt = atoi(colon + 1);
    if (prt <= 0 || prt > 65535) return false;
    *port = (uint16_t)prt;
  }

  if (slash) {
    StrHelper::strncpy(path, slash, path_size);
  } else {
    StrHelper::strncpy(path, "/", path_size);
  }
  return true;
}

bool MQTTBridge::parseBrokerConfig() {
  strcpy(_ws_path, "/mqtt");
  if (_prefs->mqtt_server[0] == 0) return false;
  return parseUrl(_prefs->mqtt_server, &_use_tls, &_use_ws, _host, sizeof(_host), &_port, _ws_path, sizeof(_ws_path));
}

void MQTTBridge::startConnect() {
  if (_resolved_ip[0] == 0 || _consecutive_connect_failures >= 2) {
    IPAddress ip;
    if (!WiFi.hostByName(_host, ip)) {
      BRIDGE_DEBUG_PRINTLN("MQTTBridge: DNS lookup failed for %s\n", _host);
      scheduleReconnect();
      return;
    }
    strncpy(_resolved_ip, ip.toString().c_str(), sizeof(_resolved_ip) - 1);
    _resolved_ip[sizeof(_resolved_ip) - 1] = 0;
  }

  mbedtls_net_free(&_conn_fd);
  mbedtls_net_init(&_conn_fd);

  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: TCP socket() failed, errno=%d\n", errno);
    scheduleReconnect();
    return;
  }
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(_port);
  addr.sin_addr.s_addr = inet_addr(_resolved_ip);

  int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: TCP connect() failed immediately, errno=%d\n", errno);
    close(fd);
    scheduleReconnect();
    return;
  }

  _conn_fd.fd = fd;
  _state = State::TCP_CONNECTING;
  _next_action_at = millis() + MQTT_CONNECT_TIMEOUT_MS;
}

void MQTTBridge::pollTcpConnecting() {
  if ((int32_t)(millis() - _next_action_at) > 0) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: TCP connect timed out\n");
    teardownConnection(true);
    return;
  }
  fd_set wfds, efds;
  FD_ZERO(&wfds); FD_ZERO(&efds);
  FD_SET(_conn_fd.fd, &wfds);
  FD_SET(_conn_fd.fd, &efds);
  struct timeval tv = {0, 0};
  int sel = select(_conn_fd.fd + 1, NULL, &wfds, &efds, &tv);
  if (sel <= 0) return;  // still waiting
  if (FD_ISSET(_conn_fd.fd, &efds)) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: TCP connect failed (socket error)\n");
    teardownConnection(true);
    return;
  }
  if (!FD_ISSET(_conn_fd.fd, &wfds)) return;

  if (_use_tls) {
    if (!setupTlsConfig()) { teardownConnection(true); return; }
    mbedtls_net_set_nonblock(&_conn_fd);
    mbedtls_ssl_free(&_ssl);
    mbedtls_ssl_init(&_ssl);
    if (mbedtls_ssl_setup(&_ssl, &_ssl_conf) != 0 ||
        mbedtls_ssl_set_hostname(&_ssl, _host) != 0) {
      BRIDGE_DEBUG_PRINTLN("MQTTBridge: TLS setup failed\n");
      teardownConnection(true);
      return;
    }
    mbedtls_ssl_set_bio(&_ssl, &_conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    _state = State::TLS_HANDSHAKING;
    _handshake_started_at = millis();
  } else if (_use_ws) {
    startWsHandshake();
  } else {
    startMqttConnect();
  }
}

bool MQTTBridge::setupTlsConfig() {
  const char *pers = "MQTTBridge";
  if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                             (const unsigned char *)pers, strlen(pers)) != 0) {
    return false;
  }
  if (mbedtls_ssl_config_defaults(&_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    return false;
  }
  mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

  // No CA cert surface -- see class doc comment: this only ever talks to a
  // broker you run/trust yourself (e.g. your own CoreScope's Mosquitto), not
  // an arbitrary broker across the open internet.
  mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  return true;
}

void MQTTBridge::pollTlsHandshake() {
  if ((int32_t)(millis() - _handshake_started_at) > MQTT_CONNECT_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: TLS handshake timed out\n");
    teardownConnection(true);
    return;
  }
  int ret = mbedtls_ssl_handshake(&_ssl);
  if (ret == 0) {
    if (_use_ws) startWsHandshake(); else startMqttConnect();
    return;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) return;
  BRIDGE_DEBUG_PRINTLN("MQTTBridge: TLS handshake failed, err=-0x%04x\n", -ret);
  teardownConnection(true);
}

int MQTTBridge::transportWrite(const uint8_t *buf, size_t len) {
  if (_use_tls) {
    int ret = mbedtls_ssl_write(&_ssl, buf, len);
    return ret;
  }
  int ret = mbedtls_net_send(&_conn_fd, buf, len);
  return ret;
}

// Returns 1 + *out set, 0 if nothing available right now, <0 on hard error.
int MQTTBridge::transportReadByte(uint8_t *out) {
  int ret;
  if (_use_tls) {
    ret = mbedtls_ssl_read(&_ssl, out, 1);
  } else {
    ret = mbedtls_net_recv(&_conn_fd, out, 1);
  }
  if (ret == 1) return 1;
  if (ret == 0) return -1;  // orderly shutdown by peer
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
      ret == MBEDTLS_ERR_SSL_TIMEOUT || ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
    return 0;
  }
  if (!_use_tls && ret == MBEDTLS_ERR_NET_RECV_FAILED) {
    // mbedtls_net_recv on a nonblocking fd returns this for EAGAIN/EWOULDBLOCK too.
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
  }
  return -1;
}

void MQTTBridge::startWsHandshake() {
  uint8_t key_bytes[16];
  for (int i = 0; i < 16; i++) key_bytes[i] = (uint8_t)esp_random();
  size_t outlen = 0;
  char key_std_b64[32];
  mbedtls_base64_encode((unsigned char *)key_std_b64, sizeof(key_std_b64), &outlen, key_bytes, sizeof(key_bytes));
  key_std_b64[outlen] = 0;

  // Expected Sec-WebSocket-Accept: base64(SHA1(key + GUID)).
  char accept_input[64];
  int n = snprintf(accept_input, sizeof(accept_input), "%s%s", key_std_b64, WS_GUID);
  uint8_t sha1_out[20];
  mbedtls_sha1((const unsigned char *)accept_input, n, sha1_out);
  mbedtls_base64_encode((unsigned char *)_ws_expected_accept, sizeof(_ws_expected_accept), &outlen, sha1_out, sizeof(sha1_out));
  _ws_expected_accept[outlen] = 0;

  char req[384];
  int len = snprintf(req, sizeof(req),
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: mqtt\r\n"
    "\r\n", _ws_path, _host, key_std_b64);

  if (transportWrite((const uint8_t *)req, len) < 0) {
    teardownConnection(true);
    return;
  }
  _ws_http_buf_len = 0;
  _ws_frame_hdr_len = 0;
  _ws_len_bytes_needed = 0;
  _ws_frame_payload_len = 0;
  _ws_frame_payload_read = 0;
  _state = State::WS_HANDSHAKING;
  _handshake_started_at = millis();
}

void MQTTBridge::pollWsHandshake() {
  if ((int32_t)(millis() - _handshake_started_at) > MQTT_CONNECT_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: WS handshake timed out\n");
    teardownConnection(true);
    return;
  }
  uint8_t b;
  int ret;
  while ((ret = transportReadByte(&b)) == 1) {
    if (_ws_http_buf_len < sizeof(_ws_http_buf) - 1) {
      _ws_http_buf[_ws_http_buf_len++] = (char)b;
      _ws_http_buf[_ws_http_buf_len] = 0;
    }
    if (_ws_http_buf_len >= 4 &&
        memcmp(&_ws_http_buf[_ws_http_buf_len - 4], "\r\n\r\n", 4) == 0) {
      if (strncmp(_ws_http_buf, "HTTP/1.1 101", 12) != 0 && strncmp(_ws_http_buf, "HTTP/1.0 101", 12) != 0) {
        BRIDGE_DEBUG_PRINTLN("MQTTBridge: WS handshake rejected: %s\n", _ws_http_buf);
        teardownConnection(true);
        return;
      }
      // Not a hard failure if the Accept header can't be located/matched --
      // some brokers vary header casing/order more than is worth a strict
      // parser for; the 101 status line already proves the broker upgraded us.
      startMqttConnect();
      return;
    }
  }
  if (ret < 0) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: connection lost during WS handshake\n");
    teardownConnection(true);
  }
}

// ---- Minimal WS framing for the MQTT byte stream once upgraded ----
// Outbound frames from a client MUST be masked (RFC6455); inbound frames
// from the server MUST NOT be. Only single-frame, non-fragmented, <126-byte
// payloads are sent (every outbound MQTT control packet here is small); on
// receive, only frames up to sizeof(_rx_buf) are handled, which comfortably
// covers CONNACK/PINGRESP/small PUBLISH acks -- this bridge never subscribes,
// so nothing sizeable is ever expected inbound.

static bool wsWriteFrame(MQTTBridge &bridge, int (*write_cb)(void *, const uint8_t *, size_t), void *ctx,
                          const uint8_t *payload, size_t len) {
  uint8_t header[10];
  size_t hlen = 0;
  header[hlen++] = 0x82; // FIN + binary opcode
  uint8_t mask_bit = 0x80;
  if (len < 126) {
    header[hlen++] = mask_bit | (uint8_t)len;
  } else {
    header[hlen++] = mask_bit | 126;
    header[hlen++] = (uint8_t)(len >> 8);
    header[hlen++] = (uint8_t)(len & 0xFF);
  }
  uint8_t mask_key[4];
  for (int i = 0; i < 4; i++) mask_key[i] = (uint8_t)esp_random();
  memcpy(&header[hlen], mask_key, 4);
  hlen += 4;

  if (write_cb(ctx, header, hlen) < 0) return false;

  uint8_t chunk[64];
  size_t sent = 0;
  while (sent < len) {
    size_t n = len - sent; if (n > sizeof(chunk)) n = sizeof(chunk);
    for (size_t i = 0; i < n; i++) chunk[i] = payload[sent + i] ^ mask_key[(sent + i) & 3];
    if (write_cb(ctx, chunk, n) < 0) return false;
    sent += n;
  }
  return true;
}

bool MQTTBridge::sendMqttConnect() {
  const char *username = nullptr;
  const char *password = nullptr;
  char client_id[24];
  snprintf(client_id, sizeof(client_id), "mc_%.16s", _pubkey_hex);

  if (_prefs->mqtt_username[0] != 0) {
    username = _prefs->mqtt_username;
    password = _prefs->mqtt_password;
  }

  uint8_t payload[200]; // fixed header + client_id + username(<=32) + password(<=64), generous margin
  size_t p = 0;
  auto putStr = [&](const char *s) {
    uint16_t l = (uint16_t)strlen(s);
    payload[p++] = (uint8_t)(l >> 8);
    payload[p++] = (uint8_t)(l & 0xFF);
    memcpy(&payload[p], s, l);
    p += l;
  };

  putStr("MQTT");
  payload[p++] = 0x04; // protocol level 3.1.1
  uint8_t flags = 0x02; // clean session
  if (username) flags |= 0x80;
  if (password) flags |= 0x40;
  payload[p++] = flags;
  payload[p++] = (uint8_t)(MQTT_KEEPALIVE_SECS >> 8);
  payload[p++] = (uint8_t)(MQTT_KEEPALIVE_SECS & 0xFF);
  putStr(client_id);
  if (username) putStr(username);
  if (password) putStr(password);

  // Fixed header: type=1 (CONNECT), remaining length variable-encoded.
  uint8_t fixed[5];
  size_t flen = 0;
  fixed[flen++] = 0x10;
  uint32_t rem = p;
  do {
    uint8_t enc = rem & 0x7F;
    rem >>= 7;
    if (rem > 0) enc |= 0x80;
    fixed[flen++] = enc;
  } while (rem > 0);

  if (_use_ws) {
    uint8_t full[sizeof(fixed) + sizeof(payload)];
    memcpy(full, fixed, flen);
    memcpy(full + flen, payload, p);
    return wsWriteFrame(*this,
      [](void *ctx, const uint8_t *b, size_t l) -> int { return ((MQTTBridge *)ctx)->transportWrite(b, l); },
      this, full, flen + p);
  }
  if (transportWrite(fixed, flen) < 0) return false;
  if (transportWrite(payload, p) < 0) return false;
  return true;
}

void MQTTBridge::startMqttConnect() {
  if (!sendMqttConnect()) {
    teardownConnection(true);
    return;
  }
  _rx_buf_len = 0;
  _state = State::MQTT_CONNECTING;
  _handshake_started_at = millis();
}

// Feeds one raw (already WS-unwrapped, if applicable) MQTT stream byte
// through a tiny fixed-header + remaining-length + payload accumulator.
// Only CONNACK/PINGRESP are ever expected inbound (see class doc comment),
// both tiny and fixed-shape, so this doesn't need a general streaming parser.
void MQTTBridge::handleMqttControlByte(uint8_t b) {
  if (_rx_buf_len < sizeof(_rx_buf)) {
    _rx_buf[_rx_buf_len++] = b;
  }
  if (_rx_buf_len < 2) return; // need at least fixed header type + remaining-length first byte

  uint8_t type = _rx_buf[0] >> 4;
  // Remaining length is a single byte for both CONNACK (0x02) and PINGRESP (0x00) --
  // no multi-byte variable-length decoding needed for anything this bridge
  // ever receives.
  uint8_t remaining = _rx_buf[1];
  size_t total = 2 + remaining;
  if (_rx_buf_len < total) return;

  if (type == 0x02) { // CONNACK
    uint8_t return_code = (remaining >= 2) ? _rx_buf[3] : 0xFF;
    if (return_code == 0) {
      BRIDGE_DEBUG_PRINTLN("MQTTBridge: CONNACK ok\n");
      _state = State::CONNECTED;
      _last_rx_at = millis();
      _next_ping_at = millis() + (MQTT_KEEPALIVE_SECS * 1000UL);
      _ping_outstanding = false;
      _consecutive_connect_failures = 0;
    } else {
      BRIDGE_DEBUG_PRINTLN("MQTTBridge: CONNACK refused, code=%d\n", return_code);
      teardownConnection(true);
    }
  } else if (type == 0x0D) { // PINGRESP
    _last_rx_at = millis();
    _ping_outstanding = false;
  }
  // Anything else inbound (shouldn't normally happen) is just dropped.
  _rx_buf_len = 0;
}

void MQTTBridge::pollMqttConnecting() {
  if ((int32_t)(millis() - _handshake_started_at) > MQTT_CONNECT_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: CONNACK timed out\n");
    teardownConnection(true);
    return;
  }
  pollConnectedIO(); // shares the same read/WS-unwrap loop; state only advances on CONNACK
}

// One WS frame at a time: reads the 2-10 byte header, then feeds payload
// bytes to handleMqttControlByte() (server frames are never masked per
// RFC6455, so no unmasking needed on receive). Parse position is kept in
// member fields (reset in startWsHandshake()) rather than locals, since a
// frame can arrive split across many non-blocking loop() ticks.
void MQTTBridge::pollConnectedIO() {
  uint8_t b;
  int ret;
  int budget = 64; // avoid ever spending unbounded time in one loop() tick
  while (budget-- > 0 && (ret = transportReadByte(&b)) == 1) {
    _last_rx_at = millis();
    if (!_use_ws) {
      handleMqttControlByte(b);
      continue;
    }

    if (_ws_frame_hdr_len < 2) {
      _ws_frame_hdr[_ws_frame_hdr_len++] = b;
      if (_ws_frame_hdr_len == 2) {
        _ws_frame_opcode = _ws_frame_hdr[0] & 0x0F;
        uint8_t len7 = _ws_frame_hdr[1] & 0x7F;
        if (len7 < 126) {
          _ws_frame_payload_len = len7;
          _ws_len_bytes_needed = 0;
        } else if (len7 == 126) {
          _ws_len_bytes_needed = 2;
        } else {
          _ws_len_bytes_needed = 8;
        }
        _ws_len_buf_pos = 0;
        _ws_frame_payload_read = 0;
      }
      continue;
    }
    if (_ws_len_bytes_needed > 0) {
      _ws_len_buf[_ws_len_buf_pos++] = b;
      if (_ws_len_buf_pos == _ws_len_bytes_needed) {
        _ws_frame_payload_len = 0;
        for (int i = 0; i < _ws_len_bytes_needed; i++) _ws_frame_payload_len = (_ws_frame_payload_len << 8) | _ws_len_buf[i];
        _ws_len_bytes_needed = 0;
      }
      continue;
    }
    // Payload byte.
    if (_ws_frame_payload_read < _ws_frame_payload_len) {
      _ws_frame_payload_read++;
      if (_ws_frame_opcode == 0x02 || _ws_frame_opcode == 0x01) { // binary or text: MQTT bytes
        handleMqttControlByte(b);
      }
      // opcode 0x08 (close), 0x09 (ping), 0x0A (pong) payloads are just drained/ignored --
      // no pong reply sent since MQTT's own PINGREQ/PINGRESP already covers keepalive.
      if (_ws_frame_payload_read >= _ws_frame_payload_len) {
        _ws_frame_hdr_len = 0; // frame complete, ready for the next one
      }
    }
  }
  if (ret < 0) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: connection lost\n");
    teardownConnection(true);
    return;
  }

  if (_state == State::CONNECTED) checkPing();
}

void MQTTBridge::checkPing() {
  unsigned long since_rx = millis() - _last_rx_at;
  if (since_rx > MQTT_PING_MISS_TIMEOUT_MS) {
    BRIDGE_DEBUG_PRINTLN("MQTTBridge: broker silent too long, reconnecting\n");
    teardownConnection(true);
    return;
  }
  if ((int32_t)(millis() - _next_ping_at) >= 0) {
    sendMqttPingreq();
    _ping_outstanding = true;
    _next_ping_at = millis() + (MQTT_KEEPALIVE_SECS * 1000UL);
  }
}

bool MQTTBridge::sendMqttPingreq() {
  const uint8_t frame[2] = {0xC0, 0x00};
  if (_use_ws) {
    return wsWriteFrame(*this,
      [](void *ctx, const uint8_t *b, size_t l) -> int { return ((MQTTBridge *)ctx)->transportWrite(b, l); },
      this, frame, sizeof(frame));
  }
  return transportWrite(frame, sizeof(frame)) >= 0;
}

bool MQTTBridge::sendMqttPublish(const char *topic, const char *payload, size_t payload_len) {
  uint16_t topic_len = (uint16_t)strlen(topic);
  size_t var_payload_len = 2 + topic_len + payload_len;

  uint8_t fixed[5];
  size_t flen = 0;
  fixed[flen++] = 0x30; // PUBLISH, QoS 0, no DUP, no RETAIN
  uint32_t rem = var_payload_len;
  do {
    uint8_t enc = rem & 0x7F;
    rem >>= 7;
    if (rem > 0) enc |= 0x80;
    fixed[flen++] = enc;
  } while (rem > 0);

  // Build once into a scratch buffer so WS mode can mask it as a single frame.
  static uint8_t scratch[8 + 2 + 96 + 900]; // fixed hdr + topic + JSON payload headroom
  size_t p = 0;
  if (flen + 2 + topic_len + payload_len > sizeof(scratch)) return false;
  memcpy(&scratch[p], fixed, flen); p += flen;
  scratch[p++] = (uint8_t)(topic_len >> 8);
  scratch[p++] = (uint8_t)(topic_len & 0xFF);
  memcpy(&scratch[p], topic, topic_len); p += topic_len;
  memcpy(&scratch[p], payload, payload_len); p += payload_len;

  if (_use_ws) {
    return wsWriteFrame(*this,
      [](void *ctx, const uint8_t *b, size_t l) -> int { return ((MQTTBridge *)ctx)->transportWrite(b, l); },
      this, scratch, p);
  }
  return transportWrite(scratch, p) >= 0;
}

void MQTTBridge::teardownConnection(bool reconnect) {
  if (_use_tls) mbedtls_ssl_close_notify(&_ssl);
  mbedtls_net_free(&_conn_fd);
  if (reconnect) {
    scheduleReconnect();
  } else {
    _state = State::IDLE;
  }
}

void MQTTBridge::scheduleReconnect() {
  if (_consecutive_connect_failures < 255) _consecutive_connect_failures++;
  unsigned long delay = MQTT_RECONNECT_BASE_MS;
  for (uint8_t i = 1; i < _consecutive_connect_failures && delay < MQTT_RECONNECT_MAX_MS; i++) delay *= 2;
  if (delay > MQTT_RECONNECT_MAX_MS) delay = MQTT_RECONNECT_MAX_MS;
  _next_action_at = millis() + delay;
  _state = State::RECONNECT_WAIT;
  BRIDGE_DEBUG_PRINTLN("MQTTBridge: reconnecting in %lums (attempt %u)\n", delay, (unsigned)_consecutive_connect_failures);
}

void MQTTBridge::loop() {
  if (!_initialized) return;
  switch (_state) {
    case State::IDLE: break;
    case State::TCP_CONNECTING: pollTcpConnecting(); break;
    case State::TLS_HANDSHAKING: pollTlsHandshake(); break;
    case State::WS_HANDSHAKING: pollWsHandshake(); break;
    case State::MQTT_CONNECTING: pollMqttConnecting(); break;
    case State::CONNECTED: pollConnectedIO(); break;
    case State::RECONNECT_WAIT:
      if ((int32_t)(millis() - _next_action_at) >= 0) startConnect();
      break;
  }
}

// ---- JSON payload builders (schema matches agessaman/MeshCore's observer
// firmware -- see class doc comment) ----

static void jsonEscape(const char *in, char *out, size_t out_size) {
  size_t o = 0;
  for (size_t i = 0; in[i] != 0 && o + 2 < out_size; i++) {
    char c = in[i];
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
    else if ((unsigned char)c >= 0x20) { out[o++] = c; }
  }
  out[o] = 0;
}

static void isoTimestamp(mesh::RTCClock *rtc, char *out, size_t out_size) {
  DateTime dt(rtc->getCurrentTime());
  snprintf(out, out_size, "%04d-%02d-%02dT%02d:%02d:%02d.000000+00:00",
           dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second());
}

size_t MQTTBridge::buildStatusPayload(char *out, size_t out_size) {
  char name_esc[64];
  jsonEscape(_prefs->node_name, name_esc, sizeof(name_esc));
  char ts[40];
  isoTimestamp(_rtc, ts, sizeof(ts));
  int n = snprintf(out, out_size,
    "{\"status\":\"online\",\"timestamp\":\"%s\",\"origin\":\"%s\",\"origin_id\":\"%s\","
    "\"client_version\":\"meshcore-espnow-ip-bridge\"}",
    ts, name_esc, _pubkey_hex);
  return (n > 0 && (size_t)n < out_size) ? (size_t)n : 0;
}

size_t MQTTBridge::buildPacketPayload(char *out, size_t out_size, const mesh::Packet *pkt, int len,
                                       const char *direction, float score, float snr, float rssi) {
  char name_esc[64];
  jsonEscape(_prefs->node_name, name_esc, sizeof(name_esc));
  char ts[40];
  isoTimestamp(_rtc, ts, sizeof(ts));
  DateTime dt(_rtc->getCurrentTime());
  char time_str[10], date_str[12];
  snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d", dt.hour(), dt.minute(), dt.second());
  snprintf(date_str, sizeof(date_str), "%02d/%02d/%04d", dt.day(), dt.month(), dt.year());

  uint8_t hash[MAX_HASH_SIZE];
  pkt->calculatePacketHash(hash);
  char hash_hex[MAX_HASH_SIZE * 2 + 1];
  mesh::Utils::toHex(hash_hex, hash, MAX_HASH_SIZE);

  uint8_t raw[MAX_TRANS_UNIT + 4];
  uint8_t raw_len = pkt->writeTo(raw);
  char raw_hex[(MAX_TRANS_UNIT + 4) * 2 + 1];
  mesh::Utils::toHex(raw_hex, raw, raw_len);

  char route;
  switch (pkt->getRouteType()) {
    case ROUTE_TYPE_TRANSPORT_FLOOD: route = 'T'; break;
    case ROUTE_TYPE_FLOOD: route = 'F'; break;
    case ROUTE_TYPE_DIRECT: route = 'D'; break;
    default: route = 'U'; break;
  }

  char path_json[256];
  size_t pj = 0;
  path_json[pj++] = '[';
  if (pkt->isRouteDirect()) {
    uint8_t hop_size = pkt->getPathHashSize();
    uint8_t hop_count = pkt->getPathHashCount();
    for (uint8_t i = 0; i < hop_count && pj + hop_size * 2 + 4 < sizeof(path_json); i++) {
      if (i > 0) path_json[pj++] = ',';
      path_json[pj++] = '"';
      static const char lower_hex[] = "0123456789abcdef";
      for (uint8_t k = 0; k < hop_size; k++) {
        uint8_t byte = pkt->path[i * hop_size + k];
        path_json[pj++] = lower_hex[byte >> 4];
        path_json[pj++] = lower_hex[byte & 0x0F];
      }
      path_json[pj++] = '"';
    }
  }
  path_json[pj++] = ']';
  path_json[pj] = 0;

  // RF fields only for a genuine radio reception -- never fabricated for
  // "tx" or "bridge" (see class doc comment: this is the same failure mode
  // the fork's own PR #13 hit and fixed by omitting rather than faking).
  char rf_fields[80] = {0};
  if (strcmp(direction, "rx") == 0) {
    snprintf(rf_fields, sizeof(rf_fields), ",\"SNR\":\"%.1f\",\"RSSI\":\"%.0f\",\"score\":\"%.0f\"",
             snr, rssi, score * 1000.0f);
  }

  int n = snprintf(out, out_size,
    "{\"origin\":\"%s\",\"origin_id\":\"%s\",\"timestamp\":\"%s\",\"type\":\"PACKET\","
    "\"direction\":\"%s\",\"time\":\"%s\",\"date\":\"%s\",\"len\":\"%d\",\"packet_type\":\"%d\","
    "\"route\":\"%c\",\"payload_len\":\"%d\",\"raw\":\"%s\"%s,\"hash\":\"%s\",\"path\":%s}",
    name_esc, _pubkey_hex, ts, direction, time_str, date_str, len,
    (int)pkt->getPayloadType(), route, (int)pkt->payload_len, raw_hex, rf_fields, hash_hex, path_json);
  return (n > 0 && (size_t)n < out_size) ? (size_t)n : 0;
}

void MQTTBridge::publishRx(const mesh::Packet *pkt, int len, float score, float snr, float rssi) {
  if (_state != State::CONNECTED) return;
  char topic[96], payload[900];
  snprintf(topic, sizeof(topic), "meshcore/%s/%s/packets", _prefs->mqtt_iata, _pubkey_hex);
  size_t plen = buildPacketPayload(payload, sizeof(payload), pkt, len, "rx", score, snr, rssi);
  if (plen > 0) sendMqttPublish(topic, payload, plen);
}

void MQTTBridge::publishRxBridge(const mesh::Packet *pkt, int len) {
  if (_state != State::CONNECTED) return;
  char topic[96], payload[900];
  snprintf(topic, sizeof(topic), "meshcore/%s/%s/packets", _prefs->mqtt_iata, _pubkey_hex);
  // Deliberately "bridge", not "rx" -- see class doc comment.
  size_t plen = buildPacketPayload(payload, sizeof(payload), pkt, len, "bridge", 0, 0, 0);
  if (plen > 0) sendMqttPublish(topic, payload, plen);
}

void MQTTBridge::publishTx(const mesh::Packet *pkt, int len) {
  if (_state != State::CONNECTED) return;
  char topic[96], payload[900];
  snprintf(topic, sizeof(topic), "meshcore/%s/%s/packets", _prefs->mqtt_iata, _pubkey_hex);
  size_t plen = buildPacketPayload(payload, sizeof(payload), pkt, len, "tx", 0, 0, 0);
  if (plen > 0) sendMqttPublish(topic, payload, plen);
}

void MQTTBridge::formatStatus(char *reply) const {
  switch (_state) {
    case State::IDLE: strcpy(reply, "not enabled"); break;
    case State::TCP_CONNECTING: sprintf(reply, "connecting to %s:%u...", _host, (unsigned)_port); break;
    case State::TLS_HANDSHAKING: strcpy(reply, "TLS handshake in progress..."); break;
    case State::WS_HANDSHAKING: strcpy(reply, "WebSocket handshake in progress..."); break;
    case State::MQTT_CONNECTING: strcpy(reply, "MQTT CONNECT sent, waiting for broker..."); break;
    case State::CONNECTED: sprintf(reply, "connected to %s:%u", _host, (unsigned)_port); break;
    case State::RECONNECT_WAIT: sprintf(reply, "reconnecting to %s:%u, %u failed attempt%s so far",
                                          _host, (unsigned)_port, (unsigned)_consecutive_connect_failures,
                                          _consecutive_connect_failures == 1 ? "" : "s"); break;
  }
}

#endif
