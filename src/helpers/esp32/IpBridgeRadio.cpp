#include "IpBridgeRadio.h"

#include <Arduino.h>
#include <WiFi.h>
#include <esp_system.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <Utils.h>

#if IP_BRIDGE_RADIO_DEBUG_LOGGING && ARDUINO
  #define IPRADIO_DEBUG_PRINTLN(F, ...) Serial.printf("IpBridgeRadio: " F "\n", ##__VA_ARGS__)
#else
  #define IPRADIO_DEBUG_PRINTLN(...) {}
#endif

// Same wire framing/magic IpBridge.cpp uses -- an unmodified IpBridge server
// needs no changes to accept this as just another client.
static constexpr uint16_t BRIDGE_PACKET_MAGIC = 0xC03E;
static constexpr uint8_t HEARTBEAT_PING = 0xF1;
static constexpr uint8_t HEARTBEAT_PONG = 0xF2;
static constexpr uint16_t OVERHEAD = 2 /*magic*/ + 2 /*length*/ + 2 /*checksum*/;

#ifndef IP_BRIDGE_RADIO_PING_INTERVAL_MS
#define IP_BRIDGE_RADIO_PING_INTERVAL_MS   15000
#endif
#ifndef IP_BRIDGE_RADIO_PONG_TIMEOUT_MS
#define IP_BRIDGE_RADIO_PONG_TIMEOUT_MS    45000
#endif
#ifndef IP_BRIDGE_RADIO_RECONNECT_DELAY_MS
#define IP_BRIDGE_RADIO_RECONNECT_DELAY_MS 5000
#endif
#ifndef IP_BRIDGE_RADIO_RECONNECT_MAX_MS
#define IP_BRIDGE_RADIO_RECONNECT_MAX_MS   60000
#endif
#ifndef IP_BRIDGE_RADIO_HANDSHAKE_POLL_INTERVAL_MS
#define IP_BRIDGE_RADIO_HANDSHAKE_POLL_INTERVAL_MS 50
#endif
#ifndef IP_BRIDGE_RADIO_HANDSHAKE_TIMEOUT_MS
#define IP_BRIDGE_RADIO_HANDSHAKE_TIMEOUT_MS 30000
#endif
#ifndef IP_BRIDGE_RADIO_TCP_CONNECT_TIMEOUT_MS
#define IP_BRIDGE_RADIO_TCP_CONNECT_TIMEOUT_MS 5000
#endif
#ifndef IP_BRIDGE_RADIO_KEEPALIVE_IDLE_SECS
#define IP_BRIDGE_RADIO_KEEPALIVE_IDLE_SECS  30
#endif
#ifndef IP_BRIDGE_RADIO_KEEPALIVE_INTVL_SECS
#define IP_BRIDGE_RADIO_KEEPALIVE_INTVL_SECS 10
#endif
#ifndef IP_BRIDGE_RADIO_KEEPALIVE_COUNT
#define IP_BRIDGE_RADIO_KEEPALIVE_COUNT      3
#endif

#define BOARD_LED_GREEN(pin, brightness) neopixelWrite(pin, brightness, 0, 0)
#define BOARD_LED_RED(pin, brightness)   neopixelWrite(pin, 0, brightness, 0)
#define BOARD_LED_BLUE(pin, brightness)  neopixelWrite(pin, 0, 0, brightness)
#define BOARD_LED_OFF(pin)               neopixelWrite(pin, 0, 0, 0)

// same algorithm as BridgeBase::fletcher16() -- must match bit-for-bit, since
// an unmodified IpBridge server on the other end computes it the same way.
static uint16_t fletcher16(const uint8_t* data, size_t len) {
  uint8_t sum1 = 0, sum2 = 0;
  for (size_t i = 0; i < len; i++) {
    sum1 = (sum1 + data[i]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return (sum2 << 8) | sum1;
}

static void applyTcpKeepalive(int fd) {
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  int idle = IP_BRIDGE_RADIO_KEEPALIVE_IDLE_SECS;
  int intvl = IP_BRIDGE_RADIO_KEEPALIVE_INTVL_SECS;
  int cnt = IP_BRIDGE_RADIO_KEEPALIVE_COUNT;
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

// Same backoff shape as IpBridge's own reconnectDelayFor() -- doubles per
// consecutive failure, capped, so a repeater that's down for a while gets
// retried less aggressively over time instead of a flat interval forever.
static uint32_t reconnectDelayFor(uint8_t consecutive_failures) {
  uint8_t shift = consecutive_failures > 6 ? 6 : consecutive_failures;
  uint32_t delay = (uint32_t)IP_BRIDGE_RADIO_RECONNECT_DELAY_MS << shift;
  return delay > IP_BRIDGE_RADIO_RECONNECT_MAX_MS ? IP_BRIDGE_RADIO_RECONNECT_MAX_MS : delay;
}

uint32_t IpBridgeRadio::getRngSeed() {
  return esp_random();
}

void IpBridgeRadio::init() {
  mbedtls_net_init(&_conn_fd);
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_ssl_conf);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_entropy_init(&_entropy);

  // Actually joining a network (WiFi.begin()) is driven by the example's own
  // main.cpp once wifi.ssid is loaded from persisted prefs -- but the WiFi
  // stack itself must exist before that. MyMesh::begin() calls setIpParams()
  // (which can immediately call WiFi.hostByName()/open a socket via
  // startConnect()) well before main.cpp's own WiFi bring-up block runs, so
  // without this, a board that boots with ip.host already configured touches
  // an uninitialized WiFi/netif stack -- confirmed live (2026-09-12): the
  // board went unresponsive on the very first reboot after ip.* params were
  // persisted. Same fix ESPNowBridgeRadio's own init() already applies for
  // the same underlying reason.
  WiFi.mode(WIFI_STA);
}

bool IpBridgeRadio::setupTlsConfig() {
  if (_tls_conf_ready) return true;

  const char* pers = "IpBridgeRadio";
  if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                             (const unsigned char*)pers, strlen(pers)) != 0) {
    IPRADIO_DEBUG_PRINTLN("mbedtls_ctr_drbg_seed failed");
    return false;
  }

  if (mbedtls_ssl_config_defaults(&_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    IPRADIO_DEBUG_PRINTLN("mbedtls_ssl_config_defaults failed");
    return false;
  }

  mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);  // PSK-only, no certs to verify
  mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

  static const int psk_ciphersuites[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    0
  };
  mbedtls_ssl_conf_ciphersuites(&_ssl_conf, psk_ciphersuites);

  size_t secret_len = strlen(_secret);
  if (mbedtls_ssl_conf_psk(&_ssl_conf, (const unsigned char*)_secret, secret_len,
                            (const unsigned char*)_own_identity, strlen(_own_identity)) != 0) {
    IPRADIO_DEBUG_PRINTLN("mbedtls_ssl_conf_psk failed");
    return false;
  }

  _tls_conf_ready = true;
  return true;
}

bool IpBridgeRadio::setupSslContext() {
  mbedtls_net_set_nonblock(&_conn_fd);
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_init(&_ssl);
  int ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf);
  if (ret != 0) {
    _last_ssl_setup_err = ret;
    _last_ssl_setup_free_heap = ESP.getFreeHeap();
    IPRADIO_DEBUG_PRINTLN("mbedtls_ssl_setup failed, ret=-0x%04x, free_heap=%u", (unsigned)(-ret), (unsigned)_last_ssl_setup_free_heap);
    return false;
  }
  mbedtls_ssl_set_bio(&_ssl, &_conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  return true;
}

void IpBridgeRadio::setIpParams(const char* host, uint16_t port, const char* secret, const uint8_t* self_pub_key) {
  teardownConnection(false);

  size_t n = strlen(host);
  if (n > sizeof(_host) - 1) n = sizeof(_host) - 1;
  memcpy(_host, host, n);
  _host[n] = 0;

  _port = port;

  n = strlen(secret);
  if (n > sizeof(_secret) - 1) n = sizeof(_secret) - 1;
  memcpy(_secret, secret, n);
  _secret[n] = 0;

  mesh::Utils::toHex(_own_identity, self_pub_key, 4);

  _resolved_ip[0] = 0;
  _consecutive_connect_failures = 0;
  _tls_conf_ready = false;  // secret/identity may have changed, re-derive PSK config

  _configured = _host[0] != 0 && _port != 0 && _secret[0] != 0;
  if (!_configured) {
    IPRADIO_DEBUG_PRINTLN("Not fully configured (host/port/secret), staying inert");
    return;
  }

  if (!setupTlsConfig()) {
    _configured = false;
    return;
  }

  startConnect();
  // Same unconditional initial call IpBridge::begin() makes -- otherwise the
  // persistent "not connected" indicator only ever lights up via
  // teardownConnection(), which the very first connection attempt never
  // reaches if it fails before HANDSHAKING (DNS/socket/TCP-connect failure).
  // Confirmed live (2026-09-12): LED stayed dark through a real failed first
  // attempt because of this gap.
  if (_state != State::IDLE) setLinkConnected(false);
}

void IpBridgeRadio::formatStatus(char* reply) const {
  if (!_configured) {
    sprintf(reply, "idle (not configured)");
    return;
  }
  unsigned long since_rx_secs = _last_rx_at == 0 ? 0 : (millis() - _last_rx_at) / 1000;
  switch (_state) {
    case State::IDLE:
      sprintf(reply, "idle (not started)");
      break;
    case State::TCP_CONNECTING:
      sprintf(reply, "connecting to %s (resolved: %s)...", _host, _resolved_ip);
      break;
    case State::HANDSHAKING:
      sprintf(reply, "authenticating with %s (resolved: %s)...", _host, _resolved_ip);
      break;
    case State::CONNECTED:
      if (_last_rx_at == 0) {
        sprintf(reply, "connected to %s (%s), nothing received yet", _host, _resolved_ip);
      } else {
        sprintf(reply, "connected to %s (%s), last heard %lus ago", _host, _resolved_ip, since_rx_secs);
      }
      break;
    case State::RECONNECT_WAIT: {
      char* dp = reply;
      if (_resolved_ip[0] == 0) {
        dp += sprintf(dp, "DNS lookup failed for %s, retrying...", _host);
      } else if (_last_ssl_setup_err != 0) {
        dp += sprintf(dp, "reconnecting to %s (%s), %u failed attempt%s so far -- last error: mbedtls_ssl_setup ret=-0x%04x, free_heap=%u",
                _host, _resolved_ip, (unsigned)_consecutive_connect_failures, _consecutive_connect_failures == 1 ? "" : "s",
                (unsigned)(-_last_ssl_setup_err), (unsigned)_last_ssl_setup_free_heap);
      } else {
        dp += sprintf(dp, "reconnecting to %s (%s), %u failed attempt%s so far", _host, _resolved_ip,
                (unsigned)_consecutive_connect_failures, _consecutive_connect_failures == 1 ? "" : "s");
      }
      // wifi_status/free_heap always appended -- disambiguates "never
      // associated to WiFi" (status != 3/WL_CONNECTED) from a real repeated
      // connect/TLS failure while WiFi is genuinely up, without needing a
      // separate debug-logging build to see it.
      sprintf(dp, " [wifi_status=%d free_heap=%u]", (int)WiFi.status(), (unsigned)ESP.getFreeHeap());
      break;
    }
  }
}

void IpBridgeRadio::scheduleReconnect() {
  _state = State::RECONNECT_WAIT;

  if (WiFi.status() != WL_CONNECTED) {
    // No network at all right now -- don't let this pile onto the backoff,
    // same reasoning as IpBridge's own scheduleReconnect().
    _consecutive_connect_failures = 0;
    _next_action_at = millis() + IP_BRIDGE_RADIO_RECONNECT_DELAY_MS;
    IPRADIO_DEBUG_PRINTLN("No WiFi yet, retrying in %us", (unsigned)(IP_BRIDGE_RADIO_RECONNECT_DELAY_MS / 1000));
    return;
  }

  _consecutive_connect_failures++;
  uint32_t delay = reconnectDelayFor(_consecutive_connect_failures);
  _next_action_at = millis() + delay;
  IPRADIO_DEBUG_PRINTLN("Reconnecting in %us (%u consecutive failure%s)",
                         (unsigned)(delay / 1000), (unsigned)_consecutive_connect_failures,
                         _consecutive_connect_failures == 1 ? "" : "s");
}

void IpBridgeRadio::startConnect() {
  if (_resolved_ip[0] == 0 || _consecutive_connect_failures >= 2) {
    IPAddress ip;
    if (!WiFi.hostByName(_host, ip)) {
      IPRADIO_DEBUG_PRINTLN("DNS lookup failed for %s", _host);
      scheduleReconnect();
      return;
    }
    strncpy(_resolved_ip, ip.toString().c_str(), sizeof(_resolved_ip) - 1);
    _resolved_ip[sizeof(_resolved_ip) - 1] = 0;
    // Deliberately not resetting _consecutive_connect_failures here -- same
    // reasoning as IpBridge's own startConnect().
    IPRADIO_DEBUG_PRINTLN("Resolved %s -> %s", _host, _resolved_ip);
  }

  mbedtls_net_free(&_conn_fd);
  mbedtls_net_init(&_conn_fd);

  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    IPRADIO_DEBUG_PRINTLN("TCP socket() failed, errno=%d", errno);
    scheduleReconnect();
    return;
  }

  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(_port);
  addr.sin_addr.s_addr = inet_addr(_resolved_ip);

  int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    IPRADIO_DEBUG_PRINTLN("TCP connect() failed immediately, errno=%d", errno);
    close(fd);
    scheduleReconnect();
    return;
  }

  applyTcpKeepalive(fd);

  _conn_fd.fd = fd;
  _state = State::TCP_CONNECTING;
  _next_action_at = millis() + IP_BRIDGE_RADIO_TCP_CONNECT_TIMEOUT_MS;
  IPRADIO_DEBUG_PRINTLN("TCP connect in progress to %s:%u", _resolved_ip, (unsigned)_port);
}

void IpBridgeRadio::pollTcpConnecting() {
  if ((int32_t)(millis() - _next_action_at) > 0) {
    IPRADIO_DEBUG_PRINTLN("TCP connect timed out");
    mbedtls_net_free(&_conn_fd);
    scheduleReconnect();
    return;
  }

  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(_conn_fd.fd, &wfds);
  struct timeval tv = {0, 0};
  int sel = select(_conn_fd.fd + 1, NULL, &wfds, NULL, &tv);
  if (sel <= 0) return;  // not resolved yet

  int sock_err = 0;
  socklen_t err_len = sizeof(sock_err);
  getsockopt(_conn_fd.fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
  if (sock_err != 0) {
    IPRADIO_DEBUG_PRINTLN("TCP connect failed, err=%d", sock_err);
    mbedtls_net_free(&_conn_fd);
    scheduleReconnect();
    return;
  }

  if (!setupSslContext()) {
    mbedtls_net_free(&_conn_fd);
    scheduleReconnect();
    return;
  }

  _rx_frame_buffer_pos = 0;
  _state = State::HANDSHAKING;
  _next_handshake_poll_at = 0;  // poll immediately
  _handshake_started_at = millis();
  IPRADIO_DEBUG_PRINTLN("TCP connected, starting TLS handshake");
}

void IpBridgeRadio::pollHandshake() {
  if ((int32_t)(millis() - _handshake_started_at) > (int32_t)IP_BRIDGE_RADIO_HANDSHAKE_TIMEOUT_MS) {
    IPRADIO_DEBUG_PRINTLN("TLS handshake timed out after %ums, giving up",
                           (unsigned)IP_BRIDGE_RADIO_HANDSHAKE_TIMEOUT_MS);
    teardownConnection(true);
    return;
  }

  int ret = mbedtls_ssl_handshake(&_ssl);
  if (ret == 0) {
    IPRADIO_DEBUG_PRINTLN("TLS session established");
    _state = State::CONNECTED;
    _last_rx_at = millis();
    _next_ping_at = millis() + IP_BRIDGE_RADIO_PING_INTERVAL_MS;
    _consecutive_connect_failures = 0;
    setLinkConnected(true);
    return;
  }
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return;  // keep polling
  }

  IPRADIO_DEBUG_PRINTLN("TLS handshake failed, err=%d", ret);
  teardownConnection(true);
}

void IpBridgeRadio::teardownConnection(bool reconnect) {
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_init(&_ssl);
  mbedtls_net_free(&_conn_fd);
  mbedtls_net_init(&_conn_fd);
  _rx_frame_buffer_pos = 0;
  _pending_rx_len = 0;

  if (_state == State::IDLE) return;  // nothing to tear down / not yet started

  if (reconnect && _configured) {
    scheduleReconnect();
    setLinkConnected(false);
  } else {
    _state = State::IDLE;
  }
}

void IpBridgeRadio::checkHeartbeat() {
  unsigned long now = millis();

  if ((int32_t)(now - _last_rx_at) > IP_BRIDGE_RADIO_PONG_TIMEOUT_MS) {
    IPRADIO_DEBUG_PRINTLN("Heartbeat timeout, link considered dead");
    teardownConnection(true);
    return;
  }

  if ((int32_t)(now - _next_ping_at) >= 0) {
    IPRADIO_DEBUG_PRINTLN("Sending heartbeat ping");
    uint8_t ping = HEARTBEAT_PING;
    sendFramed(&ping, 1);
    indicateIpPing();
    _next_ping_at = now + IP_BRIDGE_RADIO_PING_INTERVAL_MS;
  }
}

void IpBridgeRadio::pollConnectedIO() {
  checkHeartbeat();
  if (_state != State::CONNECTED) return;  // checkHeartbeat() may have torn it down

  // Stop draining as soon as one complete frame is decoded and waiting to be
  // handed out via recvRaw() -- a single-slot buffer, not a queue (see header
  // comment). TCP keeps whatever's left buffered in the OS socket for the
  // next loop() tick, so nothing is lost by not draining further right now.
  for (int i = 0; i < 4 && _pending_rx_len == 0; i++) {
    uint8_t buf[64];
    int n = mbedtls_ssl_read(&_ssl, buf, sizeof(buf));
    if (n > 0) {
      for (int j = 0; j < n && _pending_rx_len == 0; j++) processFramedByte(buf[j]);
      if (_state != State::CONNECTED) return;  // processFramedByte() can tear down (pong write failure)
      if (n < (int)sizeof(buf)) break;
      continue;
    }
    if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      teardownConnection(true);
      return;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ) {
      break;
    }
    IPRADIO_DEBUG_PRINTLN("mbedtls_ssl_read error %d", n);
    teardownConnection(true);
    return;
  }
}

void IpBridgeRadio::processFramedByte(uint8_t b) {
  if (_rx_frame_buffer_pos < 2) {
    if ((_rx_frame_buffer_pos == 0 && b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) ||
        (_rx_frame_buffer_pos == 1 && b == (BRIDGE_PACKET_MAGIC & 0xFF))) {
      _rx_frame_buffer[_rx_frame_buffer_pos++] = b;
    } else {
      _rx_frame_buffer_pos = 0;
      if (b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) {
        _rx_frame_buffer[_rx_frame_buffer_pos++] = b;
      }
    }
    return;
  }

  _rx_frame_buffer[_rx_frame_buffer_pos++] = b;
  if (_rx_frame_buffer_pos < 4) return;

  uint16_t len = (_rx_frame_buffer[2] << 8) | _rx_frame_buffer[3];
  if (len > (MAX_PACKET_SIZE - OVERHEAD)) {
    IPRADIO_DEBUG_PRINTLN("RX invalid length %d, resetting", len);
    _rx_frame_buffer_pos = 0;
    return;
  }

  if (_rx_frame_buffer_pos != len + OVERHEAD) return;  // still accumulating

  uint16_t received_checksum = (_rx_frame_buffer[4 + len] << 8) | _rx_frame_buffer[5 + len];
  if (fletcher16(_rx_frame_buffer + 4, len) != received_checksum) {
    IPRADIO_DEBUG_PRINTLN("RX checksum mismatch, len=%d, rcv=0x%04x", len, received_checksum);
    _n_recv_errors++;
    _rx_frame_buffer_pos = 0;
    return;
  }

  _last_rx_at = millis();
  _next_ping_at = millis() + IP_BRIDGE_RADIO_PING_INTERVAL_MS;  // see IpBridge's own comment on this

  if (len == 1 && _rx_frame_buffer[4] == HEARTBEAT_PING) {
    IPRADIO_DEBUG_PRINTLN("Received heartbeat ping, replying with pong");
    indicateIpPing();
    uint8_t pong = HEARTBEAT_PONG;
    sendFramed(&pong, 1);
  } else if (len == 1 && _rx_frame_buffer[4] == HEARTBEAT_PONG) {
    IPRADIO_DEBUG_PRINTLN("Received heartbeat pong");
    indicatePongReceived();
  } else {
    IPRADIO_DEBUG_PRINTLN("RX, len=%d crc=0x%04x", len, received_checksum);
    memcpy(_pending_rx, _rx_frame_buffer + 4, len);
    _pending_rx_len = len;
    _n_recv++;
  }

  _rx_frame_buffer_pos = 0;
}

void IpBridgeRadio::sendFramed(const uint8_t* payload, uint16_t len) {
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

  int ret = mbedtls_ssl_write(&_ssl, buffer, len + OVERHEAD);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    IPRADIO_DEBUG_PRINTLN("mbedtls_ssl_write error %d", ret);
    teardownConnection(true);
  }
}

int IpBridgeRadio::recvRaw(uint8_t* bytes, int sz) {
  if (_pending_rx_len == 0) return 0;
  int len = _pending_rx_len;
  _pending_rx_len = 0;
  if (len > sz) {
    // Shouldn't happen -- a genuine packet from another node's Dispatcher
    // is always <= MAX_TRANS_UNIT, same bound Dispatcher passes as sz here.
    // Drop rather than truncate: a truncated packet would just fail its own
    // checksum downstream anyway, but silently handing back fewer bytes than
    // claimed is worse than clearly discarding.
    IPRADIO_DEBUG_PRINTLN("RX frame too large for caller's buffer (%d > %d), dropping", len, sz);
    _n_recv_errors++;
    return 0;
  }
  memcpy(bytes, _pending_rx, len);
  return len;
}

uint32_t IpBridgeRadio::getEstAirtimeFor(int len_bytes) {
  // Not RF airtime -- bounds how long Dispatcher waits before declaring a
  // send failed (see Dispatcher::sendPacket()/checkSend()). A TCP/TLS write
  // to a repeater on the same LAN/internet completes in well under this.
  return 500;
}

bool IpBridgeRadio::startSendRaw(const uint8_t* bytes, int len) {
  if (_state != State::CONNECTED) return false;
  sendFramed(bytes, (uint16_t)len);
  _n_sent++;
  _send_complete = true;
  return true;
}

bool IpBridgeRadio::isSendComplete() {
  return _send_complete;
}

void IpBridgeRadio::onSendFinished() {
  _send_complete = true;
}

bool IpBridgeRadio::isInRecvMode() const {
  return _send_complete;
}

void IpBridgeRadio::loop() {
  if (_ip_ping_led_on && (int32_t)(millis() - _ip_ping_led_off_at) >= 0) {
#ifdef P_LORA_TX_NEOPIXEL_LED
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
#endif
    _ip_ping_led_on = false;
  }
  if (_ip_pong_led_on && (int32_t)(millis() - _ip_pong_led_off_at) >= 0) {
#ifdef P_LORA_TX_NEOPIXEL_LED
    BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
#endif
    _ip_pong_led_on = false;
  }
  if (_disconnect_blink_active && (int32_t)(millis() - _disconnect_next_toggle_at) >= 0) {
#ifdef P_LORA_TX_NEOPIXEL_LED
    if (_disconnect_led_on) {
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
    } else {
      BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
    }
#endif
    _disconnect_led_on = !_disconnect_led_on;
    _disconnect_next_toggle_at = millis() + 500;
  }

  if (!_configured) return;

  switch (_state) {
    case State::TCP_CONNECTING:
      pollTcpConnecting();
      break;
    case State::HANDSHAKING:
      if ((int32_t)(millis() - _next_handshake_poll_at) >= 0) {
        pollHandshake();
        _next_handshake_poll_at = millis() + IP_BRIDGE_RADIO_HANDSHAKE_POLL_INTERVAL_MS;
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

void IpBridgeRadio::indicateIpPing() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_BLUE(P_LORA_TX_NEOPIXEL_LED, 40);
#endif
  _ip_ping_led_on = true;
  _ip_ping_led_off_at = millis() + 120;
}

void IpBridgeRadio::indicatePongReceived() {
#ifdef P_LORA_TX_NEOPIXEL_LED
  BOARD_LED_GREEN(P_LORA_TX_NEOPIXEL_LED, 40);
#endif
  _ip_pong_led_on = true;
  _ip_pong_led_off_at = millis() + 180;
}

void IpBridgeRadio::setLinkConnected(bool connected) {
  if (connected) {
    _disconnect_blink_active = false;
    if (_disconnect_led_on) {
#ifdef P_LORA_TX_NEOPIXEL_LED
      BOARD_LED_OFF(P_LORA_TX_NEOPIXEL_LED);
#endif
      _disconnect_led_on = false;
    }
  } else {
    _disconnect_blink_active = true;
#ifdef P_LORA_TX_NEOPIXEL_LED
    BOARD_LED_RED(P_LORA_TX_NEOPIXEL_LED, 40);
#endif
    _disconnect_led_on = true;
    _disconnect_next_toggle_at = millis() + 500;
  }
}
