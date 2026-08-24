# IP Bridge

The IP bridge lets a repeater relay mesh traffic to one other MeshCore node over a
plain IP network (WiFi/LAN, or a routed link between two sites), instead of only RF. It's part of the
Trifecta branch: a single repeater can run real LoRa, an ESP-NOW bridge, and the
IP bridge all at once — each one independently enabled.

Transport is UDP with a DTLS-PSK session (real mbedTLS encryption, one pre-shared
key, exactly one peer per bridge). There's no certificate authority and no
identity verification beyond possessing the shared secret — see
[Security](#security) below.

## Requirements

- An ESP32-based board (`WITH_IP_BRIDGE` is only wired up on ESP32 variants).
- WiFi connectivity — the IP bridge rides on the same `WiFi` connection as the
  rest of the firmware; it does not open its own network interface.
- Exactly two peers per link: one acts as server, the other as client. There is
  no multi-peer fan-out on a single bridge instance.

## Building firmware with the IP bridge

Each variant that supports it exposes a dedicated PlatformIO environment, e.g.:

```bash
export FIRMWARE_VERSION=v1.0.0
sh build.sh build-firmware Heltec_v3_repeater_bridge_ip
```

- `..._repeater_bridge_ip` — real LoRa + IP bridge.
- `..._repeater_bridge_espnow_ip` — real LoRa + ESP-NOW bridge + IP bridge (Trifecta).
- `..._repeater_bridge_espnow` — real LoRa + ESP-NOW bridge only, no IP bridge.

Run `sh build.sh list` or `pio project config | grep 'env:'` to see exactly
which environments exist for a given board.

## Configuration

All configuration is done at runtime over the CLI (serial/BLE), never at build
time — there are no firmware-baked credentials.

### WiFi

```
set wifi.ssid <ssid>
set wifi.pwd <password>
```

The bridge won't come up until WiFi actually associates.

### IP bridge role and peer

```
set ip.host <hostname-or-ip>   # set on the CLIENT side only
set ip.port <port>             # set on BOTH sides
set ip.secret <shared-secret>  # must match on BOTH sides
```

Role is inferred from configuration, not chosen explicitly:

- **Server** — leave `ip.host` empty, set `ip.port`. Listens on that UDP port
  and accepts a DTLS-PSK handshake from the first peer that completes one.
- **Client** — set `ip.host` to the server's address (hostname or IP) and
  `ip.port` to match. Dials out to that host on that port.

`ip.secret` is the DTLS pre-shared key. It must be identical on both ends —
this is what authenticates the link, so treat it like a password, not a
convenience default.

### Enabling the bridge

```
set bridge.enabled on
```

This flag applies to whichever bridge type(s) are compiled into the firmware —
on a Trifecta build it starts the ESP-NOW bridge and the IP bridge together.

### Checking link status

```
get ip.status
```

Reports role, connection state, resolved IP (client side), and time since
last-heard traffic. No `BRIDGE_DEBUG` build needed for this — it's a live
status query, not debug tracing.

## Reachability

- **Server side**: the listening UDP port must be reachable from the client.
  On a home network behind NAT, that means forwarding that UDP port to the
  server repeater. On a LAN, VPN, or private radio-backhaul link between
  sites, no forwarding is needed — just route/port reachability between the
  two hosts.
- **Client side**: needs outbound UDP to the server's host:port. `ip.host`
  can be a hostname (resolved via DNS, e.g. a dynamic-DNS name) or a literal
  IP.
- If the client's DNS name changes IP, the bridge follows: it retries the
  last-known-good IP first on reconnect, and only re-resolves after a couple
  of consecutive failures.

## Link behavior

- **Best-effort, no retry** — like the ESP-NOW bridge, a packet that fails to
  send over the IP link is not retried at the bridge layer.
- **Heartbeat / dead-link detection** — the client pings periodically; either
  side treats the link as dead if nothing at all has been heard for a while
  and tears down and reconnects. This is the only way either side detects a
  dropped link, since UDP/DTLS gives no OS-level disconnect signal.
- **Reconnect** — the client retries on a short fixed delay (no exponential
  backoff). The server just goes back to listening for a new handshake.

## Security

- Real encryption: DTLS with a PSK ciphersuite (AES-128-GCM or AES-128-CBC),
  not a custom cipher.
- No certificates, no CA, no identity beyond the shared secret — anyone who
  has `ip.secret` can complete the handshake and become the peer. Treat it
  with the same care as a WiFi password.
- Exactly one peer per bridge instance, by design — this isn't a multi-client
  relay server.
- Traffic bridged in over IP still passes through the repeater's normal
  duplicate-suppression and packet handling like any other bridge source; the
  IP bridge doesn't grant it special trust beyond having a valid session.

## Relationship to the ESP-NOW bridge

The IP bridge and ESP-NOW bridge are independent and can run simultaneously on
the same repeater (Trifecta). They use separate configuration namespaces
(`ip.*` vs `bridge.channel`/`bridge.secret`) and separate CLI/debug output.
Note the ESP-NOW bridge's own secret is a simple isolation token, not real
cryptography — don't assume ESP-NOW-bridged traffic carries the same security
guarantee as IP-bridged traffic.
