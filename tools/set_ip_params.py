#!/usr/bin/env python3
"""
Set/get the WiFi STA credentials and IpBridge host/port/secret on a MeshCore
companion running the IpBridgeRadio build (CMD_SET_WIFI_PARAMS=68/
CMD_GET_WIFI_PARAMS=69, CMD_SET_IP_PARAMS=70/CMD_GET_IP_PARAMS=71), speaking
the raw companion-protocol USB framing directly since no official client has
UI for these commands yet -- same approach as set_bridge_params.py.

ip.secret must match a credential registered on the target repeater's own
IpBridge server via 'ip.peer.add <this device's identity> <secret>' (get this
device's identity with 'wifi get' below, or CMD_DEVICE_QUERY/app self-info) --
see planning/room-server-archive-catchup.md and IpBridge.h's own doc comment
for the per-identity credential model.

Usage:
  set_ip_params.py list                                                 list available serial ports
  set_ip_params.py <port> wifi get                                       read current wifi.ssid (password never echoed back? -- it is, see below)
  set_ip_params.py <port> wifi set <ssid> <password>                     set WiFi STA credentials
  set_ip_params.py <port> ip get                                         read current ip.host/ip.port/ip.secret
  set_ip_params.py <port> ip set <host> <port> <secret>                  set IpBridge target + secret
  set_ip_params.py <port> status                                        read live IpBridgeRadio connection state
"""
import sys, time, serial
import serial.tools.list_ports

CMD_APP_START = 1
CMD_SET_WIFI_PARAMS = 68
CMD_GET_WIFI_PARAMS = 69
CMD_SET_IP_PARAMS = 70
CMD_GET_IP_PARAMS = 71
CMD_GET_IP_STATUS = 72
RESP_CODE_OK = 0
RESP_CODE_ERR = 1
RESP_CODE_SELF_INFO = 5
RESP_CODE_WIFI_PARAMS = 30
RESP_CODE_IP_PARAMS = 31
RESP_CODE_IP_STATUS = 32

WIFI_SSID_LEN = 33
WIFI_PWD_LEN = 64
IP_HOST_LEN = 64
IP_SECRET_LEN = 32

def list_ports():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports found.")
        return
    print("Available serial ports:")
    for p in ports:
        desc = p.description if p.description and p.description != "n/a" else ""
        print(f"  {p.device:30s} {desc}")

def send_frame(ser, payload: bytes):
    hdr = bytes([ord('<'), len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    ser.write(hdr + payload)

def read_frame(ser, timeout=2.0):
    end = time.time() + timeout
    state = 0
    frame_len = 0
    buf = b""
    while time.time() < end:
        b = ser.read(1)
        if not b:
            continue
        c = b[0]
        if state == 0:
            if c == ord('>'):
                state = 1
        elif state == 1:
            frame_len = c
            state = 2
        elif state == 2:
            frame_len |= c << 8
            buf = b""
            state = 3 if frame_len > 0 else 0
        elif state == 3:
            buf += bytes([c])
            if len(buf) >= frame_len:
                return buf
    return None

def open_port(port):
    try:
        ser = serial.Serial(port, 115200, timeout=1)
    except serial.SerialException as e:
        print(f"Couldn't open {port}: {e}")
        print("Run 'set_ip_params.py list' to see available ports (it may be held")
        print("open by another program -- e.g. a browser tab, or another CLI session).")
        sys.exit(1)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.3)
    return ser

def handshake(ser):
    send_frame(ser, bytes([CMD_APP_START]) + bytes(7) + b"set_ip_params")
    resp = read_frame(ser)
    if not resp:
        print("No response to APP_START -- is this a companion_radio build with")
        print("IP_BRIDGE_RADIO (the esp32_s3_zero_ip companion envs)? A repeater/")
        print("room_server build won't speak this binary protocol at all.")
        sys.exit(1)
    if resp[0] != RESP_CODE_SELF_INFO:
        print(f"Warning: unexpected response to APP_START (code {resp[0]}), continuing anyway")

def padded(s: str, n: int) -> bytes:
    b = s.encode()[:n - 1]
    return b + b"\x00" * (n - len(b))

def unpad(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode(errors="replace")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    if sys.argv[1] == "list":
        list_ports()
        return

    if len(sys.argv) == 3 and sys.argv[2] == "status":
        port = sys.argv[1]
        ser = open_port(port)
        handshake(ser)
        send_frame(ser, bytes([CMD_GET_IP_STATUS]))
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_IP_STATUS:
            print(resp[1:].decode(errors="replace"))
        else:
            print("Unexpected response:", resp)
        ser.close()
        return

    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    port = sys.argv[1]
    group = sys.argv[2]   # "wifi" or "ip"
    action = sys.argv[3]

    if group not in ("wifi", "ip") or action not in ("get", "set"):
        print(__doc__)
        sys.exit(1)

    if group == "wifi" and action == "set" and len(sys.argv) < 6:
        print(__doc__)
        sys.exit(1)
    if group == "ip" and action == "set" and len(sys.argv) < 7:
        print(__doc__)
        sys.exit(1)

    ser = open_port(port)
    handshake(ser)

    if group == "wifi" and action == "get":
        send_frame(ser, bytes([CMD_GET_WIFI_PARAMS]))
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_WIFI_PARAMS:
            ssid = unpad(resp[1:1 + WIFI_SSID_LEN])
            pwd = unpad(resp[1 + WIFI_SSID_LEN:1 + WIFI_SSID_LEN + WIFI_PWD_LEN])
            if not ssid:
                print("Not configured yet (ssid empty).")
            else:
                print(f"ssid={ssid!r} password={pwd!r}")
        else:
            print("Unexpected response:", resp)

    elif group == "wifi" and action == "set":
        ssid, pwd = sys.argv[4], sys.argv[5]
        payload = bytes([CMD_SET_WIFI_PARAMS]) + padded(ssid, WIFI_SSID_LEN) + padded(pwd, WIFI_PWD_LEN)
        send_frame(ser, payload)
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_OK:
            print(f"OK: ssid={ssid!r}")
            print("Reboot needed for WiFi STA to actually come up with this.")
        elif resp and resp[0] == RESP_CODE_ERR:
            print("ERR:", resp[1] if len(resp) > 1 else "(no error code)")
        else:
            print("Unexpected response:", resp)

    elif group == "ip" and action == "get":
        send_frame(ser, bytes([CMD_GET_IP_PARAMS]))
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_IP_PARAMS:
            host = unpad(resp[1:1 + IP_HOST_LEN])
            port_val = resp[1 + IP_HOST_LEN] | (resp[1 + IP_HOST_LEN + 1] << 8)
            secret = unpad(resp[1 + IP_HOST_LEN + 2:1 + IP_HOST_LEN + 2 + IP_SECRET_LEN])
            if not host:
                print("Not configured yet (host empty) -- radio is inert.")
            else:
                print(f"host={host!r} port={port_val} secret={secret!r}")
        else:
            print("Unexpected response:", resp)

    elif group == "ip" and action == "set":
        host, port_val, secret = sys.argv[4], sys.argv[5], sys.argv[6]
        try:
            port_int = int(port_val)
        except ValueError:
            print(f"Port must be a number, got {port_val!r}")
            sys.exit(1)
        payload = (bytes([CMD_SET_IP_PARAMS]) + padded(host, IP_HOST_LEN) +
                   bytes([port_int & 0xFF, (port_int >> 8) & 0xFF]) + padded(secret, IP_SECRET_LEN))
        send_frame(ser, payload)
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_OK:
            print(f"OK: host={host!r} port={port_int} secret={secret!r}")
            print("Applied immediately -- no reboot needed.")
        elif resp and resp[0] == RESP_CODE_ERR:
            print("ERR:", resp[1] if len(resp) > 1 else "(no error code)")
        else:
            print("Unexpected response:", resp)

    ser.close()

if __name__ == "__main__":
    main()
