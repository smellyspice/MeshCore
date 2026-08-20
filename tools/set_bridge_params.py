#!/usr/bin/env python3
"""
Set/get the ESP-NOW bridge channel + secret on a MeshCore companion running the
ESPNowBridgeRadio build (CMD_SET_BRIDGE_PARAMS=66 / CMD_GET_BRIDGE_PARAMS=67),
speaking the raw companion-protocol USB framing directly since no official
client has UI for these new commands yet.

Both values must match the target repeater's own 'bridge.channel'/'bridge.secret'
(set via its CLI) for the companion to actually join its ESP-NOW bridge -- see
planning/ip-bridge-design.md for the wider design this is part of.

Usage:
  set_bridge_params.py list                                   list available serial ports
  set_bridge_params.py <port> get                              read current channel/secret
  set_bridge_params.py <port> set <channel 1-14> <secret>       secret: max 15 chars
"""
import sys, time, serial
import serial.tools.list_ports

CMD_APP_START = 1
CMD_SET_BRIDGE_PARAMS = 66
CMD_GET_BRIDGE_PARAMS = 67
RESP_CODE_OK = 0
RESP_CODE_ERR = 1
RESP_CODE_SELF_INFO = 5
RESP_CODE_BRIDGE_PARAMS = 29

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
        print("Run 'set_bridge_params.py list' to see available ports (it may be held")
        print("open by another program -- e.g. a browser tab, or another CLI session).")
        sys.exit(1)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.3)
    return ser

def handshake(ser):
    send_frame(ser, bytes([CMD_APP_START]) + bytes(7) + b"set_bridge_params")
    resp = read_frame(ser)
    if not resp:
        print("No response to APP_START -- is this a companion_radio build with")
        print("ESPNOW_BRIDGE_RADIO (the esp32_s3_zero companion envs)? A repeater/")
        print("room_server build won't speak this binary protocol at all.")
        sys.exit(1)
    if resp[0] != RESP_CODE_SELF_INFO:
        print(f"Warning: unexpected response to APP_START (code {resp[0]}), continuing anyway")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) >= 2 else 1)

    if sys.argv[1] == "list":
        list_ports()
        return

    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    port = sys.argv[1]
    action = sys.argv[2]

    if action == "set" and len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    if action == "set":
        try:
            channel = int(sys.argv[3])
        except ValueError:
            print(f"Channel must be a number 1-14, got {sys.argv[3]!r}")
            sys.exit(1)
        if not (1 <= channel <= 14):
            print(f"Channel must be 1-14, got {channel}")
            sys.exit(1)
        secret_arg = sys.argv[4]
        if len(secret_arg) > 15:
            print(f"Secret truncated to 15 chars (was {len(secret_arg)}): {secret_arg[:15]!r}")

    ser = open_port(port)
    handshake(ser)

    if action == "get":
        send_frame(ser, bytes([CMD_GET_BRIDGE_PARAMS]))
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_BRIDGE_PARAMS:
            channel = resp[1]
            secret = resp[2:18].split(b"\x00")[0].decode(errors="replace")
            if channel == 0 and not secret:
                print("Not configured yet (channel=0, secret empty) -- radio is inert.")
            else:
                print(f"channel={channel} secret={secret!r}")
        else:
            print("Unexpected response:", resp)

    elif action == "set":
        secret = secret_arg.encode()[:15]
        secret_padded = secret + b"\x00" * (16 - len(secret))
        send_frame(ser, bytes([CMD_SET_BRIDGE_PARAMS, channel]) + secret_padded)
        resp = read_frame(ser)
        if resp and resp[0] == RESP_CODE_OK:
            print(f"OK: channel={channel} secret={secret_arg[:15]!r}")
            print("Applied immediately -- no reboot needed.")
        elif resp and resp[0] == RESP_CODE_ERR:
            print("ERR:", resp[1] if len(resp) > 1 else "(no error code)")
        else:
            print("Unexpected response:", resp)
    else:
        print(f"Unknown action {action!r}\n")
        print(__doc__)
        sys.exit(1)

    ser.close()

if __name__ == "__main__":
    main()
