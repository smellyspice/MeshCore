#!/usr/bin/env python3
"""
Send a plain text message to an existing contact on a companion_radio board,
over the raw companion-protocol USB framing (CMD_GET_CONTACTS=4 to find the
contact by name, CMD_SEND_TXT_MSG=2 to send) -- for testing end-to-end
delivery through the bridge chain without needing the phone app.

Usage:
  send_companion_msg.py <port> list
  send_companion_msg.py <port> send "<contact name substring>" "<message text>"
"""
import sys, time, struct, serial

CMD_APP_START = 1
CMD_SEND_TXT_MSG = 2
CMD_GET_CONTACTS = 4
RESP_CODE_OK = 0
RESP_CODE_ERR = 1
RESP_CODE_CONTACTS_START = 2
RESP_CODE_CONTACT = 3
RESP_CODE_END_OF_CONTACTS = 4
RESP_CODE_SELF_INFO = 5
RESP_CODE_SENT = 6

PUB_KEY_SIZE = 32
MAX_PATH_SIZE = 64
TXT_TYPE_PLAIN = 0

def send_frame(ser, payload: bytes):
    hdr = bytes([ord('<'), len(payload) & 0xFF, (len(payload) >> 8) & 0xFF])
    ser.write(hdr + payload)

def read_frame(ser, timeout=3.0):
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
        sys.exit(1)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.3)
    return ser

def handshake(ser):
    send_frame(ser, bytes([CMD_APP_START]) + bytes(7) + b"send_companion_msg")
    resp = read_frame(ser)
    if not resp or resp[0] != RESP_CODE_SELF_INFO:
        print("Warning: unexpected/no response to APP_START:", resp)

def parse_contact(frame):
    # frame[0] == RESP_CODE_CONTACT already stripped by caller
    i = 0
    pub_key = frame[i:i+PUB_KEY_SIZE]; i += PUB_KEY_SIZE
    ctype = frame[i]; i += 1
    flags = frame[i]; i += 1
    out_path_len = frame[i]; i += 1
    out_path = frame[i:i+MAX_PATH_SIZE]; i += MAX_PATH_SIZE
    name = frame[i:i+32].split(b"\x00")[0].decode(errors="replace"); i += 32
    last_advert_ts = struct.unpack("<I", frame[i:i+4])[0]; i += 4
    return {"pub_key": pub_key, "type": ctype, "name": name, "last_advert_ts": last_advert_ts}

def get_contacts(ser, timeout_total=15.0):
    send_frame(ser, bytes([CMD_GET_CONTACTS]))
    resp = read_frame(ser)
    if not resp or resp[0] != RESP_CODE_CONTACTS_START:
        print("Unexpected response to CMD_GET_CONTACTS:", resp)
        return []
    count = struct.unpack("<I", resp[1:5])[0]
    contacts = []
    end = time.time() + timeout_total
    # Always read until RESP_CODE_END_OF_CONTACTS explicitly arrives, not just
    # until `count` contacts are seen -- otherwise that trailing frame is left
    # sitting in the serial buffer and gets misread as the reply to whatever
    # command is sent next.
    while time.time() < end:
        f = read_frame(ser, timeout=3.0)
        if f is None:
            break
        if f[0] == RESP_CODE_CONTACT:
            contacts.append(parse_contact(f[1:]))
        elif f[0] == RESP_CODE_END_OF_CONTACTS:
            break
    return contacts

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    port = sys.argv[1]
    action = sys.argv[2]

    ser = open_port(port)
    handshake(ser)

    contacts = get_contacts(ser)

    if action == "list":
        print(f"{len(contacts)} contact(s):")
        for c in contacts:
            print(f"  {c['name']!r:20s} type={c['type']} pubkey6={c['pub_key'][:6].hex()}")
        return

    if action == "send":
        if len(sys.argv) < 5:
            print(__doc__)
            sys.exit(1)
        name_filter = sys.argv[3].lower()
        text = sys.argv[4]

        matches = [c for c in contacts if name_filter in c["name"].lower()]
        if not matches:
            print(f"No contact matching {sys.argv[3]!r} found. Known contacts:")
            for c in contacts:
                print(f"  {c['name']!r}")
            sys.exit(1)
        if len(matches) > 1:
            print(f"Multiple contacts match {sys.argv[3]!r}, be more specific:")
            for c in matches:
                print(f"  {c['name']!r}")
            sys.exit(1)

        target = matches[0]
        print(f"Sending to {target['name']!r} (pubkey6={target['pub_key'][:6].hex()})")

        msg_timestamp = int(time.time())
        pub_key_prefix = target["pub_key"][:6]
        payload = bytes([CMD_SEND_TXT_MSG, TXT_TYPE_PLAIN, 0]) + struct.pack("<I", msg_timestamp) + pub_key_prefix + text.encode()
        send_frame(ser, payload)
        resp = read_frame(ser, timeout=5.0)
        if resp and resp[0] == RESP_CODE_SENT:
            is_flood = resp[1]
            expected_ack = struct.unpack("<I", resp[2:6])[0]
            est_timeout = struct.unpack("<I", resp[6:10])[0]
            print(f"Sent OK: flood={bool(is_flood)} expected_ack={expected_ack:#010x} est_timeout={est_timeout}ms")
        elif resp and resp[0] == RESP_CODE_ERR:
            print("ERR:", resp[1] if len(resp) > 1 else "(no code)")
        else:
            print("Unexpected response:", resp)
        return

    print(__doc__)
    sys.exit(1)

if __name__ == "__main__":
    main()
