#!/usr/bin/env python3
"""
Auto-connects to every MeshCore-looking serial port and streams their debug
output live, each board's lines prefixed and color-coded so multiple boards
can be watched at once in one terminal -- a cheap Wireshark-ish view built
entirely on top of the existing BRIDGE_DEBUG/MESH_DEBUG serial prints, no
firmware changes needed.

Usage:
  watch_boards.py            # auto-detect and watch all matching ports
  watch_boards.py --all      # also include ports that don't look like
                              # ESP32 boards (e.g. unknown USB-serial adapters)
  watch_boards.py --rescan 5 # how often (seconds) to look for newly
                              # plugged-in/reset boards (default 3)

Ctrl+C to quit. New boards plugged in mid-run are picked up automatically;
boards that disconnect (reset, unplug, port grabbed by something else) are
dropped and reported, without killing the other streams.

Companion_radio boards (no text CLI reply -- they speak a binary framed
protocol on serial instead, see tools/send_companion_msg.py) are detected
and skipped rather than connected to.

While running: press 'n' to send 'neighbors.all' to every connected
repeater at once (each reply streams in through its own line as usual,
just like typing the command by hand on each board one at a time), or 'q'
to quit (same as Ctrl+C).

Each board's [label] keeps its own fixed color so you can tell streams
apart; message text is separately colored by what kind of event it is --
bright magenta for traffic-engineering decisions (trySendViaBridge/
tryRelayViaBridge redirects, the IP-bridge PATH delay queue), yellow for
real RF transmit/receive, dim for bridge-only chatter that never touches
the radio.

Advert node names/coordinates are decoded and shown inline next to a real
RF-received advert's summary line -- adverts aren't encrypted (only
signed), so this needs no keys. Other traffic (chat, channel posts, etc.)
is genuinely encrypted and not decoded.
"""
import re
import sys
import time
import threading
import argparse
import select
import termios
import tty

import serial
import serial.tools.list_ports

# Payload types, from src/Packet.h -- used to annotate "type=N" occurrences
# in simple_repeater's text CLI debug lines with a readable name.
PAYLOAD_TYPE_NAMES = {
    0x00: "REQ", 0x01: "RESPONSE", 0x02: "TXT_MSG", 0x03: "ACK",
    0x04: "ADVERT", 0x05: "GRP_TXT", 0x06: "GRP_DATA", 0x07: "ANON_REQ",
    0x08: "PATH", 0x09: "TRACE", 0x0A: "MULTIPART", 0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}
TYPE_RE = re.compile(r"type=(\d+)")

# Advert payloads aren't encrypted (only signed), so node name/coords are
# plain bytes on the wire -- decodable without any keys. Mirrors
# src/helpers/AdvertDataHelpers.cpp's AdvertDataParser format exactly.
ADV_TYPE_NAMES = {0: "NONE", 1: "CHAT", 2: "REPEATER", 3: "ROOM", 4: "SENSOR"}
ADV_LATLON_MASK, ADV_FEAT1_MASK, ADV_FEAT2_MASK, ADV_NAME_MASK = 0x10, 0x20, 0x40, 0x80
PUB_KEY_SIZE, SIGNATURE_SIZE = 32, 64  # src/MeshCore.h
RAW_LINE_RE = re.compile(r"RAW: ([0-9A-Fa-f]+)")
PAYLOAD_LEN_RE = re.compile(r"payload_len=(\d+)")


def decode_advert(app_data):
    """Returns a short human-readable string for an advert's app_data bytes
    (the part after pubkey+timestamp+signature), or None if it doesn't
    parse as a valid/known advert shape."""
    if not app_data:
        return None
    flags = app_data[0]
    i = 1
    lat = lon = None
    if flags & ADV_LATLON_MASK:
        if len(app_data) < i + 8:
            return None
        lat = int.from_bytes(app_data[i:i + 4], "little", signed=True)
        lon = int.from_bytes(app_data[i + 4:i + 8], "little", signed=True)
        i += 8
    if flags & ADV_FEAT1_MASK:
        i += 2
    if flags & ADV_FEAT2_MASK:
        i += 2
    name = None
    if flags & ADV_NAME_MASK and len(app_data) > i:
        name = app_data[i:].decode("utf-8", errors="replace")
    parts = [f"advert type={ADV_TYPE_NAMES.get(flags & 0x0F, flags & 0x0F)}"]
    if name:
        parts.append(f"name={name!r}")
    if lat is not None:
        parts.append(f"lat={lat / 1e6:.5f} lon={lon / 1e6:.5f}")
    return " ".join(parts)


def extract_advert_from_raw(raw_hex, payload_len):
    """raw_hex is the full on-air packet (header+path+payload) captured by
    logRxRaw()'s 'RAW:' line; payload is always its tail, so no need to
    parse header/path fields to find the offset. Returns decode_advert()'s
    result, or None."""
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if len(raw) < payload_len or payload_len < PUB_KEY_SIZE + SIGNATURE_SIZE + 4:
        return None
    payload = raw[-payload_len:]
    app_data = payload[PUB_KEY_SIZE + 4 + SIGNATURE_SIZE:]  # pubkey, timestamp(4), signature
    return decode_advert(app_data)

# Semantic coloring for the message content itself -- separate from each
# board's own [label] color (which just tracks *which* board), this tracks
# *what kind* of event the line represents, checked in this priority order:
#   1. The IP-bridge PATH delay queue holding/releasing a packet to prefer
#      a real RF path -- the specific traffic-engineering decision this
#      tool exists to make visible, so it gets the loudest treatment
#      (colored background, not just text color) and its own two colors:
#      red = held back, green = released. Checked first, wins over
#      everything else.
#   2. Other bridge-redirect decisions (trySendViaBridge, tryRelayViaBridge).
#   3. Real RF transmit/receive -- lines from the plain (non-"BRIDGE:")
#      Dispatcher TX/RX logging, i.e. actual airtime.
#   4. Bridge-only traffic -- ESPNOW/IP bridge chatter (heartbeats, bridge
#      RX/TX, connection status) that never touches the radio.
# Anything else (CLI replies, boot messages, etc.) is left uncolored.
CAT_HOLD = "\033[1;97;41m"     # bold white on red -- packet held back
CAT_RELEASE = "\033[1;30;102m"  # bold black on bright green -- packet released
CAT_DECISION = "\033[1;95m"    # bold bright magenta
CAT_RF = "\033[1;33m"          # bold yellow
CAT_BRIDGE = "\033[2;37m"      # dim white
CAT_RESET = "\033[0m"

DECISION_MARKERS = ("trySendViaBridge:", "tryRelayViaBridge:")


def categorize_color(text):
    if "queueDelayedIpSend: holding" in text:
        return CAT_HOLD
    if "flushPendingIpSends: releasing" in text:
        return CAT_RELEASE
    if any(m in text for m in DECISION_MARKERS):
        return CAT_DECISION
    if "BRIDGE:" not in text and (": TX," in text or ": RX," in text or "RSSI=" in text):
        return CAT_RF
    if "BRIDGE:" in text:
        return CAT_BRIDGE
    return None


def annotate_types(text):
    """Appends a readable payload-type name next to any 'type=N' found in a
    text CLI debug line, e.g. 'type=2' -> 'type=2(TXT_MSG)'. Leaves the line
    unchanged if no type=N is present, or the code isn't a known payload type."""
    def repl(m):
        code = int(m.group(1))
        name = PAYLOAD_TYPE_NAMES.get(code)
        return f"type={code}({name})" if name else m.group(0)
    return TYPE_RE.sub(repl, text)


# 'neighbors'/'neighbors.all' reply entries -- see formatAllNeighborsReply()/
# formatNeighborsReply() in examples/simple_repeater/MyMesh.cpp -- come back
# as terse colon-separated fields (hash:age_secs:snr:via). Reformatted here
# into an aligned, labeled row whenever this exact shape is seen, regardless
# of whether it was triggered by the 'n' hotkey or typed by hand.
NEIGHBOR_ENTRY_RE = re.compile(r"^([0-9A-Fa-f]{8}):(-?\d+):(-?\d+):(RF|IP|ESPNOW|RS232|\?)$")
COMMAND_ECHO_TEXTS = {"neighbors.all", "neighbors"}


def prettify_or_none(text):
    """Returns a reformatted line for a recognized shape (currently just
    neighbor entries), or None if this line isn't one -- caller falls back
    to printing the original text unchanged."""
    stripped = text.strip()
    if stripped.startswith("->"):
        stripped = stripped[2:].strip()
    m = NEIGHBOR_ENTRY_RE.match(stripped)
    if m:
        pubkey_hash, age, snr, via = m.groups()
        return f"    {pubkey_hash}  age={age:>5}s  snr={snr:>4}  via={via}"
    return None


def is_command_echo(text):
    return text.strip() in COMMAND_ECHO_TEXTS

# ESP32-S3 native USB JTAG/serial (Xiao S3 WIO, ESP32-S3-Zero, etc.) and the
# CP210x/CH340 USB-UART bridges typical Heltec/other boards use. Not
# exhaustive -- pass --all to watch every serial port instead of filtering.
KNOWN_BOARD_VIDPIDS = {
    (0x303A, 0x1001),  # Espressif USB JTAG/serial (native USB CDC)
    (0x10C4, 0xEA60),  # Silicon Labs CP210x
    (0x1A86, 0x7523),  # QinHeng CH340
    (0x1A86, 0x55D4),  # QinHeng CH9102 (newer CH34x variant)
}

COLORS = ["\033[36m", "\033[32m", "\033[35m", "\033[33m", "\033[34m", "\033[31m", "\033[96m", "\033[92m"]
RESET = "\033[0m"

print_lock = threading.Lock()
watched = {}  # port device -> thread
active_serials = {}  # port device -> open Serial handle, for text-CLI boards only, used by the 'n' hotkey
skipped_ports = set()  # ports identified as companion boards -- don't retry every rescan
stop_flag = threading.Event()


def looks_like_board(port, include_all):
    if include_all:
        return True
    return (port.vid, port.pid) in KNOWN_BOARD_VIDPIDS


def probe_name(ser):
    """Best-effort 'get name' query to label the stream with something more
    useful than a port path -- transient, not stored anywhere (port paths
    get reused across boards, so labeling by name each run is the correct
    approach, not caching it)."""
    try:
        ser.reset_input_buffer()
        ser.write(b"get name\r\n")
        deadline = time.time() + 1.5
        buf = b""
        while time.time() < deadline:
            chunk = ser.read(ser.in_waiting or 1)
            if chunk:
                buf += chunk
                # Don't stop at the first newline -- unrelated debug chatter
                # (e.g. a heartbeat pong log line) can interleave and arrive
                # before the actual reply, so keep reading until we've
                # actually seen the reply line or run out of time.
                if b"->" in buf and b"\n" in buf.split(b"->", 1)[1]:
                    break
        text = buf.decode(errors="replace")
        for line in text.splitlines():
            if "->" in line:
                return line.split("->", 1)[1].strip(" >")
    except Exception:
        pass
    return None


def watch_port(port_device, color):
    label = port_device.rsplit("/", 1)[-1]
    try:
        ser = serial.Serial(port_device, 115200, timeout=0.5)
    except Exception as e:
        with print_lock:
            print(f"{color}[{label}]{RESET} could not open: {e}")
        return

    time.sleep(0.3)
    name = probe_name(ser)
    if name is None:
        # No text-CLI reply -> most likely a companion_radio board, which
        # speaks a binary framed protocol on serial instead (see
        # tools/send_companion_msg.py) -- not what this tool is for, and
        # decoding it fights over the port with anything actually using
        # that board (phone app, send_companion_msg.py). Skip it.
        with print_lock:
            print(f"{color}[{label}]{RESET} looks like a companion board (no text CLI reply) -- skipping")
        ser.close()
        skipped_ports.add(port_device)
        watched.pop(port_device, None)
        return

    label = f"{label}/{name}"
    active_serials[port_device] = ser
    with print_lock:
        print(f"{color}[{label}]{RESET} connected")

    buf = b""
    consecutive_errors = 0
    last_raw_hex = None  # most recent 'RAW:' hex dump, paired with the RX summary line right after it
    try:
        while not stop_flag.is_set():
            try:
                chunk = ser.read(ser.in_waiting or 1)
            except (serial.SerialException, OSError):
                # pyserial/macOS occasionally throws a spurious "readiness
                # to read but returned no data" on a healthy port -- only
                # treat it as a real disconnect after it happens repeatedly.
                consecutive_errors += 1
                if consecutive_errors > 5:
                    raise
                time.sleep(0.1)
                continue
            consecutive_errors = 0
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode(errors="replace").rstrip("\r")
                if not text or is_command_echo(text):
                    continue
                pretty = prettify_or_none(text)
                if pretty is not None:
                    with print_lock:
                        print(f"{color}[{label}]{RESET} {pretty}")
                    continue

                raw_m = RAW_LINE_RE.search(text)
                if raw_m:
                    last_raw_hex = raw_m.group(1)

                text = annotate_types(text)
                advert_note = ""
                if "type=4(ADVERT)" in text and last_raw_hex:
                    len_m = PAYLOAD_LEN_RE.search(text)
                    if len_m:
                        decoded = extract_advert_from_raw(last_raw_hex, int(len_m.group(1)))
                        if decoded:
                            advert_note = f"  \033[1m[{decoded}]{RESET}"
                    last_raw_hex = None  # consumed -- don't reuse for a later, unrelated advert

                cat_color = categorize_color(text)
                body = f"{cat_color}{text}{CAT_RESET}" if cat_color else text
                with print_lock:
                    print(f"{color}[{label}]{RESET} {body}{advert_note}")
    except (serial.SerialException, OSError) as e:
        with print_lock:
            print(f"{color}[{label}]{RESET} disconnected: {e}")
    finally:
        try:
            ser.close()
        except Exception:
            pass
        watched.pop(port_device, None)
        active_serials.pop(port_device, None)


def dump_neighbors_all():
    boards = list(active_serials.items())
    with print_lock:
        print(f"\n\033[1m== neighbors.all -- {len(boards)} board(s) =={RESET}")
    for port_device, ser in boards:
        try:
            ser.write(b"neighbors.all\r\n")
        except Exception as e:
            with print_lock:
                print(f"  {port_device}: failed to send -- {e}")


def keypress_listener():
    """Reads single keypresses without needing Enter -- 'n' triggers
    dump_neighbors_all(), 'q' stops the same way Ctrl+C does. cbreak mode
    (not raw) keeps Ctrl+C's normal signal behavior working."""
    if not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop_flag.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.2)
            if r:
                ch = sys.stdin.read(1)
                if ch == "n":
                    dump_neighbors_all()
                elif ch == "q":
                    stop_flag.set()
                elif ch in ("\r", "\n"):
                    with print_lock:
                        print()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="watch every serial port, not just recognized board VID:PIDs")
    ap.add_argument("--rescan", type=float, default=3.0, help="seconds between rescans for new/removed boards (default 3)")
    args = ap.parse_args()

    print("watch_boards.py -- 'n' = dump neighbors.all from all boards, Enter = blank line, 'q'/Ctrl+C to quit\n")
    threading.Thread(target=keypress_listener, daemon=True).start()

    color_idx = 0
    try:
        while not stop_flag.is_set():
            ports = serial.tools.list_ports.comports()
            for port in ports:
                if port.device in watched or port.device in skipped_ports:
                    continue
                if not looks_like_board(port, args.all):
                    continue
                color = COLORS[color_idx % len(COLORS)]
                color_idx += 1
                t = threading.Thread(target=watch_port, args=(port.device, color), daemon=True)
                watched[port.device] = t
                t.start()
            time.sleep(args.rescan)
    except KeyboardInterrupt:
        stop_flag.set()
        with print_lock:
            print("\nstopping...")
        time.sleep(0.6)


if __name__ == "__main__":
    main()
