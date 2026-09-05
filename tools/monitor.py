#!/usr/bin/env python3
"""
Pretty live monitor for the RSSI field-test firmware (base station or
roamer). Reads raw serial text and reformats it -- base station "status"
tables get redrawn as an aligned, color-coded block (green/yellow/red by
loss %, colored RSSI bin); roamer per-beacon lines get a compact
timestamped one-liner. Unrecognized lines (boot banners, crashes) pass
through unchanged so nothing is silently swallowed.

Usage:
  monitor.py <port> [--baud 115200] [--log FILE]
  monitor.py --list

--list shows available serial ports (device path, description, and
USB VID:PID/serial number when known) so you can tell which one to pass
as <port>, then exits without connecting to anything.

--log also writes every raw line (with a wall-clock timestamp) to FILE,
in case you want the untouched record for later analysis.
"""
import sys
import re
import time
import argparse
import serial
import serial.tools.list_ports

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
GREY = "\033[90m"

STATUS_HEADER_RE = re.compile(r"=== status @ seq=(\d+), my_tx_power=(-?\d+)dBm ===")
ROAMER_LINE_RE = re.compile(
    r"roamer (\d+): loss=([\d.]+)% \((\d+)/(\d+)\) uplink_loss=([\d.]+)% \((\d+)/(\d+) acks lost\)"
    r" last_rssi=(-?\d+)dBm \[(\w+)\]"
    r"\s+bins bad=(\d+) fair=(\d+) good=(\d+) great=(\d+)"
)
LEVEL_HEADER_RE = re.compile(r"by tx power \(down = ")
LEVEL_LINE_RE = re.compile(
    r"(-?\d+)dBm: down (\d+)/(\d+) \(([\d.]+)%\) avg_rssi=(-?[\d.]+)dBm"
    r"\s+up n=(\d+) avg_rssi=(-?[\d.]+)dBm"
    r"\s+roamer_tx (\d+)/(\d+) \(([\d.]+)%\)"
)
BEACON_LINE_RE = re.compile(
    r"beacon seq=(\d+) base_pwr=(-?\d+)dBm rssi=(-?\d+)dBm -> acked at my_pwr=(-?\d+)dBm"
)
LEARNED_MAC_RE = re.compile(r"Learned base MAC: (.+)")

# Roamer-side: its own send-confirmation stats (attempted vs driver-confirmed
# delivered, per its own tx power) -- independent of whatever the base saw.
SEND_STATS_HEADER_RE = re.compile(r"=== my send stats @ my_tx_power=(-?\d+)dBm ===")
SEND_STATS_LINE_RE = re.compile(r"(-?\d+)dBm: sent (\d+)/(\d+) confirmed \(([\d.]+)%\)")


def bin_color(name):
    return {"BAD": RED, "FAIR": YELLOW, "GOOD": CYAN, "GREAT": GREEN}.get(name, RESET)


def loss_color(pct):
    if pct >= 20:
        return RED
    if pct >= 5:
        return YELLOW
    return GREEN


def render_status_block(seq, my_tx_power, roamers):
    lines = [f"{BOLD}--- status @ seq={seq}  (my tx power: {my_tx_power}dBm) ---{RESET}"]
    if not roamers:
        lines.append(f"{GREY}  (no roamers heard yet){RESET}")
    for summary, levels in roamers:
        (rid, loss, acked, expected, uplink_loss, acks_lost, ack_span,
         rssi, binname, bad, fair, good, great) = summary
        lc = loss_color(float(loss))
        ulc = loss_color(float(uplink_loss))
        bc = bin_color(binname)
        lines.append(
            f"  roamer {BOLD}{rid}{RESET}: "
            f"loss={lc}{loss:>5}%{RESET} ({acked}/{expected})  "
            f"uplink_loss={ulc}{uplink_loss:>5}%{RESET} ({acks_lost}/{ack_span} acks lost)  "
            f"rssi={bc}{rssi:>4}dBm [{binname}]{RESET}  "
            f"bins: {RED}bad={bad}{RESET} {YELLOW}fair={fair}{RESET} "
            f"{CYAN}good={good}{RESET} {GREEN}great={great}{RESET}"
        )
        for lvl in levels:
            dbm, d_ok, d_sent, d_pct, d_rssi, u_n, u_rssi, r_ok, r_sent, r_pct = lvl
            pc = loss_color(100.0 - float(d_pct))  # color by success rate, not loss
            rc = loss_color(100.0 - float(r_pct))
            lines.append(
                f"      {dbm:>3}dBm:  "
                f"down {pc}{d_ok}/{d_sent} ({d_pct}%){RESET} avg_rssi={d_rssi}dBm   "
                f"up n={u_n} avg_rssi={u_rssi}dBm   "
                f"roamer_tx {rc}{r_ok}/{r_sent} ({r_pct}%){RESET}"
            )
    return "\n".join(lines)


def render_send_stats_block(my_tx_power, rows):
    lines = [f"{BOLD}--- my send stats  (my tx power: {my_tx_power}dBm) ---{RESET}"]
    for dbm, sent, attempted, pct in rows:
        pc = loss_color(100.0 - float(pct))  # color by confirm rate, not loss
        lines.append(f"  {dbm:>3}dBm:  sent {pc}{sent}/{attempted} confirmed ({pct}%){RESET}")
    return "\n".join(lines)


def list_ports():
    ports = sorted(serial.tools.list_ports.comports(), key=lambda p: p.device)
    if not ports:
        print("No serial ports found.")
        return
    for p in ports:
        ident = f"{p.vid:04x}:{p.pid:04x}" if p.vid is not None else "----:----"
        desc = p.description or "?"
        serial_no = f" serial={p.serial_number}" if p.serial_number else ""
        print(f"{BOLD}{p.device}{RESET}  [{ident}]  {desc}{serial_no}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", help="serial port, e.g. /dev/cu.usbmodem101")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log")
    ap.add_argument("--list", action="store_true", help="list available serial ports and exit")
    args = ap.parse_args()

    if args.list:
        list_ports()
        return

    if not args.port:
        ap.error("port is required unless --list is given")

    logf = open(args.log, "a") if args.log else None

    ser = serial.Serial(args.port, args.baud, timeout=0.5)
    print(f"{DIM}Connected to {args.port} @ {args.baud}. Ctrl+C to quit.{RESET}\n")

    buf = ""
    pending_status = None  # (seq, my_tx_power, [ (summary, [levels]) ]) while collecting
    current_roamer = None  # the (summary, [levels]) entry level-rows attach to
    pending_send_stats = None  # (my_tx_power, [rows]) while collecting a roamer's own stats

    try:
        while True:
            chunk = ser.read(2000)
            if not chunk:
                continue
            buf += chunk.decode(errors="replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.rstrip("\r")
                if not line:
                    continue

                if logf:
                    logf.write(f"[{time.strftime('%H:%M:%S')}] {line}\n")
                    logf.flush()

                m = STATUS_HEADER_RE.search(line)
                if m:
                    if pending_status is not None:
                        print(render_status_block(*pending_status))
                        print()
                    pending_status = (m.group(1), m.group(2), [])
                    current_roamer = None
                    continue

                m = ROAMER_LINE_RE.search(line)
                if m and pending_status is not None:
                    current_roamer = (m.groups(), [])
                    pending_status[2].append(current_roamer)
                    continue

                if LEVEL_HEADER_RE.search(line):
                    continue  # explanatory line, redundant with the box itself

                m = LEVEL_LINE_RE.search(line)
                if m and current_roamer is not None:
                    current_roamer[1].append(m.groups())
                    continue

                m = BEACON_LINE_RE.search(line)
                if m:
                    seq, base_pwr, rssi, my_pwr = m.groups()
                    ts = time.strftime("%H:%M:%S")
                    print(f"{GREY}[{ts}]{RESET} seq={seq} base_pwr={base_pwr}dBm "
                          f"rssi={CYAN}{rssi}dBm{RESET} -> acked at my_pwr={my_pwr}dBm")
                    continue

                m = LEARNED_MAC_RE.search(line)
                if m:
                    print(f"{BOLD}{GREEN}Base learned: {m.group(1)}{RESET}")
                    continue

                m = SEND_STATS_HEADER_RE.search(line)
                if m:
                    if pending_send_stats is not None:
                        print(render_send_stats_block(*pending_send_stats))
                        print()
                    pending_send_stats = (m.group(1), [])
                    continue

                m = SEND_STATS_LINE_RE.search(line)
                if m and pending_send_stats is not None:
                    pending_send_stats[1].append(m.groups())
                    continue

                # Anything else (boot banner, role/channel line, fatal errors) --
                # print through unchanged rather than hide it.
                print(line)

    except KeyboardInterrupt:
        pass
    finally:
        if pending_status is not None:
            print(render_status_block(*pending_status))
        if pending_send_stats is not None:
            print(render_send_stats_block(*pending_send_stats))
        if logf:
            logf.close()
        ser.close()


if __name__ == "__main__":
    main()
