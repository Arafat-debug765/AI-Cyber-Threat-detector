#!/usr/bin/env python3
"""Capture live IPv4 packets into the CSV format the detector expects.

Requires scapy and elevated privileges (packet capture needs raw sockets):

    sudo python scripts/live_capture.py --count 500 --iface en0

Only capture traffic on networks you own or are authorised to monitor.
"""
from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
          "packet_length"]
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "data" / "packets.csv"


def capture(output: Path, count: int, iface: str | None, bpf_filter: str) -> None:
    try:
        from scapy.all import IP, TCP, UDP, sniff  # imported lazily: scapy is optional
    except ImportError:
        sys.exit("scapy is not installed. Install it with: pip install scapy")

    output.parent.mkdir(parents=True, exist_ok=True)
    # Append only if the file already has the right header, otherwise start
    # fresh — the original version appended headerless rows, which silently
    # corrupted the dataset (pandas read the first packet as column names).
    write_header = _needs_header(output)

    with output.open("a" if not write_header else "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        if write_header:
            writer.writeheader()

        captured = 0

        def process(packet) -> None:
            nonlocal captured
            if IP not in packet:
                return
            # Ports are what make port scans and service sweeps visible to the
            # flow features; ICMP and other protocols simply have none.
            layer = packet.getlayer(TCP) or packet.getlayer(UDP)
            writer.writerow({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "src_port": int(layer.sport) if layer is not None else 0,
                "dst_port": int(layer.dport) if layer is not None else 0,
                "protocol": int(packet[IP].proto),
                "packet_length": len(packet),
            })
            captured += 1
            if captured % 25 == 0:
                handle.flush()
                print(f"  captured {captured} packets…", flush=True)

        print(f"Capturing to {output} (Ctrl-C to stop)")
        try:
            sniff(prn=process, store=0, count=count, iface=iface, filter=bpf_filter or None)
        except KeyboardInterrupt:
            print("\nStopped by user.")
        except PermissionError:
            sys.exit("Permission denied. Packet capture needs root: try sudo.")
        finally:
            handle.flush()
            print(f"[OK] Wrote {captured} packets to {output}")


def _needs_header(path: Path) -> bool:
    """True when the file is absent, empty, or lacks our header row."""
    if not path.exists() or path.stat().st_size == 0:
        return True
    with path.open(newline="") as handle:
        first = handle.readline().strip()
    return first.split(",") != FIELDS


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"CSV to write (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="stop after N packets (0 = run until Ctrl-C)")
    parser.add_argument("-i", "--iface", help="interface to sniff (default: scapy's default)")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default="ip",
                        help="BPF capture filter (default: 'ip')")
    args = parser.parse_args()

    capture(args.output, args.count, args.iface, args.bpf_filter)


if __name__ == "__main__":
    main()
