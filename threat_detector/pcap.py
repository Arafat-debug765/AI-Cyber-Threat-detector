"""Convert a packet capture into the CSV this tool analyses.

Users have `.pcap` files, not CSVs. Without this the only ways in were a live
capture needing root or the synthetic generator, which made the tool
impossible to point at real evidence.
"""
from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_length"]


class PcapError(RuntimeError):
    """Raised when a capture cannot be read or contains nothing usable."""


def convert(source: Path, output: Path, limit: int | None = None) -> dict:
    """Read `source` and write the packet CSV to `output`.

    Packets are streamed rather than loaded as a list: a capture big enough to
    be interesting does not fit comfortably in memory, and `rdpcap` reads the
    whole file before returning.
    """
    source, output = Path(source), Path(output)
    if not source.exists():
        raise PcapError(f"Capture not found: {source.name}")

    try:
        from scapy.all import IP, TCP, UDP, PcapReader
    except ImportError as exc:
        raise PcapError(
            "Reading captures needs scapy. Install it with: pip install 'ai-threat-detector[capture]'"
        ) from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    written = skipped = 0

    try:
        with PcapReader(str(source)) as packets, output.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()

            for packet in packets:
                if limit is not None and written >= limit:
                    break
                if IP not in packet:
                    skipped += 1  # IPv6, ARP, loopback control traffic
                    continue

                layer = packet.getlayer(TCP) or packet.getlayer(UDP)
                stamp = getattr(packet, "time", None)
                writer.writerow({
                    "timestamp": _iso(stamp),
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "src_port": int(layer.sport) if layer is not None else 0,
                    "dst_port": int(layer.dport) if layer is not None else 0,
                    "protocol": int(packet[IP].proto),
                    "packet_length": len(packet),
                })
                written += 1
    except PcapError:
        raise
    except Exception as exc:  # scapy raises a variety of things on a bad file
        raise PcapError(f"Could not read {source.name}: {exc}") from exc

    if written == 0:
        raise PcapError(
            f"{source.name} contained no IPv4 packets ({skipped} skipped). "
            "This tool analyses IPv4 traffic only."
        )

    logger.info("Converted %d packets from %s (%d skipped)", written, source, skipped)
    return {"packets": written, "skipped": skipped, "output": str(output)}


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="seconds")
