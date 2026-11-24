"""Convert a packet capture into the CSV this tool analyses.

Users have `.pcap` files, not CSVs. Without this the only ways in were a live
capture needing root or the synthetic generator, which made the tool
impossible to point at real evidence.
"""
from __future__ import annotations

import csv
import logging
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

from .features import CSV_FIELDS as FIELDS

logger = logging.getLogger(__name__)


class PcapError(RuntimeError):
    """Raised when a capture cannot be read or contains nothing usable."""


def convert(source: Path, output: Path, limit: int | None = None) -> dict:
    """Read `source` and write the packet CSV to `output`.

    Two properties matter more than speed here.

    **A failure never destroys existing data.** The CSV is written to a
    temporary file beside `output` and moved into place only once the capture
    has been read. Previously `output` was truncated up front, so pointing
    ingest at a damaged capture wiped whatever was already there.

    **A truncated capture is reported, not passed off as complete.** scapy
    stops quietly at a corrupt record, so a capture that is valid for its
    first 1,500 bytes produced "[OK] Wrote 21 packets" — and replaced 6,920
    rows of good data. How much of the file was actually consumed is now
    checked and returned as `truncated_bytes`.

    Packets are streamed rather than loaded as a list, since `rdpcap` reads the
    whole file into memory before returning.
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
    scratch = output.with_name(f".{output.name}.{os.getpid()}.partial")
    written = skipped = 0
    interrupted: str | None = None

    try:
        with PcapReader(str(source)) as packets, scratch.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()

            stream = iter(packets)
            while True:
                if limit is not None and written >= limit:
                    break
                try:
                    packet = next(stream)
                except StopIteration:
                    break
                except Exception as exc:
                    # pcapng readers raise on a damaged block where pcap
                    # readers stop quietly. Either way, what came before the
                    # damage is good data: keep it and report the truncation.
                    if written == 0:
                        raise
                    interrupted = str(exc)
                    break
                if IP not in packet:
                    skipped += 1  # IPv6, ARP, loopback control traffic
                    continue

                layer = packet.getlayer(TCP) or packet.getlayer(UDP)
                writer.writerow({
                    "timestamp": _iso(getattr(packet, "time", None)),
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "src_port": int(layer.sport) if layer is not None else 0,
                    "dst_port": int(layer.dport) if layer is not None else 0,
                    "protocol": int(packet[IP].proto),
                    "packet_length": len(packet),
                })
                written += 1

    except PcapError:
        scratch.unlink(missing_ok=True)
        raise
    except Exception as exc:  # scapy raises a variety of things on a bad file
        scratch.unlink(missing_ok=True)
        raise PcapError(f"Could not read {source.name}: {exc}") from exc

    if written == 0:
        scratch.unlink(missing_ok=True)
        raise PcapError(
            f"{source.name} contained no IPv4 packets ({skipped} skipped). "
            "This tool analyses IPv4 traffic only. Nothing was written."
        )

    truncated = _trailing_bytes(source) if limit is None else 0
    if interrupted and not truncated:
        # The reader gave up even though the container looked whole: the
        # damage is inside a block, so the remainder cannot be measured.
        truncated = max(1, source.stat().st_size - _bytes_before_damage(source))
    os.replace(scratch, output)

    if truncated:
        logger.warning(
            "%s ended early: %d bytes after the last readable packet were "
            "skipped. The capture is truncated or corrupt; the CSV holds only "
            "what came before the damage.", source.name, truncated,
        )
    logger.info("Converted %d packets from %s (%d skipped)", written, source, skipped)
    return {
        "packets": written,
        "skipped": skipped,
        "truncated_bytes": truncated,
        "output": str(output),
    }


# pcap global-header magics -> struct byte order. The second pair is the
# nanosecond-resolution variant.
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BOM = 0x1A2B3C4D


def _trailing_bytes(source: Path) -> int:
    """Bytes at the end of a capture that do not form a complete record.

    Walks the container structure directly — record headers for pcap, block
    lengths for pcapng — rather than trusting how far scapy got. scapy reads a
    cut-off final record as end-of-file, so its position equals the file size
    and a truncated capture looks complete; the declared lengths do not lie.
    Reads headers only and seeks over payloads, so it is cheap on large files.
    Returns 0 for compressed captures, which cannot be walked this way.
    """
    size = source.stat().st_size
    with source.open("rb") as handle:
        magic = handle.read(4)
        if magic[:2] == b"\x1f\x8b":
            return 0
        if magic in _PCAP_MAGIC:
            return _walk_pcap(handle, size, _PCAP_MAGIC[magic])
        if magic == _PCAPNG_SHB:
            return _walk_pcapng(handle, size)
    return 0


def _bytes_before_damage(source: Path) -> int:
    """Best-effort size of the readable prefix; the whole file if unknown."""
    return source.stat().st_size - _trailing_bytes(source)


def _walk_pcap(handle, size: int, order: str) -> int:
    position = 24  # global header
    handle.seek(position)
    while position < size:
        header = handle.read(16)
        if len(header) < 16:
            return size - position
        (included,) = struct.unpack(f"{order}I", header[8:12])
        if position + 16 + included > size:
            return size - position
        position += 16 + included
        handle.seek(position)
    return 0


def _walk_pcapng(handle, size: int) -> int:
    position, order = 0, "<"
    while position < size:
        handle.seek(position)
        header = handle.read(12)
        if len(header) < 12:
            return size - position
        if header[:4] == _PCAPNG_SHB:
            # Each section declares its own byte order.
            order = "<" if struct.unpack("<I", header[8:12])[0] == _PCAPNG_BOM else ">"
        (length,) = struct.unpack(f"{order}I", header[4:8])
        if length < 12 or length % 4 or position + length > size:
            return size - position
        position += length
    return 0


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat(timespec="seconds")
