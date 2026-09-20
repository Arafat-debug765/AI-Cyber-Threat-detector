"""Generate a synthetic capture containing realistic attack behaviour.

Baseline traffic is ordinary internal hosts talking to a handful of servers.
Planted on top are four behaviours a per-packet model cannot see, because each
individual packet is unremarkable — only the pattern across packets is wrong:

  port scan   one source, many destination ports, tiny packets, fast
  host sweep  one source, many destination hosts, same port
  beacon      one source, one destination, rigidly regular interval
  exfil       one source, one external destination, sustained large payloads

    threat-detector generate --count 6000
    threat-detector generate --no-attacks     # clean baseline
"""
from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import BASE_DIR

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_length"]
TCP, UDP, ICMP = 6, 17, 1
SERVERS = ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
SERVER_PORTS = [80, 443, 8080, 53]
DEFAULT_OUTPUT = BASE_DIR / "data" / "packets.csv"


def _ts(start: datetime, offset: float) -> str:
    return (start + timedelta(seconds=offset)).isoformat(timespec="seconds")


def baseline(rng: random.Random, start: datetime, count: int, hosts: int) -> list:
    """Ordinary internal hosts holding short conversations with servers."""
    rows = []
    for _ in range(count):
        offset = rng.uniform(0, 600)
        protocol = rng.choices([TCP, UDP, ICMP], weights=[70, 25, 5])[0]
        rows.append({
            "timestamp": _ts(start, offset),
            "src_ip": f"192.168.0.{rng.randint(10, 10 + hosts - 1)}",
            "dst_ip": rng.choice(SERVERS),
            "src_port": rng.randint(32768, 60999),
            "dst_port": rng.choice(SERVER_PORTS) if protocol != ICMP else 0,
            "protocol": protocol,
            "packet_length": rng.randint(200, 900) if protocol == TCP else rng.randint(60, 300),
        })
    return rows


def port_scan(rng: random.Random, start: datetime, source: str) -> list:
    """SYN-scan shape: hundreds of ports on one host, minimum-size packets."""
    at = rng.uniform(60, 500)
    return [{
        "timestamp": _ts(start, at + port * 0.05),
        "src_ip": source,
        "dst_ip": SERVERS[0],
        "src_port": rng.randint(32768, 60999),
        "dst_port": port,
        "protocol": TCP,
        "packet_length": 44,
    } for port in range(1, 301)]


def host_sweep(rng: random.Random, start: datetime, source: str) -> list:
    """One service, swept across a whole subnet."""
    at = rng.uniform(60, 500)
    return [{
        "timestamp": _ts(start, at + host * 0.08),
        "src_ip": source,
        "dst_ip": f"10.0.0.{host}",
        "src_port": rng.randint(32768, 60999),
        "dst_port": 445,
        "protocol": TCP,
        "packet_length": 60,
    } for host in range(1, 201)]


def beacon(rng: random.Random, start: datetime, source: str) -> list:
    """Command-and-control check-in: same size, same target, exact interval."""
    interval = 30
    return [{
        "timestamp": _ts(start, tick * interval),
        "src_ip": source,
        "dst_ip": "203.0.113.77",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": TCP,
        "packet_length": 128,
    } for tick in range(20)]


def exfil(rng: random.Random, start: datetime, source: str) -> list:
    """Sustained upload to one external host — normal packets, abnormal volume."""
    at = rng.uniform(60, 400)
    return [{
        "timestamp": _ts(start, at + i * 0.02),
        "src_ip": source,
        "dst_ip": "198.51.100.23",
        "src_port": 51000,
        "dst_port": 443,
        "protocol": TCP,
        "packet_length": rng.randint(1300, 1500),
    } for i in range(400)]


ATTACKS = {
    "port_scan": (port_scan, "192.168.0.66"),
    "host_sweep": (host_sweep, "192.168.0.67"),
    "beacon": (beacon, "192.168.0.68"),
    "exfil": (exfil, "192.168.0.69"),
}


def generate(output: Path, count: int, hosts: int, seed: int, with_attacks: bool) -> None:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(seconds=900)

    rows = baseline(rng, start, count, hosts)
    planted = {}
    if with_attacks:
        for name, (builder, source) in ATTACKS.items():
            attack_rows = builder(rng, start, source)
            rows.extend(attack_rows)
            planted[name] = (source, len(attack_rows))

    rows.sort(key=lambda r: r["timestamp"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote {len(rows)} packets to {output}")
    for name, (source, packets) in planted.items():
        print(f"     planted {name:<11} from {source} ({packets} packets)")
    if planted:
        print("     these are invisible per-packet; run with FEATURE_SET=flow (the default)")
