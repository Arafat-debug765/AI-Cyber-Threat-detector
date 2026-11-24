"""Capture ingestion — the path real evidence comes in by."""
import csv

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, wrpcap  # noqa: E402
from scapy.utils import PcapNgWriter  # noqa: E402

from threat_detector import pcap  # noqa: E402

T0 = 1767225600.0  # 2026-01-01T00:00:00Z
MACS = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def _packets():
    out = []
    for i in range(30):
        p = Ether(**MACS) / IP(src="192.168.0.5", dst="10.0.0.1") / TCP(sport=40000 + i, dport=443)
        p.time = T0 + i
        out.append(p)
    v6 = Ether(**MACS) / IPv6(src="fe80::1", dst="fe80::2") / UDP()
    v6.time = T0
    ping = Ether(**MACS) / IP(src="192.168.0.9", dst="10.0.0.1") / ICMP()
    ping.time = T0 + 5
    return [*out, v6, ping]


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), _packets())
    return path


@pytest.fixture
def capture_ng(tmp_path):
    path = tmp_path / "capture.pcapng"
    writer = PcapNgWriter(str(path))
    for packet in _packets():
        writer.write(packet)
    writer.close()
    return path


def _rows(path):
    with path.open() as handle:
        return list(csv.DictReader(handle))


@pytest.mark.parametrize("fixture", ["capture", "capture_ng"])
def test_round_trip(fixture, request, tmp_path):
    source = request.getfixturevalue(fixture)
    result = pcap.convert(source, tmp_path / "out.csv")

    assert result == {**result, "packets": 31, "skipped": 1, "truncated_bytes": 0}
    rows = _rows(tmp_path / "out.csv")
    assert rows[0]["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert {r["dst_port"] for r in rows if r["protocol"] == "1"} == {"0"}  # ICMP has no ports


def test_truncated_capture_is_salvaged_and_flagged(capture, tmp_path):
    """tcpdump killed mid-write: keep what came before, and say it is partial.

    scapy stops quietly at a cut-off record, so this used to report a clean
    success — and overwrite existing data with the fragment.
    """
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(capture.read_bytes()[:1500] + b"\xff" * 16)

    result = pcap.convert(cut, tmp_path / "out.csv")
    assert 0 < result["packets"] < 31
    assert result["truncated_bytes"] > 0


def test_truncated_pcapng_is_salvaged_too(capture_ng, tmp_path):
    """pcapng readers raise on a damaged block rather than stopping quietly."""
    cut = tmp_path / "cut.pcapng"
    cut.write_bytes(capture_ng.read_bytes()[:1200])

    result = pcap.convert(cut, tmp_path / "out.csv")
    assert result["packets"] > 0
    assert result["truncated_bytes"] > 0


def test_a_failed_ingest_never_destroys_existing_data(tmp_path):
    existing = tmp_path / "packets.csv"
    existing.write_text("precious\n" * 100)
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture")

    with pytest.raises(pcap.PcapError):
        pcap.convert(junk, existing)
    assert existing.read_text() == "precious\n" * 100


def test_no_partial_files_are_left_behind(tmp_path):
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"nope")
    with pytest.raises(pcap.PcapError):
        pcap.convert(junk, tmp_path / "out.csv")
    assert not (tmp_path / "out.csv").exists()
    assert not list(tmp_path.glob(".*partial"))


def test_ipv6_only_capture_writes_nothing(tmp_path):
    only_v6 = Ether(**MACS) / IPv6(src="fe80::1", dst="fe80::2") / UDP()
    source = tmp_path / "v6.pcap"
    wrpcap(str(source), [only_v6] * 3)

    with pytest.raises(pcap.PcapError, match="no IPv4 packets"):
        pcap.convert(source, tmp_path / "out.csv")
    assert not (tmp_path / "out.csv").exists()


def test_limit_stops_early_without_claiming_truncation(capture, tmp_path):
    result = pcap.convert(capture, tmp_path / "out.csv", limit=5)
    assert result["packets"] == 5
    assert result["truncated_bytes"] == 0


def test_missing_capture(tmp_path):
    with pytest.raises(pcap.PcapError, match="not found"):
        pcap.convert(tmp_path / "absent.pcap", tmp_path / "out.csv")
