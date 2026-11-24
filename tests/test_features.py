import pandas as pd
import pytest

from threat_detector.features import DataError, build_features, ip_to_int, load_packets


def test_ip_to_int_is_collision_free():
    # The old sum-of-octets encoding mapped both of these to 366.
    assert ip_to_int("192.168.1.5") != ip_to_int("5.1.168.192")


def test_ip_to_int_known_value():
    assert ip_to_int("0.0.1.0") == 256
    assert ip_to_int("255.255.255.255") == 4294967295


@pytest.mark.parametrize("bad", ["", "not-an-ip", "999.1.1.1", "10.0.0"])
def test_ip_to_int_rejects_invalid(bad):
    with pytest.raises(DataError):
        ip_to_int(bad)


def test_build_features_shape_and_columns():
    df = pd.DataFrame([
        {"src_ip": "192.168.0.1", "dst_ip": "10.0.0.1", "protocol": 6, "packet_length": 120},
        {"src_ip": "192.168.0.2", "dst_ip": "10.0.0.2", "protocol": 17, "packet_length": 640},
    ])
    features = build_features(df)
    assert list(features.columns) == ["src_ip_int", "dst_ip_int", "protocol", "packet_length"]
    assert len(features) == 2


def test_build_features_rejects_non_numeric():
    df = pd.DataFrame([
        {"src_ip": "192.168.0.1", "dst_ip": "10.0.0.1", "protocol": "tcp", "packet_length": 120},
    ])
    with pytest.raises(DataError, match="Non-numeric"):
        build_features(df)


def test_load_packets_missing_file(tmp_path):
    with pytest.raises(DataError, match="not found"):
        load_packets(tmp_path / "nope.csv")


def test_error_messages_never_contain_absolute_paths(tmp_path):
    """These strings are surfaced verbatim in HTTP responses."""
    with pytest.raises(DataError) as excinfo:
        load_packets(tmp_path / "nope.csv")
    assert str(tmp_path) not in str(excinfo.value)


def test_load_packets_missing_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("src_ip,dst_ip\n192.168.0.1,10.0.0.1\n")
    with pytest.raises(DataError, match="missing required column"):
        load_packets(path)


def test_load_packets_empty_file(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("")
    with pytest.raises(DataError, match="empty"):
        load_packets(path)


# ---- cleaning: drop what cannot be analysed, say so, fail only when empty ----

from threat_detector.features import clean_packets, parse_timestamps, rows_dropped  # noqa: E402

ROW = {"timestamp": "2026-01-01T00:00:00", "src_ip": "192.168.0.5", "dst_ip": "10.0.0.1",
       "dst_port": 443, "protocol": 6, "packet_length": 300}


def test_padded_headers_are_accepted(tmp_path):
    """Spreadsheet exports write 'src_ip, dst_ip' — every column looked missing."""
    path = tmp_path / "padded.csv"
    path.write_text("timestamp, src_ip, dst_ip, protocol, packet_length\n"
                    "2026-01-01T00:00:00, 192.168.0.5, 10.0.0.1, 6, 300\n")
    assert list(load_packets(path).columns)[:3] == ["timestamp", "src_ip", "dst_ip"]


def test_one_ipv6_row_no_longer_rejects_the_capture():
    """A dual-stack network produces IPv6 rows; the rest is still analysable."""
    df = pd.DataFrame([ROW] * 5 + [{**ROW, "src_ip": "fe80::1"}])
    clean = clean_packets(df)
    assert len(clean) == 5
    assert rows_dropped(clean) == {"non_ipv4_address": 1}


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("src_ip", "", "non_ipv4_address"),
    ("dst_ip", "not-an-ip", "non_ipv4_address"),
    ("packet_length", "abc", "non_numeric_field"),
    ("packet_length", -5, "out_of_range_value"),
    ("packet_length", 0, "out_of_range_value"),
    ("protocol", 300, "out_of_range_value"),
])
def test_each_kind_of_bad_row_is_counted(field, value, reason):
    clean = clean_packets(pd.DataFrame([ROW] * 3 + [{**ROW, field: value}]))
    assert len(clean) == 3
    assert rows_dropped(clean) == {reason: 1}


def test_drop_counts_add_up_when_a_row_has_several_problems():
    bad = {**ROW, "src_ip": "", "packet_length": -1}
    clean = clean_packets(pd.DataFrame([ROW, bad]))
    assert sum(rows_dropped(clean).values()) == 1


def test_nothing_usable_is_an_error_that_explains_why():
    with pytest.raises(DataError, match=r"No usable rows.*non ipv4 address"):
        clean_packets(pd.DataFrame([{**ROW, "src_ip": "fe80::1"}] * 3))


def test_drops_are_reported_in_results(config, dataset):
    """Silently discarding rows would make the tool untrustworthy."""
    from threat_detector import model as model_service

    with config.data_file.open("a") as handle:
        handle.write("2026-01-01T09:00:00,fe80::1,10.0.0.1,6,300\n")
    trained = model_service.train(config)
    assert trained["rows_dropped"] == {"non_ipv4_address": 1}
    assert model_service.detect(config)["rows_dropped"] == {"non_ipv4_address": 1}


# ---- timestamps --------------------------------------------------------------

@pytest.mark.parametrize("value", [
    1767225600,             # epoch seconds: what tcpdump, tshark and scapy export
    1767225600.25,          # fractional seconds
    1767225600000,          # milliseconds
    1767225600000000,       # microseconds
    "2026-01-01T00:00:00Z",
    "2026-01-01 00:00:00",
])
def test_timestamps_land_in_the_right_year(value):
    """pandas reads a bare integer as nanoseconds: 2026 became 1970."""
    parsed = parse_timestamps(pd.Series([value] * 3))
    assert parsed.dt.year.tolist() == [2026, 2026, 2026]


def test_unparsable_timestamps_are_dropped_not_fatal():
    df = pd.DataFrame([ROW] * 3 + [{**ROW, "timestamp": "yesterday-ish"}])
    clean = clean_packets(df, require_timestamps=True)
    assert len(clean) == 3
    assert rows_dropped(clean) == {"unparsable_timestamp": 1}


def test_the_same_seed_produces_the_same_traffic(tmp_path):
    """The generator promised reproducibility and did not deliver it: the
    sub-second part of the clock decided how each packet's offset rounded."""
    import time

    from threat_detector import synth

    def relative(path):
        ts = pd.to_datetime(pd.read_csv(path)["timestamp"], utc=True)
        return (ts - ts.min()).dt.total_seconds().tolist()

    synth.generate(tmp_path / "a.csv", 2000, 25, 42, True)
    time.sleep(0.37)
    synth.generate(tmp_path / "b.csv", 2000, 25, 42, True)
    assert relative(tmp_path / "a.csv") == relative(tmp_path / "b.csv")


def test_a_fixed_start_reproduces_the_file_exactly(tmp_path):
    from datetime import datetime, timezone

    from threat_detector import synth

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    synth.generate(tmp_path / "a.csv", 500, 10, 3, True, start=start)
    synth.generate(tmp_path / "b.csv", 500, 10, 3, True, start=start)
    assert (tmp_path / "a.csv").read_bytes() == (tmp_path / "b.csv").read_bytes()
