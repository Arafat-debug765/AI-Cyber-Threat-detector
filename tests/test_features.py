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
