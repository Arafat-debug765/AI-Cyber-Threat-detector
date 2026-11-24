"""Flow-level detection: the behaviour per-packet features cannot represent."""
import pandas as pd
import pytest

from tests.conftest import train_and_wait
from threat_detector import model as model_service
from threat_detector.features import DataError
from threat_detector.sessions import FLOW_FEATURE_COLUMNS, build_flow_features

SCANNER = "192.168.0.66"
ROW_BASE = {"src_ip": "192.168.0.5", "dst_ip": "10.0.0.1", "dst_port": 443,
            "protocol": 6, "packet_length": 300}


def test_flow_aggregation_shape(flow_config, flow_dataset):
    rows, matrix = model_service.load_for_model(flow_config)
    assert list(matrix.columns) == FLOW_FEATURE_COLUMNS
    assert {"src_ip", "window_start"}.issubset(rows.columns)
    assert len(rows) == len(matrix)
    # Twelve hosts over four windows, plus the scanner's single window.
    assert len(rows) < 200


def test_scanner_session_looks_different(flow_config, flow_dataset):
    rows, _ = model_service.load_for_model(flow_config)
    scanner = rows[rows["src_ip"] == SCANNER].iloc[0]
    ordinary = rows[rows["src_ip"] != SCANNER]

    assert scanner["distinct_dst_ports"] == 60
    assert scanner["distinct_dst_ports"] > ordinary["distinct_dst_ports"].max()
    assert scanner["small_packet_ratio"] == 1.0
    assert ordinary["small_packet_ratio"].max() == 0.0


def test_flow_mode_flags_the_scanner(flow_config, flow_dataset):
    """The whole point: this source is invisible to per-packet features."""
    model_service.train(flow_config)
    result = model_service.detect(flow_config)

    flagged_sources = {row["src_ip"] for row in result["anomalies"]}
    assert SCANNER in flagged_sources


def test_packet_mode_misses_the_scanner(config, flow_dataset):
    """Same data, packet features: every scan packet is an ordinary small TCP packet.

    This is the evidence for the flow default. If this test ever starts
    passing the scanner, the dataset stopped being a fair comparison.
    """
    config.data_file.write_bytes(flow_dataset.read_bytes())
    model_service.train(config)
    result = model_service.detect(config)

    flagged = [row for row in result["anomalies"] if row["src_ip"] == SCANNER]
    scan_packets = 60
    # Packet mode cannot single the scanner out: it catches at most a token few
    # of its 60 packets, and only by coincidence of length.
    assert len(flagged) < scan_packets


def test_flow_summary_breaks_down_by_source(flow_config, flow_dataset):
    model_service.train(flow_config)
    summary = model_service.summarize(flow_config)

    assert summary["unit"] == "sessions"
    assert summary["breakdown_label"] == "source"
    # Ranked by flagged share: the scanner has 1 of 1 sessions flagged.
    assert summary["protocols"][0]["name"] == SCANNER


def test_flow_api_round_trip(flow_client, flow_dataset):
    record = train_and_wait(flow_client)
    assert record["result"]["feature_set"] == "flow"
    payload = flow_client.get("/api/anomalies").get_json()
    assert payload["count"] >= 1
    assert "src_ip" in payload["anomalies"][0]


def test_flow_requires_timestamps():
    df = pd.DataFrame([
        {"src_ip": "192.168.0.1", "dst_ip": "10.0.0.1", "protocol": 6, "packet_length": 100},
    ])
    with pytest.raises(DataError, match="timestamp"):
        build_flow_features(df)


def test_flow_rejects_unparsable_timestamps():
    df = pd.DataFrame([
        {"timestamp": "not-a-time", "src_ip": "192.168.0.1", "dst_ip": "10.0.0.1",
         "protocol": 6, "packet_length": 100},
    ])
    with pytest.raises(DataError, match="timestamp"):
        build_flow_features(df)


def test_interarrival_flags_regular_beaconing():
    """Machine timers are regular in a way human traffic is not."""
    beacon = [{"timestamp": f"2026-01-01T00:00:{s:02d}", "src_ip": "192.168.0.7",
               "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": 6,
               "packet_length": 120} for s in range(0, 60, 5)]
    human = [{"timestamp": f"2026-01-01T00:00:{s:02d}", "src_ip": "192.168.0.8",
              "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": 6,
              "packet_length": 120} for s in (0, 1, 2, 9, 30, 31, 55)]

    flows = build_flow_features(pd.DataFrame(beacon + human))
    by_source = flows.set_index("src_ip")
    assert by_source.loc["192.168.0.7", "std_interarrival"] == 0.0
    assert by_source.loc["192.168.0.8", "std_interarrival"] > 5.0


def test_single_packet_window_has_no_nan():
    """NaN spread would drop the row at fit time instead of scoring it."""
    df = pd.DataFrame([
        {"timestamp": "2026-01-01T00:00:00", "src_ip": "192.168.0.1",
         "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": 6, "packet_length": 100},
    ])
    flows = build_flow_features(df)
    assert not flows[FLOW_FEATURE_COLUMNS].isna().any().any()
    assert flows.iloc[0]["std_length"] == 0.0


# ---- degenerate windows ---------------------------------------------------

def test_tiny_windows_are_dropped_before_fitting():
    """A one-packet window is a capture-boundary artifact, not behaviour.

    Left in, it scores as an extreme outlier on every feature at once, and a
    threshold calibrated at the minimum baseline score is then set by that
    artifact — which hid a 200-host sweep underneath it.
    """
    rows = [{"timestamp": f"2026-01-01T00:00:{s:02d}", "src_ip": "192.168.0.5",
             "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": 6,
             "packet_length": 300} for s in range(10)]
    rows.append({"timestamp": "2026-01-01T00:00:01", "src_ip": "192.168.0.99",
                 "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": 6,
                 "packet_length": 300})

    kept = build_flow_features(pd.DataFrame(rows), 300, min_packets=3)
    assert set(kept["src_ip"]) == {"192.168.0.5"}

    everything = build_flow_features(pd.DataFrame(rows), 300, min_packets=0)
    assert set(everything["src_ip"]) == {"192.168.0.5", "192.168.0.99"}


def test_dropping_everything_is_an_error_not_an_empty_model():
    rows = [{"timestamp": "2026-01-01T00:00:00", "src_ip": f"192.168.0.{i}",
             "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": 6,
             "packet_length": 300} for i in range(1, 5)]
    with pytest.raises(DataError, match="MIN_SESSION_PACKETS"):
        build_flow_features(pd.DataFrame(rows), 300, min_packets=5)


def test_timestamps_are_serialised_as_iso_not_epoch_millis(flow_config, flow_dataset):
    """`window_start: 1789878600000` is unreadable and unit-ambiguous."""
    model_service.train(flow_config)
    row = model_service.detect(flow_config)["anomalies"][0]
    assert isinstance(row["window_start"], str)
    assert row["window_start"].startswith("2026-01-01T")


def test_vectorised_interarrival_matches_the_per_session_definition():
    """Speed-up guard: the vectorised gaps must equal the obvious computation.

    Inter-arrival stats used to be computed by a Python function per session,
    which dominated runtime; the vectorised version must not change a number.
    """
    import numpy as np

    rng = np.random.default_rng(5)
    n = 3000
    df = pd.DataFrame({
        "timestamp": 1767225600 + rng.uniform(0, 1200, n),
        "src_ip": [f"192.168.0.{h}" for h in rng.integers(1, 40, n)],
        "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": 6,
        "packet_length": rng.integers(40, 1500, n),
    })
    got = build_flow_features(df, 300).set_index(["src_ip", "window_start"])

    ts = pd.to_datetime(df["timestamp"], unit="s", utc=True)
    width = pd.Timedelta(seconds=300)
    windows = ts.min() + ((ts - ts.min()) // width) * width  # anchored at the first packet
    for (src, window), group in df.assign(ts=ts, w=windows).groupby(["src_ip", "w"]):
        gaps = group["ts"].sort_values().diff().dt.total_seconds().dropna()
        mean = gaps.mean() if len(gaps) else 0.0
        std = gaps.std(ddof=0) if len(gaps) else 0.0
        assert got.loc[(src, window), "mean_interarrival"] == pytest.approx(mean)
        assert got.loc[(src, window), "std_interarrival"] == pytest.approx(std)



def test_results_do_not_depend_on_the_time_of_day_a_capture_started():
    """The same traffic, recorded at a different wall-clock phase, must analyse
    identically. With clock-aligned windows a capture starting at :54:58 got a
    two-second first window whose sliver sessions set the alert threshold and
    hid three of four attacks.
    """
    rows = [{"timestamp": 1767225600 + s, "src_ip": f"192.168.0.{1 + s % 9}",
             "dst_ip": "10.0.0.5", "dst_port": 443, "protocol": 6, "packet_length": 300}
            for s in range(0, 900)]
    reference = build_flow_features(pd.DataFrame(rows), 300)
    for phase in (2, 58, 150, 298):
        shifted = [{**r, "timestamp": r["timestamp"] + phase} for r in rows]
        got = build_flow_features(pd.DataFrame(shifted), 300)
        cols = ["src_ip", "packets", "bytes_total", "distinct_dst_ips", "std_interarrival"]
        pd.testing.assert_frame_equal(got[cols], reference[cols])


def test_first_window_starts_at_the_first_packet():
    rows = [{**ROW_BASE, "timestamp": f"2026-01-01T03:54:{58 + s % 2:02d}"} for s in range(4)]
    got = build_flow_features(pd.DataFrame(rows), 300)
    assert str(got["window_start"].iloc[0]) == "2026-01-01 03:54:58+00:00"


def test_a_sliver_of_a_final_window_is_dropped():
    """Three packets in the last second of a capture are not five minutes of behaviour."""
    rows = [{**ROW_BASE, "timestamp": 1767225600 + s, "src_ip": f"192.168.0.{1 + s % 5}"}
            for s in range(0, 600)]
    rows += [{**ROW_BASE, "timestamp": 1767225600 + 601, "src_ip": "192.168.0.99"}] * 3
    kept = build_flow_features(pd.DataFrame(rows), 300, min_packets=3, min_coverage=0.5)
    assert "192.168.0.99" not in set(kept["src_ip"])
    unfiltered = build_flow_features(pd.DataFrame(rows), 300, min_packets=3, min_coverage=0)
    assert "192.168.0.99" in set(unfiltered["src_ip"])


def test_a_capture_shorter_than_one_window_is_kept():
    """All of it is partial window; dropping it would leave nothing."""
    rows = [{**ROW_BASE, "timestamp": 1767225600 + s} for s in range(30)]
    assert len(build_flow_features(pd.DataFrame(rows), 300, min_coverage=0.5)) == 1


def test_coverage_setting_is_validated():
    from threat_detector.config import Config

    with pytest.raises(ValueError, match="MIN_WINDOW_COVERAGE"):
        Config(min_window_coverage=1.5)
