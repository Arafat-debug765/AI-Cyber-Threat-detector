"""Baseline fitting and threshold calibration.

The central property: a detector must be silent on traffic that contains
nothing wrong. A quota-based detector cannot be, by construction.
"""
import math
from dataclasses import replace

import pytest

from tests.conftest import write_sessions
from threat_detector import model as model_service


def _clean_baseline(tmp_path):
    """The same shape of traffic as the fixture, minus the scanner."""
    path = tmp_path / "baseline.csv"
    write_sessions(path)
    lines = path.read_text().splitlines()
    kept = [lines[0]] + [row for row in lines[1:] if "192.168.0.66" not in row]
    path.write_text("\n".join(kept) + "\n")
    return path


def test_without_baseline_it_falls_back_to_a_quota(flow_config, flow_dataset):
    result = model_service.train(flow_config)
    assert result["fitted_on_baseline"] is False
    assert result["calibration_quantile"] == model_service.FALLBACK_QUANTILE


def test_baseline_training_reports_its_source(flow_config, flow_dataset, tmp_path):
    config = replace(flow_config, baseline_file=_clean_baseline(tmp_path))
    result = model_service.train(config)

    assert result["fitted_on_baseline"] is True
    assert result["fitted_on"].endswith("baseline.csv")
    assert result["calibration_quantile"] == model_service.DEFAULT_FALSE_POSITIVE_RATE


def test_the_quantile_is_a_false_positive_rate(flow_config, tmp_path):
    """The threshold is set at this quantile of the baseline's own scores.

    So scoring the baseline back produces about that fraction of alerts — by
    construction. It is an operating point, not a promise of silence.
    """
    baseline = _clean_baseline(tmp_path)
    config = replace(flow_config, baseline_file=baseline, data_file=baseline,
                     calibration_quantile=0.05)
    model_service.train(config)

    result = model_service.detect(config)
    expected = math.ceil(0.05 * result["total_packets"])
    assert result["count"] <= expected


def test_the_strictest_rate_keeps_known_good_traffic_quietest(flow_config, tmp_path):
    """Rate 0.0 puts the bar at the least typical baseline session, scored
    out-of-fold. Known-good traffic is then nearly — not exactly — silent: a
    session can sit just past an out-of-fold threshold when the final model
    scores it. It must never be noisier than a looser setting."""
    baseline = _clean_baseline(tmp_path)

    def alerts(rate):
        config = replace(flow_config, baseline_file=baseline, data_file=baseline,
                         calibration_quantile=rate, model_file=tmp_path / f"m{rate}.pkl")
        model_service.train(config)
        result = model_service.detect(config)
        return result["count"], result["total_packets"]

    strict, total = alerts(0.0)
    loose, _ = alerts(0.05)
    assert strict <= loose
    assert strict <= math.ceil(0.05 * total)


def _baseline_rows(lone_outlier: bool):
    import random

    rng = random.Random(3)
    rows = []
    for host in range(40):
        for packet in range(100):
            rows.append({"timestamp": 1767225600 + packet * 3 + rng.random(),
                         "src_ip": f"192.168.0.{10 + host}", "dst_ip": "10.0.0.5",
                         "dst_port": rng.choice([80, 443]), "protocol": 6,
                         "packet_length": rng.randint(200, 900)})
    if lone_outlier:  # three packets in one instant: zero gaps, almost no volume
        rows += [{"timestamp": 1767225650, "src_ip": "192.168.0.99", "dst_ip": "10.0.0.5",
                  "dst_port": 443, "protocol": 6, "packet_length": 60}] * 3
    return rows


@pytest.mark.parametrize("lone_outlier", [True, False])
def test_a_lone_outlying_baseline_session_is_called_out(lone_outlier, flow_config, tmp_path, caplog):
    """At rate 0.0 the least typical session sets the bar; a freak one must not
    do so silently — training succeeds and detection just stops working."""
    import csv
    import logging

    baseline = tmp_path / "base.csv"
    rows = _baseline_rows(lone_outlier)
    with baseline.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    config = replace(flow_config, baseline_file=baseline, data_file=baseline,
                     calibration_quantile=0.0, window_seconds=600)
    with caplog.at_level(logging.WARNING):
        model_service.train(config)

    warned = any("single baseline session" in r.message for r in caplog.records)
    assert warned is lone_outlier


def test_a_short_baseline_is_called_out(flow_config, tmp_path, caplog):
    import logging

    baseline = _clean_baseline(tmp_path)
    config = replace(flow_config, baseline_file=baseline)
    with caplog.at_level(logging.WARNING):
        result = model_service.train(config)
    assert result["short_baseline"] is True
    assert any("halving each time it doubles" in r.message for r in caplog.records)


def test_baseline_trained_model_still_flags_the_scanner(flow_config, flow_dataset, tmp_path):
    config = replace(flow_config, baseline_file=_clean_baseline(tmp_path))
    model_service.train(config)

    flagged = {row["src_ip"] for row in model_service.detect(config)["anomalies"]}
    assert "192.168.0.66" in flagged


def test_threshold_is_stored_with_the_model(flow_config, flow_dataset):
    trained = model_service.train(flow_config)
    bundle = model_service.load_model(flow_config)

    assert bundle["threshold"] == trained["threshold"] or abs(
        bundle["threshold"] - trained["threshold"]
    ) < 1e-6
    assert bundle["feature_set"] == "flow"
    assert bundle["feature_columns"]


def test_explicit_threshold_overrides_calibration(flow_config, flow_dataset):
    model_service.train(flow_config)
    silent = replace(flow_config, score_threshold=-99.0)
    assert model_service.detect(silent)["count"] == 0

    noisy = replace(flow_config, score_threshold=99.0)
    assert model_service.detect(noisy)["count"] == model_service.detect(noisy)["total_packets"]


def test_feature_set_mismatch_is_refused(flow_config, flow_dataset):
    """A flow model must not silently score packet features, or vice versa."""
    model_service.train(flow_config)
    mismatched = replace(flow_config, feature_set="packet")

    try:
        model_service.detect(mismatched)
    except model_service.ModelNotTrained as exc:
        assert "feature" in str(exc).lower() or "FEATURE_SET" in str(exc)
    else:
        raise AssertionError("expected a refusal on feature-set mismatch")
