from dataclasses import replace

import pytest

from threat_detector import model as model_service
from threat_detector.features import DataError
from threat_detector.model import ModelNotTrained


def test_train_persists_model(config, dataset):
    result = model_service.train(config)
    assert config.model_file.exists()
    assert result["algorithm"] == "iforest"
    assert result["n_estimators"] == 100
    assert result["rows_trained"] == 200
    assert result["features"] == ["src_ip_int", "dst_ip_int", "protocol", "packet_length"]


def test_detect_requires_a_trained_model(config, dataset):
    with pytest.raises(ModelNotTrained):
        model_service.detect(config)


def test_detect_flags_the_planted_outliers(config, dataset):
    model_service.train(config)
    result = model_service.detect(config)

    assert result["total_packets"] == 200
    assert result["count"] > 0
    # Every planted outlier used protocol 47 with a 60000-byte payload.
    flagged_lengths = {row["packet_length"] for row in result["anomalies"]}
    assert 60000 in flagged_lengths
    # Sorted most-anomalous-first.
    scores = [row["anomaly_score"] for row in result["anomalies"]]
    assert scores == sorted(scores)


def test_detect_respects_limit(config, dataset):
    model_service.train(config)
    result = model_service.detect(config, limit=2)
    assert result["returned"] <= 2
    assert len(result["anomalies"]) <= 2


def test_train_without_dataset_raises(config):
    with pytest.raises(DataError):
        model_service.train(config)


def test_training_is_reproducible(config, dataset):
    first = model_service.train(config)
    scores_a = model_service.detect(config)["anomalies"]
    model_service.train(config)
    scores_b = model_service.detect(config)["anomalies"]
    assert first["rows_trained"] == 200
    assert [r["anomaly_score"] for r in scores_a] == [r["anomaly_score"] for r in scores_b]


def test_status_reports_disk_state(config, dataset):
    before = model_service.status(config)
    assert before["dataset_present"] is True
    assert before["model_trained"] is False

    model_service.train(config)
    after = model_service.status(config)
    assert after["model_trained"] is True
    assert after["trained_at"] is not None


def test_summary_aggregates_match_detection(config, dataset):
    model_service.train(config)
    summary = model_service.summarize(config)
    detected = model_service.detect(config)

    assert summary["total_packets"] == 200
    assert summary["flagged"] == detected["count"]
    assert 0.0 <= summary["flag_rate"] <= 1.0
    assert summary["min_score"] <= summary["max_score"]


def test_summary_histogram_covers_every_packet(config, dataset):
    model_service.train(config)
    summary = model_service.summarize(config)

    bins = summary["score_histogram"]
    assert len(bins) == 24
    counted = sum(b["normal"] + b["flagged"] for b in bins)
    assert counted == summary["total_packets"]
    # Bins are contiguous and ascending.
    for earlier, later in zip(bins, bins[1:]):
        assert earlier["end"] <= later["start"] + 1e-9


def test_summary_protocol_breakdown(config, dataset):
    model_service.train(config)
    protocols = model_service.summarize(config)["protocols"]

    # Ranked most-flagged first — the noisiest group is rarely the interesting one.
    assert protocols == sorted(
        protocols, key=lambda r: (r["flagged"], r["total"]), reverse=True
    )
    assert sum(r["total"] for r in protocols) == 200
    names = {r["name"] for r in protocols}
    assert {"ICMP", "TCP", "UDP"} & names
    # Protocol 47 (GRE) is only used by the planted outliers.
    gre = [r for r in protocols if r["protocol"] == 47]
    assert gre and gre[0]["flagged"] > 0


def test_summary_requires_a_model(config, dataset):
    with pytest.raises(ModelNotTrained):
        model_service.summarize(config)


def test_lof_algorithm_trains_and_detects(config, dataset):
    """LOF is an alternative detector, selected with ALGORITHM=lof."""
    lof_config = replace(config, algorithm="lof")
    result = model_service.train(lof_config)
    assert result["algorithm"] == "lof"

    detected = model_service.detect(lof_config)
    assert detected["total_packets"] == 200
    assert detected["count"] > 0


def test_unknown_algorithm_is_rejected(config):
    with pytest.raises(ValueError, match="Unknown ALGORITHM"):
        replace(config, algorithm="magic")
