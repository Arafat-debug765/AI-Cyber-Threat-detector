"""Background training: concurrency, crash recovery, and cache invalidation."""
import time
from dataclasses import replace

import pytest

from tests.conftest import train_and_wait
from threat_detector import jobs
from threat_detector import model as model_service


def test_job_records_success(config, dataset):
    record = jobs.start(config, model_service.train)
    assert record["state"] == jobs.RUNNING

    finished = jobs.wait(config)
    assert finished["state"] == jobs.SUCCEEDED
    assert finished["result"]["rows_trained"] == 200


def test_job_records_failure_without_crashing_the_server(config):
    """No dataset: the run fails, the app keeps serving."""
    jobs.start(config, model_service.train)
    finished = jobs.wait(config)

    assert finished["state"] == jobs.FAILED
    assert "not found" in finished["error"]


def test_second_run_is_refused_while_one_is_going(config, dataset):
    def slow(cfg):
        time.sleep(0.5)
        return model_service.train(cfg)

    jobs.start(config, slow)
    with pytest.raises(jobs.JobInProgress):
        jobs.start(config, model_service.train)
    jobs.wait(config)


def test_concurrent_training_is_refused_over_http(client, dataset):
    """Two overlapping trainings would race onto the same model file."""
    first = client.post("/api/train")
    assert first.status_code == 202
    second = client.post("/api/train")
    assert second.status_code in {202, 409}  # 409 unless the first already finished
    jobs.wait(client.application.config["APP_CONFIG"])


def test_dead_job_does_not_block_forever(config, dataset):
    """A container restarted mid-fit must not wedge training permanently."""
    jobs._write(config.job_file, {
        "state": jobs.RUNNING,
        "started_at": time.time(),
        "pid": 999_999,  # a pid that cannot exist
        "error": None,
        "result": None,
    })

    recovered = jobs.status(config)
    assert recovered["state"] == jobs.FAILED
    assert "gone" in recovered["error"]

    # And a new run is allowed again.
    assert jobs.start(config, model_service.train)["state"] == jobs.RUNNING
    jobs.wait(config)


def test_status_is_empty_before_any_run(config):
    assert jobs.status(config) == {"state": None}


def test_corrupt_status_file_is_ignored(config):
    config.job_file.parent.mkdir(parents=True, exist_ok=True)
    config.job_file.write_text("{not json")
    assert jobs.status(config) == {"state": None}


# ---- the scoring cache ----------------------------------------------------

def test_scoring_is_computed_once_per_state(config, dataset):
    model_service.train(config)
    first = model_service.scored(config)
    second = model_service.scored(config)
    assert first is second  # same objects: no second pass over the capture


def test_cache_is_invalidated_by_retraining(config, dataset):
    model_service.train(config)
    first = model_service.scored(config)
    model_service.train(config)
    assert model_service.scored(config) is not first


def test_cache_is_invalidated_by_new_data(config, dataset, tmp_path):
    from tests.conftest import write_packets

    model_service.train(config)
    first = model_service.scored(config)

    time.sleep(0.01)
    write_packets(config.data_file, rows=120)
    assert model_service.scored(config) is not first


def test_cache_respects_a_changed_threshold(config, dataset):
    model_service.train(config)
    baseline = model_service.detect(config)["count"]
    silenced = model_service.detect(replace(config, score_threshold=-99.0))["count"]
    assert silenced == 0
    assert model_service.detect(config)["count"] == baseline


def test_detect_and_summary_agree(client, dataset):
    """Both endpoints read the same scoring pass, so they cannot disagree."""
    train_and_wait(client)
    detected = client.get("/api/anomalies").get_json()
    summary = client.get("/api/summary").get_json()

    assert detected["count"] == summary["flagged"]
    assert detected["total_packets"] == summary["total_packets"]
