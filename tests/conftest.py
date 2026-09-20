import csv
import random
import sys
from pathlib import Path

import pytest
from flask.testing import FlaskClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_detector import create_app, jobs
from threat_detector.auth import CSRF_HEADER, CSRF_VALUE
from threat_detector.config import Config


class BrowserLikeClient(FlaskClient):
    """A client that behaves like the app's own front end.

    The real UI sends the anti-CSRF header on every request, so the default
    test client does too. Tests that a *missing* header is rejected use a raw
    client in test_auth.py instead.
    """

    def open(self, *args, **kwargs):
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault(CSRF_HEADER, CSRF_VALUE)
        return super().open(*args, headers=headers, **kwargs)


def train_and_wait(client, path: str = "/api/train", **kwargs) -> dict:
    """POST to the training endpoint and block until the job finishes.

    Training is asynchronous over HTTP, so a test that wants a trained model
    has to wait for the worker rather than assume the response means "done".
    """
    response = client.post(path, **kwargs)
    assert response.status_code == 202, response.get_data(as_text=True)
    record = jobs.wait(client.application.config["APP_CONFIG"], timeout=60)
    return record


def write_packets(path: Path, rows: int = 200) -> Path:
    """A small, deterministic dataset with a handful of obvious outliers."""
    random.seed(7)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "packet_length"]
        )
        writer.writeheader()
        for i in range(rows):
            anomalous = i % 40 == 0
            writer.writerow({
                "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}",
                "src_ip": "203.0.113.9" if anomalous else f"192.168.0.{i % 250 + 1}",
                "dst_ip": f"10.0.0.{i % 250 + 1}",
                "protocol": 47 if anomalous else random.choice([1, 6, 17]),
                "packet_length": 60000 if anomalous else random.randint(40, 600),
            })
    return path


def write_sessions(path: Path) -> Path:
    """Traffic with repeat sources, one of which runs a port scan.

    Twelve ordinary hosts hold short conversations with a couple of servers;
    one host sweeps 60 ports in a single window. Only the flow features can
    tell those apart — per packet, every one of the scanner's packets looks
    like an unremarkable small TCP packet.
    """
    random.seed(11)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for host in range(12):
        for minute in range(4):
            for packet in range(random.randint(6, 14)):
                rows.append({
                    "timestamp": f"2026-01-01T00:{minute:02d}:{packet % 60:02d}",
                    "src_ip": f"192.168.0.{10 + host}",
                    "dst_ip": f"10.0.0.{random.choice([5, 6])}",
                    "dst_port": random.choice([80, 443]),
                    "protocol": 6,
                    "packet_length": random.randint(200, 900),
                })
    for port in range(60):
        rows.append({
            "timestamp": f"2026-01-01T00:02:{port % 60:02d}",
            "src_ip": "192.168.0.66",
            "dst_ip": "10.0.0.5",
            "dst_port": 1000 + port,
            "protocol": 6,
            "packet_length": 44,
        })

    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def config(tmp_path) -> Config:
    """Packet-level config: one row in, one row scored.

    Declared explicitly rather than relying on the default, which is `flow` —
    these tests assert per-packet counts and would otherwise silently change
    meaning if the default moved again.
    """
    cfg = Config(
        data_file=tmp_path / "data" / "packets.csv",
        model_file=tmp_path / "models" / "model.pkl",
        feature_set="packet",
    )
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def flow_config(tmp_path) -> Config:
    """Flow-level config: rows are (source, time window) sessions."""
    cfg = Config(
        data_file=tmp_path / "data" / "packets.csv",
        model_file=tmp_path / "models" / "model.pkl",
        feature_set="flow",
        window_seconds=60,
    )
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def dataset(config) -> Path:
    return write_packets(config.data_file)


@pytest.fixture
def client(config):
    app = create_app(config)
    app.config.update(TESTING=True)
    app.test_client_class = BrowserLikeClient
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def flow_dataset(flow_config) -> Path:
    return write_sessions(flow_config.data_file)


@pytest.fixture
def flow_client(flow_config):
    app = create_app(flow_config)
    app.config.update(TESTING=True)
    app.test_client_class = BrowserLikeClient
    with app.test_client() as test_client:
        yield test_client
