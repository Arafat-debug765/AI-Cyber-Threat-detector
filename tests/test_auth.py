"""Access control: who may reach this service, and from where.

The API exposes a full picture of the monitored network and can start an
expensive training run, so "anyone who can open the port" is not an acceptable
authorisation model.
"""
from dataclasses import replace

import pytest

from threat_detector import create_app
from threat_detector.auth import CSRF_HEADER, CSRF_VALUE, is_loopback


@pytest.fixture
def raw_client(config):
    """A plain client that sends none of the headers the front end sends."""
    app = create_app(config)
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def token_client(config):
    app = create_app(replace(config, api_token="s3cret"))
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


# ---- CSRF -----------------------------------------------------------------

def test_cross_site_post_is_rejected(raw_client):
    """A page the operator visits must not be able to start a training run."""
    response = raw_client.post("/api/train")
    assert response.status_code == 403
    assert CSRF_HEADER in response.get_json()["error"]


def test_legacy_post_is_protected_too(raw_client):
    assert raw_client.post("/train").status_code == 403


def test_reads_do_not_need_the_header(raw_client):
    assert raw_client.get("/api/status").status_code == 200


def test_post_with_the_header_is_allowed(raw_client, dataset):
    response = raw_client.post("/api/train", headers={CSRF_HEADER: CSRF_VALUE})
    assert response.status_code == 202


# ---- Host header / DNS rebinding -----------------------------------------

def test_unknown_host_is_rejected(raw_client):
    response = raw_client.get("/api/status", headers={"Host": "evil.example.com"})
    assert response.status_code == 403
    assert "Host" in response.get_json()["error"]


def test_configured_host_is_accepted(raw_client):
    assert raw_client.get("/api/status", headers={"Host": "localhost:5000"}).status_code == 200


def test_wildcard_disables_the_host_check(config):
    app = create_app(replace(config, allowed_hosts=("*",)))
    app.config.update(TESTING=True)
    with app.test_client() as client:
        assert client.get("/api/status", headers={"Host": "anything.test"}).status_code == 200


# ---- Token ----------------------------------------------------------------

def test_api_requires_the_token_when_configured(token_client):
    response = token_client.get("/api/status")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_bearer_token_is_accepted(token_client):
    response = token_client.get("/api/status", headers={"Authorization": "Bearer s3cret"})
    assert response.status_code == 200


def test_x_api_token_header_is_accepted(token_client):
    assert token_client.get("/api/status", headers={"X-API-Token": "s3cret"}).status_code == 200


def test_wrong_token_is_rejected(token_client):
    response = token_client.get("/api/status", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 403


def test_health_stays_public_for_probes(token_client):
    """A load balancer cannot be expected to hold the API token."""
    assert token_client.get("/health").status_code == 200


def test_the_ui_still_loads_with_a_token_configured(token_client):
    """A 401 on the page makes the UI unusable, and unusable auth gets removed.

    Browsers do not prompt for Bearer credentials, so gating the HTML and its
    assets leaves an operator no way in. The token guards the data endpoints;
    the page itself carries none.
    """
    assert token_client.get("/").status_code == 200
    assert token_client.get("/static/app.js").status_code == 200


def test_legacy_data_endpoints_are_guarded_too(token_client):
    """/anomalies is an alias for /api/anomalies and returns the same data."""
    assert token_client.get("/anomalies").status_code == 401
    # The POST is refused by the CSRF check first, which runs before the token
    # check — a different status, the same refusal.
    assert token_client.post("/train").status_code == 403


def test_non_ascii_token_is_rejected_not_a_crash(token_client):
    """Header bytes are attacker-controlled; a str compare 500s on demand."""
    response = token_client.get("/api/status", headers={"Authorization": "Bearer \u00e9"})
    assert response.status_code == 403


def test_a_valid_token_also_satisfies_the_csrf_check(token_client, dataset):
    """An API client authenticating properly is not a drive-by browser POST."""
    response = token_client.post("/api/train", headers={"Authorization": "Bearer s3cret"})
    assert response.status_code == 202


# ---- Response hardening ---------------------------------------------------

def test_security_headers_are_present(raw_client):
    headers = raw_client.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_oversized_body_is_refused(raw_client):
    response = raw_client.post(
        "/api/train",
        headers={CSRF_HEADER: CSRF_VALUE},
        data=b"x" * (2 << 20),
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    ("host", "expected"),
    [("127.0.0.1", True), ("::1", True), ("localhost", True), ("0.0.0.0", False),
     ("192.168.1.10", False),
     # Werkzeug treats an empty host as every interface, so it must not count
     # as loopback — otherwise HOST= serves the analysis unauthenticated.
     ("", False)],
)
def test_is_loopback(host, expected):
    assert is_loopback(host) is expected
