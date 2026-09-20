"""Access control for the HTTP layer.

Three separate problems, none of which the app previously addressed:

1. **Anyone who can reach the port can use it.** The API exposes a full picture
   of the monitored network — source addresses, ports contacted, volumes — and
   lets a caller start an expensive training run. `API_TOKEN` gates `/api/*`.

2. **A browser on any website can reach 127.0.0.1.** A page the operator visits
   can POST to this service, and with DNS rebinding it can read the responses
   too. Checking the `Host` header stops a hostile domain being pointed at this
   port, and requiring a non-simple request on state-changing routes stops the
   drive-by POST that needs no rebinding at all.

3. **Nothing distinguished "no token configured" from "listening on the
   world".** Unauthenticated is a reasonable default on loopback and is never
   acceptable off it, so binding outside loopback without a token is refused at
   startup rather than being a footnote in the README.
"""
from __future__ import annotations

import hmac
import ipaddress
import logging

from flask import current_app, jsonify, request

logger = logging.getLogger(__name__)

# State-changing requests must carry something a cross-origin <form> cannot
# send. Any custom header forces a CORS preflight, which a hostile page cannot
# satisfy without this service explicitly allowing its origin — and it does not.
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "threat-detector"

# The token guards data, not the shell. Serving the page and its assets
# unauthenticated is deliberate: they contain nothing, browsers do not prompt
# for Bearer auth, and a 401 on `GET /` makes the UI unusable — at which point
# the operator's only move is to turn authentication off entirely.
_GUARDED_PREFIXES = ("/api/",)
_GUARDED_PATHS = frozenset({"/train", "/anomalies"})


def _needs_token(path: str) -> bool:
    return path.startswith(_GUARDED_PREFIXES) or path in _GUARDED_PATHS


def _config():
    return current_app.config["APP_CONFIG"]


def _unauthorized(message: str, status: int = 401):
    response = jsonify({"error": message})
    response.status_code = status
    if status == 401:
        response.headers["WWW-Authenticate"] = 'Bearer realm="threat-detector"'
    return response


def _presented_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("X-API-Token") or None


def check_host() -> object | None:
    """Reject requests whose Host header this instance does not answer to."""
    allowed = _config().allowed_hosts
    if "*" in allowed:
        return None

    # Strip the port: Host is "example.com:5000", and ":5000" is not identity.
    host = (request.host or "").lower()
    name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if name.startswith("[") and "]" in name:  # bracketed IPv6
        name = name[: name.index("]") + 1]

    if name in allowed or host in allowed:
        return None

    logger.warning("Rejected request with unrecognised Host header: %r", request.host)
    return _unauthorized(
        "Unrecognised Host header. Add this hostname to ALLOWED_HOSTS if it is "
        "legitimate.",
        status=403,
    )


def check_size() -> object | None:
    """Reject an oversized body up front.

    Flask only enforces MAX_CONTENT_LENGTH when something reads the request
    data, and these handlers never do — so an arbitrarily large body would be
    accepted and silently ignored. Checking Content-Length explicitly refuses
    it before it is buffered.
    """
    limit = _config().max_content_length
    if request.content_length is not None and request.content_length > limit:
        return _unauthorized(
            f"Request body exceeds the {limit} byte limit.", status=413
        )
    return None


def check_csrf() -> object | None:
    """Require a preflight-forcing header on state-changing requests."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None
    if request.headers.get(CSRF_HEADER, "").strip().lower() == CSRF_VALUE:
        return None
    if _presented_token():  # a real API client authenticating properly
        return None
    return _unauthorized(
        f"State-changing requests must send {CSRF_HEADER}: {CSRF_VALUE} "
        "(or an API token). This blocks cross-site requests from a page the "
        "operator happens to be visiting.",
        status=403,
    )


def check_token() -> object | None:
    """Require the shared secret on /api/* when one is configured."""
    config = _config()
    if config.api_token is None:
        return None
    if not _needs_token(request.path):
        return None

    presented = _presented_token()
    if presented is None:
        return _unauthorized("Authentication required. Send 'Authorization: Bearer <token>'.")
    # Compare as bytes: compare_digest raises on non-ASCII str, and a header is
    # attacker-controlled, so a str comparison turns into a 500 on demand.
    # compare_digest itself is what stops the correct prefix leaking via timing.
    if not hmac.compare_digest(presented.encode("utf-8", "surrogateescape"),
                               config.api_token.encode("utf-8")):
        logger.warning("Rejected a request with an invalid API token from %s", request.remote_addr)
        return _unauthorized("Invalid API token.", status=403)
    return None


def install(app) -> None:
    """Wire the checks in, in the order they should reject."""

    @app.before_request
    def _guard():
        for check in (check_host, check_size, check_csrf, check_token):
            rejection = check()
            if rejection is not None:
                return rejection
        return None

    @app.after_request
    def _headers(response):
        # The UI is same-origin and loads no third-party code; say so, so a
        # reflected-content bug cannot escalate into script execution.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response


def is_loopback(host: str) -> bool:
    """True when binding to `host` keeps the service off the network.

    An empty host is *not* loopback: Werkzeug treats it as "every interface",
    so treating it as safe would let `HOST=` serve the analysis to the network
    with no authentication — the exact thing this check exists to prevent.
    """
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"
