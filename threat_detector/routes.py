"""HTTP layer: thin handlers that delegate to the model module."""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import jobs
from . import model as model_service
from .features import DataError
from .integrity import IntegrityError
from .jobs import JobInProgress
from .model import ModelNotTrained

logger = logging.getLogger(__name__)
bp = Blueprint("main", __name__)


def _config():
    return current_app.config["APP_CONFIG"]


@bp.route("/")
def home():
    return render_template("index.html")


@bp.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@bp.route("/api/status")
def status():
    config = _config()
    payload = model_service.status(config)
    payload["training"] = jobs.status(config)
    return jsonify(payload), 200


@bp.route("/api/train", methods=["POST"])
def train():
    """Start a training run.

    Returns 202 immediately rather than holding the connection open for the
    whole fit: a capture large enough to be worth analysing takes longer than
    any sane HTTP timeout. Poll /api/status for progress.
    """
    config = _config()
    record = jobs.start(config, model_service.train)
    return jsonify({
        "message": "Training started.",
        "training": record,
        "poll": "/api/status",
    }), 202


@bp.route("/api/summary")
def summary():
    """Aggregate view of the last scoring run, for the dashboard charts."""
    return jsonify(model_service.summarize(_config())), 200


@bp.route("/api/anomalies")
def anomalies():
    limit = request.args.get("limit", type=int)
    if limit is not None and limit < 1:
        return jsonify({"error": "limit must be a positive integer."}), 400
    return jsonify(model_service.detect(_config(), limit=limit)), 200


# Legacy paths kept so existing clients and the original README keep working.
bp.add_url_rule("/train", view_func=train, methods=["POST"], endpoint="train_legacy")
bp.add_url_rule("/anomalies", view_func=anomalies, endpoint="anomalies_legacy")


@bp.app_errorhandler(DataError)
def handle_data_error(exc: DataError):
    logger.warning("Dataset problem: %s", exc)
    return jsonify({"error": str(exc)}), 400


@bp.app_errorhandler(IntegrityError)
def handle_integrity_error(exc: IntegrityError):
    logger.error("Model integrity check failed: %s", exc)
    return jsonify({"error": str(exc)}), 409


@bp.app_errorhandler(JobInProgress)
def handle_job_in_progress(exc: JobInProgress):
    return jsonify({"error": str(exc)}), 409


@bp.app_errorhandler(ModelNotTrained)
def handle_untrained(exc: ModelNotTrained):
    return jsonify({"error": str(exc)}), 409


@bp.app_errorhandler(HTTPException)
def handle_http_exception(exc: HTTPException):
    """Render Werkzeug's own errors (404, 405, 400 ...) as JSON, not HTML.

    Without this, the catch-all below would turn a 405 Method Not Allowed into
    a 500, hiding the real problem from clients and filling the log with
    tracebacks for ordinary routing mistakes.
    """
    return jsonify({"error": exc.description or exc.name}), exc.code or 500


@bp.app_errorhandler(Exception)
def handle_unexpected(exc: Exception):
    # Log the detail, return a generic message: stack traces and filesystem
    # paths in an HTTP response are an information leak.
    logger.exception("Unhandled error: %s", exc)
    return jsonify({"error": "Internal server error."}), 500
