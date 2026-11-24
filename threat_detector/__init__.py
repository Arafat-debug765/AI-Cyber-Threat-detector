"""Application factory for the AI Cyber Threat Detector."""
from __future__ import annotations

import logging

from flask import Flask

from . import auth
from .config import Config

__version__ = "1.0.0"

__all__ = ["Config", "__version__", "create_app"]

logger = logging.getLogger(__name__)


def create_app(config: Config | None = None) -> Flask:
    """Build a configured Flask app.

    Taking config as an argument (rather than reading globals at import time)
    is what lets the test-suite point the app at a temporary dataset.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = Flask(__name__)
    cfg = config or Config()
    cfg.ensure_dirs()
    app.config["APP_CONFIG"] = cfg
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_content_length

    from .routes import bp

    app.register_blueprint(bp)
    auth.install(app)

    if cfg.api_token is None:
        logger.warning(
            "No API_TOKEN set: anyone who can reach this port can read the "
            "analysis and start a training run. Acceptable on loopback only."
        )
    return app
