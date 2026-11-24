"""Application configuration, driven by environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "threat-detector"


def user_config_dir() -> Path:
    """Per-user configuration directory, honouring XDG_CONFIG_HOME."""
    root = os.getenv("XDG_CONFIG_HOME")
    base = Path(root).expanduser() if root else Path.home() / ".config"
    return base / APP_NAME


def _contamination(raw: str) -> float | str:
    if raw.strip().lower() == "auto":
        return "auto"
    value = float(raw)
    if not 0.0 < value <= 0.5:
        raise ValueError("CONTAMINATION must be in (0, 0.5] or 'auto'.")
    return value


def _host_list(raw: str) -> tuple[str, ...]:
    """Parse ALLOWED_HOSTS. "*" disables the check entirely."""
    hosts = tuple(h.strip().lower() for h in raw.split(",") if h.strip())
    return hosts or ("127.0.0.1",)


def _env_path(name: str, default: str | Path) -> Path:
    """Resolve a path setting; relative paths mean the working directory.

    These used to resolve against the package's own location. From a source
    checkout that happened to be the repository, so it looked right — but an
    installed copy lives in site-packages, and every relative default (the
    capture, the model, and the signing key) was written *into the Python
    installation*: shared by every user of it, invisible to the person who ran
    the command, orphaned by `pip uninstall`, and a PermissionError on a system
    Python. A command-line tool's relative paths mean "here".
    """
    value = Path(os.getenv(name) or default).expanduser()
    return value if value.is_absolute() else Path.cwd() / value


@dataclass(frozen=True)
class Config:
    """Runtime settings. Every field can be overridden by an env var."""

    # default_factory, not a direct call: a plain call would freeze the value at
    # import time, so an env var set afterwards (or by a test) would be ignored.
    data_file: Path = field(default_factory=lambda: _env_path("DATA_FILE", "data/packets.csv"))
    model_file: Path = field(default_factory=lambda: _env_path("MODEL_FILE", "models/model.pkl"))
    # The key authenticating the model deliberately does not live beside it:
    # anything able to write the model could usually read a key in the same
    # directory, which would defeat the signature.
    # Default: the user's config directory, outside any project tree, so the
    # key cannot be committed with the code or shared through a data volume.
    key_file: Path = field(
        default_factory=lambda: _env_path("MODEL_KEY_FILE", user_config_dir() / "model_signing.key")
    )

    # "packet" scores each packet in isolation; "flow" aggregates packets into
    # (source, time window) sessions first, which is what makes scans, sweeps
    # and beaconing detectable at all. See README "Detection altitude".
    feature_set: str = field(default_factory=lambda: os.getenv("FEATURE_SET", "flow").lower())
    window_seconds: int = field(default_factory=lambda: int(os.getenv("WINDOW_SECONDS", "300")))

    # Windows holding fewer packets than this are dropped before fitting. A
    # one-packet window is a capture-boundary artifact, not behaviour, and it
    # scores as an extreme outlier — which, with a threshold calibrated at the
    # minimum baseline score, let a single artifact set the alert bar for the
    # whole system and hid real attacks underneath it. 0 disables the filter.
    min_session_packets: int = field(
        default_factory=lambda: int(os.getenv("MIN_SESSION_PACKETS", "3"))
    )
    # Sessions from a window the capture spans for less than this fraction of
    # its length are dropped. Only the last window can be partial (windows are
    # anchored at the first packet), and a sliver of it once held sessions of
    # three packets in the same second: zero inter-arrival, tiny volume, the
    # most anomalous thing in the baseline — and the threshold calibrated on
    # them hid all four reference attacks.
    min_window_coverage: float = field(
        default_factory=lambda: float(os.getenv("MIN_WINDOW_COVERAGE", "0.5"))
    )

    # Detector: "auto" (default), "lof" or "iforest". `auto` picks by setting,
    # and the choice was measured, not assumed:
    #
    #   flow mode -> LOF. Fitting on a clean baseline is *novelty* detection,
    #     and LOF's distance-based score keeps growing as a session moves
    #     further from anything normal. IsolationForest's does not: a session
    #     at ten times the baseline maximum isolates like one *at* the maximum,
    #     so an exfil moving 560 KB against a ~45 KB baseline scored as less
    #     anomalous than an ordinary host. Across 700 trials with independent
    #     recording times, LOF found all four reference attacks every time;
    #     IsolationForest did so in 695.
    #   packet mode -> IsolationForest, kept for comparison with the original
    #     design, which is what its documented figures describe.
    #
    # An earlier benchmark preferred IsolationForest because it fitted on
    # contaminated data, where LOF's weakness (a tight cluster of anomalies
    # looks locally dense) applies. A clean baseline removes that weakness.
    algorithm: str = field(default_factory=lambda: os.getenv("ALGORITHM", "auto").lower())

    # IsolationForest hyper-parameters.
    n_estimators: int = field(default_factory=lambda: int(os.getenv("N_ESTIMATORS", "100")))
    # "auto" leaves the score offset at scikit-learn's data-independent
    # convention, which is what makes SCORE_THRESHOLD mean the same thing across
    # datasets. A numeric value re-anchors the offset to a quota of the training
    # data, and a fixed threshold then drifts with whatever you trained on.
    contamination: float | str = field(
        default_factory=lambda: _contamination(os.getenv("CONTAMINATION", "auto"))
    )
    random_state: int = field(default_factory=lambda: int(os.getenv("RANDOM_STATE", "42")))

    # Optional baseline capture to fit on. Training on the same traffic you are
    # inspecting teaches the model that the attack is part of normal — the
    # single most important thing to get right here. Point this at known-good
    # traffic and DATA_FILE at the traffic under suspicion.
    baseline_file: Path | None = field(
        default_factory=lambda: (
            _env_path("BASELINE_FILE", "") if os.getenv("BASELINE_FILE") else None
        )
    )

    # The alert threshold is set at this quantile of the *baseline's* scores,
    # which makes it a target false-positive rate: 0.02 means "accept about 2%
    # of known-good sessions alarming". This is an operating point on the ROC
    # curve, chosen by measurement (see docs/ARCHITECTURE.md): across eight
    # independent baselines, 0.02 caught all four reference attacks every time
    # at ~2 false alerts per 75 sessions, while 0.0 — nothing known-good may
    # alarm — caught all four in only six of eight, because the threshold is
    # then set by whatever the single weirdest baseline session happens to be.
    #
    # 0.0 is still available and still meaningful; it trades recall for silence.
    # Left unset it resolves at training time: the default rate with a baseline,
    # or a small quota without one, since fitting and scoring the same file
    # makes any rate below 1/n mathematically silent.
    calibration_quantile: float | None = field(
        default_factory=lambda: (
            float(os.environ["CALIBRATION_QUANTILE"])
            if os.getenv("CALIBRATION_QUANTILE")
            else None
        )
    )

    # Manual override of the calibrated threshold.
    score_threshold: float | None = field(
        default_factory=lambda: (
            float(os.environ["SCORE_THRESHOLD"]) if os.getenv("SCORE_THRESHOLD") else None
        )
    )

    # Cap on how many anomaly rows a single API response may return.
    max_results: int = field(default_factory=lambda: int(os.getenv("MAX_RESULTS", "500")))

    debug: bool = field(
        default_factory=lambda: os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    )

    # ---- access control -------------------------------------------------
    # Shared secret required on /api/*. Unset is allowed only while bound to
    # loopback; serve.py refuses to expose an unauthenticated instance.
    api_token: str | None = field(default_factory=lambda: os.getenv("API_TOKEN") or None)

    # Host headers this instance answers to. A browser on any website can reach
    # a service on 127.0.0.1, and DNS rebinding lets an attacker's page read the
    # responses; checking Host is what stops a hostile page pointing its own
    # domain at this port.
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: _host_list(
            # Names a client puts in Host. 0.0.0.0 used to be listed too; it is
            # a bind address, and no legitimate client ever sends it.
            os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]")
        )
    )

    # Nothing here accepts an upload; a body larger than this is a mistake or
    # an attack, and is rejected before it is buffered.
    max_content_length: int = field(
        default_factory=lambda: int(os.getenv("MAX_CONTENT_LENGTH", str(1 << 20)))
    )

    def __post_init__(self) -> None:
        if self.feature_set not in {"packet", "flow"}:
            raise ValueError(
                f"Unknown FEATURE_SET {self.feature_set!r}. Expected 'packet' or 'flow'."
            )
        if self.calibration_quantile is not None and not 0.0 <= self.calibration_quantile < 1.0:
            raise ValueError("CALIBRATION_QUANTILE must be in [0.0, 1.0).")
        if self.window_seconds < 1:
            raise ValueError("WINDOW_SECONDS must be at least 1.")
        if self.min_session_packets < 0:
            raise ValueError("MIN_SESSION_PACKETS must be zero or positive.")
        if self.algorithm not in {"auto", "iforest", "lof"}:
            raise ValueError(
                f"Unknown ALGORITHM {self.algorithm!r}. Expected 'auto', 'lof' or 'iforest'."
            )
        if not 0.0 <= self.min_window_coverage < 1.0:
            raise ValueError("MIN_WINDOW_COVERAGE must be in [0.0, 1.0).")
        if self.max_content_length < 1:
            raise ValueError("MAX_CONTENT_LENGTH must be positive.")

    @property
    def estimator(self) -> str:
        """The detector actually used, with `auto` resolved by feature set.

        Resolved on read rather than stored, so `replace(config,
        feature_set=...)` re-resolves instead of carrying a stale choice.
        """
        if self.algorithm != "auto":
            return self.algorithm
        return "lof" if self.feature_set == "flow" else "iforest"

    @property
    def job_file(self) -> Path:
        """Where training progress is recorded.

        On disk rather than in memory so status survives a restart and is
        visible to every worker when served under gunicorn.
        """
        return self.model_file.with_name(self.model_file.name + ".training.json")

    def ensure_dirs(self) -> None:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.model_file.parent.mkdir(parents=True, exist_ok=True)
        # Owner-only: the directory holding the signing key should not be
        # listable by other accounts, even though the key itself is 0600.
        self.key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
