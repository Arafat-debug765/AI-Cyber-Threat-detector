"""Training, persistence and scoring for the anomaly detector."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .config import BASE_DIR, Config
from .features import build_features, load_packets
from .integrity import IntegrityError, dump_signed, load_signed, signing_key
from .sessions import build_flow_features, flow_matrix

logger = logging.getLogger(__name__)

# One scoring pass, shared. Clicking "Detect" calls /api/anomalies and
# /api/summary, which previously each re-read the capture and re-ran the model
# over every row — twice the work for one button press, growing linearly with
# the capture. Keyed on what would invalidate it: the files themselves.
_cache_lock = threading.Lock()
_cache: dict | None = None


def _fingerprint(config: Config) -> tuple:
    """Everything that would change the result, cheaply observable."""
    def stamp(path: Path) -> tuple:
        try:
            stat = Path(path).stat()
        except OSError:
            return (None, None)
        return (stat.st_mtime_ns, stat.st_size)

    return (
        stamp(config.model_file),
        stamp(config.data_file),
        str(config.data_file),
        str(config.model_file),
        config.feature_set,
        config.window_seconds,
        config.min_session_packets,
        config.score_threshold,
    )


def scored(config: Config) -> tuple[dict, pd.DataFrame, np.ndarray, np.ndarray]:
    """(bundle, reportable rows, scores, flags) for the current data and model."""
    global _cache
    key = _fingerprint(config)

    with _cache_lock:
        if _cache is not None and _cache["key"] == key:
            return _cache["value"]

    bundle = load_model(config)
    raw, features = load_for_model(config)
    scores = bundle["model"].decision_function(features)
    flags = _flag(scores, bundle, config)
    value = (bundle, raw, scores, flags)

    with _cache_lock:
        _cache = {"key": key, "value": value, "features": features}
    return value


def clear_cache() -> None:
    """Drop the memoised scoring pass. Called after training."""
    global _cache
    with _cache_lock:
        _cache = None


class ModelNotTrained(RuntimeError):
    """Raised when a prediction is requested before a model exists on disk."""


BUNDLE_VERSION = 2

# Without a clean baseline the model is fitted on the very data it will score,
# so the lowest training score *is* the most anomalous row: a 0.0 quantile can
# never fire. Fall back to a small quota and say so.
FALLBACK_QUANTILE = 0.02

# Default target false-positive rate against the baseline. Measured, not
# guessed — see the comment on Config.calibration_quantile.
DEFAULT_FALSE_POSITIVE_RATE = 0.02

# How far below the rest of the baseline a single session has to sit before we
# treat it as an artifact rather than a data point. Expressed in units of the
# spread of the remaining scores.
_OUTLIER_MARGIN = 3.0


def _calibration_quantile(config: Config) -> float:
    if config.calibration_quantile is not None:
        return config.calibration_quantile
    if config.baseline_file is not None:
        return DEFAULT_FALSE_POSITIVE_RATE
    logger.warning(
        "No BASELINE_FILE set: fitting on the traffic under inspection, so "
        "alerts are a %.0f%% quota rather than a calibrated judgement. Point "
        "BASELINE_FILE at known-good traffic for real detection.",
        FALLBACK_QUANTILE * 100,
    )
    return FALLBACK_QUANTILE


def _warn_if_threshold_is_set_by_an_outlier(scores, quantile: float, threshold: float) -> None:
    """Say so when one freak baseline session is deciding the alert bar.

    At quantile 0.0 the threshold is the single lowest baseline score. If that
    score sits far below everything else it is usually an artifact — a short
    window at the edge of the capture — and it drags the bar down far enough to
    hide real attacks underneath it. That failure is silent otherwise: training
    succeeds, detection simply stops working.
    """
    ordered = np.sort(np.asarray(scores))
    if quantile > 0 or len(ordered) < 10:
        return

    rest = ordered[1:]
    spread = float(np.percentile(rest, 75) - np.percentile(rest, 25))
    gap = float(rest[0] - ordered[0])
    if spread > 0 and gap > _OUTLIER_MARGIN * spread:
        logger.warning(
            "The alert threshold (%.4f) is set by a single baseline session "
            "scoring %.4f below the next one — likely an artifact, not "
            "behaviour. Real anomalies may score above it and go unreported. "
            "Raise MIN_SESSION_PACKETS, or set CALIBRATION_QUANTILE to a small "
            "false-positive rate such as %.2f.",
            threshold, gap, DEFAULT_FALSE_POSITIVE_RATE,
        )


def load_for_model(config: Config, path: Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (reportable rows, numeric matrix) for the configured feature set.

    In flow mode the reportable row *is* a session — one source over one time
    window — which is also the unit an analyst can act on. In packet mode it is
    the packet.
    """
    df = load_packets(path or config.data_file)
    if config.feature_set == "flow":
        flows = build_flow_features(df, config.window_seconds, config.min_session_packets)
        return flows, flow_matrix(flows)
    return df, build_features(df)


def build_estimator(config: Config):
    """Construct the configured detector.

    IsolationForest splits on raw thresholds, so it needs no scaling. LOF is
    distance-based and is meaningless unscaled here — packet_length spans a far
    wider range than protocol — so it is wrapped in a scaling pipeline.
    `novelty=True` is what makes a LOF model persistable and reusable at all.
    """
    if config.algorithm == "lof":
        return Pipeline([
            ("scale", StandardScaler()),
            ("lof", LocalOutlierFactor(
                n_neighbors=20,
                # LOF has no "auto" mode; fall back to the conventional quota.
                contamination=0.05 if config.contamination == "auto" else config.contamination,
                novelty=True,
            )),
        ])
    return IsolationForest(
        n_estimators=config.n_estimators,
        contamination=config.contamination,
        random_state=config.random_state,
    )


def train(config: Config) -> dict:
    """Fit the detector and calibrate its alert threshold.

    Fits on `baseline_file` when one is configured, otherwise on the dataset
    itself. Fitting on the traffic under inspection is the default only because
    a first-run demo has nothing else; it is methodologically weak, because an
    attack present in the training data pulls the notion of "normal" toward
    itself. The response says which file was used.
    """
    fit_path = config.baseline_file or config.data_file
    _, features = load_for_model(config, fit_path)
    model = build_estimator(config)
    model.fit(features)

    # Calibrate on the training scores: raw scores are only comparable within a
    # single fitted model, so a hard-coded threshold would drift with the data.
    training_scores = model.decision_function(features)
    quantile = _calibration_quantile(config)
    threshold = float(np.quantile(training_scores, quantile))
    _warn_if_threshold_is_set_by_an_outlier(training_scores, quantile, threshold)

    bundle = {
        "version": BUNDLE_VERSION,
        "model": model,
        "algorithm": config.algorithm,
        "feature_set": config.feature_set,
        "window_seconds": config.window_seconds,
        "min_session_packets": config.min_session_packets,
        "feature_columns": list(features.columns),
        "threshold": threshold,
        "fitted_on": _public_path(fit_path),
        "rows_trained": len(features),
    }

    config.ensure_dirs()
    dump_signed(bundle, config.model_file, _key(config))
    clear_cache()
    logger.info("Trained %s/%s on %d rows from %s (threshold %.6f), saved to %s",
                config.algorithm, config.feature_set, len(features), fit_path,
                threshold, config.model_file)

    summary = {
        "message": "Model trained successfully.",
        "algorithm": config.algorithm,
        "feature_set": config.feature_set,
        "rows_trained": len(features),
        "features": list(features.columns),
        "contamination": config.contamination,
        "threshold": round(threshold, 6),
        "calibration_quantile": quantile,
        "fitted_on": _public_path(fit_path),
        "fitted_on_baseline": config.baseline_file is not None,
        "model_path": _public_path(config.model_file),
    }
    if config.algorithm == "iforest":
        summary["n_estimators"] = config.n_estimators
    return summary


def _key(config: Config) -> bytes:
    return signing_key(config.key_file, models_dir=config.model_file.parent)


def load_model(config: Config) -> dict:
    """Load the saved bundle, refusing anything that does not match this config.

    The MAC is checked inside `load_signed` before any unpickling happens.
    """
    if not Path(config.model_file).exists():
        raise ModelNotTrained("No trained model found. POST to /api/train first.")

    bundle = load_signed(config.model_file, _key(config))

    if not isinstance(bundle, dict) or bundle.get("version") != BUNDLE_VERSION:
        raise ModelNotTrained(
            "Stored model is from an older version of this app. Retrain it."
        )

    # A model is only meaningful against the shape of data it was fitted on.
    # Scoring 60-second sessions with a model fitted on 300-second ones produces
    # confident nonsense, so these disagreements are refused rather than warned
    # about.
    for setting, current in (
        ("feature_set", config.feature_set),
        ("algorithm", config.algorithm),
    ):
        if bundle.get(setting) != current:
            raise ModelNotTrained(
                f"Stored model was fitted with {setting}='{bundle.get(setting)}' "
                f"but this instance is configured for '{current}'. "
                "Retrain, or switch the setting back."
            )
    if config.feature_set == "flow" and bundle.get("window_seconds") != config.window_seconds:
        raise ModelNotTrained(
            f"Stored model was fitted with WINDOW_SECONDS="
            f"{bundle.get('window_seconds')} but this instance uses "
            f"{config.window_seconds}. Session features are not comparable "
            "across window sizes — retrain, or switch the setting back."
        )
    return bundle


def detect(config: Config, limit: int | None = None) -> dict:
    """Score every packet and return the rows flagged as anomalous.

    Rows are sorted by anomaly score (most anomalous first) so a truncated
    response still shows the packets that matter most.
    """
    _bundle, raw, scores, predictions = scored(config)

    results = raw.copy()
    results["anomaly_score"] = scores
    anomalies = results[predictions == -1].sort_values("anomaly_score")

    total_flagged = len(anomalies)
    cap = config.max_results if limit is None else min(limit, config.max_results)
    truncated = total_flagged > cap

    return {
        "anomalies": _to_records(anomalies.head(cap)),
        "count": total_flagged,
        "returned": min(total_flagged, cap),
        "truncated": truncated,
        "total_packets": len(results),
    }


# IANA protocol numbers worth naming in the UI.
PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

SCORE_BINS = 24


def summarize(config: Config) -> dict:
    """Aggregates for the dashboard: score distribution and protocol split.

    Computed server-side so the browser never has to hold the full dataset,
    and so the numbers on the charts are the same ones the model produced.
    """
    _bundle, raw, scores, flags = scored(config)
    flagged = flags == -1

    frame = pd.DataFrame({"score": scores, "flagged": flagged})
    if config.feature_set == "flow":
        frame["group"] = raw["src_ip"].to_numpy()
        breakdown_label, unit = "source", "sessions"
    else:
        frame["group"] = raw["protocol"].astype(int).to_numpy()
        breakdown_label, unit = "protocol", "packets"

    return {
        "unit": unit,
        "breakdown_label": breakdown_label,
        "total_packets": len(frame),
        "flagged": int(frame["flagged"].sum()),
        "flag_rate": round(float(frame["flagged"].mean()), 4),
        "min_score": round(float(frame["score"].min()), 6),
        "max_score": round(float(frame["score"].max()), 6),
        "score_histogram": _score_histogram(frame),
        "protocols": _group_breakdown(frame, breakdown_label),
    }


def _score_histogram(frame: pd.DataFrame) -> list:
    """Bin anomaly scores, splitting each bin into normal vs flagged counts."""
    # Equal-width bins over the observed range. `include_lowest` only works
    # with a bin *count* — with an IntervalIndex pandas ignores it, and the
    # single lowest-scoring packet (the most anomalous one) falls out of the
    # left-open first interval and disappears from the chart.
    binned = pd.cut(frame["score"], bins=SCORE_BINS, include_lowest=True)
    grouped = frame.groupby([binned, "flagged"], observed=False).size().unstack(fill_value=0)

    bins = []
    for interval, row in grouped.iterrows():
        bins.append({
            "start": round(float(interval.left), 6),
            "end": round(float(interval.right), 6),
            "normal": int(row.get(False, 0)),
            "flagged": int(row.get(True, 0)),
        })
    return bins


def _group_breakdown(frame: pd.DataFrame, label: str) -> list:
    """Normal/flagged counts per group (protocol, or source in flow mode)."""
    grouped = frame.groupby(["group", "flagged"], observed=True).size().unstack(fill_value=0)
    rows = []
    for key, row in grouped.iterrows():
        normal, flagged = int(row.get(False, 0)), int(row.get(True, 0))
        name = PROTOCOL_NAMES.get(key, f"proto {key}") if label == "protocol" else str(key)
        rows.append({
            "protocol": int(key) if label == "protocol" else None,
            "name": name,
            "normal": normal,
            "flagged": flagged,
            "total": normal + flagged,
        })
    # Rank by flagged count, then by what share of the group's activity was
    # flagged: "1 of 1 sessions" is a stronger signal than "1 of 40".
    rows.sort(key=lambda r: (r["flagged"], r["flagged"] / r["total"]), reverse=True)
    return rows


def _flag(scores, bundle: dict, config: Config):
    """Anomalous/normal per row, judged against the calibrated threshold.

    An explicit SCORE_THRESHOLD wins; otherwise the threshold stored with the
    model is used. Either way the decision is absolute — clean traffic produces
    no alerts, instead of the fixed quota `predict()` would always emit.
    """
    threshold = config.score_threshold
    if threshold is None:
        threshold = bundle["threshold"]
    return np.where(scores < threshold, -1, 1)


def status(config: Config) -> dict:
    """Describe what the app currently has on disk, for the UI to display."""
    model_path = Path(config.model_file)
    data_path = Path(config.data_file)
    info = {
        "model_trained": model_path.exists(),
        "model_path": _public_path(model_path),
        "dataset_present": data_path.exists(),
        "dataset_path": _public_path(data_path),
        "feature_set": config.feature_set,
        "algorithm": config.algorithm,
        "window_seconds": config.window_seconds,
        "fitted_on_baseline": config.baseline_file is not None,
        "trained_at": (
            pd.Timestamp(model_path.stat().st_mtime, unit="s", tz="UTC").isoformat()
            if model_path.exists()
            else None
        ),
        "model_usable": False,
        "model_problem": None,
    }
    # "A file exists" is not the same as "a model this instance can use". Say
    # which, so the UI does not offer Detect against a model that will 409.
    if model_path.exists():
        try:
            bundle = load_model(config)
        except (ModelNotTrained, IntegrityError) as exc:
            info["model_problem"] = str(exc)
        else:
            info["model_usable"] = True
            info["threshold"] = round(float(bundle["threshold"]), 6)
            info["rows_trained"] = bundle.get("rows_trained")
            info["fitted_on"] = bundle.get("fitted_on")
    return info


def _public_path(path: Path) -> str:
    """A path safe to hand to a client: relative to the project root if possible.

    The API is unauthenticated, so absolute paths in responses would disclose
    the host account name and directory layout. Logs keep the full path.
    """
    try:
        return str(Path(path).relative_to(BASE_DIR))
    except ValueError:
        return Path(path).name


def _to_records(df: pd.DataFrame) -> list:
    """JSON-safe records.

    Flask's encoder chokes on numpy scalars (int64/float64), so round-trip
    through pandas' own JSON writer, which normalises them to Python types.
    Datetimes become ISO-8601 strings rather than pandas' default epoch
    milliseconds — `window_start: 1789878600000` is unreadable in the API and
    on the command line, and every consumer would have to know the unit.
    """
    return json.loads(df.to_json(orient="records", date_format="iso"))
