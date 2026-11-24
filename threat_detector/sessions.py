"""Flow-level feature engineering.

Per-packet features (two IPs, a protocol, a length) can only describe a packet
in isolation, so they cannot represent the things that actually look like an
attack: a port scan is *many destinations ports from one source in a short
window*, beaconing is *regular inter-arrival times*, exfiltration is *volume
skewed to one destination*. None of that survives being looked at one packet at
a time.

This module aggregates packets into (source, time window) sessions and derives
the behavioural features that make those patterns visible.
"""
from __future__ import annotations

import ipaddress
import logging

import pandas as pd

from .features import DROPPED_ATTR, DataError, clean_packets, rows_dropped

logger = logging.getLogger(__name__)

FLOW_FEATURE_COLUMNS = [
    "packets",
    "bytes_total",
    "mean_length",
    "std_length",
    "distinct_dst_ips",
    "distinct_dst_ports",
    "distinct_protocols",
    "mean_interarrival",
    "std_interarrival",
    "small_packet_ratio",
    "external_dst_ratio",
]

# Identity columns kept alongside the features so a flagged row is actionable.
FLOW_KEY_COLUMNS = ["src_ip", "window_start"]

SMALL_PACKET_BYTES = 100


def _is_external(address: str) -> bool:
    """True when the address is outside RFC1918 space."""
    try:
        return not ipaddress.IPv4Address(str(address).strip()).is_private
    except ValueError:
        return False


def build_flow_features(
    df: pd.DataFrame,
    window_seconds: int = 60,
    min_packets: int = 0,
    min_coverage: float = 0.0,
) -> pd.DataFrame:
    """Aggregate packets into per-source, per-window behavioural sessions.

    Accepts raw packet rows; anything that cannot be analysed is dropped by
    `clean_packets`, and the counts travel on `.attrs` with the result.

    Returns a frame with a RangeIndex carrying the identity columns
    (src_ip, window_start) and FLOW_FEATURE_COLUMNS.

    `min_packets` drops windows too small to describe behaviour. A window
    holding one packet — which is what the first and last window of any capture
    tends to be — looks like an extreme outlier to the model on every feature
    at once, and is an artifact of where the capture happened to start, not
    something an analyst can act on.
    """
    if window_seconds < 1:
        raise DataError("window_seconds must be at least 1.")

    clean = clean_packets(df, require_timestamps=True)
    dropped = rows_dropped(clean)

    work = pd.DataFrame({
        "src_ip": clean["src_ip"].astype(str).str.strip(),
        "dst_ip": clean["dst_ip"].astype(str).str.strip(),
        "protocol": clean["protocol"],
        "packet_length": clean["packet_length"],
        "timestamp": clean["_ts"],
        # Ports are optional: captures without a transport layer have none,
        # and distinct_dst_ports then degenerates to a constant.
        "dst_port": (pd.to_numeric(clean["dst_port"], errors="coerce").fillna(0)
                     if "dst_port" in clean.columns else 0),
    })
    work["external_dst"] = work["dst_ip"].map(_is_external)
    work["small_packet"] = work["packet_length"] < SMALL_PACKET_BYTES
    # Windows are anchored at the capture's first packet, not the wall clock.
    # Flooring to clock boundaries meant a capture that began at 03:54:58 got
    # a two-second first window: every host contributed a sliver session of a
    # few packets, those slivers scored as the most anomalous thing in the
    # baseline, and the threshold calibrated on them sat below three of the
    # four reference attacks. The same traffic recorded a minute later was
    # analysed correctly. Results must not depend on the time of day a capture
    # happened to start.
    width = pd.Timedelta(seconds=window_seconds)
    origin = work["timestamp"].min()
    work["window_start"] = origin + ((work["timestamp"] - origin) // width) * width
    end = work["timestamp"].max()

    keys = ["src_ip", "window_start"]
    work = work.sort_values([*keys, "timestamp"], kind="stable")
    # Gap to the previous packet *within the same session*: vectorised, rather
    # than calling a Python function once per session, which dominated runtime
    # on captures with many short sessions.
    work["gap"] = work.groupby(keys, sort=False)["timestamp"].diff().dt.total_seconds()

    grouped = work.groupby(keys, sort=True)
    features = grouped.agg(
        packets=("packet_length", "size"),
        bytes_total=("packet_length", "sum"),
        mean_length=("packet_length", "mean"),
        std_length=("packet_length", "std"),
        distinct_dst_ips=("dst_ip", "nunique"),
        distinct_dst_ports=("dst_port", "nunique"),
        distinct_protocols=("protocol", "nunique"),
        small_packet_ratio=("small_packet", "mean"),
        external_dst_ratio=("external_dst", "mean"),
        mean_interarrival=("gap", "mean"),
    )
    # Population deviation (ddof=0): a two-packet session has one gap and
    # therefore zero spread, not an undefined one.
    features["std_interarrival"] = grouped["gap"].std(ddof=0)

    # A single-packet window has no spread and no gap; zero is the honest value,
    # and NaN would silently drop the row at fit time.
    features = features.fillna(0.0).reset_index()

    if min_coverage > 0:
        # How much of each window the capture actually spans. Anchoring makes
        # every window complete except possibly the last; a session from a
        # window the capture covers for two seconds describes two seconds of
        # behaviour and is not comparable with five minutes of it.
        covered = ((end - features["window_start"]).clip(upper=width) / width).clip(lower=0)
        partial = covered < min_coverage
        # A capture shorter than one window is *all* partial window; keep it.
        if partial.any() and not partial.all():
            logger.info("Ignored %d session(s) in a window the capture covers "
                        "for under %.0f%% of its length", int(partial.sum()), min_coverage * 100)
            features = features[~partial].reset_index(drop=True)

    if min_packets > 1:
        keep = features["packets"] >= min_packets
        tiny = int((~keep).sum())
        if tiny:
            logger.info("Ignored %d session(s) with fewer than %d packets", tiny, min_packets)
        features = features[keep].reset_index(drop=True)
        if features.empty:
            raise DataError(
                f"Every session had fewer than {min_packets} packets. Lower "
                "MIN_SESSION_PACKETS, or widen WINDOW_SECONDS so sessions "
                "gather enough traffic to describe behaviour."
            )

    features.attrs[DROPPED_ATTR] = dropped
    return features


def flow_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """The numeric columns handed to the model, in a stable order."""
    return features[FLOW_FEATURE_COLUMNS]
