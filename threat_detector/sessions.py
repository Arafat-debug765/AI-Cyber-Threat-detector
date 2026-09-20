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

from .features import DataError, ip_to_int

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


def _parse_timestamps(df: pd.DataFrame) -> pd.Series:
    if "timestamp" not in df.columns:
        raise DataError(
            "Flow features need a 'timestamp' column. Either add one or run with "
            "FEATURE_SET=packet."
        )
    stamps = pd.to_datetime(df["timestamp"], errors="coerce", utc=True, format="mixed")
    if stamps.isna().all():
        raise DataError("No parsable values in the 'timestamp' column.")
    if stamps.isna().any():
        raise DataError(
            f"{int(stamps.isna().sum())} row(s) have an unparsable timestamp."
        )
    return stamps


def _is_external(address: str) -> bool:
    """True when the address is outside RFC1918 space."""
    try:
        return not ipaddress.IPv4Address(str(address).strip()).is_private
    except ValueError:
        return False


def build_flow_features(
    df: pd.DataFrame, window_seconds: int = 60, min_packets: int = 0
) -> pd.DataFrame:
    """Aggregate packets into per-source, per-window behavioural sessions.

    Returns a frame whose index is a RangeIndex and which carries both the
    identity columns (src_ip, window_start) and FLOW_FEATURE_COLUMNS.

    `min_packets` drops windows too small to describe behaviour. A window
    holding one packet — which is what the first and last window of any capture
    tends to be — looks like an extreme outlier to the model on every feature
    at once, and is an artifact of where the capture happened to start, not
    something an analyst can act on.
    """
    if window_seconds < 1:
        raise DataError("window_seconds must be at least 1.")

    work = pd.DataFrame({
        "src_ip": df["src_ip"].astype(str),
        "dst_ip": df["dst_ip"].astype(str),
        "protocol": pd.to_numeric(df["protocol"], errors="coerce"),
        "packet_length": pd.to_numeric(df["packet_length"], errors="coerce"),
        "timestamp": _parse_timestamps(df),
    })
    # Ports are optional: captures without a transport layer simply have none,
    # and distinct_dst_ports then degenerates to a constant rather than failing.
    work["dst_port"] = (
        pd.to_numeric(df["dst_port"], errors="coerce") if "dst_port" in df.columns else 0
    )
    work["external_dst"] = work["dst_ip"].map(_is_external)
    work["small_packet"] = work["packet_length"] < SMALL_PACKET_BYTES

    if work[["protocol", "packet_length"]].isna().any().any():
        raise DataError("Non-numeric protocol/packet_length values in the dataset.")

    work["window_start"] = work["timestamp"].dt.floor(f"{window_seconds}s")
    work = work.sort_values("timestamp")

    grouped = work.groupby(["src_ip", "window_start"], sort=True)
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
    )

    gaps = grouped["timestamp"].apply(_interarrival_stats)
    features["mean_interarrival"] = gaps.map(lambda pair: pair[0])
    features["std_interarrival"] = gaps.map(lambda pair: pair[1])

    # A single-packet window has no spread and no gap; zero is the honest value,
    # and NaN would silently drop the row at fit time.
    features = features.fillna(0.0).reset_index()
    features["src_ip_int"] = features["src_ip"].map(ip_to_int)

    if min_packets > 1:
        keep = features["packets"] >= min_packets
        dropped = int((~keep).sum())
        if dropped:
            logger.info("Ignored %d session(s) with fewer than %d packets",
                        dropped, min_packets)
        features = features[keep].reset_index(drop=True)
        if features.empty:
            raise DataError(
                f"Every session had fewer than {min_packets} packets. Lower "
                "MIN_SESSION_PACKETS, or widen WINDOW_SECONDS so sessions "
                "gather enough traffic to describe behaviour."
            )
    return features


def _interarrival_stats(stamps: pd.Series) -> tuple[float, float]:
    """Mean and standard deviation of gaps between packets, in seconds.

    A low std with a non-trivial mean is the signature of beaconing: machine
    timers are regular in a way human-driven traffic is not.
    """
    if len(stamps) < 2:
        return (0.0, 0.0)
    gaps = stamps.sort_values().diff().dt.total_seconds().dropna()
    return (float(gaps.mean()), float(gaps.std(ddof=0)))


def flow_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """The numeric columns handed to the model, in a stable order."""
    return features[FLOW_FEATURE_COLUMNS]
