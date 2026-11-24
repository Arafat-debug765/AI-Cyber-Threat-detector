"""Loading, cleaning and per-packet feature engineering.

Real captures are messy. A dual-stack network produces IPv6 rows, exports pad
headers with spaces, tools disagree about timestamp formats, and a single
malformed row is routine. The rule here: **drop what cannot be analysed, say
how much was dropped and why, and fail only when nothing usable is left.**
Rejecting a million-row capture because of one IPv6 packet made the tool
unusable on exactly the networks it is meant for; silently dropping rows would
make it untrustworthy. Counting them, and surfacing the count in every result,
is the honest middle.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

REQUIRED_COLUMNS: list[str] = ["src_ip", "dst_ip", "protocol", "packet_length"]
FEATURE_COLUMNS: list[str] = ["src_ip_int", "dst_ip_int", "protocol", "packet_length"]

# The CSV schema every producer writes: the generator, pcap ingest, and live
# capture. Defined once so the three cannot drift apart.
CSV_FIELDS: list[str] = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_length",
]

# Key under DataFrame.attrs carrying the per-reason drop counts, so they travel
# with the frame to the model layer without widening every signature.
DROPPED_ATTR = "rows_dropped"


class DataError(ValueError):
    """Raised when the packet dataset is missing, empty, or has nothing usable."""


def ip_to_int(address: str) -> int:
    """Convert a dotted-quad IPv4 address to its 32-bit integer value.

    The original implementation summed the octets, which collided badly
    (192.168.1.5 and 5.1.168.192 both hashed to 366). A packed integer keeps
    every address distinct and preserves subnet ordering, which is exactly the
    structure IsolationForest can split on.
    """
    try:
        return int(ipaddress.IPv4Address(str(address).strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise DataError(f"Invalid IPv4 address: {address!r}") from exc


def _is_ipv4(address) -> bool:
    try:
        ipaddress.IPv4Address(str(address).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def parse_timestamps(column: pd.Series) -> pd.Series:
    """Parse a timestamp column into UTC datetimes; NaT where it cannot.

    Numeric timestamps are Unix epoch values, and their unit is inferred from
    magnitude. pandas' default reads a bare integer as *nanoseconds*, so
    `1767225600` — 2026-01-01 in seconds, the format tcpdump, tshark and scapy
    all export — silently became 1970-01-01T00:00:01.767. Every packet then
    landed in one window at the epoch, sessions merged across the whole
    capture, and detection produced confident garbage with no error at all.
    """
    numeric = pd.to_numeric(column, errors="coerce")
    if numeric.notna().mean() > 0.5:
        magnitude = float(np.nanmedian(np.abs(numeric.to_numpy(dtype=float))))
        # Seconds stay below 1e11 until the year 5138; each step up is x1000.
        unit = ("s" if magnitude < 1e11 else
                "ms" if magnitude < 1e14 else
                "us" if magnitude < 1e17 else "ns")
        return pd.to_datetime(numeric, unit=unit, utc=True, errors="coerce")
    return pd.to_datetime(column, errors="coerce", utc=True, format="mixed")


def load_packets(path: Path) -> pd.DataFrame:
    """Read the packet CSV and check it has the columns analysis needs.

    Error messages name the file, never its absolute path: these strings are
    returned to HTTP clients, and a full path leaks the account name and
    directory layout of the host.
    """
    path = Path(path)
    if not path.exists():
        raise DataError(
            f"Dataset '{path.name}' not found. "
            "Generate one with: threat-detector generate"
        )
    try:
        df = pd.read_csv(path, skipinitialspace=True)
    except pd.errors.EmptyDataError as exc:
        raise DataError(f"Dataset '{path.name}' is empty.") from exc
    except pd.errors.ParserError as exc:
        raise DataError(f"Dataset '{path.name}' is not valid CSV: {exc}") from exc

    # Hand-edited and spreadsheet-exported CSVs pad headers ("src_ip, dst_ip"),
    # which made every column look missing.
    df.columns = [str(c).strip() for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise DataError(
            f"Dataset '{path.name}' is missing required column(s): {', '.join(missing)}. "
            f"Expected at least: {', '.join(REQUIRED_COLUMNS)}"
        )
    if df.empty:
        raise DataError(f"Dataset '{path.name}' contains no rows.")
    return df


def clean_packets(df: pd.DataFrame, require_timestamps: bool = False) -> pd.DataFrame:
    """Drop rows that cannot be analysed, recording how many and why.

    Returns a copy with numeric columns coerced, a parsed `_ts` column when
    timestamps are required, and the drop counts in `.attrs[DROPPED_ATTR]`.
    """
    work = df.copy()
    work["protocol"] = pd.to_numeric(work["protocol"], errors="coerce")
    work["packet_length"] = pd.to_numeric(work["packet_length"], errors="coerce")

    reasons: dict[str, pd.Series] = {
        "non_ipv4_address": ~(work["src_ip"].map(_is_ipv4) & work["dst_ip"].map(_is_ipv4)),
        "non_numeric_field": work[["protocol", "packet_length"]].isna().any(axis=1),
        # A packet has positive length, and IP protocol numbers are one byte.
        "out_of_range_value": (work["packet_length"] <= 0)
        | ~work["protocol"].between(0, 255),
    }
    if require_timestamps:
        if "timestamp" not in work.columns:
            raise DataError(
                "Flow features need a 'timestamp' column. Either add one or run "
                "with FEATURE_SET=packet."
            )
        work["_ts"] = parse_timestamps(work["timestamp"])
        reasons["unparsable_timestamp"] = work["_ts"].isna()

    # Attribute each dropped row to the first reason that applies, so the
    # counts add up to the number of rows actually removed.
    bad = pd.Series(False, index=work.index)
    dropped: dict[str, int] = {}
    for reason, mask in reasons.items():
        fresh = mask.fillna(True) & ~bad
        if fresh.any():
            dropped[reason] = int(fresh.sum())
        bad |= mask.fillna(True)

    clean = work[~bad].reset_index(drop=True)
    total = int(bad.sum())
    if clean.empty:
        detail = ", ".join(f"{n} {r.replace('_', ' ')}" for r, n in dropped.items())
        raise DataError(f"No usable rows: all {len(work)} were dropped ({detail}).")
    if total:
        logger.warning(
            "Dropped %d of %d rows that cannot be analysed: %s",
            total, len(work), ", ".join(f"{r}={n}" for r, n in dropped.items()),
        )

    clean.attrs[DROPPED_ATTR] = dropped
    return clean


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Turn cleaned packet rows into the numeric matrix the model consumes."""
    features = pd.DataFrame(index=df.index)
    features["src_ip_int"] = df["src_ip"].map(ip_to_int)
    features["dst_ip_int"] = df["dst_ip"].map(ip_to_int)
    features["protocol"] = pd.to_numeric(df["protocol"], errors="coerce")
    features["packet_length"] = pd.to_numeric(df["packet_length"], errors="coerce")

    invalid = features[["protocol", "packet_length"]].isna().any(axis=1)
    if invalid.any():
        bad_rows = df.index[invalid].tolist()[:5]
        raise DataError(
            "Non-numeric protocol/packet_length values in row(s): "
            f"{bad_rows}{' ...' if invalid.sum() > 5 else ''}"
        )
    return features[FEATURE_COLUMNS]


def rows_dropped(frame: pd.DataFrame) -> dict[str, int]:
    """Drop counts recorded on a frame by clean_packets, by reason."""
    return dict(frame.attrs.get(DROPPED_ATTR, {}))
