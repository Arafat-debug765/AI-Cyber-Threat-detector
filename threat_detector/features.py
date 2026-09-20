"""Feature engineering for raw packet records."""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS: list[str] = ["src_ip", "dst_ip", "protocol", "packet_length"]
FEATURE_COLUMNS: list[str] = ["src_ip_int", "dst_ip_int", "protocol", "packet_length"]


class DataError(ValueError):
    """Raised when the packet dataset is missing, empty or malformed."""


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


def load_packets(path: Path) -> pd.DataFrame:
    """Read the packet CSV, validating that it is usable.

    Error messages name the file, never its absolute path: these strings are
    returned to unauthenticated HTTP clients, and a full path leaks the account
    name and directory layout of the host.
    """
    path = Path(path)
    if not path.exists():
        raise DataError(
            f"Dataset '{path.name}' not found. "
            "Generate one with: threat-detector generate"
        )
    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError as exc:
        raise DataError(f"Dataset '{path.name}' is empty.") from exc

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise DataError(
            f"Dataset '{path.name}' is missing required column(s): {', '.join(missing)}. "
            f"Expected at least: {', '.join(REQUIRED_COLUMNS)}"
        )
    if df.empty:
        raise DataError(f"Dataset '{path.name}' contains no rows.")
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Turn raw packet rows into the numeric matrix the model consumes."""
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


def load_features(path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load the dataset once and return (raw rows, feature matrix)."""
    df = load_packets(path)
    return df, build_features(df)
