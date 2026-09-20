"""End-to-end detection check: does it find planted attacks, and stay quiet?

Unit tests confirm the code runs. This confirms the detector still *detects* —
the property that actually matters, and the one a refactor can silently break.
Used by `threat-detector selfcheck` and by CI.
"""
from __future__ import annotations

import math
import sys
from dataclasses import replace

from .config import Config
from .model import detect, train
from .synth import ATTACKS

# All four planted behaviours must be found. This was three while the threshold
# was calibrated at the baseline minimum, which made recall hostage to the
# baseline's worst artifact; at the measured default false-positive rate it is
# four out of four across every seed tried, so the gate says four.
REQUIRED_HITS = 4


def run(config: Config) -> int:
    """Return a process exit code: 0 pass, 1 detection regression, 2 misuse."""
    if config.baseline_file is None:
        print("Set a baseline (--baseline or BASELINE_FILE) to a known-good capture.",
              file=sys.stderr)
        return 2

    trained = train(config)
    print(f"fitted {trained['algorithm']}/{trained['feature_set']} on "
          f"{trained['rows_trained']} rows from {trained['fitted_on']}, "
          f"threshold {trained['threshold']}")

    sources = {source: name for name, (_, source) in ATTACKS.items()}
    result = detect(config)
    flagged = [row["src_ip"] for row in result["anomalies"]]
    caught = {sources[ip] for ip in flagged if ip in sources}
    false_positives = [ip for ip in flagged if ip not in sources]

    print(f"alerts: {result['count']} of {result['total_packets']} sessions")
    print(f"caught: {sorted(caught) or 'NONE'}")
    print(f"false positives: {len(false_positives)}")

    # Scored against the baseline it was fitted to, the model should alarm on
    # no more than the calibrated false-positive rate — that rate is what the
    # threshold was chosen to deliver, so anything above it is a regression.
    quiet = detect(replace(config, data_file=config.baseline_file))
    rate = trained["calibration_quantile"]
    allowed = math.ceil(rate * quiet["total_packets"])
    print(f"alerts on clean baseline: {quiet['count']} "
          f"(allowed {allowed} at a {rate:.1%} false-positive rate)")

    failures = []
    if len(caught) < REQUIRED_HITS:
        failures.append(f"found only {len(caught)}/{len(ATTACKS)} attacks "
                        f"(need {REQUIRED_HITS})")
    if quiet["count"] > allowed:
        failures.append(f"{quiet['count']} alerts on known-good traffic, "
                        f"above the {allowed} implied by the calibrated rate")

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0
