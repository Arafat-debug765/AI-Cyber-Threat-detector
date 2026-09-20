#!/usr/bin/env python3
"""Benchmark anomaly-detection models on labelled synthetic traffic.

The app is unsupervised, but synthetic data has ground truth, so model choice
can be measured instead of guessed. Two difficulty regimes are generated:

  obvious    — anomalies use rare protocols, huge payloads, off-subnet sources
  subtle     — anomalies look ordinary except for one mildly-off attribute
  overlapping— every attribute is individually in-range; only the *combination*
               is wrong (an ICMP packet carrying a TCP-sized payload). This is
               the regime that actually separates the models.

    python scripts/benchmark_models.py
    python scripts/benchmark_models.py --count 5000 --regime subtle
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_detector.features import FEATURE_COLUMNS, build_features

NORMAL_PROTOCOLS = [1, 6, 17]
ODD_PROTOCOLS = [47, 50, 89, 132]

# Normal traffic pairs each protocol with a characteristic payload size.
PROTOCOL_LENGTHS = {1: (40, 120), 6: (200, 800), 17: (60, 300)}


def make_dataset(count: int, rate: float, regime: str, seed: int) -> tuple[pd.DataFrame, np.ndarray]:
    """Return (features, labels) with 1 = anomaly."""
    rng = random.Random(seed)
    rows, labels = [], []
    for _ in range(count):
        anomalous = rng.random() < rate
        if not anomalous:
            protocol = rng.choice(NORMAL_PROTOCOLS)
            low, high = PROTOCOL_LENGTHS[protocol] if regime == "overlapping" else (40, 600)
            row = {
                "src_ip": f"192.168.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "dst_ip": f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "protocol": protocol,
                "packet_length": rng.randint(low, high),
            }
        elif regime == "overlapping":
            # Same protocols, same global length range as normal traffic — but
            # the payload size belongs to a *different* protocol. No single
            # feature is out of band; only the pairing is wrong.
            protocol = rng.choice(NORMAL_PROTOCOLS)
            other = rng.choice([p for p in NORMAL_PROTOCOLS if p != protocol])
            low, high = PROTOCOL_LENGTHS[other]
            row = {
                "src_ip": f"192.168.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "dst_ip": f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "protocol": protocol,
                "packet_length": rng.randint(low, high),
            }
        elif regime == "obvious":
            row = {
                "src_ip": f"{rng.randint(11, 223)}.{rng.randint(0, 255)}."
                          f"{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                "dst_ip": f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "protocol": rng.choice(ODD_PROTOCOLS),
                "packet_length": rng.randint(4000, 65535),
            }
        else:  # subtle: ordinary protocol, one attribute mildly out of band
            row = {
                "src_ip": f"192.168.{rng.randint(8, 11)}.{rng.randint(1, 254)}",
                "dst_ip": f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
                "protocol": rng.choice(NORMAL_PROTOCOLS),
                "packet_length": rng.randint(700, 1100),
            }
        rows.append(row)
        labels.append(1 if anomalous else 0)
    return build_features(pd.DataFrame(rows)), np.array(labels)


class RankEnsemble:
    """Average the percentile ranks of IsolationForest and LOF.

    The two fail in opposite directions: IsolationForest misses contextual
    anomalies (in-range values, wrong combination), LOF misses *clustered*
    global outliers because a tight clump of them looks locally dense. Ranking
    each and averaging keeps whichever one is confident.
    """

    def __init__(self, contamination: float, seed: int):
        self.contamination = contamination
        self.forest = IsolationForest(n_estimators=100, contamination=contamination,
                                      random_state=seed)
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=contamination)

    def fit_score(self, X):
        forest_scores = self.forest.fit(X).decision_function(X)
        self.lof.fit_predict(X)
        lof_scores = self.lof.negative_outlier_factor_

        combined = (_percentile_rank(forest_scores) + _percentile_rank(lof_scores)) / 2
        cutoff = np.quantile(combined, self.contamination)
        predictions = np.where(combined <= cutoff, -1, 1)
        return predictions, combined


def _percentile_rank(values) -> np.ndarray:
    """Map scores to [0, 1] by rank, so two incomparable scales can be averaged."""
    order = np.argsort(np.argsort(values))
    return order / max(len(values) - 1, 1)


def candidates(contamination: float, seed: int) -> dict:
    """Model name -> (estimator, needs_scaling).

    IsolationForest splits on raw thresholds so scale is irrelevant to it;
    the distance- and kernel-based models are meaningless without scaling,
    because packet_length spans 3 orders of magnitude more than protocol.
    """
    return {
        "IsolationForest": (
            IsolationForest(n_estimators=100, contamination=contamination, random_state=seed),
            False,
        ),
        "IsolationForest (scaled)": (
            IsolationForest(n_estimators=100, contamination=contamination, random_state=seed),
            True,
        ),
        "LocalOutlierFactor": (
            LocalOutlierFactor(n_neighbors=20, contamination=contamination),
            True,
        ),
        "OneClassSVM (rbf)": (
            OneClassSVM(kernel="rbf", gamma="scale", nu=contamination),
            True,
        ),
        "EllipticEnvelope": (
            EllipticEnvelope(contamination=contamination, random_state=seed, support_fraction=0.9),
            True,
        ),
        "Ensemble (IF + LOF ranks)": (RankEnsemble(contamination, seed), False),
    }


def evaluate(name, estimator, scaled, X, y) -> dict:
    model = make_pipeline(StandardScaler(), estimator) if scaled else estimator

    started = time.perf_counter()
    if isinstance(estimator, RankEnsemble):
        scaled_X = StandardScaler().fit_transform(X)
        predictions, scores = estimator.fit_score(scaled_X)
    elif isinstance(estimator, LocalOutlierFactor):
        # LOF is transductive by default: no separate predict step.
        predictions = model.fit_predict(X)
        scores = estimator.negative_outlier_factor_
    else:
        model.fit(X)
        predictions = model.predict(X)
        scores = model.decision_function(X)
    elapsed = time.perf_counter() - started

    flagged = (predictions == -1).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, flagged, average="binary", zero_division=0
    )
    # Lower decision_function = more anomalous, so negate for ranking metrics.
    ranked = -np.asarray(scores)
    return {
        "model": name,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc_score(y, ranked),
        "pr_auc": average_precision_score(y, ranked),
        "seconds": elapsed,
    }


def run(count: int, rate: float, regime: str, seed: int) -> pd.DataFrame:
    X, y = make_dataset(count, rate, regime, seed)
    print(f"\n=== {regime}: {count} packets, {int(y.sum())} anomalies "
          f"({y.mean() * 100:.1f}%), features {FEATURE_COLUMNS}")

    results = [
        evaluate(name, est, scaled, X, y)
        for name, (est, scaled) in candidates(contamination=float(y.mean()), seed=seed).items()
    ]
    table = pd.DataFrame(results).sort_values("pr_auc", ascending=False)
    with pd.option_context("display.float_format", "{:.3f}".format, "display.width", 120):
        print(table.to_string(index=False))
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", "--count", type=int, default=4000)
    parser.add_argument("-a", "--anomaly-rate", type=float, default=0.03)
    parser.add_argument("-s", "--seed", type=int, default=42)
    parser.add_argument("-r", "--regime",
                        choices=["obvious", "subtle", "overlapping", "all"], default="all")
    args = parser.parse_args()

    regimes = ["obvious", "subtle", "overlapping"] if args.regime == "all" else [args.regime]
    for regime in regimes:
        run(args.count, args.anomaly_rate, regime, args.seed)


if __name__ == "__main__":
    main()
