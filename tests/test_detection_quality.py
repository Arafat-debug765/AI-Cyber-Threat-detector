"""Detection quality on cases that have actually broken it.

Unit tests prove the code runs. These prove the detector still *detects*, on
the specific captures that once defeated it — each found by randomised search,
diagnosed, and fixed. They are slower than the rest of the suite, and worth it.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from threat_detector import model as model_service
from threat_detector import synth
from threat_detector.config import Config

ATTACKERS = {source: name for name, (_, source) in synth.ATTACKS.items()}
T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def _run(tmp_path, capture_seed, baseline_seed, capture_at, baseline_at, **settings):
    cap, base = tmp_path / "cap.csv", tmp_path / "base.csv"
    synth.generate(cap, 6000, 25, capture_seed, True, start=T0 + timedelta(seconds=capture_at))
    synth.generate(base, 6000, 25, baseline_seed, False, start=T0 + timedelta(seconds=baseline_at))
    config = Config(data_file=cap, baseline_file=base, model_file=tmp_path / "m.pkl",
                    key_file=tmp_path / "k", **settings)
    model_service.train(config)
    found = {ATTACKERS[r["src_ip"]] for r in model_service.detect(config)["anomalies"]
             if r["src_ip"] in ATTACKERS}
    quiet = model_service.detect(replace(config, data_file=base))["count"]
    return found, quiet


# (capture seed, baseline seed, capture start offset, baseline start offset).
# Every case here was found by randomised search and verified to FAIL under the
# previous defaults (IsolationForest, no coverage filter) before being fixed —
# a regression test that passes on the old behaviour guards nothing.
# Window anchoring is guarded separately, by the phase-invariance test in
# test_sessions.py.
REGRESSIONS = {
    # A sliver of the final window held sessions of three packets in one
    # second; they set the threshold and hid all four attacks.   old: 0/4
    "tail-sliver sessions set the threshold": (7283, 80440, 80579.649, 18169.856),
    # IsolationForest scores do not extrapolate: the exfil, at 12x the
    # baseline's byte count, scored as less anomalous than an ordinary host.
    "exfil beyond the baseline range": (39347, 10576, 10394.381, 43391.040),       # old: 3/4
    "exfil beyond the baseline range (2)":
        (56424, 85583, 17592.801921791714, 44336.291163643655),                    # old: 3/4
    "exfil beyond the baseline range (3)":
        (76859, 87801, 67728.95688846378, 27798.673454455555),                     # old: 3/4
}


@pytest.mark.parametrize("case", list(REGRESSIONS))
def test_known_hard_case(case, tmp_path):
    found, quiet = _run(tmp_path, *REGRESSIONS[case])
    assert found == set(ATTACKERS.values()), f"missed {set(ATTACKERS.values()) - found}"
    assert quiet <= 4  # selfcheck's 5% tripwire on ~75 sessions; observed max is 2


@pytest.mark.parametrize("trial", range(6))
def test_independent_recording_times(trial, tmp_path):
    """Capture and baseline recorded at unrelated times, with sub-second jitter."""
    found, _ = _run(tmp_path, 1000 + trial, 5000 + trial,
                    3_600 * trial + 0.137 * trial, 7_919 * trial + 0.71)
    assert found == set(ATTACKERS.values())


def test_isolation_forest_is_still_available(tmp_path):
    """Explicitly requested, it still runs — it is just no longer the default."""
    found, _ = _run(tmp_path, 1, 501, 0.0, 0.0, algorithm="iforest")
    assert found  # finds attacks; the measured gap is in the tail, not here


def test_auto_resolves_by_mode():
    assert Config(feature_set="flow").estimator == "lof"
    assert Config(feature_set="packet").estimator == "iforest"
    assert Config(feature_set="flow", algorithm="iforest").estimator == "iforest"
    # Resolved on read, so changing the mode re-resolves rather than going stale.
    assert replace(Config(feature_set="flow"), feature_set="packet").estimator == "iforest"


def test_too_small_a_baseline_is_refused_with_a_reason(tmp_path):
    from threat_detector.features import DataError

    base = tmp_path / "tiny.csv"
    synth.generate(base, 40, 2, 1, False)
    config = Config(data_file=base, baseline_file=base, model_file=tmp_path / "m.pkl",
                    key_file=tmp_path / "k")
    with pytest.raises(DataError, match="need at least"):
        model_service.train(config)
