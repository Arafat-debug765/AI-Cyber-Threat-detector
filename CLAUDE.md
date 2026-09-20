# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[all]'                  # editable install + scapy, gunicorn, dev tools

threat-detector generate --output data/packets.csv                  # capture with attacks
threat-detector generate --output data/baseline.csv --no-attacks    # known-good
threat-detector --baseline data/baseline.csv train
threat-detector detect
threat-detector --baseline data/baseline.csv selfcheck              # detection-quality gate
threat-detector serve                                               # 127.0.0.1:5000

pytest                                   # whole suite
ruff check .                             # lint (ruff.toml, target py39)
pytest tests/test_sessions.py::test_flow_mode_flags_the_scanner     # one test
pytest -k calibration                    # by keyword
```

macOS: port 5000 is taken by AirPlay Receiver, which answers `403 AirTunes`.
Use `threat-detector serve --port 5050`, and hit `127.0.0.1` rather than
`localhost` —
`localhost` resolves to `::1` first, where AirPlay listens.

## Architecture

Flask app factory (`create_app`) + a service layer, deliberately split so the
HTTP layer holds no logic:

- `threat_detector/config.py` — frozen `Config` dataclass, every field from an env var.
  Paths resolve against `BASE_DIR`. **Config is passed in, never read from
  globals** — that is what lets tests point the app at a `tmp_path` dataset.
- `threat_detector/features.py` — CSV load, validation, feature engineering. Raises
  `DataError` for anything wrong with the data.
- `threat_detector/model.py` — `train`, `detect`, `summarize`, `status`. Raises
  `ModelNotTrained` when no `model.pkl` exists.
- `threat_detector/routes.py` — thin handlers that call the service layer and map domain
  exceptions to 400/409 via `app_errorhandler`. **No logic lives here**: anything
  the web interface can do, `cli.py` must be able to do too.
- `threat_detector/auth.py` — Host allowlist, CSRF header, API token, security
  headers. Installed by the factory as a single `before_request` chain.
- `threat_detector/jobs.py` — background training. State is a JSON file beside the
  model, not memory, so it survives a restart and is visible to every gunicorn
  worker.
- `threat_detector/integrity.py` — the signature lives *inside* the model file so
  one `os.replace` installs both atomically. Two files could not be replaced
  together, and a crash between them bricked the instance.

Two feature sets, chosen by `FEATURE_SET`:

- `flow` (default, `threat_detector/sessions.py`) — packets aggregated into (source, window)
  sessions with behavioural features. This is the one that can represent scans,
  sweeps and beaconing; per-packet features cannot, and no model choice fixes
  that. `WINDOW_SECONDS` must exceed the period of any beacon to be detected.
- `packet` (`threat_detector/features.py`) — the original per-packet features. IPs are packed
  32-bit integers, not summed octets (the sum collides: `192.168.1.5` and
  `5.1.168.192` both give 366).

Anything building a row for the model must use a **named DataFrame** so sklearn
matches columns by name, not position.

**`BASELINE_FILE` is the setting that matters most.** Fitting on the traffic
under inspection teaches the model the attack is normal. With a baseline the
threshold is calibrated at quantile 0.0 of the baseline scores (nothing
known-good may alarm); without one it silently degrades to a 2% quota and logs a
warning. Do not "fix" a quiet detector by removing the baseline.

The saved artifact is a **bundle** (`BUNDLE_VERSION`), not a bare estimator: it
carries the threshold, feature set, window and columns, and `load_model` refuses
a bundle whose feature set disagrees with the current config.

`contamination` is a budget, not a discovery: the model flags that fraction of
the dataset whether or not that many packets are genuinely abnormal.

**`CALIBRATION_QUANTILE` is a target false-positive rate, not a safety margin.**
The threshold sits at that quantile of the *baseline's* scores, so 0.02 means
"accept ~2% of known-good sessions alarming". Setting it to 0.0 sounds stricter
and detects worse: the bar becomes the single lowest baseline score, so one
freak session decides it. Measured across eight baselines — 0.02 caught 4/4
reference attacks every run, 0.0 managed 6 runs out of 8. Do not "tighten" this
to 0.0 without re-running `selfcheck` across several seeds.

`MIN_SESSION_PACKETS` removes the commonest such artifact (a one-packet window
at a capture boundary). Any statistic taken at the extreme of a small sample is
set by its worst artifact — expect this class of bug to recur.

`model.scored()` memoises one scoring pass per (model, capture) fingerprint;
`/api/anomalies` and `/api/summary` share it. Call `clear_cache()` after
anything that changes the model.

`ALGORITHM` picks the detector (`iforest` default, `lof` alternative) via
`model.build_estimator`. The choice is benchmarked, not assumed — run
`scripts/benchmark_models.py` before changing the default; its `overlapping`
regime is the one that actually separates the candidates. An IF+LOF rank
ensemble was measured and rejected as worse than either alone.

## Constraints worth keeping

- **The API is unauthenticated.** Error strings and JSON responses must never
  contain absolute paths — `features.py` names files, `model.py:_public_path`
  relativises them. There are tests asserting this.
- **Packet data is attacker-influenced.** The front end renders values with
  `textContent` and builds SVG with `createElementNS`. Never introduce
  `innerHTML` with data-derived strings.
- The catch-all `Exception` handler must stay *below* the `HTTPException`
  handler in `routes.py`, or ordinary 404/405s become 500s.
- `/train` and `/anomalies` are legacy aliases for the `/api/*` routes and are
  covered by tests — keep them working.
- No front-end build step and no CDN: charts in `threat_detector/static/charts.js` are
  hand-rolled SVG. Keep it dependency-free.
- `joblib.load` unpickles, which executes code. `threat_detector/integrity.py` signs every
  saved model and **verifies before loading, never after** — checking afterwards
  would be checking a file that already ran. Do not add a load path that skips
  `verify()`.

## Data

`data/*.csv` and `models/*.pkl` are git-ignored and regenerated, never committed.
`threat_detector/synth.py` is seeded (default 42), so datasets are
reproducible; `RANDOM_STATE` does the same for the model.
