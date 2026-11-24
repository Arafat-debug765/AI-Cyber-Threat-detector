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
timeout 300 pytest                       # the suite runs in ~10s; a hang is a bug
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
- `threat_detector/features.py` — CSV load, cleaning, per-packet features, and
  the one CSV schema (`CSV_FIELDS`) every producer writes. `clean_packets`
  **drops rows that cannot be analysed and records why** in
  `.attrs["rows_dropped"]`, surfaced in every train/detect result; it raises
  `DataError` only when nothing usable is left. Rejecting a whole capture over
  one IPv6 row made the tool unusable on dual-stack networks; dropping silently
  would make it untrustworthy. Keep both halves of that.
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
under inspection teaches the model the attack is normal; without a baseline the
app flags a fixed 2% quota and logs a warning, which found ~half the reference
attacks. Do not "fix" a quiet detector by removing the baseline.

The saved artifact is a **bundle** (`BUNDLE_VERSION`), not a bare estimator: it
carries the threshold, feature set, algorithm, window and columns, and
`load_model` refuses a bundle whose feature set, algorithm or window disagrees
with the current config.

**Timestamps go through `features.parse_timestamps`, never bare
`pd.to_datetime`.** pandas reads an integer as nanoseconds, so epoch seconds —
what tcpdump, tshark and scapy export — became 1970, every packet fell in one
window, and detection silently produced garbage. The helper infers the unit
from magnitude.

**Relative paths mean the working directory; the key lives in
`~/.config/threat-detector/`.** Paths once resolved against the package
location, so an installed copy wrote its model and signing key into
site-packages. Editable installs hid this because there the package *is* the
repo. CI installs the wheel into a fresh venv and fails if anything lands
inside it.

`contamination` is a budget, not a discovery: the model flags that fraction of
the dataset whether or not that many packets are genuinely abnormal.

**Detector: `ALGORITHM=auto` → LOF in flow mode, IsolationForest in packet
mode.** With a baseline this is *novelty* detection, and IsolationForest scores
do not extrapolate — a session at 10× the baseline maximum isolates like one at
the maximum, so a 560 KB exfil scored as less anomalous than an ordinary host.
LOF: 700/700 trials found all four attacks; IsolationForest: 695/700. The old
`scripts/benchmark_models.py` result (IsolationForest wins) fitted on
contaminated data — the outlier-detection question, not the one the app asks.

**Calibration is out-of-fold** (`model._out_of_fold_scores`, 5 folds, seeded):
each baseline session is scored by a model that never saw it. A novelty model
scoring its own training data is biased toward "normal", so in-sample
thresholds were too tight. `CALIBRATION_QUANTILE` defaults to **0.0** — measured
best with LOF: 200/200 trials, 1.5% false alarms on *separate* clean traffic.

**Measure false alarms on separate clean traffic, never on the baseline.**
In-sample figures are optimistic by construction; this project published
in-sample numbers for two releases before catching it. `selfcheck`'s
clean-baseline check is a 5% regression tripwire, not an FP estimate.

**Windows are anchored at each capture's first packet**, never the wall clock:
clock-aligned windows made results depend on the time of day a capture started
(a 2-second first window's sliver sessions hid 3 of 4 attacks).
`MIN_WINDOW_COVERAGE` (0.5) drops sessions from a final window the capture
barely spans; `MIN_SESSION_PACKETS` (3) drops tiny sessions. Any statistic taken
at the extreme of a small sample is set by its worst artifact — expect this
class of bug to recur.

**Verify detection changes with randomised trials, not single runs**: generate
hundreds of capture/baseline pairs with independent seeds *and independent
start times with sub-second jitter*. Every calibration bug above passed the
unit tests and a fixed-seed selfcheck; each was found this way.
`tests/test_detection_quality.py` pins the specific trials that once failed —
each verified to fail on the old defaults. A regression case that passes on
the old behaviour guards nothing.

`synth.generate` is reproducible only because `start` is floored to the second;
an unfloored clock made the same seed yield different traffic.

`model.scored()` memoises one scoring pass per (model, capture) fingerprint;
`/api/anomalies` and `/api/summary` share it. Call `clear_cache()` after
anything that changes the model.

## Constraints worth keeping

- **Responses never contain absolute paths.** Even with `API_TOKEN` set, a path
  discloses the host account name and layout — `features.py` names files,
  `model.py:_public_path` relativises them. There are tests asserting this.
- **Tests are hermetic** (`conftest.py:hermetic_environment`): each gets its own
  HOME, XDG_CONFIG_HOME and working directory, and every config env var is
  cleared. Before this the suite signed models with the repo's real dev key and
  picked up whatever was exported in the shell. A new setting means adding its
  env var to `_CONFIG_ENV`.
- **No test may start a real server** — `test_cli.py` patches `Flask.run`. One
  that did hung the suite indefinitely.
- **Ingest writes atomically and detects truncation from the container
  structure**, not from scapy's file position: scapy treats a cut-off final
  record as EOF, so a damaged capture used to report success and overwrite good
  data with a fragment.
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
