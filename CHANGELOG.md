# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [semantic versioning](https://semver.org/).

## [1.0.0] — 2026-11-24

First release intended to be installed and used by someone other than its
author.

### Added
- Installable package and a single CLI: `threat-detector generate | ingest |
  train | detect | inspect | selfcheck | serve`.
- `.pcap` / `.pcapng` ingestion, so the tool can be pointed at real evidence
  instead of only synthetic or live capture.
- Authentication (`API_TOKEN`), `Host` allowlisting, CSRF protection, request
  size limits and security response headers.
- Background training with progress on disk; `POST /api/train` now returns 202.
- Docker image and compose file, running as a non-root user with a read-only
  root filesystem.
- `docs/ARCHITECTURE.md` and `docs/SECURITY.md`.
- Tests for the CLI and for capture ingestion, which had none; detection-quality
  regression tests pinned to the specific trials that once failed; Dependabot;
  CI on Python 3.13 and a check that an installed wheel works from any
  directory.

### Changed
- **The default detector for sessions is LOF**, and the threshold is calibrated
  on out-of-fold scores at quantile 0.0. Measured with independently recorded
  captures: all four reference attacks in 300/300 trials, a 1.3% false-alarm
  rate on separate clean traffic. IsolationForest remains available and is
  still the default for packet mode.
- Session windows are anchored at each capture's first packet instead of the
  wall clock, and sessions from a barely-spanned final window are dropped
  (`MIN_WINDOW_COVERAGE`).
- Training warns when the baseline has under 100 sessions.
- Relative paths resolve against the working directory, and the signing key
  defaults to `~/.config/threat-detector/`. **An installed copy previously wrote
  both into site-packages.** Keys from earlier locations are still read, so
  existing models keep verifying.
- Unanalysable rows (IPv6, blank or malformed fields, non-positive lengths) are
  dropped and counted in `rows_dropped` rather than rejecting the whole capture.
- Session aggregation is vectorised: 8× faster on captures with many short
  sessions (100k packets: 3.8s → 0.5s), with identical results.
- Package renamed `app` → `threat_detector`; an installed distribution should
  not occupy a name that generic.
- Model files are a single signed artifact; the separate `.sig` file is gone.
  **Existing models must be retrained.**
- The signing key moved out of the model directory to `.secrets/`.
- Timestamps in API responses are ISO-8601 rather than epoch milliseconds.
- `/api/anomalies` and `/api/summary` share one scoring pass instead of each
  re-scoring the capture.

### Fixed
- Detection depended on the time of day a capture started; on unlucky timing,
  three of four attacks went unreported.
- False-alarm figures in earlier documentation were measured on the baseline
  itself and so understated; all are now measured on separate clean traffic.
- `synth.generate` was not reproducible: the same seed produced different
  traffic depending on the sub-second part of the clock.
- Epoch timestamps — the format tcpdump, tshark and scapy export — were read as
  nanoseconds and landed in 1970, silently collapsing every packet into one
  session.
- A capture damaged mid-file reported success and overwrote existing data.
  Ingest now writes atomically and flags truncated captures as `[PARTIAL]`.
- The container healthcheck failed once `ALLOWED_HOSTS` named a real domain.
- CSV headers padded with spaces are accepted.
- Sessions too small to describe behaviour no longer set the alert threshold,
  and training warns when one session is visibly deciding it.
- Models are refused when the configuration they were fitted under no longer
  matches — previously a window-size change produced confident nonsense.
- An interrupted training run no longer bricks the instance.
- `inspect` works against the current model format and verifies its signature.

## [0.2.0] — 2026-09-07

### Added
- Session-level detection, baseline fitting, threshold calibration.
- HMAC-signed model files.
- Dashboard, detection-quality gate in CI.

### Fixed
- Per-packet IP encoding collisions; headerless capture CSVs; XSS in the
  results table; `debug=True` in the entry point; absolute paths in errors.

## [0.1.0]

Initial upload: a Flask app, an IsolationForest over four per-packet features.
