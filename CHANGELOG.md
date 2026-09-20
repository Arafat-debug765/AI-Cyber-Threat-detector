# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [semantic versioning](https://semver.org/).

## [1.0.0] — 2026-09-20

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

### Changed
- Package renamed `app` → `threat_detector`; an installed distribution should
  not occupy a name that generic.
- Model files are a single signed artifact; the separate `.sig` file is gone.
  **Existing models must be retrained.**
- The signing key moved out of the model directory to `.secrets/`.
- Timestamps in API responses are ISO-8601 rather than epoch milliseconds.
- `/api/anomalies` and `/api/summary` share one scoring pass instead of each
  re-scoring the capture.

### Fixed
- The alert threshold is a measured false-positive rate (default 2%) rather
  than the lowest baseline score, which made recall hostage to whatever freak
  session the baseline happened to contain. Sessions too small to describe
  behaviour are dropped before fitting, and training warns when one session is
  visibly deciding the threshold. Together: 4 of 4 reference attacks in 12 of
  12 runs, up from 2 of 4.
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
