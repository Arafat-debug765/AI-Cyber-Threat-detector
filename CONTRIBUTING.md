# Contributing

## Getting set up

```bash
git clone https://github.com/Arafat-debug765/AI-Cyber-Threat-detector.git
cd AI-Cyber-Threat-detector
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[all]'
```

## Before opening a pull request

```bash
pytest
ruff check .
threat-detector generate --output data/packets.csv
threat-detector generate --output data/baseline.csv --no-attacks
threat-detector --baseline data/baseline.csv selfcheck
```

`selfcheck` is the one that matters. Unit tests confirm the code runs;
`selfcheck` confirms the detector still detects. **If it fails, treat it as a
real regression, not a flaky test** — the usual causes are a change to the
features, to `WINDOW_SECONDS`, or to how the threshold is calibrated.

## What makes a change likely to be accepted

- **A detection claim comes with a measurement.** "This should catch X better"
  is not reviewable. Add the behaviour to `synth.py` and show the before/after
  from `selfcheck`.
- **New settings are validated in `Config.__post_init__`** and documented in
  `.env.example`. A setting that fails at use time instead of startup is a
  setting that fails in production.
- **`routes.py` gains no logic.** Anything the web interface can do, the CLI
  must be able to do.
- **Packet-derived values are never interpolated into HTML or a shell.** They
  are attacker-influenced input.

## Things that will be asked about in review

Adding a model, changing a default threshold, or changing the feature set —
these need numbers from `scripts/benchmark_models.py` or `selfcheck`, because
the project has been wrong about all three before and only measurement caught
it.
