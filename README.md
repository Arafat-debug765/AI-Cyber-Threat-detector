# 🛡️ AI Cyber Threat Detector

Finds hosts behaving unlike the rest of your network, from a packet capture.

It groups packets into per-source time windows, learns what normal looks like
from a capture you know is clean, and reports the sessions that do not match —
ranked, and **silent when nothing is wrong**.

On the bundled reference capture it finds a port scan, a host sweep, a C2
beacon and a data exfil — **4 of 4 across 12 independent runs**, at about **2
false alerts per 75 sessions** — where scoring the same traffic packet-by-packet
finds 2 and needs 346 alerts to do it.

---

## Install

```bash
pip install 'ai-threat-detector[capture] @ git+https://github.com/Arafat-debug765/AI-Cyber-Threat-detector'
```

Or from a clone:

```bash
git clone https://github.com/Arafat-debug765/AI-Cyber-Threat-detector.git && cd AI-Cyber-Threat-detector && pip install -e '.[all]'
```

Python 3.9+. The `capture` extra pulls in scapy, needed only to read `.pcap`
files or capture live traffic.

## Try it in one minute

```bash
threat-detector generate --output packets.csv
threat-detector generate --output baseline.csv --no-attacks
threat-detector --data packets.csv --baseline baseline.csv train
threat-detector --data packets.csv detect
```

```
7 of 79 sessions flagged

src_ip        window_start              packets  bytes_total  distinct_dst_ips  distinct_dst_ports  std_interarrival  anomaly_score
192.168.0.66  2026-09-20T04:30:00.000Z  300      13200        1                 300                 0.2183            -0.2377
192.168.0.69  2026-09-20T04:35:00.000Z  400      559659       1                 1                   0.1402            -0.2288
192.168.0.67  2026-09-20T04:35:00.000Z  200      12000        200               1                   0.2719            -0.2168
192.168.0.68  2026-09-20T04:30:00.000Z  10       1280         1                 1                   0.0000            -0.2008
```

Those are, in order: a port scan (300 ports, one host), an exfil (560 KB to one
external address), a host sweep (200 hosts, one port), and a C2 beacon — whose
tell is `std_interarrival` of exactly zero. Machines keep time; people do not.

The remaining alerts are the calibrated false-positive budget, and that budget
is the point: the alert threshold is set at a chosen quantile of the baseline's
own scores, so `CALIBRATION_QUANTILE` **is** the false-positive rate you are
accepting. It defaults to 2%, which was measured — see below.

## Use it on your own traffic

```bash
threat-detector ingest quiet-hour.pcap --output baseline.csv   # known-good
threat-detector ingest today.pcap      --output packets.csv    # suspect
threat-detector --data packets.csv --baseline baseline.csv train
threat-detector --data packets.csv detect
```

**The baseline is the most important input.** Fitting on the traffic you are
inspecting teaches the model that whatever is in there is normal. Point
`--baseline` at a capture from a period you believe was clean.

Capture live instead (needs root, and permission to monitor the network):

```bash
sudo python scripts/live_capture.py --iface en0 --count 5000 --output packets.csv
```

## The web interface

```bash
threat-detector --data packets.csv --baseline baseline.csv serve
```

Open <http://127.0.0.1:5000>, click **Train model**, then **Detect anomalies**
for a dashboard of the score distribution and the flagged sessions.

> **macOS:** AirPlay Receiver holds port 5000 and answers `403 AirTunes`. Use
> `--port 5050`, and browse to `127.0.0.1` rather than `localhost` — the latter
> resolves to `::1` first, where AirPlay listens.

Exposing it to anything beyond loopback requires a token, and the server will
refuse otherwise:

```bash
API_TOKEN=$(openssl rand -hex 32) threat-detector serve --host 0.0.0.0 --production
```

Put TLS in front of it. The API describes your network's traffic in detail; a
bearer token over plain HTTP is a token you have given away.

## Docker

```bash
API_TOKEN=$(openssl rand -hex 32) docker compose up --build
```

Runs as a non-root user with a read-only root filesystem, bound to loopback.
Put your `packets.csv` and `baseline.csv` in `./data`.

## Configuration

Every setting is an environment variable; see [.env.example](.env.example).
The ones that change results:

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_FILE` | unset | known-good capture to fit on — **set this** |
| `DATA_FILE` | `data/packets.csv` | the capture under inspection |
| `WINDOW_SECONDS` | `300` | session length. Must exceed the period of any beacon you hope to see |
| `MIN_SESSION_PACKETS` | `3` | windows smaller than this are artifacts, not behaviour |
| `CALIBRATION_QUANTILE` | `0.02` | target false-positive rate against the baseline |
| `FEATURE_SET` | `flow` | `flow` (sessions) or `packet` (the original, kept for comparison) |
| `ALGORITHM` | `iforest` | `iforest`, or `lof` for contextual anomalies |
| `API_TOKEN` | unset | required to serve off loopback |
| `ALLOWED_HOSTS` | loopback names | `Host` allowlist; blocks DNS rebinding |
| `MODEL_KEY_FILE` | `.secrets/…` | HMAC key protecting the model file |

`WINDOW_SECONDS` matters more than the choice of model. Measured on the
reference capture: 60s finds 3 of 4 attacks, **300s finds 4 of 4**, 600s drops
back to 3.

`CALIBRATION_QUANTILE` is the operating point. Measured across eight
independent baselines:

| rate | attacks caught /4 | alerts on ~75 clean sessions |
|---|---|---|
| `0.0` — nothing known-good may alarm | 4/4 in 6 of 8 runs | 0 |
| `0.01` | 4/4 in 7 of 8 | 1 |
| **`0.02` (default)** | **4/4 in 8 of 8** | 2 |
| `0.05` | 4/4 in 8 of 8 | 4 |

`0.0` sounds strictest and is the weakest: with the threshold at the single
lowest baseline score, whatever freak session the baseline happens to contain
sets the bar, and real attacks score above it. The app warns when it detects
that happening. Set `0.0` when a missed detection costs less than a false one.

## How it decides

Eleven behavioural features per session — packet and byte counts, payload size
spread, distinct destination hosts, ports and protocols, inter-arrival mean and
deviation, small-packet and external-destination ratios. An IsolationForest is
fitted on the baseline, and the alert threshold is calibrated as a quantile of
the baseline's own scores, so "unusual" means unusual *for your network*.

Model choice was measured, not assumed
([`scripts/benchmark_models.py`](scripts/benchmark_models.py)): IsolationForest
wins on globally extreme anomalies, LOF by 4× on contextual ones, and an
IF+LOF ensemble was tried and rejected as worse than either alone. The far
bigger win came from changing *what the model looks at* rather than which model
looks at it — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What this is not

Not an IDS. It does not run inline, block anything, or carry rules, signatures
or threat intelligence, and it cannot name what it found — only that a host
behaved unlike the rest. Its output is a queue to investigate, not a verdict.

Other limits, stated rather than buried: a poisoned baseline defeats it
entirely; beacon detection depends on window alignment; IPv6 is skipped; the
capture is held in memory (~1 GB per 10M packets); and model files are pickles,
so signing makes them safe to reload, never safe to accept from someone else.

## Development

```bash
pip install -e '.[all]'
pytest                # 118 tests
ruff check .
threat-detector --baseline data/baseline.csv selfcheck
```

`selfcheck` is the important one: it fails if the detector stops finding the
planted attacks or starts alarming on clean traffic. It runs in CI, because
unit tests cannot tell you detection got worse.

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/SECURITY.md](docs/SECURITY.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).
