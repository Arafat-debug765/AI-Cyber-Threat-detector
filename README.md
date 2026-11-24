# 🛡️ AI Cyber Threat Detector

Finds hosts behaving unlike the rest of your network, from a packet capture.

It groups packets into per-source time windows, learns what normal looks like
from a capture you know is clean, and reports the sessions that do not match,
ranked so the ones furthest from normal come first.

On the bundled reference attacks — a port scan, a host sweep, a C2 beacon and a
data exfil — it found **all four in 300 of 300 trials** with independently
recorded captures, at a **1.3% false-alarm rate** on separate clean traffic
(no false alarms at all on 62% of clean captures). Scoring the same traffic
packet-by-packet finds 2 of 4 and needs 346 alerts to do it.

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
6 of 55 sessions flagged

src_ip        window_start              packets  bytes_total  distinct_dst_ips  distinct_dst_ports  std_interarrival  anomaly_score
192.168.0.66  2026-11-24T04:32:44.000Z  300      13200        1                 300                 0.2183            -110.7284
192.168.0.67  2026-11-24T04:37:44.000Z  200      12000        200               1                   0.2719            -73.2035
192.168.0.68  2026-11-24T04:32:44.000Z  10       1280         1                 1                   0.0000            -40.4965
192.168.0.68  2026-11-24T04:37:44.000Z  10       1280         1                 1                   0.0000            -40.4965
192.168.0.69  2026-11-24T04:37:44.000Z  400      559659       1                 1                   0.1402            -37.1628
192.168.0.34  2026-11-24T04:32:44.000Z  156      73744        3                 5                   1.9403            -0.5814
```

In order: a port scan (300 ports, one host), a host sweep (200 hosts, one
port), a C2 beacon in two consecutive windows — its tell is `std_interarrival`
of exactly zero, because machines keep time and people do not — and an exfil
(560 KB to one external address).

Read the last column. The attacks score between −37 and −111; the one ordinary
host that crossed the line scores −0.58, barely past the threshold of −0.20.
The ranking puts what matters at the top by a wide margin, which is what a
queue to investigate needs.

## Use it on your own traffic

```bash
threat-detector ingest quiet-hour.pcap --output baseline.csv   # known-good
threat-detector ingest today.pcap      --output packets.csv    # suspect
threat-detector --data packets.csv --baseline baseline.csv train
threat-detector --data packets.csv detect
```

**The baseline is the most important input.** Fitting on the traffic you are
inspecting teaches the model that whatever is in there is normal. Point
`--baseline` at a capture from a period you believe was clean. Without one, the
tool falls back to flagging a fixed 2% of the capture, and on the reference data
that found about half the attacks.

**A longer baseline means fewer false alarms**, and nothing else changes: every
attack was found at every length measured.

| baseline recorded | sessions | false alarms per clean capture | clean captures with none |
|---|---|---|---|
| 10 minutes | ~50 | 0.99 | 49% |
| 20 minutes | ~100 | 0.44 | 73% |
| 40 minutes | ~200 | **0.21** | **84%** |

Training warns when a baseline is under 100 sessions.

Captures from real networks are messy, and that is handled rather than fatal:
IPv6 packets, blank or malformed fields, and padded CSV headers are dropped or
tolerated, with the counts reported as `rows_dropped` in every result.
Timestamps may be ISO-8601 or Unix epoch (seconds, ms, µs or ns). A capture
that is damaged part-way through is salvaged up to the damage and reported as
`[PARTIAL]`, and a failed ingest never overwrites an existing file.

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
Relative paths mean the directory you run the command from.
The ones that change results:

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_FILE` | unset | known-good capture to fit on — **set this** |
| `DATA_FILE` | `data/packets.csv` | the capture under inspection |
| `WINDOW_SECONDS` | `300` | session length. Must exceed the period of any beacon you hope to see |
| `MIN_SESSION_PACKETS` | `3` | sessions smaller than this are artifacts, not behaviour |
| `MIN_WINDOW_COVERAGE` | `0.5` | drop sessions from a window the capture barely spans |
| `CALIBRATION_QUANTILE` | `0.0` | where the threshold sits among baseline scores (see below) |
| `FEATURE_SET` | `flow` | `flow` (sessions) or `packet` (the original, kept for comparison) |
| `ALGORITHM` | `auto` | `auto` (LOF for sessions), `lof`, or `iforest` |
| `API_TOKEN` | unset | required to serve off loopback |
| `ALLOWED_HOSTS` | loopback names | `Host` allowlist; blocks DNS rebinding |
| `MODEL_KEY_FILE` | `~/.config/threat-detector/…` | HMAC key protecting the model file |

`WINDOW_SECONDS` matters more than the choice of model. Measured on the
reference capture: 60s finds 3 of 4 attacks, **300s finds 4 of 4**, 600s drops
back to 3.

`CALIBRATION_QUANTILE` is the operating point: the threshold sits at that
quantile of the baseline's scores, each computed by a model that did not see
the session it is scoring. Measured over 200 trials, with false alarms counted
on a *separate* clean capture:

| rate | all four attacks found | false-alarm rate on separate clean traffic |
|---|---|---|
| **`0.0` (default)** | **200/200** | **1.5%** |
| `0.01` | 200/200 | 1.8% |
| `0.02` | 200/200 | 2.7% |

With the default detector, the strictest setting costs nothing in recall: attack
sessions score dozens of times further from normal than the threshold, so
there is no recall to trade. Training warns if a single freak baseline session
is setting the bar.

## How it decides

Eleven behavioural features per session — packet and byte counts, payload size
spread, distinct destination hosts, ports and protocols, inter-arrival mean and
deviation, small-packet and external-destination ratios. A Local Outlier Factor
model is fitted on the baseline, and the alert threshold is calibrated on
out-of-fold scores, so "unusual" means unusual *for your network*.

**Why LOF.** Fitting on known-clean traffic is *novelty* detection, and LOF's
distance-based score keeps growing the further a session moves from anything
normal. IsolationForest's does not: a session at ten times the baseline maximum
isolates like one *at* the maximum. So an exfil moving 560 KB against a ~45 KB
baseline scored as less anomalous than an ordinary host. On identical trials
LOF found all four attacks 700 times out of 700; IsolationForest 695, missing
up to two attacks in a run. IsolationForest is still the
default for packet mode, and available via `ALGORITHM=iforest`.

An earlier version of this project chose IsolationForest — from a benchmark run
on contaminated data, where LOF's real weakness (a tight cluster of anomalies
looks locally dense) applies. A clean baseline removes that weakness. The
benchmark answered a question the application no longer asks. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
pytest                # 188 tests, ~20s
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
