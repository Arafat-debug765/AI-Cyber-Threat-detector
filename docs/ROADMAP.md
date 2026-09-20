# Roadmap

Ordered by what most changes whether the tool is useful, not by effort.

## Now — shipped in 1.0.0

Installable, authenticated, reads real captures, detects all four reference
attacks with no false positives, and proves it in CI.

## Next

**A periodicity feature.** Beacon detection currently leans on
`std_interarrival` within a single window, so a beacon whose period is close to
`WINDOW_SECONDS` can be missed. Autocorrelation of inter-arrival times per
source over the whole capture would catch it regardless of alignment, and would
also catch slow beacons that no window size currently sees.

**Multi-window analysis.** One `WINDOW_SECONDS` is a compromise: 60s finds
bursts, 600s finds slow patterns, neither finds both. Scoring at several
windows and taking the strongest signal per source removes the operator's need
to guess.

**Explanation per alert.** The model says a session is unusual; it cannot say
which feature drove that. Per-feature attribution (the depth each feature
contributed in the isolation path) would turn "192.168.0.66 is anomalous" into
"…because it touched 300 distinct ports", which is the difference between a
queue item and a finding.

**IPv6.** Currently skipped at ingest. On a dual-stack network that is a blind
spot an attacker can simply walk through.

## Later

**Streaming ingest.** The capture is held in memory. Chunked aggregation would
lift the ceiling from ~10M packets to arbitrary captures, and is a prerequisite
for anything continuous.

**Baseline management.** One file today. Real networks change shape by hour and
by weekday; a baseline per time bucket, with drift detection to say when it has
gone stale, is the difference between a demo and something you leave running.

**An audit log.** Who queried the analysis, and when.

## Not planned

**Inline blocking.** This is an offline triage tool. Anything that drops
traffic on an unsupervised model's say-so will eventually drop something it
should not.

**Signatures or threat intelligence feeds.** Solved elsewhere, and better. The
value here is catching the thing no signature exists for.

**Replacing the model with a neural network.** The measured bottleneck was
never model capacity — it was what the model was shown. Session features on an
IsolationForest beat per-packet features on anything.
