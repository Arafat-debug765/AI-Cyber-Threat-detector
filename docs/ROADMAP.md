# Roadmap

Ordered by what most changes whether the tool is useful, not by effort.

## Now — shipped in 1.0.0

Installable, authenticated, reads real captures, and finds all four reference
attacks in 300 of 300 independently recorded trials at a 1.3% false-alarm rate
— verified in CI on every change, with the trials that once broke it pinned as
regression tests.

## Next

**A periodicity feature.** Beacon detection currently leans on
`std_interarrival` within a single window, so a beacon whose period approaches
`WINDOW_SECONDS` puts too few check-ins in each session to show its regularity. Autocorrelation of inter-arrival times per
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

**Replacing the model with a neural network.** The measured bottlenecks were
never model capacity: they were what the model was shown (sessions, not
packets), which question it was answering (novelty, not outlier detection), and
how its threshold was measured (out-of-fold, not in-sample). Each of those
mattered more than any model swap could.

**Shrinking the false-alarm rate by tuning on the reference data.** It is
synthetic. The 1.3% figure is a property of these generators; tuning it lower
here would be fitting the test, not improving the tool. The honest lever is a
longer baseline, which the measurements already show halves false alarms per
doubling.
