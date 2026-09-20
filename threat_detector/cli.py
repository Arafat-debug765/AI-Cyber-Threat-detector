"""Command line interface.

One entry point instead of a directory of loosely related scripts, each with
its own conventions and its own idea of where files live.

    threat-detector generate                 # synthetic capture with attacks
    threat-detector ingest capture.pcap      # convert a real capture
    threat-detector train                    # fit and calibrate
    threat-detector detect                   # report flagged sessions
    threat-detector inspect                  # what the saved model is
    threat-detector serve                    # the web interface
    threat-detector selfcheck                # does detection still work?
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__, pcap, synth
from . import model as model_service
from .auth import is_loopback
from .config import Config
from .features import DataError
from .integrity import IntegrityError
from .model import ModelNotTrained

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )


# ---- commands -------------------------------------------------------------

def cmd_generate(args, config: Config) -> int:
    output = args.output or config.data_file
    synth.generate(output, args.count, args.hosts, args.seed, not args.no_attacks)
    return 0


def cmd_ingest(args, config: Config) -> int:
    result = pcap.convert(args.capture, args.output or config.data_file, args.limit)
    print(f"[OK] Wrote {result['packets']} packets to {result['output']} "
          f"({result['skipped']} non-IPv4 packets skipped)")
    return 0


def cmd_train(args, config: Config) -> int:
    summary = model_service.train(config)
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0
    print(f"Fitted {summary['algorithm']}/{summary['feature_set']} on "
          f"{summary['rows_trained']} rows from {summary['fitted_on']}")
    print(f"Alert threshold: {summary['threshold']} "
          f"(quantile {summary['calibration_quantile']})")
    if not summary["fitted_on_baseline"]:
        print("\nWarning: fitted on the traffic being inspected. Point --baseline "
              "at known-good traffic for real detection.", file=sys.stderr)
    return 0


def cmd_detect(args, config: Config) -> int:
    result = model_service.detect(config, limit=args.limit)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    unit = "sessions" if config.feature_set == "flow" else "packets"
    print(f"{result['count']} of {result['total_packets']} {unit} flagged\n")
    if not result["anomalies"]:
        print("Nothing anomalous. (With a baseline configured, that is a real answer.)")
        return 0

    columns = _display_columns(result["anomalies"][0])
    widths = [max(len(c), *(len(_fmt(row.get(c))) for row in result["anomalies"]))
              for c in columns]
    print("  ".join(c.ljust(w) for c, w in zip(columns, widths)))
    print("  ".join("-" * w for w in widths))
    for row in result["anomalies"]:
        print("  ".join(_fmt(row.get(c)).ljust(w) for c, w in zip(columns, widths)))
    if result["truncated"]:
        print(f"\n... {result['count'] - result['returned']} more (use --limit)")
    return 0


def cmd_inspect(args, config: Config) -> int:
    bundle = model_service.load_model(config)
    for field in ("algorithm", "feature_set", "window_seconds", "rows_trained",
                  "threshold", "fitted_on"):
        print(f"{field:<16} {bundle.get(field)}")
    print(f"{'features':<16} {', '.join(bundle.get('feature_columns', []))}")
    return 0


def cmd_selfcheck(args, config: Config) -> int:
    from .selfcheck import run

    return run(config)


def cmd_serve(args, config: Config) -> int:
    from . import create_app

    host = args.host or os.getenv("HOST", "127.0.0.1")
    port = args.port or int(os.getenv("PORT", "5000"))

    # Refusing here rather than warning: an unauthenticated service on a
    # routable address exposes the monitored network's traffic to anyone who
    # can reach the port, and "it was in the README" is not a control.
    if not is_loopback(host) and config.api_token is None:
        print(
            f"Refusing to listen on {host} without authentication.\n"
            "Set API_TOKEN, or bind to 127.0.0.1. The API exposes your network "
            "traffic analysis and can start training runs.",
            file=sys.stderr,
        )
        return 2

    app = create_app(config)
    if args.production:
        return _serve_production(app, host, port, args.workers)

    print(f"Serving on http://{host}:{port}  (development server)")
    app.run(host=host, port=port, debug=config.debug)
    return 0


def _serve_production(app, host: str, port: int, workers: int) -> int:
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:
        print("Production mode needs gunicorn: pip install 'ai-threat-detector[server]'",
              file=sys.stderr)
        return 2

    class Served(BaseApplication):
        def load_config(self):
            self.cfg.set("bind", f"{host}:{port}")
            # Training state is shared through a file, so extra workers are
            # safe; threads keep the UI responsive during a fit.
            self.cfg.set("workers", workers)
            self.cfg.set("threads", 4)
            self.cfg.set("timeout", 120)

        def load(self):
            return app

    print(f"Serving on http://{host}:{port}  ({workers} workers)")
    Served().run()
    return 0


# ---- helpers --------------------------------------------------------------

_PREFERRED_COLUMNS = [
    "src_ip", "window_start", "packets", "bytes_total", "distinct_dst_ips",
    "distinct_dst_ports", "std_interarrival", "timestamp", "dst_ip", "protocol",
    "packet_length", "anomaly_score",
]


def _display_columns(row: dict) -> list[str]:
    present = [c for c in _PREFERRED_COLUMNS if c in row]
    return present or list(row)[:8]


def _fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}" if abs(value) < 1000 else f"{value:.0f}"
    return str(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-detector",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--data", type=Path, help="capture CSV to analyse (DATA_FILE)")
    parser.add_argument("--baseline", type=Path,
                        help="known-good capture to fit on (BASELINE_FILE) — "
                             "the setting that matters most")
    parser.add_argument("--model", type=Path, help="model file (MODEL_FILE)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="write a synthetic capture with planted attacks")
    gen.add_argument("-o", "--output", type=Path)
    gen.add_argument("-c", "--count", type=int, default=6000)
    gen.add_argument("--hosts", type=int, default=25)
    gen.add_argument("-s", "--seed", type=int, default=42)
    gen.add_argument("--no-attacks", action="store_true",
                     help="clean baseline, for fitting against")
    gen.set_defaults(func=cmd_generate)

    ing = sub.add_parser("ingest", help="convert a .pcap/.pcapng into the CSV format")
    ing.add_argument("capture", type=Path)
    ing.add_argument("-o", "--output", type=Path)
    ing.add_argument("--limit", type=int, help="stop after N packets")
    ing.set_defaults(func=cmd_ingest)

    tr = sub.add_parser("train", help="fit the detector and calibrate its threshold")
    tr.add_argument("--json", action="store_true")
    tr.set_defaults(func=cmd_train)

    det = sub.add_parser("detect", help="report flagged sessions")
    det.add_argument("--limit", type=int)
    det.add_argument("--json", action="store_true")
    det.set_defaults(func=cmd_detect)

    ins = sub.add_parser("inspect", help="describe the saved model")
    ins.set_defaults(func=cmd_inspect)

    chk = sub.add_parser("selfcheck", help="verify detection still works end to end")
    chk.set_defaults(func=cmd_selfcheck)

    srv = sub.add_parser("serve", help="run the web interface")
    srv.add_argument("--host")
    srv.add_argument("--port", type=int)
    srv.add_argument("--production", action="store_true", help="serve with gunicorn")
    srv.add_argument("--workers", type=int, default=2)
    srv.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    config = Config()
    overrides = {}
    if args.data:
        overrides["data_file"] = args.data.resolve()
    if args.baseline:
        overrides["baseline_file"] = args.baseline.resolve()
    if args.model:
        overrides["model_file"] = args.model.resolve()
    if overrides:
        config = replace(config, **overrides)

    try:
        return args.func(args, config)
    except (DataError, ModelNotTrained, IntegrityError, pcap.PcapError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
