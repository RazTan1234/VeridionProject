import argparse
import logging
import sys
from pathlib import Path

import pyarrow.parquet as pq

from techdetect import config, detect, external, extract, fetch, report, signatures

PATH_OPTIONS = {
    "raw_dir": ("--raw-dir", config.RAW_DIR),
    "signals": ("--signals", config.SIGNALS_DIR / "signals.jsonl"),
    "signatures": ("--signatures", config.SIGNATURES_DIR),
    "detections": ("--detections", config.DETECTIONS_DIR / "detections.jsonl"),
    "reports_dir": ("--reports-dir", config.REPORTS_DIR),
    "ground_truth": ("--ground-truth", config.VALIDATION_FILE),
}


def command_fetch(args) -> int:
    domains = pq.read_table(args.input).column("root_domain").to_pylist()[: args.limit]
    return fetch.run_fetch(domains, args.raw_dir, refresh=set(args.refresh or []))


def command_signatures(args) -> int:
    if args.sync:
        external.run_sync(config.EXTERNAL_SIGNATURES_DIR)
    for key, value in sorted(signatures.describe(signatures.load_signatures(args.signatures)).items()):
        logging.info("  %-28s %d", key, value)
    return 0


COMMANDS = {
    "fetch": ("download raw data for every domain", command_fetch, ["raw_dir"]),
    "signatures": ("sync and inspect signature sources", command_signatures, ["signatures"]),
    "extract": ("turn raw data into signals", lambda args: extract.run_extract(args.raw_dir, args.signals), ["raw_dir", "signals"]),
    "detect": (
        "match signals against signatures",
        lambda args: detect.run_detect(args.signals, args.signatures, args.detections, args.raw_dir),
        ["signals", "signatures", "detections", "raw_dir"],
    ),
    "report": (
        "write final output and metrics",
        lambda args: report.run_report(args.detections, args.raw_dir, args.reports_dir),
        ["detections", "raw_dir", "reports_dir"],
    ),
    "validate": (
        "score detections against the manual ground truth",
        lambda args: max(report.run_validate(args.detections, args.ground_truth, args.reports_dir, threshold) for threshold in (0.0, 0.8)),
        ["detections", "ground_truth", "reports_dir"],
    ),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="techdetect")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (description, handler, options) in COMMANDS.items():
        command = subparsers.add_parser(name, help=description)
        for option in options:
            flag, default = PATH_OPTIONS[option]
            command.add_argument(flag, dest=option, type=Path, default=default)
        command.set_defaults(handler=handler)
    subparsers.choices["fetch"].add_argument("--input", type=Path, default=config.INPUT_PARQUET)
    subparsers.choices["fetch"].add_argument("--limit", type=int)
    subparsers.choices["fetch"].add_argument("--refresh", nargs="*", choices=["home", "dns", "tls"])
    subparsers.choices["signatures"].add_argument("--sync", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
