import argparse
import logging
import sys

import pyarrow.parquet as pq

from techdetect import config, detect, extract, fetch, report


def load_domains(path) -> list[str]:
    table = pq.read_table(path)
    return table.column("root_domain").to_pylist()


def command_fetch(args) -> int:
    domains = load_domains(args.input)
    if args.limit:
        domains = domains[: args.limit]
    logging.info("fetching %d domains into %s", len(domains), args.raw_dir)
    return fetch.run_fetch(domains, args.raw_dir)


def command_extract(args) -> int:
    logging.info("extracting signals from %s", args.raw_dir)
    return extract.run_extract(args.raw_dir, args.signals)


def command_detect(args) -> int:
    logging.info("detecting with signatures from %s", args.signatures)
    return detect.run_detect(args.signals, args.signatures, args.detections)


def command_report(args) -> int:
    logging.info("writing report into %s", args.reports_dir)
    return report.run_report(args.detections, args.raw_dir, args.reports_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="techdetect")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch", help="download raw data for every domain")
    fetch_parser.add_argument("--input", default=config.INPUT_PARQUET)
    fetch_parser.add_argument("--raw-dir", dest="raw_dir", default=config.RAW_DIR)
    fetch_parser.add_argument("--limit", type=int, default=None)
    fetch_parser.set_defaults(handler=command_fetch)

    extract_parser = subparsers.add_parser("extract", help="turn raw data into signals")
    extract_parser.add_argument("--raw-dir", dest="raw_dir", default=config.RAW_DIR)
    extract_parser.add_argument("--signals", default=config.SIGNALS_DIR / "signals.jsonl")
    extract_parser.set_defaults(handler=command_extract)

    detect_parser = subparsers.add_parser("detect", help="match signals against signatures")
    detect_parser.add_argument("--signals", default=config.SIGNALS_DIR / "signals.jsonl")
    detect_parser.add_argument("--signatures", default=config.SIGNATURES_DIR)
    detect_parser.add_argument("--detections", default=config.DETECTIONS_DIR / "detections.jsonl")
    detect_parser.set_defaults(handler=command_detect)

    report_parser = subparsers.add_parser("report", help="write final output and metrics")
    report_parser.add_argument("--detections", default=config.DETECTIONS_DIR / "detections.jsonl")
    report_parser.add_argument("--raw-dir", dest="raw_dir", default=config.RAW_DIR)
    report_parser.add_argument("--reports-dir", dest="reports_dir", default=config.REPORTS_DIR)
    report_parser.set_defaults(handler=command_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
