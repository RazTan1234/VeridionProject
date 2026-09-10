from pathlib import Path


def write_output(detections_path: Path, reports_dir: Path) -> Path:
    raise NotImplementedError


def build_metrics(detections_path: Path, raw_dir: Path) -> dict:
    raise NotImplementedError


def run_report(detections_path: Path, raw_dir: Path, reports_dir: Path) -> int:
    raise NotImplementedError
