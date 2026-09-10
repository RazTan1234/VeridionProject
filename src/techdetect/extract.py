from pathlib import Path

from techdetect.models import FetchRecord, Signal


def extract_from_record(record: FetchRecord, raw_dir: Path) -> list[Signal]:
    raise NotImplementedError


def run_extract(raw_dir: Path, signals_path: Path) -> int:
    raise NotImplementedError
