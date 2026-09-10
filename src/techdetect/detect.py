from pathlib import Path

from techdetect.models import Detection, Signal, Signature


def match_signals(signals: list[Signal], signatures: list[Signature]) -> list[Detection]:
    raise NotImplementedError


def combine_confidence(weights: list[float]) -> float:
    raise NotImplementedError


def apply_implications(detections: list[Detection], signatures: list[Signature]) -> list[Detection]:
    raise NotImplementedError


def run_detect(signals_path: Path, signatures_dir: Path, detections_path: Path) -> int:
    raise NotImplementedError
