from pathlib import Path

from techdetect.models import Signature


def download_external(destination: Path, revision: str) -> Path:
    raise NotImplementedError


def convert_external(source: Path) -> list[Signature]:
    raise NotImplementedError
