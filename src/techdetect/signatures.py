from pathlib import Path

from techdetect.models import Signature


def load_signatures(root: Path) -> list[Signature]:
    raise NotImplementedError
