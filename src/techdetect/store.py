from pathlib import Path


def content_ref(payload: bytes) -> str:
    raise NotImplementedError


def write_content(root: Path, payload: bytes) -> str:
    raise NotImplementedError


def read_content(root: Path, ref: str) -> bytes:
    raise NotImplementedError


def write_records(path: Path, records) -> int:
    raise NotImplementedError


def read_records(path: Path, model):
    raise NotImplementedError
