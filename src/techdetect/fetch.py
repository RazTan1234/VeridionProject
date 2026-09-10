from pathlib import Path

from techdetect.models import FetchRecord


async def fetch_document(client, domain: str, document_id: str, url: str) -> FetchRecord:
    raise NotImplementedError


async def fetch_domain(client, domain: str, raw_dir: Path) -> list[FetchRecord]:
    raise NotImplementedError


def run_fetch(domains: list[str], raw_dir: Path) -> int:
    raise NotImplementedError
