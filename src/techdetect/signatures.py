import logging
from collections import Counter
from pathlib import Path

import regex
import yaml
from selectolax.lexbor import LexborHTMLParser

from techdetect.models import Signature, SignalKind
from techdetect.store import read_records

EXTERNAL_FILE = "technologies.jsonl"
EMPTY_DOCUMENT = LexborHTMLParser("<html><body></body></html>")


class SignatureError(ValueError):
    pass


def slug(name: str) -> str:
    return regex.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def pattern_problem(signature: Signature) -> str | None:
    for pattern in signature.patterns:
        if pattern.value:
            try:
                regex.compile(pattern.value, regex.IGNORECASE)
            except regex.error as error:
                return f"invalid regex {pattern.value!r}: {error}"
        if pattern.kind is SignalKind.DOM:
            if not pattern.key:
                return "dom pattern without selector"
            try:
                EMPTY_DOCUMENT.css(pattern.key)
            except Exception as error:
                return f"invalid selector {pattern.key!r}: {error}"
    return None


def load_own(directory: Path) -> list[Signature]:
    signatures = []
    for path in sorted(Path(directory).glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in document.get("technologies") or []:
            try:
                signature = Signature(id=f"own:{slug(entry['name'])}", source="own", **entry)
            except Exception as error:
                raise SignatureError(f"{path.name}: {entry.get('name')}: {error}") from error
            problem = pattern_problem(signature)
            if problem:
                raise SignatureError(f"{path.name}: {signature.name}: {problem}")
            signatures.append(signature)
    return signatures


def load_external(directory: Path) -> list[Signature]:
    path = Path(directory) / EXTERNAL_FILE
    if not path.exists():
        logging.warning("no external signatures at %s, run `techdetect signatures --sync`", path)
        return []
    return list(read_records(path, Signature))


def load_signatures(root: Path) -> list[Signature]:
    root = Path(root)
    return load_own(root / "own") + load_external(root / "external")


def describe(signatures: list[Signature]) -> Counter:
    stats: Counter = Counter()
    for signature in signatures:
        stats[f"{signature.source}_technologies"] += 1
        for pattern in signature.patterns:
            stats[f"{signature.source}_patterns"] += 1
            stats[f"kind_{pattern.kind.value}"] += 1
    stats["distinct_names"] = len({signature.name.lower() for signature in signatures})
    return stats
