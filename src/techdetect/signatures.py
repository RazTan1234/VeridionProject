import logging
from collections import Counter
from pathlib import Path

import regex
import yaml
from selectolax.lexbor import LexborHTMLParser

from techdetect.models import Pattern, Signature, SignalKind
from techdetect.store import read_records

EXTERNAL_FILE = "technologies.jsonl"
EMPTY_DOCUMENT = LexborHTMLParser("<html><body></body></html>")


class SignatureError(ValueError):
    pass


def pattern_problem(pattern: Pattern) -> str | None:
    if pattern.value:
        try:
            regex.compile(pattern.value, regex.IGNORECASE)
        except regex.error as error:
            return f"invalid regex {pattern.value!r}: {error}"
    if pattern.kind is SignalKind.DOM:
        try:
            EMPTY_DOCUMENT.css(pattern.key or "")
        except Exception as error:
            return f"invalid selector {pattern.key!r}: {error}"
    return None


def load_own(directory: Path) -> list[Signature]:
    signatures = []
    for path in sorted(Path(directory).glob("*.yaml")):
        for entry in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("technologies") or []:
            try:
                slug = regex.sub(r"[^a-z0-9]+", "-", entry["name"].lower()).strip("-")
                signature = Signature(id=f"own:{slug}", source="own", **entry)
            except Exception as error:
                raise SignatureError(f"{path.name}: {entry.get('name')}: {error}") from error
            if problems := [problem for problem in map(pattern_problem, signature.patterns) if problem]:
                raise SignatureError(f"{path.name}: {signature.name}: {problems[0]}")
            signatures.append(signature)
    return signatures


def load_external(directory: Path) -> list[Signature]:
    path = Path(directory) / EXTERNAL_FILE
    if not path.exists():
        logging.warning("no external signatures at %s, run `techdetect signatures --sync`", path)
        return []
    return list(read_records(path, Signature))


def load_signatures(root: Path) -> list[Signature]:
    return load_own(Path(root) / "own") + load_external(Path(root) / "external")


def describe(signatures: list[Signature]) -> Counter:
    stats = Counter(distinct_names=len({signature.name.lower() for signature in signatures}))
    for signature in signatures:
        stats[f"{signature.source}_technologies"] += 1
        stats[f"{signature.source}_patterns"] += len(signature.patterns)
        stats.update(f"kind_{pattern.kind.value}" for pattern in signature.patterns)
    return stats
