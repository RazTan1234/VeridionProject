import json
import logging
from collections import Counter
from pathlib import Path

import httpx

from techdetect import config
from techdetect.models import Pattern, SignalKind, Signature
from techdetect.signatures import pattern_problem
from techdetect.store import write_records

TAG_SEPARATOR = "\\;"
TECHNOLOGY_FILES = [f"technologies/{letter}.json" for letter in "_abcdefghijklmnopqrstuvwxyz"]
FIELD_KINDS = {
    "headers": SignalKind.HTTP_HEADER,
    "cookies": SignalKind.COOKIE,
    "meta": SignalKind.META,
    "dns": SignalKind.DNS_RECORD,
    "scriptSrc": SignalKind.SCRIPT_SRC,
    "html": SignalKind.HTML_TEXT,
    "url": SignalKind.PAGE_URL,
    "certIssuer": SignalKind.TLS_ISSUER,
    "robots": SignalKind.ROBOTS_LINE,
}
KEYED_FIELDS = {"headers", "cookies", "meta", "dns"}
UNSUPPORTED_FIELDS = ("js", "scripts", "text", "xhr", "css", "probe")
DNS_KEY_ALIASES = {"CNAME": "www.CNAME"}


def as_list(value) -> list:
    return [] if value is None else value if isinstance(value, list) else [value]


def split_tags(raw: str) -> tuple[str, str | None, int]:
    expression, *tags = raw.split(TAG_SEPARATOR)
    version, confidence = None, 100
    for tag in tags:
        name, _, argument = tag.partition(":")
        if name == "version":
            version = argument
        elif name == "confidence" and argument.isdigit():
            confidence = int(argument)
    return expression, version, confidence


def build_pattern(kind: SignalKind, raw, stats: Counter, key=None, attribute=None) -> Pattern | None:
    expression, version, confidence = split_tags(raw) if isinstance(raw, str) else ("", None, 100)
    pattern = Pattern(kind=kind, key=key, attribute=attribute, value=expression or None, version=version or None, confidence=confidence)
    if problem := pattern_problem(pattern):
        stats["rejected_invalid_selector" if problem.startswith("invalid selector") else "rejected_invalid_regex"] += 1
        return None
    return pattern


def dom_patterns(spec, stats: Counter) -> list[Pattern]:
    selectors = spec if isinstance(spec, dict) else {selector: {} for selector in as_list(spec)}
    patterns = []
    for selector, rules in selectors.items():
        rules = rules if isinstance(rules, dict) else {}
        candidates = [("", None)] if not rules or "exists" in rules else []
        candidates += [(raw, attribute) for attribute, raw in (rules.get("attributes") or {}).items()]
        candidates += [(rules["text"], "#text")] if "text" in rules else []
        if "properties" in rules:
            stats["rejected_dom_properties"] += 1
        for raw, attribute in candidates:
            if pattern := build_pattern(SignalKind.DOM, raw, stats, key=selector, attribute=attribute):
                patterns.append(pattern)
    return patterns


def technology_names(value) -> list[str]:
    return [item.split(TAG_SEPARATOR)[0].strip() for item in as_list(value) if isinstance(item, str)]


def convert_technology(name: str, spec: dict, categories: dict[str, str], stats: Counter) -> Signature:
    patterns = []
    for field, kind in FIELD_KINDS.items():
        if field in KEYED_FIELDS:
            for key, raw_values in (spec.get(field) or {}).items():
                if kind is SignalKind.DNS_RECORD:
                    key = DNS_KEY_ALIASES.get(key, key)
                elif kind in (SignalKind.HTTP_HEADER, SignalKind.META):
                    key = key.lower()
                patterns += [p for raw in as_list(raw_values) or [""] if (p := build_pattern(kind, raw, stats, key=key))]
        else:
            patterns += [p for raw in as_list(spec.get(field)) if (p := build_pattern(kind, raw, stats))]
    if "dom" in spec:
        patterns += dom_patterns(spec["dom"], stats)

    stats.update(f"unsupported_field_{field}" for field in UNSUPPORTED_FIELDS if field in spec)
    stats.update(f"patterns_{pattern.kind.value}" for pattern in patterns)
    stats.update(["technologies", "technologies_detectable" if patterns else "technologies_without_patterns"])

    def category_names(field: str) -> list[str]:
        return [categories.get(str(identifier), str(identifier)) for identifier in as_list(spec.get(field))]

    return Signature(
        id=f"external:{name}",
        name=name,
        categories=category_names("cats"),
        website=spec.get("website"),
        source="external",
        patterns=patterns,
        implies=technology_names(spec.get("implies")),
        requires=technology_names(spec.get("requires")),
        requires_category=category_names("requiresCategory"),
        excludes=technology_names(spec.get("excludes")),
    )


def download_external(destination: Path, revision: str) -> Path:
    target = Path(destination) / "source" / revision
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for relative in ["categories.json", *TECHNOLOGY_FILES]:
            path = target / relative
            if not path.exists():
                url = config.EXTERNAL_RAW_URL.format(repository=config.EXTERNAL_REPOSITORY, revision=revision, path=relative)
                response = client.get(url)
                response.raise_for_status()
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(response.content)
    return target


def run_sync(destination: Path, revision: str = config.EXTERNAL_REVISION) -> Counter:
    source = download_external(destination, revision)
    categories = {key: entry.get("name", key) for key, entry in json.loads((source / "categories.json").read_text("utf-8")).items()}
    stats, signatures = Counter(), []
    for relative in TECHNOLOGY_FILES:
        for name, spec in json.loads((source / relative).read_text("utf-8")).items():
            signatures.append(convert_technology(name, spec, categories, stats))

    write_records(Path(destination) / "technologies.jsonl", signatures)
    report = {"repository": config.EXTERNAL_REPOSITORY, "revision": revision, "license": config.EXTERNAL_LICENSE, "stats": dict(sorted(stats.items()))}
    (Path(destination) / "conversion_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    logging.info("converted %d technologies from %s@%s", stats["technologies"], config.EXTERNAL_REPOSITORY, revision[:12])
    return stats
