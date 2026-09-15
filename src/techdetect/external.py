import json
import logging
from collections import Counter
from pathlib import Path

import httpx
import regex
from selectolax.lexbor import LexborHTMLParser

from techdetect import config
from techdetect.models import Pattern, Signature, SignalKind
from techdetect.store import write_records

TAG_SEPARATOR = "\\;"
TECHNOLOGY_FILES = [f"technologies/{letter}.json" for letter in "_abcdefghijklmnopqrstuvwxyz"]
KEYED_FIELDS = {
    "headers": SignalKind.HTTP_HEADER,
    "cookies": SignalKind.COOKIE,
    "meta": SignalKind.META,
    "dns": SignalKind.DNS_RECORD,
}
LISTED_FIELDS = {
    "scriptSrc": SignalKind.SCRIPT_SRC,
    "scripts": SignalKind.HTML_TEXT,
    "html": SignalKind.HTML_TEXT,
    "text": SignalKind.HTML_TEXT,
    "url": SignalKind.PAGE_URL,
    "certIssuer": SignalKind.TLS_ISSUER,
    "robots": SignalKind.ROBOTS_LINE,
}
UNSUPPORTED_FIELDS = ("js", "xhr", "css", "probe")
DNS_KEY_ALIASES = {"CNAME": "www.CNAME"}
EMPTY_DOCUMENT = LexborHTMLParser("<html><body></body></html>")


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def split_tags(raw: str) -> tuple[str, str | None, int]:
    parts = raw.split(TAG_SEPARATOR)
    expression, version, confidence = parts[0], None, 100
    for tag in parts[1:]:
        name, _, argument = tag.partition(":")
        if name == "version":
            version = argument
        elif name == "confidence" and argument.isdigit():
            confidence = int(argument)
    return expression, version, confidence


def valid_expression(expression: str) -> bool:
    try:
        regex.compile(expression, regex.IGNORECASE)
    except regex.error:
        return False
    return True


def valid_selector(selector: str) -> bool:
    try:
        EMPTY_DOCUMENT.css(selector)
    except Exception:
        return False
    return True


def build_pattern(
    kind: SignalKind, raw, stats: Counter, key: str | None = None, attribute: str | None = None
) -> Pattern | None:
    expression, version, confidence = split_tags(raw) if isinstance(raw, str) else ("", None, 100)
    if expression and not valid_expression(expression):
        stats["rejected_invalid_regex"] += 1
        return None
    return Pattern(
        kind=kind,
        key=key,
        attribute=attribute,
        value=expression or None,
        version=version or None,
        confidence=confidence,
    )


def dom_patterns(spec, stats: Counter) -> list[Pattern]:
    patterns: list[Pattern] = []
    if isinstance(spec, (str, list)):
        rules_by_selector = {selector: {} for selector in as_list(spec)}
    elif isinstance(spec, dict):
        rules_by_selector = spec
    else:
        return patterns

    for selector, rules in rules_by_selector.items():
        if not valid_selector(selector):
            stats["rejected_invalid_selector"] += 1
            continue
        rules = rules if isinstance(rules, dict) else {}
        if not rules or "exists" in rules:
            patterns.append(Pattern(kind=SignalKind.DOM, key=selector))
        for attribute, raw in (rules.get("attributes") or {}).items():
            pattern = build_pattern(SignalKind.DOM, raw, stats, key=selector, attribute=attribute)
            if pattern:
                patterns.append(pattern)
        if "text" in rules:
            pattern = build_pattern(SignalKind.DOM, rules["text"], stats, key=selector, attribute="#text")
            if pattern:
                patterns.append(pattern)
        if "properties" in rules:
            stats["rejected_dom_properties"] += 1
    return patterns


def technology_names(value) -> list[str]:
    return [item.split(TAG_SEPARATOR)[0].strip() for item in as_list(value) if isinstance(item, str)]


def convert_technology(name: str, spec: dict, categories: dict[str, str], stats: Counter) -> Signature:
    patterns: list[Pattern] = []

    for field, kind in KEYED_FIELDS.items():
        for key, raw_values in (spec.get(field) or {}).items():
            normalized_key = DNS_KEY_ALIASES.get(key, key) if kind is SignalKind.DNS_RECORD else key
            if kind in (SignalKind.HTTP_HEADER, SignalKind.META):
                normalized_key = normalized_key.lower()
            for raw in as_list(raw_values) or [""]:
                pattern = build_pattern(kind, raw, stats, key=normalized_key)
                if pattern:
                    patterns.append(pattern)

    for field, kind in LISTED_FIELDS.items():
        for raw in as_list(spec.get(field)):
            pattern = build_pattern(kind, raw, stats)
            if pattern:
                patterns.append(pattern)

    if "dom" in spec:
        patterns.extend(dom_patterns(spec["dom"], stats))

    for field in UNSUPPORTED_FIELDS:
        if field in spec:
            stats[f"unsupported_field_{field}"] += 1

    for pattern in patterns:
        stats[f"patterns_{pattern.kind.value}"] += 1
    stats["technologies"] += 1
    stats["technologies_detectable" if patterns else "technologies_without_patterns"] += 1

    return Signature(
        id=f"external:{name}",
        name=name,
        categories=[categories.get(str(identifier), str(identifier)) for identifier in as_list(spec.get("cats"))],
        website=spec.get("website"),
        source="external",
        patterns=patterns,
        implies=technology_names(spec.get("implies")),
        requires=technology_names(spec.get("requires")),
        requires_category=[
            categories.get(str(identifier), str(identifier)) for identifier in as_list(spec.get("requiresCategory"))
        ],
        excludes=technology_names(spec.get("excludes")),
    )


def download_external(destination: Path, revision: str) -> Path:
    target = Path(destination) / "source" / revision
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for relative in ["categories.json", *TECHNOLOGY_FILES]:
            path = target / relative
            if path.exists():
                continue
            url = config.EXTERNAL_RAW_URL.format(
                repository=config.EXTERNAL_REPOSITORY, revision=revision, path=relative
            )
            response = client.get(url)
            response.raise_for_status()
            path.parent.mkdir(parents=True, exist_ok=True)
            partial = path.with_suffix(path.suffix + ".part")
            partial.write_bytes(response.content)
            partial.replace(path)
    return target


def convert_external(source: Path) -> tuple[list[Signature], Counter]:
    source = Path(source)
    raw_categories = json.loads((source / "categories.json").read_text(encoding="utf-8"))
    categories = {identifier: entry.get("name", identifier) for identifier, entry in raw_categories.items()}

    stats: Counter = Counter()
    signatures = []
    for relative in TECHNOLOGY_FILES:
        technologies = json.loads((source / relative).read_text(encoding="utf-8"))
        for name, spec in technologies.items():
            signatures.append(convert_technology(name, spec, categories, stats))
    return signatures, stats


def run_sync(destination: Path, revision: str = config.EXTERNAL_REVISION) -> Counter:
    destination = Path(destination)
    source = download_external(destination, revision)
    signatures, stats = convert_external(source)
    write_records(destination / "technologies.jsonl", signatures)
    report = {
        "repository": config.EXTERNAL_REPOSITORY,
        "revision": revision,
        "license": config.EXTERNAL_LICENSE,
        "stats": dict(sorted(stats.items())),
    }
    (destination / "conversion_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    logging.info("converted %d external technologies from %s@%s", stats["technologies"], config.EXTERNAL_REPOSITORY, revision[:12])
    return stats
