import logging
import time
from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from pathlib import Path

import regex
from selectolax.lexbor import LexborHTMLParser

from techdetect import config
from techdetect.extract import decode_body, latest_records
from techdetect.models import Detection, Evidence, SignalKind, Signal
from techdetect.signatures import load_signatures
from techdetect.store import read_content, read_records, write_records

VERSION_SHAPE = regex.compile(r"^[\w.+-]{1,30}$")
GROUP_REFERENCE = regex.compile(r"\\(\d+)")
SNIPPET_RADIUS = 60
IMPLIED_WEIGHT_FACTOR = 0.9


def search(compiled, text: str):
    try:
        return compiled.search(text, timeout=config.REGEX_TIMEOUT_SECONDS)
    except TimeoutError:
        return None


def resolve_version(template: str | None, match) -> str | None:
    if not template or match is None:
        return None
    resolved = GROUP_REFERENCE.sub(
        lambda ref: (match.group(int(ref.group(1))) or "") if int(ref.group(1)) <= len(match.groups()) else "",
        template,
    )
    if "?" in resolved and ":" in resolved:
        condition, _, branches = resolved.partition("?")
        present, _, absent = branches.partition(":")
        resolved = present if condition else absent
    resolved = resolved.strip()
    return resolved if VERSION_SHAPE.match(resolved) else None


class Catalog:
    def __init__(self, signatures):
        self.names: dict[str, str] = {}
        self.traits = defaultdict(lambda: {"categories": [], "implies": set(), "requires": set(), "requires_category": set(), "excludes": set()})
        self.keyed = defaultdict(list)
        self.wildcard = defaultdict(list)
        self.plain = defaultdict(list)
        for signature in signatures:
            key = signature.name.lower()
            if key not in self.names or signature.source == "external":
                self.names[key] = signature.name
            traits = self.traits[key]
            traits["categories"] += [c for c in signature.categories if c not in traits["categories"]]
            for field in ("implies", "requires", "excludes"):
                traits[field].update(name.lower() for name in getattr(signature, field))
            traits["requires_category"].update(signature.requires_category)
            for pattern in signature.patterns:
                rule = (key, signature, pattern, regex.compile(pattern.value, regex.IGNORECASE) if pattern.value else None)
                if pattern.kind is SignalKind.DOM or not pattern.key:
                    self.plain[pattern.kind].append(rule)
                elif "*" in pattern.key:
                    self.wildcard[pattern.kind].append(rule)
                else:
                    self.keyed[(pattern.kind, pattern.key.lower())].append(rule)

    def rules_for(self, signal: Signal):
        if signal.key is None:
            return self.plain[signal.kind]
        key = signal.key.lower()
        wildcards = [rule for rule in self.wildcard[signal.kind] if fnmatchcase(key, rule[2].key.lower())]
        return self.keyed[(signal.kind, key)] + wildcards + self.plain[signal.kind]


class Accumulator:
    def __init__(self):
        self.evidence: dict[tuple, Evidence] = {}
        self.tiers = defaultdict(set)
        self.versions = defaultdict(Counter)

    def add(self, signal: Signal, rule, snippet: str, version: str | None) -> None:
        tech, signature, pattern, _ = rule
        kind = pattern.kind
        weight = pattern.weight if pattern.weight is not None else config.KIND_WEIGHTS[kind.value] * pattern.confidence / 100
        identity = (signal.domain, tech, signature.id, f"{signal.observation_id}:{kind.value}")
        evidence = self.evidence.get(identity)
        if evidence is None:
            evidence = self.evidence[identity] = Evidence(
                signature_id=signature.id,
                signature_source=signature.source,
                signal_kind=kind,
                document_id=signal.document_id,
                observation_id=signal.observation_id,
                location=signal.location,
                matched_pattern=pattern.key if pattern.kind is SignalKind.DOM and not pattern.value else pattern.value,
                weight=round(weight, 3),
            )
        if snippet and snippet not in evidence.snippets and len(evidence.snippets) < 5:
            evidence.snippets.append(snippet[: config.MAX_SIGNAL_VALUE_CHARS])
        evidence.weight = max(evidence.weight, round(weight, 3))
        self.tiers[(signal.domain, tech)].add(signal.tier)
        if version:
            self.versions[(signal.domain, tech)][(version, kind.value)] += 1


def match_fields(signal: Signal, catalog: Catalog, found: Accumulator) -> None:
    for rule in catalog.rules_for(signal):
        pattern, compiled = rule[2], rule[3]
        match = search(compiled, signal.value or "") if compiled else None
        if compiled and not match:
            continue
        snippet = f"{signal.key}: {signal.value}" if signal.key else signal.value
        found.add(signal, rule, snippet, resolve_version(pattern.version, match))


def match_document(signal: Signal, text: str, catalog: Catalog, found: Accumulator) -> None:
    for rule in catalog.plain[SignalKind.HTML_TEXT]:
        match = search(rule[3], text)
        if match:
            start, end = max(match.start() - SNIPPET_RADIUS, 0), match.end() + SNIPPET_RADIUS
            found.add(signal, rule, " ".join(text[start:end].split()), resolve_version(rule[2].version, match))

    tree = LexborHTMLParser(text)
    for rule in catalog.plain[SignalKind.DOM]:
        pattern, compiled = rule[2], rule[3]
        try:
            nodes = tree.css(pattern.key)
        except Exception:
            continue
        for node in nodes:
            if pattern.attribute is None:
                found.add(signal, rule, f"<{node.tag}> matches {pattern.key}", None)
                break
            candidate = node.text() if pattern.attribute == "#text" else node.attributes.get(pattern.attribute)
            match = search(compiled, candidate) if compiled and candidate else None
            if candidate is not None and (compiled is None or match):
                found.add(signal, rule, f"{pattern.key} {pattern.attribute}={candidate[:200]}", resolve_version(pattern.version, match))
                break


def noisy_or(weights) -> float:
    remaining = 1.0
    for weight in weights:
        remaining *= 1 - weight
    return round(1 - remaining, 4)


def build_direct(found: Accumulator, catalog: Catalog, offsite_documents: set) -> dict[str, dict[str, Detection]]:
    grouped = defaultdict(list)
    for (domain, tech, _, _), evidence in found.evidence.items():
        grouped[(domain, tech)].append(evidence)

    by_domain = defaultdict(dict)
    for (domain, tech), evidences in grouped.items():
        strongest = defaultdict(float)
        for evidence in evidences:
            strongest[evidence.observation_id] = max(strongest[evidence.observation_id], evidence.weight)
        documents = sorted({evidence.document_id for evidence in evidences})
        versions = found.versions[(domain, tech)]
        version, version_source = max(versions, key=lambda item: (versions[item], len(item[0]))) if versions else (None, None)
        by_domain[domain][tech] = Detection(
            domain=domain,
            technology=catalog.names[tech],
            categories=catalog.traits[tech]["categories"],
            version=version,
            version_source=version_source,
            confidence=noisy_or(strongest.values()),
            offsite=all((domain, document) in offsite_documents for document in documents),
            tiers=sorted(found.tiers[(domain, tech)], key=lambda tier: tier.value),
            documents=documents,
            evidence=sorted(evidences, key=lambda evidence: -evidence.weight),
        )
    return by_domain


def with_implications(active: dict[str, Detection], catalog: Catalog) -> dict[str, Detection]:
    found = dict(active)
    queue = list(active)
    while queue:
        source = queue.pop()
        for implied in catalog.traits[source]["implies"]:
            if implied in found or implied not in catalog.names:
                continue
            parent = found[source]
            found[implied] = Detection(
                domain=parent.domain,
                technology=catalog.names[implied],
                categories=catalog.traits[implied]["categories"],
                confidence=round(parent.confidence * IMPLIED_WEIGHT_FACTOR, 4),
                inferred=True,
                offsite=parent.offsite,
                tiers=parent.tiers,
                documents=parent.documents,
                evidence=[
                    Evidence(
                        signature_id=f"implied:{source}",
                        signature_source="inferred",
                        implied_by=parent.technology,
                        snippets=[f"implied by {parent.technology}"],
                        weight=round(parent.confidence * IMPLIED_WEIGHT_FACTOR, 4),
                    )
                ],
            )
            queue.append(implied)
    return found


def requirements_met(tech: str, found: dict[str, Detection], catalog: Catalog) -> bool:
    traits = catalog.traits[tech]
    if traits["requires"] and not traits["requires"] & (found.keys() - {tech}):
        return False
    if traits["requires_category"]:
        present = {category for key, detection in found.items() if key != tech for category in detection.categories}
        return bool(traits["requires_category"] & present)
    return True


def resolve(direct: dict[str, Detection], catalog: Catalog) -> dict[str, Detection]:
    active = dict(direct)
    for _ in range(5):
        found = with_implications(active, catalog)
        kept = {tech: detection for tech, detection in active.items() if requirements_met(tech, found, catalog)}
        if len(kept) == len(active):
            break
        active = kept
    found = with_implications(active, catalog)
    excluded = {name for tech in active for name in catalog.traits[tech]["excludes"]}
    return {tech: detection for tech, detection in found.items() if tech not in excluded}


def run_detect(signals_path, signatures_dir, detections_path, raw_dir) -> int:
    started = time.perf_counter()
    raw_dir = Path(raw_dir)
    catalog = Catalog(load_signatures(Path(signatures_dir)))
    records = {(record.domain, record.document_id): record for record in latest_records(raw_dir / "manifest.jsonl")}
    offsite_documents = {identity for identity, record in records.items() if record.offsite}

    found = Accumulator()
    for signal in read_records(Path(signals_path), Signal):
        if signal.kind is SignalKind.HTML_TEXT:
            record = records[(signal.domain, signal.document_id)]
            text = decode_body(read_content(raw_dir, signal.content_ref), record.content_type)
            match_document(signal, text, catalog, found)
        else:
            match_fields(signal, catalog, found)

    detections = []
    for domain, direct in build_direct(found, catalog, offsite_documents).items():
        detections.extend(resolve(direct, catalog).values())
    detections.sort(key=lambda detection: (detection.domain, -detection.confidence, detection.technology))

    write_records(Path(detections_path), detections)
    logging.info(
        "wrote %d detections, %d distinct technologies, %d inferred, in %.1fs",
        len(detections),
        len({detection.technology.lower() for detection in detections}),
        sum(detection.inferred for detection in detections),
        time.perf_counter() - started,
    )
    return 0
