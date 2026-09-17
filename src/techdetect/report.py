import csv
import json
import logging
import statistics
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from techdetect.extract import latest_records
from techdetect.models import Detection
from techdetect.store import read_records

CONFIDENT = 0.8


def distinct(detections) -> int:
    return len({detection.technology.lower() for detection in detections})


def build_metrics(detections: list[Detection], records) -> dict:
    homes = [record for record in records if record.document_id == "home"]
    direct = [detection for detection in detections if not detection.inferred]

    sources = defaultdict(set)
    tiers = defaultdict(set)
    kinds = defaultdict(set)
    for detection in direct:
        name = detection.technology.lower()
        sources[name].update(evidence.signature_source for evidence in detection.evidence)
        tiers[name].update(tier.value for tier in detection.tiers)
        kinds[name].update(evidence.signal_kind.value for evidence in detection.evidence)

    per_domain = Counter(detection.domain for detection in detections)
    counts = [per_domain.get(record.domain, 0) for record in homes]

    return {
        "domains": {
            "total": len(homes),
            "with_detections": sum(1 for count in counts if count),
            "home_outcomes": dict(Counter(record.outcome.value for record in homes).most_common()),
            "offsite_redirects": sum(1 for record in homes if record.offsite),
        },
        "detections": {
            "total": len(detections),
            "direct": len(direct),
            "inferred": len(detections) - len(direct),
            "offsite": sum(detection.offsite for detection in detections),
            "per_domain_median": statistics.median(counts) if counts else 0,
            "per_domain_max": max(counts, default=0),
        },
        "distinct_technologies": {
            "all": distinct(detections),
            "direct": distinct(direct),
            f"confidence_at_least_{CONFIDENT}": distinct(d for d in detections if d.confidence >= CONFIDENT),
            "excluding_offsite": distinct(d for d in detections if not d.offsite),
        },
        "distinct_by_signature_source": {
            "own_only": sum(1 for found in sources.values() if found == {"own"}),
            "external_only": sum(1 for found in sources.values() if found == {"external"}),
            "both": sum(1 for found in sources.values() if found == {"own", "external"}),
        },
        "distinct_by_tier": {
            tier: {
                "seen": sum(1 for found in tiers.values() if tier in found),
                "only_this_tier": sum(1 for found in tiers.values() if found == {tier}),
            }
            for tier in sorted({tier for found in tiers.values() for tier in found})
        },
        "distinct_by_signal_kind": dict(
            Counter(kind for found in kinds.values() for kind in found).most_common()
        ),
        "top_technologies": dict(Counter(detection.technology for detection in detections).most_common(30)),
        "top_categories": dict(
            Counter(category for detection in detections for category in detection.categories).most_common(20)
        ),
    }


def write_outputs(detections: list[Detection], records, reports_dir: Path) -> None:
    outcomes = {record.domain: record.outcome.value for record in records if record.document_id == "home"}
    by_domain = defaultdict(list)
    for detection in detections:
        by_domain[detection.domain].append(detection.model_dump(mode="json", exclude={"domain"}))

    document = [
        {"domain": domain, "fetch_outcome": outcome, "technologies": by_domain.get(domain, [])}
        for domain, outcome in sorted(outcomes.items())
    ]
    (reports_dir / "technologies.json").write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")

    with open(reports_dir / "technologies.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "technology", "categories", "version", "confidence", "inferred", "offsite", "sources", "evidence"])
        for detection in detections:
            strongest = detection.evidence[0]
            writer.writerow([
                detection.domain,
                detection.technology,
                "; ".join(detection.categories),
                detection.version or "",
                detection.confidence,
                detection.inferred,
                detection.offsite,
                "; ".join(sorted({evidence.signature_source for evidence in detection.evidence})),
                f"{strongest.location or ''} | {(strongest.snippets or [''])[0]}",
            ])


def run_report(detections_path, raw_dir, reports_dir) -> int:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    detections = list(read_records(Path(detections_path), Detection))
    records = latest_records(Path(raw_dir) / "manifest.jsonl")

    write_outputs(detections, records, reports_dir)
    metrics = build_metrics(detections, records)
    (reports_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    for section in ("domains", "detections", "distinct_technologies", "distinct_by_signature_source", "distinct_by_tier"):
        logging.info("%s: %s", section, json.dumps(metrics[section]))
    return 0


def run_validate(detections_path, ground_truth_path, reports_dir, threshold: float = 0.0) -> int:
    truth = yaml.safe_load(Path(ground_truth_path).read_text(encoding="utf-8"))["domains"]
    predicted = defaultdict(set)
    for detection in read_records(Path(detections_path), Detection):
        if detection.confidence >= threshold:
            predicted[detection.domain].add(detection.technology.lower())

    rows, totals = [], Counter()
    for entry in truth:
        present = {name.lower() for name in entry.get("present", [])}
        ignored = {name.lower() for name in entry.get("unverifiable", [])}
        found = predicted[entry["domain"]] - ignored
        row = {
            "domain": entry["domain"],
            "true_positives": sorted(found & present),
            "false_positives": sorted(found - present),
            "false_negatives": sorted(present - found),
        }
        totals.update({key: len(row[key]) for key in ("true_positives", "false_positives", "false_negatives")})
        rows.append(row)

    true_positives = totals["true_positives"]
    summary = {
        "threshold": threshold,
        "domains": len(rows),
        **totals,
        "precision": round(true_positives / max(true_positives + totals["false_positives"], 1), 3),
        "recall": round(true_positives / max(true_positives + totals["false_negatives"], 1), 3),
    }
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / f"validation_{threshold}.json").write_text(json.dumps({"summary": summary, "domains": rows}, indent=2), encoding="utf-8")
    logging.info("validation at confidence >= %s: %s", threshold, json.dumps(summary))
    return 0
