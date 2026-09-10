TECHDETECT := .venv/bin/techdetect
PYTEST := .venv/bin/pytest

INPUT := data/input/domains.snappy.parquet
MANIFEST := data/raw/manifest.jsonl
SIGNALS := data/signals/signals.jsonl
DETECTIONS := data/detections/detections.jsonl
REPORT := data/reports/technologies.parquet

SIGNATURE_FILES := $(wildcard signatures/own/*.yaml) $(wildcard signatures/external/*.yaml)

LIMIT :=
FETCH_ARGS := $(if $(LIMIT),--limit $(LIMIT),)

.DEFAULT_GOAL := report

.PHONY: install fetch extract detect report test clean clean-raw

install:
	.venv/bin/pip install -e ".[dev]"

$(MANIFEST): $(INPUT)
	$(TECHDETECT) fetch $(FETCH_ARGS)

$(SIGNALS): $(MANIFEST)
	$(TECHDETECT) extract

$(DETECTIONS): $(SIGNALS) $(SIGNATURE_FILES)
	$(TECHDETECT) detect

$(REPORT): $(DETECTIONS)
	$(TECHDETECT) report

fetch: $(MANIFEST)
extract: $(SIGNALS)
detect: $(DETECTIONS)
report: $(REPORT)

test:
	$(PYTEST) -q

clean:
	rm -rf data/signals data/detections data/reports

clean-raw:
	rm -rf data/raw
