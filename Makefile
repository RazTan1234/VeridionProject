TECHDETECT := .venv/bin/techdetect
PYTEST := .venv/bin/pytest

INPUT := data/input/domains.snappy.parquet
MANIFEST := data/raw/manifest.jsonl
SIGNALS := data/signals/signals.jsonl
DETECTIONS := data/detections/detections.jsonl
REPORT := data/reports/technologies.parquet

EXTERNAL_SIGNATURES := signatures/external/technologies.jsonl
SIGNATURE_FILES := $(wildcard signatures/own/*.yaml) $(EXTERNAL_SIGNATURES)

LIMIT :=
FETCH_ARGS := $(if $(LIMIT),--limit $(LIMIT),)

.DEFAULT_GOAL := report

.PHONY: install signatures fetch extract detect report test clean clean-raw

install:
	.venv/bin/pip install -e ".[dev]"

$(EXTERNAL_SIGNATURES):
	$(TECHDETECT) signatures --sync

signatures: $(EXTERNAL_SIGNATURES)
	$(TECHDETECT) signatures

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
