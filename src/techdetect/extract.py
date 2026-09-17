import json
import logging
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

from selectolax.lexbor import LexborHTMLParser

from techdetect import config
from techdetect.models import FetchRecord, Signal, SignalKind, Tier
from techdetect.store import read_content, read_records, write_records

CHARSET_IN_CONTENT_TYPE = re.compile(r"charset=([\w.:-]+)", re.IGNORECASE)
CHARSET_IN_MARKUP = re.compile(rb"<meta[^>]+charset=[\"']?([\w.:-]+)", re.IGNORECASE)
LINK_HEADER_URL = re.compile(r"<([^>]+)>")
CSP_SOURCE_HOST = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(\*\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:/.*)?$")
CSP_HEADERS = ("content-security-policy", "content-security-policy-report-only")
RESOURCE_ATTRIBUTES = (("link", "href"), ("iframe", "src"), ("img", "src"), ("source", "src"), ("video", "src"), ("embed", "src"), ("form", "action"))
SKIPPED_REFERENCES = ("data:", "#", "javascript:", "mailto:")
HOST_KINDS = {SignalKind.SCRIPT_SRC: SignalKind.SCRIPT_HOST, SignalKind.URL_PATH: SignalKind.LINK_HOST}
DOCUMENT_TIERS = {"dns": Tier.DNS, "tls": Tier.TLS}
HTTP_DOCUMENTS = ("home", "robots", "wp_json")


def host_of(url: str | None) -> str | None:
    try:
        return urlparse(url).hostname if url else None
    except ValueError:
        return None


def decode_body(payload: bytes, content_type: str | None) -> str:
    match = CHARSET_IN_CONTENT_TYPE.search(content_type or "")
    charset = match.group(1) if match else None
    if not charset:
        sniffed = CHARSET_IN_MARKUP.search(payload[:4096])
        charset = sniffed.group(1).decode("ascii", "ignore") if sniffed else "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def looks_like_html(record: FetchRecord, text: str) -> bool:
    return "html" in (record.content_type or "").lower() or text.lstrip()[:1] == "<"


def parse_json_payload(text: str):
    start = text.find("{")
    try:
        return json.loads(text[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        return None


class SignalWriter:
    def __init__(self, record: FetchRecord):
        self.record = record
        self.tier = DOCUMENT_TIERS.get(record.document_id, Tier.HTTP)
        self.location = record.final_url or record.requested_url
        self.signals: list[Signal] = []
        self.seen: set[tuple] = set()

    def add(self, observation: str, kind: SignalKind, value=None, key=None, content_ref=None) -> None:
        if isinstance(value, str):
            value = value.strip()[: config.MAX_SIGNAL_VALUE_CHARS]
        identity = (kind, key, value, content_ref)
        if (not value and content_ref is None) or identity in self.seen:
            return
        self.seen.add(identity)
        self.signals.append(
            Signal(
                domain=self.record.domain,
                document_id=self.record.document_id,
                observation_id=f"{self.record.document_id}:{observation}",
                kind=kind,
                key=key,
                value=value,
                content_ref=content_ref,
                tier=self.tier,
                location=self.location,
            )
        )

    def add_reference(self, observation: str, kind: SignalKind, reference: str) -> None:
        absolute = urljoin(self.location, reference.strip())
        self.add(observation, kind, absolute)
        host = host_of(absolute)
        if host and host != self.record.served_by_host:
            self.add(observation, HOST_KINDS[kind], host)


def add_http_signals(writer: SignalWriter) -> None:
    record = writer.record
    for name, value in record.headers.items():
        name = name.lower()
        if name == "set-cookie":
            continue
        observation = f"header:{name}"
        writer.add(observation, SignalKind.HTTP_HEADER, value, key=name)
        if name in CSP_HEADERS:
            for token in re.split(r"[\s;]+", value.lower()):
                if match := CSP_SOURCE_HOST.match(token):
                    writer.add(observation, SignalKind.CSP_HOST, match.group(2))
        if name == "link":
            for url in LINK_HEADER_URL.findall(value):
                writer.add_reference(observation, SignalKind.URL_PATH, url)

    for index, raw_cookie in enumerate(record.set_cookie):
        name, _, rest = raw_cookie.partition("=")
        writer.add(f"cookie:{index}", SignalKind.COOKIE, rest.split(";", 1)[0] or name.strip(), key=name.strip())

    if record.document_id == "home":
        writer.add("hostname:input", SignalKind.HOSTNAME, record.domain)
        if record.served_by_host and record.served_by_host != record.domain:
            writer.add("hostname:served", SignalKind.HOSTNAME, record.served_by_host)
        writer.add("url:final", SignalKind.PAGE_URL, record.final_url)
        for index, step in enumerate(record.redirect_chain):
            writer.add(f"redirect:{index}", SignalKind.PAGE_URL, step.get("url"))
            writer.add(f"redirect:{index}", SignalKind.HOSTNAME, host_of(step.get("url")))


def add_html_signals(writer: SignalWriter, text: str) -> None:
    writer.add("html", SignalKind.HTML_TEXT, content_ref=writer.record.content_ref)
    tree = LexborHTMLParser(text)
    for index, node in enumerate(tree.css("meta")):
        attributes = node.attributes
        key = attributes.get("name") or attributes.get("property") or attributes.get("http-equiv")
        if key and attributes.get("content"):
            writer.add(f"meta:{index}", SignalKind.META, attributes["content"], key=key.lower())
    for index, node in enumerate(tree.css("script[src]")):
        if source := node.attributes.get("src"):
            writer.add_reference(f"script:{index}", SignalKind.SCRIPT_SRC, source)
    for tag, attribute in RESOURCE_ATTRIBUTES:
        for index, node in enumerate(tree.css(f"{tag}[{attribute}]")):
            reference = node.attributes.get(attribute)
            if reference and not reference.startswith(SKIPPED_REFERENCES):
                writer.add_reference(f"{tag}:{index}", SignalKind.URL_PATH, reference)


def add_document_signals(writer: SignalWriter, text: str) -> None:
    document = writer.record.document_id
    if document == "robots":
        for index, line in enumerate(text.splitlines()):
            if line.strip():
                writer.add(f"line:{index}", SignalKind.ROBOTS_LINE, line)
        return

    payload = parse_json_payload(text)
    if not isinstance(payload, dict):
        return
    if document == "wp_json":
        for namespace in payload.get("namespaces") or []:
            if isinstance(namespace, str):
                writer.add("namespaces", SignalKind.WP_REST_NAMESPACE, namespace)
    elif document == "dns":
        for label, values in payload.items():
            for index, value in enumerate(values):
                cleaned = value.replace('" "', "").strip('"').rstrip(".").lower()
                writer.add(f"{label}:{index}", SignalKind.DNS_RECORD, cleaned, key=label)
    elif document == "tls":
        issuer, subject = payload.get("issuer") or {}, payload.get("subject") or {}
        writer.add("issuer", SignalKind.TLS_ISSUER, issuer.get("organizationName"), key="organization")
        writer.add("issuer", SignalKind.TLS_ISSUER, issuer.get("commonName"), key="common_name")
        writer.add("subject", SignalKind.TLS_SUBJECT, subject.get("commonName"), key="common_name")


def extract_from_record(record: FetchRecord, raw_dir: Path) -> list[Signal]:
    writer = SignalWriter(record)
    document = record.document_id
    if document in HTTP_DOCUMENTS and record.final_url:
        add_http_signals(writer)
    if record.content_ref:
        text = decode_body(read_content(raw_dir, record.content_ref), record.content_type)
        is_html = looks_like_html(record, text)
        if document == "home" and is_html:
            add_html_signals(writer, text)
        elif (document == "robots" and not is_html) or document in ("wp_json", "dns", "tls"):
            add_document_signals(writer, text)
    return writer.signals


def latest_records(manifest_path: Path) -> list[FetchRecord]:
    latest: dict[tuple[str, str], FetchRecord] = {}
    for record in read_records(manifest_path, FetchRecord):
        previous = latest.get((record.domain, record.document_id))
        if not (previous and previous.content_ref and not record.content_ref):
            latest[(record.domain, record.document_id)] = record
    return list(latest.values())


def run_extract(raw_dir: Path, signals_path: Path) -> int:
    records = latest_records(Path(raw_dir) / "manifest.jsonl")
    signals, failures = [], 0
    for record in records:
        try:
            signals.extend(extract_from_record(record, Path(raw_dir)))
        except Exception as error:
            failures += 1
            logging.warning("extraction failed for %s/%s: %s", record.domain, record.document_id, error)
    count = write_records(Path(signals_path), signals)
    logging.info("wrote %d signals from %d records (%d failed)", count, len(records), failures)
    for kind, total in Counter(signal.kind.value for signal in signals).most_common():
        logging.info("  %-18s %d", kind, total)
    return 0 if failures < len(records) else 1
