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
RESOURCE_ATTRIBUTES = (
    ("link", "href"),
    ("iframe", "src"),
    ("img", "src"),
    ("source", "src"),
    ("video", "src"),
    ("embed", "src"),
    ("form", "action"),
)
DOCUMENT_TIERS = {"dns": Tier.DNS, "tls": Tier.TLS}


def clip(value: str | None) -> str | None:
    if value is None:
        return None
    return value[: config.MAX_SIGNAL_VALUE_CHARS]


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlparse(url).hostname
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
    if "html" in (record.content_type or "").lower():
        return True
    return text.lstrip()[:1] == "<"


class SignalWriter:
    def __init__(self, record: FetchRecord):
        self.record = record
        self.tier = DOCUMENT_TIERS.get(record.document_id, Tier.HTTP)
        self.location = record.final_url or record.requested_url
        self.signals: list[Signal] = []
        self.seen: set[tuple] = set()

    def add(
        self,
        observation: str,
        kind: SignalKind,
        value: str | None = None,
        key: str | None = None,
        content_ref: str | None = None,
    ) -> None:
        value = clip(value.strip()) if isinstance(value, str) else value
        if value in ("", None) and content_ref is None:
            return
        identity = (kind, key, value, content_ref)
        if identity in self.seen:
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


def add_header_signals(writer: SignalWriter) -> None:
    record = writer.record
    for name, value in record.headers.items():
        name = name.lower()
        if name == "set-cookie":
            continue
        observation = f"header:{name}"
        writer.add(observation, SignalKind.HTTP_HEADER, value, key=name)

        if name in CSP_HEADERS:
            for token in re.split(r"[\s;]+", value.lower()):
                match = CSP_SOURCE_HOST.match(token)
                if match:
                    writer.add(observation, SignalKind.CSP_HOST, match.group(2))

        if name == "link":
            for url in LINK_HEADER_URL.findall(value):
                absolute = urljoin(writer.location, url)
                writer.add(observation, SignalKind.URL_PATH, absolute)
                linked_host = host_of(absolute)
                if linked_host and linked_host != record.served_by_host:
                    writer.add(observation, SignalKind.LINK_HOST, linked_host)


def add_cookie_signals(writer: SignalWriter) -> None:
    for index, raw_cookie in enumerate(writer.record.set_cookie):
        name, _, rest = raw_cookie.partition("=")
        value = rest.split(";", 1)[0]
        writer.add(f"cookie:{index}", SignalKind.COOKIE, value or name.strip(), key=name.strip())


def add_location_signals(writer: SignalWriter) -> None:
    record = writer.record
    writer.add("hostname:input", SignalKind.HOSTNAME, record.domain)
    if record.served_by_host and record.served_by_host != record.domain:
        writer.add("hostname:served", SignalKind.HOSTNAME, record.served_by_host)
    writer.add("url:final", SignalKind.PAGE_URL, record.final_url)
    for index, step in enumerate(record.redirect_chain):
        writer.add(f"redirect:{index}", SignalKind.PAGE_URL, step.get("url"))
        writer.add(f"redirect:{index}", SignalKind.HOSTNAME, host_of(step.get("url")))


def add_html_signals(writer: SignalWriter, text: str) -> None:
    record = writer.record
    writer.add("html", SignalKind.HTML_TEXT, content_ref=record.content_ref)

    tree = LexborHTMLParser(text)

    for index, node in enumerate(tree.css("meta")):
        attributes = node.attributes
        key = attributes.get("name") or attributes.get("property") or attributes.get("http-equiv")
        content = attributes.get("content")
        if key and content:
            writer.add(f"meta:{index}", SignalKind.META, content, key=key.lower())

    for index, node in enumerate(tree.css("script[src]")):
        source = node.attributes.get("src")
        if not source:
            continue
        absolute = urljoin(writer.location, source.strip())
        writer.add(f"script:{index}", SignalKind.SCRIPT_SRC, absolute)
        script_host = host_of(absolute)
        if script_host and script_host != record.served_by_host:
            writer.add(f"script:{index}", SignalKind.SCRIPT_HOST, script_host)

    for tag, attribute in RESOURCE_ATTRIBUTES:
        for index, node in enumerate(tree.css(f"{tag}[{attribute}]")):
            reference = node.attributes.get(attribute)
            if not reference or reference.startswith(("data:", "#", "javascript:", "mailto:")):
                continue
            absolute = urljoin(writer.location, reference.strip())
            observation = f"{tag}:{index}"
            writer.add(observation, SignalKind.URL_PATH, absolute)
            resource_host = host_of(absolute)
            if resource_host and resource_host != record.served_by_host:
                writer.add(observation, SignalKind.LINK_HOST, resource_host)


def add_robots_signals(writer: SignalWriter, text: str) -> None:
    for index, line in enumerate(text.splitlines()):
        if line.strip():
            writer.add(f"line:{index}", SignalKind.ROBOTS_LINE, line)


def parse_json_payload(text: str):
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


def add_wp_json_signals(writer: SignalWriter, text: str) -> None:
    payload = parse_json_payload(text)
    if not isinstance(payload, dict):
        return
    for namespace in payload.get("namespaces") or []:
        if isinstance(namespace, str):
            writer.add("namespaces", SignalKind.WP_REST_NAMESPACE, namespace)


def add_dns_signals(writer: SignalWriter, text: str) -> None:
    payload = parse_json_payload(text) or {}
    for label, values in payload.items():
        for index, value in enumerate(values):
            cleaned = value.replace('" "', "").strip('"').rstrip(".").lower()
            writer.add(f"{label}:{index}", SignalKind.DNS_RECORD, cleaned, key=label)


def add_tls_signals(writer: SignalWriter, text: str) -> None:
    payload = parse_json_payload(text) or {}
    issuer = payload.get("issuer") or {}
    subject = payload.get("subject") or {}
    writer.add("issuer", SignalKind.TLS_ISSUER, issuer.get("organizationName"), key="organization")
    writer.add("issuer", SignalKind.TLS_ISSUER, issuer.get("commonName"), key="common_name")
    writer.add("subject", SignalKind.TLS_SUBJECT, subject.get("commonName"), key="common_name")


def extract_from_record(record: FetchRecord, raw_dir: Path) -> list[Signal]:
    writer = SignalWriter(record)
    document = record.document_id

    if document in ("home", "robots", "wp_json") and record.final_url:
        add_header_signals(writer)
        add_cookie_signals(writer)
        if document == "home":
            add_location_signals(writer)

    if not record.content_ref:
        return writer.signals

    payload = read_content(raw_dir, record.content_ref)
    text = decode_body(payload, record.content_type)

    if document == "home" and looks_like_html(record, text):
        add_html_signals(writer, text)
    elif document == "robots" and not looks_like_html(record, text):
        add_robots_signals(writer, text)
    elif document == "wp_json":
        add_wp_json_signals(writer, text)
    elif document == "dns":
        add_dns_signals(writer, text)
    elif document == "tls":
        add_tls_signals(writer, text)

    return writer.signals


def latest_records(manifest_path: Path) -> list[FetchRecord]:
    latest: dict[tuple[str, str], FetchRecord] = {}
    for record in read_records(manifest_path, FetchRecord):
        identity = (record.domain, record.document_id)
        previous = latest.get(identity)
        if previous and previous.content_ref and not record.content_ref:
            continue
        latest[identity] = record
    return list(latest.values())


def run_extract(raw_dir, signals_path) -> int:
    raw_dir = Path(raw_dir)
    signals_path = Path(signals_path)
    records = latest_records(raw_dir / "manifest.jsonl")

    signals: list[Signal] = []
    failures = 0
    for record in records:
        try:
            signals.extend(extract_from_record(record, raw_dir))
        except Exception as error:
            failures += 1
            logging.warning("extraction failed for %s/%s: %s", record.domain, record.document_id, error)

    count = write_records(signals_path, signals)
    by_kind = Counter(signal.kind.value for signal in signals)
    logging.info("wrote %d signals from %d records (%d failed)", count, len(records), failures)
    for kind, total in by_kind.most_common():
        logging.info("  %-18s %d", kind, total)
    return 0 if failures < len(records) else 1
