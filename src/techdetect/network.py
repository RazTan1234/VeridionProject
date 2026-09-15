import asyncio
import json
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import certifi
import dns.asyncresolver

from techdetect import config
from techdetect.models import Attempt, FetchOutcome, FetchRecord
from techdetect.store import write_content


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def query_label(prefix: str, record_type: str) -> str:
    return f"{prefix}{record_type}" if prefix else record_type


async def query(resolver, name: str, record_type: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, record_type)
    except Exception:
        return []
    return [record.to_text() for record in answer]


async def resolve_dns(domain: str, raw_dir: Path) -> FetchRecord:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = config.DNS_LIFETIME_SECONDS
    started = time.perf_counter()

    answers = await asyncio.gather(
        *(query(resolver, f"{prefix}{domain}", record_type) for prefix, record_type in config.DNS_QUERIES)
    )
    results = {
        query_label(prefix, record_type): values
        for (prefix, record_type), values in zip(config.DNS_QUERIES, answers)
    }
    elapsed = round(time.perf_counter() - started, 2)
    found = any(results.values())

    record = FetchRecord(
        domain=domain,
        document_id="dns",
        requested_url=f"dns:{domain}",
        outcome=FetchOutcome.CONTENT if found else FetchOutcome.ERROR,
        attempts=[
            Attempt(
                url=f"dns:{domain}",
                outcome="response" if found else "error",
                error_type=None if found else "NoRecords",
                elapsed_seconds=elapsed,
            )
        ],
        fetched_at=utc_now(),
        elapsed_seconds=elapsed,
    )
    if found:
        payload = json.dumps(results, sort_keys=True).encode("utf-8")
        record.content_ref = write_content(raw_dir, payload)
        record.content_bytes = len(payload)
        record.content_type = "application/json"
    return record


def flatten_name(name_tuples) -> dict[str, str]:
    flat = {}
    for relative_name in name_tuples or ():
        for key, value in relative_name:
            flat[key] = value
    return flat


async def read_certificate(domain: str) -> dict:
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(domain, config.TLS_PORT, ssl=context, server_hostname=domain),
        timeout=config.CONNECT_TIMEOUT,
    )
    try:
        certificate = writer.get_extra_info("peercert") or {}
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
    return {
        "issuer": flatten_name(certificate.get("issuer")),
        "subject": flatten_name(certificate.get("subject")),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
    }


async def inspect_certificate(domain: str, raw_dir: Path) -> FetchRecord:
    started = time.perf_counter()
    url = f"tls:{domain}:{config.TLS_PORT}"
    try:
        details = await read_certificate(domain)
    except Exception as error:
        elapsed = round(time.perf_counter() - started, 2)
        return FetchRecord(
            domain=domain,
            document_id="tls",
            requested_url=url,
            outcome=FetchOutcome.ERROR,
            attempts=[
                Attempt(
                    url=url,
                    outcome="error",
                    error_type=type(error).__name__,
                    error_message=str(error)[:200],
                    tls_related=isinstance(error, ssl.SSLError),
                    elapsed_seconds=elapsed,
                )
            ],
            fetched_at=utc_now(),
            elapsed_seconds=elapsed,
        )

    elapsed = round(time.perf_counter() - started, 2)
    payload = json.dumps(details, sort_keys=True).encode("utf-8")
    return FetchRecord(
        domain=domain,
        document_id="tls",
        requested_url=url,
        outcome=FetchOutcome.CONTENT,
        attempts=[Attempt(url=url, outcome="response", elapsed_seconds=elapsed)],
        content_ref=write_content(raw_dir, payload),
        content_bytes=len(payload),
        content_type="application/json",
        fetched_at=utc_now(),
        elapsed_seconds=elapsed,
    )
