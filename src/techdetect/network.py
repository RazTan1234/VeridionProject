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


def build_record(domain: str, document_id: str, url: str, started: float, raw_dir: Path, payload=None, error=None) -> FetchRecord:
    elapsed = round(time.perf_counter() - started, 2)
    record = FetchRecord(
        domain=domain,
        document_id=document_id,
        requested_url=url,
        outcome=FetchOutcome.ERROR,
        fetched_at=utc_now(),
        elapsed_seconds=elapsed,
        attempts=[
            Attempt(
                url=url,
                outcome="error",
                error_type=type(error).__name__ if error else "NoRecords",
                error_message=str(error)[:200] if error else None,
                tls_related=isinstance(error, ssl.SSLError),
                elapsed_seconds=elapsed,
            )
        ],
    )
    if payload:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        record.outcome = FetchOutcome.CONTENT
        record.attempts = [Attempt(url=url, outcome="response", elapsed_seconds=elapsed)]
        record.content_ref, record.content_bytes, record.content_type = write_content(raw_dir, body), len(body), "application/json"
    return record


async def query(resolver, name: str, record_type: str) -> list[str]:
    try:
        return [answer.to_text() for answer in await resolver.resolve(name, record_type)]
    except Exception:
        return []


async def resolve_dns(domain: str, raw_dir: Path) -> FetchRecord:
    started = time.perf_counter()
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = config.DNS_LIFETIME_SECONDS
    answers = await asyncio.gather(*(query(resolver, f"{prefix}{domain}", kind) for prefix, kind in config.DNS_QUERIES))
    results = {f"{prefix}{kind}": values for (prefix, kind), values in zip(config.DNS_QUERIES, answers)}
    return build_record(domain, "dns", f"dns:{domain}", started, raw_dir, payload=results if any(answers) else None)


def flatten_name(name_tuples) -> dict[str, str]:
    return {key: value for relative_name in name_tuples or () for key, value in relative_name}


async def inspect_certificate(domain: str, raw_dir: Path) -> FetchRecord:
    started = time.perf_counter()
    url = f"tls:{domain}:{config.TLS_PORT}"
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, config.TLS_PORT, ssl=context, server_hostname=domain),
            timeout=config.CONNECT_TIMEOUT,
        )
    except Exception as error:
        return build_record(domain, "tls", url, started, raw_dir, error=error)

    certificate = writer.get_extra_info("peercert") or {}
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass
    details = {
        "issuer": flatten_name(certificate.get("issuer")),
        "subject": flatten_name(certificate.get("subject")),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
    }
    return build_record(domain, "tls", url, started, raw_dir, payload=details)
