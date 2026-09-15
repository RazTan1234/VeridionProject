import asyncio
import logging
import re
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import tldextract

from techdetect import config
from techdetect.models import Attempt, FetchOutcome, FetchRecord
from techdetect.network import inspect_certificate, resolve_dns
from techdetect.store import read_content, read_records, write_content

EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

TIMEOUT = httpx.Timeout(
    connect=config.CONNECT_TIMEOUT,
    read=config.READ_TIMEOUT,
    write=config.READ_TIMEOUT,
    pool=config.CONNECT_TIMEOUT,
)

WORDPRESS_API_LINK = re.compile(r'<([^>]+)>;\s*rel="https://api\.w\.org/"')
WORDPRESS_PATH = re.compile(
    r'(?:https?://([^/"\'\s]+))?(?:/wp-content/|/wp-includes/|/xmlrpc\.php|/wp-admin)',
    re.IGNORECASE,
)

def looks_like_tls_error(error: Exception) ->bool:
    current=error
    for _ in range(10):
        if current is None:
            return False
        if isinstance(current, ssl.SSLError):
            return True
        current = current.__cause__ or current.__context__
    return False

async def http_get(client: httpx.AsyncClient, url: str) -> tuple[Attempt, httpx.Response | None]:
    started=time.perf_counter()
    try:
        response= await client.get(url, headers=config.REQUEST_HEADERS)
    except Exception as error:
        attempt= Attempt(
            url=url,
            outcome="error",
            error_type=type(error).__name__,
            error_message=str(error)[:200],
            tls_related=looks_like_tls_error(error),
            elapsed_seconds=round(time.perf_counter() - started, 2),
        )
        return attempt,None
    attempt = Attempt(
          url=url,
          outcome="response",
          status=response.status_code,
          elapsed_seconds=round(time.perf_counter() - started, 2),
      )
    return attempt, response

def is_transient(attempt: Attempt) ->bool:
    if attempt.outcome== "error":
        return attempt.error_type in config.TRANSIENT_ERRORS
    return attempt.status in config.RETRYABLE_STATUS

async def get_with_retry(
    client: httpx.AsyncClient, url: str, max_retries: int | None = None
) -> tuple[list[Attempt], httpx.Response | None]:
    if max_retries is None:
        max_retries = config.MAX_RETRIES

    attempts = []
    delay = config.RETRY_BACKOFF_SECONDS
    response = None

    for round_index in range(max_retries + 1):
        attempt, response = await http_get(client, url)
        attempts.append(attempt)

        if not is_transient(attempt):
            return attempts, response

        if round_index < max_retries:
            await asyncio.sleep(delay)
            delay *= 2

    return attempts, response


def registrable_domain(host: str | None) -> str:
    if not host:
        return ""
    return EXTRACT(host).top_domain_under_public_suffix


def classify_outcome(
    status: int, headers, text: str, size: int, document_id: str
) -> FetchOutcome:
    lowered = text.lower()
    is_page = document_id == "home"

    if status in (403, 429, 503) and (
        "cf-mitigated" in headers
        or any(marker in lowered for marker in config.CHALLENGE_MARKERS)
    ):
        return FetchOutcome.CHALLENGED

    if status in (404, 410):
        return FetchOutcome.NOT_FOUND

    if (
        is_page
        and size < config.PARKED_BODY_LIMIT
        and any(marker in lowered for marker in config.PARKING_MARKERS)
    ):
        return FetchOutcome.PARKED

    if status >= 500 or status in (409, 526):
        return FetchOutcome.ORIGIN_ERROR

    if status >= 400:
        return FetchOutcome.HTTP_ERROR

    if size < (config.EMPTY_BODY_LIMIT if is_page else 1):
        return FetchOutcome.EMPTY

    return FetchOutcome.CONTENT


async def fetch_document(
    client: httpx.AsyncClient,
    domain: str,
    document_id: str,
    url: str,
    raw_dir: Path,
) -> FetchRecord:
    attempts, response = await get_with_retry(client, url)

    if response is None and attempts[-1].tls_related:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=TIMEOUT, verify=False
        ) as unverified_client:
            retried, response = await get_with_retry(unverified_client, url)
        attempts.extend(retried)

    if response is None and url.startswith("https://"):
        retried, response = await get_with_retry(
            client, url.replace("https://", "http://", 1), max_retries=0
        )
        attempts.extend(retried)

    fetched_at = datetime.now(timezone.utc).isoformat()
    elapsed = round(sum(attempt.elapsed_seconds for attempt in attempts), 2)

    if response is None:
        return FetchRecord(
            domain=domain,
            document_id=document_id,
            requested_url=url,
            outcome=FetchOutcome.ERROR,
            attempts=attempts,
            fetched_at=fetched_at,
            elapsed_seconds=elapsed,
        )

    body = response.content[: config.MAX_BODY_BYTES]
    text = body.decode(response.encoding or "utf-8", errors="replace")
    final_url = str(response.url)
    served_by_host = urlparse(final_url).hostname

    return FetchRecord(
        domain=domain,
        document_id=document_id,
        requested_url=url,
        final_url=final_url,
        served_by_host=served_by_host,
        offsite=registrable_domain(served_by_host) != registrable_domain(domain),
        status=response.status_code,
        outcome=classify_outcome(
            response.status_code, response.headers, text, len(body), document_id
        ),
        redirect_chain=[
            {"url": str(step.url), "status": step.status_code} for step in response.history
        ],
        attempts=attempts,
        headers=dict(response.headers),
        set_cookie=response.headers.get_list("set-cookie"),
        content_ref=write_content(raw_dir, body),
        content_bytes=len(body),
        content_type=response.headers.get("content-type"),
        fetched_at=fetched_at,
        elapsed_seconds=elapsed,
    )


def mentions_own_wordpress(text: str, host: str | None) -> bool:
    own = registrable_domain(host)
    for match in WORDPRESS_PATH.finditer(text):
        linked_host = match.group(1)
        if linked_host is None or registrable_domain(linked_host) == own:
            return True
    return False


def wordpress_api_url(records: list[FetchRecord], raw_dir: Path, base: str) -> str | None:
    for record in records:
        match = WORDPRESS_API_LINK.search(record.headers.get("link", ""))
        if match:
            return match.group(1)

    for record in records:
        if not record.content_ref:
            continue
        text = read_content(raw_dir, record.content_ref).decode("utf-8", errors="replace")
        if mentions_own_wordpress(text, record.served_by_host):
            return f"{base}/wp-json/"
    return None


async def fetch_domain(
    client: httpx.AsyncClient, domain: str, raw_dir: Path
) -> list[FetchRecord]:
    home = await fetch_document(client, domain, "home", f"https://{domain}", raw_dir)
    base = (home.final_url or f"https://{domain}").rstrip("/")

    robots = await fetch_document(client, domain, "robots", f"{base}/robots.txt", raw_dir)
    records = [home, robots]

    api_url = wordpress_api_url(records, raw_dir, base)
    if api_url:
        api = await fetch_document(client, domain, "wp_json", api_url, raw_dir)
        if api.outcome is not FetchOutcome.CONTENT and "rest_route" not in api_url:
            api = await fetch_document(
                client, domain, "wp_json", f"{base}/?rest_route=/", raw_dir
            )
        records.append(api)

    return records


HTTP_DOCUMENTS = {"home", "robots", "wp_json"}
ALL_DOCUMENTS = ("home", "dns", "tls")


def fetched_documents(manifest_path: Path) -> dict[str, set[str]]:
    present: dict[str, set[str]] = {}
    if not manifest_path.exists():
        return present
    for record in read_records(manifest_path, FetchRecord):
        present.setdefault(record.domain, set()).add(record.document_id)
    return present


def failure_record(domain: str, document_id: str, error: Exception) -> FetchRecord:
    return FetchRecord(
        domain=domain,
        document_id=document_id,
        requested_url=f"https://{domain}",
        outcome=FetchOutcome.ERROR,
        attempts=[
            Attempt(
                url=f"https://{domain}",
                outcome="error",
                error_type=type(error).__name__,
                error_message=str(error)[:200],
            )
        ],
        fetched_at=datetime.now(timezone.utc).isoformat(),
    )


async def fetch_missing(
    client: httpx.AsyncClient, domain: str, missing: set[str], raw_dir: Path
) -> list[FetchRecord]:
    jobs = []
    if "home" in missing:
        jobs.append(fetch_domain(client, domain, raw_dir))
    if "dns" in missing:
        jobs.append(resolve_dns(domain, raw_dir))
    if "tls" in missing:
        jobs.append(inspect_certificate(domain, raw_dir))

    records: list[FetchRecord] = []
    for result in await asyncio.gather(*jobs, return_exceptions=True):
        if isinstance(result, Exception):
            logging.error("%s failed unexpectedly: %s", domain, result)
            records.append(failure_record(domain, sorted(missing)[0], result))
        elif isinstance(result, list):
            records.extend(result)
        else:
            records.append(result)
    return records


async def fetch_all(plan: dict[str, set[str]], raw_dir: Path, manifest_path: Path) -> int:
    semaphore = asyncio.Semaphore(config.MAX_CONCURRENCY)
    limits = httpx.Limits(max_connections=config.MAX_CONCURRENCY * 2)
    written = 0

    async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, limits=limits) as client:

        async def worker(domain: str) -> tuple[str, list[FetchRecord]]:
            async with semaphore:
                return domain, await fetch_missing(client, domain, plan[domain], raw_dir)

        tasks = [asyncio.create_task(worker(domain)) for domain in plan]
        with open(manifest_path, "a", encoding="utf-8") as handle:
            for finished, task in enumerate(asyncio.as_completed(tasks), start=1):
                domain, records = await task
                for record in records:
                    handle.write(record.model_dump_json() + "\n")
                    written += 1
                handle.flush()
                logging.info(
                    "[%d/%d] %s %s",
                    finished,
                    len(plan),
                    domain,
                    " ".join(f"{r.document_id}={r.outcome.value}" for r in records),
                )

    return written


def run_fetch(domains: list[str], raw_dir, refresh: set[str] | None = None) -> int:
    raw_dir = Path(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = raw_dir / "manifest.jsonl"

    present = fetched_documents(manifest_path)
    plan = {
        domain: missing
        for domain in domains
        if (missing := (set(ALL_DOCUMENTS) - present.get(domain, set())) | (refresh or set()))
    }

    logging.info("%d domains need work, %d already complete", len(plan), len(domains) - len(plan))
    if not plan:
        return 0

    written = asyncio.run(fetch_all(plan, raw_dir, manifest_path))
    logging.info("wrote %d records to %s", written, manifest_path)
    return 0
