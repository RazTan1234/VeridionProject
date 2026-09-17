import asyncio
import logging
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
import tldextract

from techdetect import config
from techdetect.models import Attempt, FetchOutcome, FetchRecord
from techdetect.network import inspect_certificate, resolve_dns, utc_now
from techdetect.store import read_content, read_records, write_content

DOCUMENTS = ("home", "dns", "tls")
EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
TIMEOUT = httpx.Timeout(config.READ_TIMEOUT, connect=config.CONNECT_TIMEOUT)
WORDPRESS_API_LINK = re.compile(r'<([^>]+)>;\s*rel="https://api\.w\.org/"')
WORDPRESS_PATH = re.compile(r'(?:https?://([^/"\'\s]+))?(?:/wp-content/|/wp-includes/|/xmlrpc\.php|/wp-admin)', re.IGNORECASE)


def registrable_domain(host: str | None) -> str:
    return EXTRACT(host).top_domain_under_public_suffix if host else ""


def looks_like_tls_error(error: BaseException | None) -> bool:
    for _ in range(10):
        if error is None:
            return False
        if isinstance(error, ssl.SSLError):
            return True
        error = error.__cause__ or error.__context__
    return False


async def http_get(client: httpx.AsyncClient, url: str) -> tuple[Attempt, httpx.Response | None]:
    started = time.perf_counter()
    try:
        response = await client.get(url, headers=config.REQUEST_HEADERS)
    except Exception as error:
        elapsed = round(time.perf_counter() - started, 2)
        attempt = Attempt(
            url=url,
            outcome="error",
            error_type=type(error).__name__,
            error_message=str(error)[:200],
            tls_related=looks_like_tls_error(error),
            elapsed_seconds=elapsed,
        )
        return attempt, None
    elapsed = round(time.perf_counter() - started, 2)
    return Attempt(url=url, outcome="response", status=response.status_code, elapsed_seconds=elapsed), response


def is_transient(attempt: Attempt) -> bool:
    if attempt.outcome == "error":
        return attempt.error_type in config.TRANSIENT_ERRORS
    return attempt.status in config.RETRYABLE_STATUS


async def get_with_retry(client: httpx.AsyncClient, url: str, max_retries: int = config.MAX_RETRIES):
    attempts, delay = [], config.RETRY_BACKOFF_SECONDS
    for round_index in range(max_retries + 1):
        attempt, response = await http_get(client, url)
        attempts.append(attempt)
        if not is_transient(attempt):
            break
        if round_index < max_retries:
            await asyncio.sleep(delay)
            delay *= 2
    return attempts, response


def classify_outcome(status: int, headers, text: str, size: int, document_id: str) -> FetchOutcome:
    lowered, is_page = text.lower(), document_id == "home"
    if status in (403, 429, 503) and ("cf-mitigated" in headers or any(m in lowered for m in config.CHALLENGE_MARKERS)):
        return FetchOutcome.CHALLENGED
    if status in (404, 410):
        return FetchOutcome.NOT_FOUND
    if is_page and size < config.PARKED_BODY_LIMIT and any(m in lowered for m in config.PARKING_MARKERS):
        return FetchOutcome.PARKED
    if status >= 500 or status in (409, 526):
        return FetchOutcome.ORIGIN_ERROR
    if status >= 400:
        return FetchOutcome.HTTP_ERROR
    if size < (config.EMPTY_BODY_LIMIT if is_page else 1):
        return FetchOutcome.EMPTY
    return FetchOutcome.CONTENT


async def fetch_document(client: httpx.AsyncClient, domain: str, document_id: str, url: str, raw_dir: Path) -> FetchRecord:
    attempts, response = await get_with_retry(client, url)
    if response is None and attempts[-1].tls_related:
        async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, verify=False) as unverified_client:
            retried, response = await get_with_retry(unverified_client, url)
        attempts += retried
    if response is None and url.startswith("https://"):
        retried, response = await get_with_retry(client, url.replace("https://", "http://", 1), max_retries=0)
        attempts += retried

    record = FetchRecord(
        domain=domain,
        document_id=document_id,
        requested_url=url,
        outcome=FetchOutcome.ERROR,
        attempts=attempts,
        fetched_at=utc_now(),
        elapsed_seconds=round(sum(attempt.elapsed_seconds for attempt in attempts), 2),
    )
    if response is None:
        return record

    body = response.content[: config.MAX_BODY_BYTES]
    text = body.decode(response.encoding or "utf-8", errors="replace")
    record.final_url = str(response.url)
    record.served_by_host = urlparse(record.final_url).hostname
    record.offsite = registrable_domain(record.served_by_host) != registrable_domain(domain)
    record.status = response.status_code
    record.outcome = classify_outcome(response.status_code, response.headers, text, len(body), document_id)
    record.redirect_chain = [{"url": str(step.url), "status": step.status_code} for step in response.history]
    record.headers = dict(response.headers)
    record.set_cookie = response.headers.get_list("set-cookie")
    record.content_ref = write_content(raw_dir, body)
    record.content_bytes = len(body)
    record.content_type = response.headers.get("content-type")
    return record


def mentions_own_wordpress(text: str, host: str | None) -> bool:
    own = registrable_domain(host)
    return any(m.group(1) is None or registrable_domain(m.group(1)) == own for m in WORDPRESS_PATH.finditer(text))


def wordpress_api_url(records: list[FetchRecord], raw_dir: Path, base: str) -> str | None:
    for record in records:
        if match := WORDPRESS_API_LINK.search(record.headers.get("link", "")):
            return match.group(1)
    for record in records:
        if record.content_ref:
            text = read_content(raw_dir, record.content_ref).decode("utf-8", errors="replace")
            if mentions_own_wordpress(text, record.served_by_host):
                return f"{base}/wp-json/"
    return None


async def fetch_site(client: httpx.AsyncClient, domain: str, raw_dir: Path) -> list[FetchRecord]:
    home = await fetch_document(client, domain, "home", f"https://{domain}", raw_dir)
    base = (home.final_url or f"https://{domain}").rstrip("/")
    records = [home, await fetch_document(client, domain, "robots", f"{base}/robots.txt", raw_dir)]
    if api_url := wordpress_api_url(records, raw_dir, base):
        api = await fetch_document(client, domain, "wp_json", api_url, raw_dir)
        if api.outcome is not FetchOutcome.CONTENT and "rest_route" not in api_url:
            api = await fetch_document(client, domain, "wp_json", f"{base}/?rest_route=/", raw_dir)
        records.append(api)
    return records


async def fetch_missing(client: httpx.AsyncClient, domain: str, missing: set[str], raw_dir: Path) -> list[FetchRecord]:
    jobs = {
        "home": lambda: fetch_site(client, domain, raw_dir),
        "dns": lambda: resolve_dns(domain, raw_dir),
        "tls": lambda: inspect_certificate(domain, raw_dir),
    }
    documents = sorted(missing)
    records = []
    for document_id, result in zip(documents, await asyncio.gather(*(jobs[d]() for d in documents), return_exceptions=True)):
        if isinstance(result, Exception):
            logging.error("%s %s failed unexpectedly: %s", domain, document_id, result)
            url = f"https://{domain}"
            failure = Attempt(url=url, outcome="error", error_type=type(result).__name__, error_message=str(result)[:200])
            result = FetchRecord(
                domain=domain, document_id=document_id, requested_url=url, outcome=FetchOutcome.ERROR,
                attempts=[failure], fetched_at=utc_now(),
            )
        records.extend(result if isinstance(result, list) else [result])
    return records


def fetched_documents(manifest_path: Path) -> dict[str, set[str]]:
    present: dict[str, set[str]] = {}
    if manifest_path.exists():
        for record in read_records(manifest_path, FetchRecord):
            present.setdefault(record.domain, set()).add(record.document_id)
    return present


async def fetch_all(plan: dict[str, set[str]], raw_dir: Path, manifest_path: Path) -> int:
    semaphore, written = asyncio.Semaphore(config.MAX_CONCURRENCY), 0
    limits = httpx.Limits(max_connections=config.MAX_CONCURRENCY * 2)
    async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, limits=limits) as client:

        async def worker(domain: str):
            async with semaphore:
                return domain, await fetch_missing(client, domain, plan[domain], raw_dir)

        with open(manifest_path, "a", encoding="utf-8") as handle:
            tasks = [asyncio.create_task(worker(domain)) for domain in plan]
            for finished, task in enumerate(asyncio.as_completed(tasks), start=1):
                domain, records = await task
                handle.writelines(record.model_dump_json() + "\n" for record in records)
                handle.flush()
                written += len(records)
                outcomes = " ".join(f"{record.document_id}={record.outcome.value}" for record in records)
                logging.info("[%d/%d] %s %s", finished, len(plan), domain, outcomes)
    return written


def run_fetch(domains: list[str], raw_dir: Path, refresh: set[str] = frozenset()) -> int:
    raw_dir = Path(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = raw_dir / "manifest.jsonl"
    present = fetched_documents(manifest_path)
    plan = {domain: missing for domain in domains if (missing := (set(DOCUMENTS) - present.get(domain, set())) | set(refresh))}
    logging.info("%d of %d domains need work", len(plan), len(domains))
    if plan:
        written = asyncio.run(fetch_all(plan, raw_dir, manifest_path))
        logging.info("wrote %d records to %s", written, manifest_path)
    return 0
