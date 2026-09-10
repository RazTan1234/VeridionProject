import ssl
import time
from pathlib import Path
import asyncio
import httpx

from techdetect import config
from techdetect.models import Attempt, FetchRecord

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

async def get_with_retry(client: httpx.AsyncClient, url: str) -> tuple[list[Attempt], httpx.Response | None]:
    attempts=[]
    delay=config.RETRY_BACKOFF_SECONDS
    response=None

    for round_index in range(config.MAX_RETRIES +1):
        attempt,response = await http_get(client,url)
        attempts.append(attempt)

        if not is_transient(attempt):
            return attempts, response

        if round_index<config.MAX_RETRIES:
            await asyncio.sleep(delay)
            delay*=2
    return attempts,response

async def fetch_document(client, domain: str, document_id: str, url: str) -> FetchRecord:
    raise NotImplementedError


async def fetch_domain(client, domain: str, raw_dir: Path) -> list[FetchRecord]:
    raise NotImplementedError


def run_fetch(domains: list[str], raw_dir: Path) -> int:
    raise NotImplementedError
