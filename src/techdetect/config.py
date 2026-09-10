from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_PARQUET = PROJECT_ROOT / "data" / "input" / "domains.snappy.parquet"
RAW_DIR = PROJECT_ROOT / "data" / "raw"
SIGNALS_DIR = PROJECT_ROOT / "data" / "signals"
DETECTIONS_DIR = PROJECT_ROOT / "data" / "detections"
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"
SIGNATURES_DIR = PROJECT_ROOT / "signatures"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,*;q=0.5",
}

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
MAX_BODY_BYTES = 3_000_000
MAX_CONCURRENCY = 16
MAX_CONCURRENCY_PER_HOST = 2
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.5

DNS_RECORD_TYPES = ("A", "MX", "TXT", "NS", "CNAME")

PARKED_BODY_LIMIT = 2500
EMPTY_BODY_LIMIT = 200

TRANSIENT_ERRORS = {
      "ConnectTimeout",
      "ReadTimeout",
      "WriteTimeout",
      "PoolTimeout",
      "RemoteProtocolError",
  }

RETRYABLE_STATUS = {429, 502, 503, 504}