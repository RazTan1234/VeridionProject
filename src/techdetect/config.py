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

CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "checking your browser",
    "enable javascript and cookies",
    "captcha",
    "ddos protection",
    "access denied",
    "you don't have permission",
)

PARKING_MARKERS = (
    "this domain",
    "domain is for sale",
    "buy this domain",
    "parked",
    "/lander",
    "domain for sale",
    "godaddy.com/forsale",
    "sedoparking",
    "afternic",
)

DNS_QUERIES = (
    ("", "A"),
    ("", "MX"),
    ("", "TXT"),
    ("", "NS"),
    ("", "CAA"),
    ("", "SOA"),
    ("www.", "CNAME"),
    ("_dmarc.", "TXT"),
)
DNS_LIFETIME_SECONDS = 5.0
TLS_PORT = 443

MAX_SIGNAL_VALUE_CHARS = 1000

OWN_SIGNATURES_DIR = SIGNATURES_DIR / "own"
EXTERNAL_SIGNATURES_DIR = SIGNATURES_DIR / "external"
EXTERNAL_REPOSITORY = "enthec/webappanalyzer"
EXTERNAL_REVISION = "f757f890006a836ec3518f78ca5e2e2a9793728a"
EXTERNAL_LICENSE = "GPL-3.0"
EXTERNAL_RAW_URL = "https://raw.githubusercontent.com/{repository}/{revision}/src/{path}"

REGEX_TIMEOUT_SECONDS = 0.5

KIND_WEIGHTS = {
    "hostname": 0.9,
    "http_header": 0.85,
    "cookie": 0.8,
    "meta": 0.9,
    "html_text": 0.7,
    "dom": 0.75,
    "script_src": 0.85,
    "script_host": 0.8,
    "link_host": 0.7,
    "csp_host": 0.5,
    "url_path": 0.75,
    "page_url": 0.8,
    "robots_line": 0.7,
    "wp_rest_namespace": 0.95,
    "dns_record": 0.85,
    "tls_issuer": 0.9,
    "tls_subject": 0.8,
    "js_global": 0.9,
}
