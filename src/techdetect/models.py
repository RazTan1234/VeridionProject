from enum import Enum
from typing import Literal

from pydantic import BaseModel


class FetchOutcome(str, Enum):
    CONTENT = "content"
    CHALLENGED = "challenged"
    PARKED = "parked"
    NOT_FOUND = "not_found"
    ORIGIN_ERROR = "origin_error"
    HTTP_ERROR = "http_error"
    EMPTY = "empty"
    ERROR = "error"


class SignalKind(str, Enum):
    HOSTNAME = "hostname"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    META = "meta"
    HTML_TEXT = "html_text"
    SCRIPT_SRC = "script_src"
    SCRIPT_HOST = "script_host"
    LINK_HOST = "link_host"
    CSP_HOST = "csp_host"
    URL_PATH = "url_path"
    PAGE_URL = "page_url"
    ROBOTS_LINE = "robots_line"
    WP_REST_NAMESPACE = "wp_rest_namespace"
    DNS_RECORD = "dns_record"
    TLS_ISSUER = "tls_issuer"
    TLS_SUBJECT = "tls_subject"
    DOM = "dom"


class Tier(str, Enum):
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"


class Attempt(BaseModel):
    url: str
    outcome: Literal["response", "error"]
    status: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    elapsed_seconds: float = 0.0
    tls_related: bool = False


class FetchRecord(BaseModel):
    domain: str
    document_id: str
    requested_url: str
    final_url: str | None = None
    served_by_host: str | None = None
    offsite: bool = False
    status: int | None = None
    outcome: FetchOutcome
    redirect_chain: list[dict] = []
    attempts: list[Attempt] = []
    headers: dict[str, str] = {}
    set_cookie: list[str] = []
    content_ref: str | None = None
    content_bytes: int = 0
    content_type: str | None = None
    fetched_at: str
    elapsed_seconds: float = 0.0


class Signal(BaseModel):
    domain: str
    document_id: str
    observation_id: str
    kind: SignalKind
    key: str | None = None
    value: str | None = None
    content_ref: str | None = None
    tier: Tier
    location: str


class Evidence(BaseModel):
    signature_id: str
    signature_source: Literal["own", "external", "inferred"]
    signal_kind: SignalKind | None = None
    document_id: str | None = None
    observation_id: str | None = None
    location: str | None = None
    snippets: list[str] = []
    matched_pattern: str | None = None
    implied_by: str | None = None
    weight: float


class Detection(BaseModel):
    domain: str
    technology: str
    categories: list[str] = []
    version: str | None = None
    version_source: str | None = None
    confidence: float
    inferred: bool = False
    offsite: bool = False
    tiers: list[Tier] = []
    documents: list[str] = []
    evidence: list[Evidence] = []


class Pattern(BaseModel):
    kind: SignalKind
    key: str | None = None
    attribute: str | None = None
    value: str | None = None
    version: str | None = None
    confidence: int = 100
    weight: float | None = None


class Signature(BaseModel):
    id: str
    name: str
    categories: list[str] = []
    website: str | None = None
    source: Literal["own", "external"] = "own"
    patterns: list[Pattern] = []
    implies: list[str] = []
    requires: list[str] = []
    requires_category: list[str] = []
    excludes: list[str] = []
