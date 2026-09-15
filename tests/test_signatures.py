from collections import Counter

import pytest

from techdetect.external import convert_technology, dom_patterns, split_tags
from techdetect.models import SignalKind
from techdetect.signatures import SignatureError, load_own


def test_split_tags_extracts_version_and_confidence():
    assert split_tags(r"jquery-([\d.]+)\;version:\1\;confidence:50") == (r"jquery-([\d.]+)", r"\1", 50)


def test_split_tags_without_tags_defaults_to_full_confidence():
    assert split_tags("^nginx") == ("^nginx", None, 100)


def test_convert_technology_maps_every_supported_field():
    spec = {
        "cats": [1],
        "headers": {"X-Powered-By": "^Express$"},
        "cookies": {"PHPSESSID": ""},
        "meta": {"Generator": r"WordPress ?([\d.]+)?\;version:\1"},
        "scriptSrc": ["/wp-includes/"],
        "html": "<link[^>]+wp-content",
        "dns": {"CNAME": r"\.wixdns\.net"},
        "certIssuer": "Let's Encrypt",
        "implies": [r"PHP\;confidence:50"],
        "js": {"wp": ""},
    }
    stats = Counter()
    signature = convert_technology("Example", spec, {"1": "CMS"}, stats)

    kinds = Counter(pattern.kind for pattern in signature.patterns)
    for kind in (
        SignalKind.HTTP_HEADER,
        SignalKind.COOKIE,
        SignalKind.META,
        SignalKind.SCRIPT_SRC,
        SignalKind.HTML_TEXT,
        SignalKind.DNS_RECORD,
        SignalKind.TLS_ISSUER,
    ):
        assert kinds[kind] == 1

    header = next(p for p in signature.patterns if p.kind is SignalKind.HTTP_HEADER)
    assert header.key == "x-powered-by"
    meta = next(p for p in signature.patterns if p.kind is SignalKind.META)
    assert meta.key == "generator" and meta.version == r"\1"
    cookie = next(p for p in signature.patterns if p.kind is SignalKind.COOKIE)
    assert cookie.key == "PHPSESSID" and cookie.value is None
    dns = next(p for p in signature.patterns if p.kind is SignalKind.DNS_RECORD)
    assert dns.key == "www.CNAME"

    assert signature.categories == ["CMS"]
    assert signature.implies == ["PHP"]
    assert signature.source == "external"
    assert stats["unsupported_field_js"] == 1


def test_invalid_regex_is_rejected_and_counted():
    stats = Counter()
    signature = convert_technology("Broken", {"html": "([unclosed"}, {}, stats)
    assert signature.patterns == []
    assert stats["rejected_invalid_regex"] == 1


def test_dom_patterns_cover_selectors_attributes_and_text():
    stats = Counter()
    patterns = dom_patterns(
        {
            "script.aioseo-schema": {},
            "meta[name='x']": {"attributes": {"content": r"^v(\d)\;version:\1"}},
            "div.footer": {"text": "Powered by X"},
            "div.props": {"properties": {"foo": ""}},
        },
        stats,
    )
    described = {(p.key, p.attribute, p.value) for p in patterns}
    assert ("script.aioseo-schema", None, None) in described
    assert ("meta[name='x']", "content", r"^v(\d)") in described
    assert ("div.footer", "#text", "Powered by X") in described
    assert stats["rejected_dom_properties"] == 1


def test_own_loader_builds_ids_and_rejects_bad_regex(tmp_path):
    (tmp_path / "good.yaml").write_text(
        "technologies:\n"
        "  - name: Simply.com\n"
        "    categories: [Hosting]\n"
        "    patterns:\n"
        "      - {kind: http_header, key: server, value: '^Simply\\.com$'}\n",
        encoding="utf-8",
    )
    loaded = load_own(tmp_path)
    assert loaded[0].id == "own:simply-com"
    assert loaded[0].source == "own"

    (tmp_path / "bad.yaml").write_text(
        "technologies:\n  - name: Bad\n    patterns:\n      - {kind: html_text, value: '([oops'}\n",
        encoding="utf-8",
    )
    with pytest.raises(SignatureError):
        load_own(tmp_path)


def test_own_loader_rejects_unknown_signal_kind(tmp_path):
    (tmp_path / "typo.yaml").write_text(
        "technologies:\n  - name: Typo\n    patterns:\n      - {kind: http_headers, key: server}\n",
        encoding="utf-8",
    )
    with pytest.raises(SignatureError):
        load_own(tmp_path)


def test_repository_own_signatures_load_cleanly():
    from pathlib import Path

    signatures = load_own(Path(__file__).resolve().parents[1] / "signatures" / "own")
    assert signatures
    assert all(signature.source == "own" for signature in signatures)
    assert all(signature.patterns for signature in signatures)
