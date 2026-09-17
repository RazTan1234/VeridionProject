import regex

from techdetect.detect import Accumulator, Catalog, build_direct, match_document, match_fields, noisy_or, resolve, resolve_version
from techdetect.models import Pattern, Signal, SignalKind, Signature, Tier


def signal(kind, value=None, key=None, observation="home:x", document="home", content_ref=None):
    return Signal(
        domain="site.test",
        document_id=document,
        observation_id=observation,
        kind=kind,
        key=key,
        value=value,
        content_ref=content_ref,
        tier=Tier.HTTP,
        location="https://site.test/",
    )


def detect(signatures, signals, text=None):
    catalog = Catalog(signatures)
    found = Accumulator()
    for item in signals:
        if item.kind is SignalKind.HTML_TEXT:
            match_document(item, text, catalog, found)
        else:
            match_fields(item, catalog, found)
    direct = build_direct(found, catalog, set()).get("site.test", {})
    return resolve(direct, catalog)


def test_noisy_or_combines_independent_evidence():
    assert noisy_or([0.8]) == 0.8
    assert noisy_or([0.8, 0.8]) == 0.96


def test_resolve_version_substitutes_groups_and_ternaries():
    match = regex.search(r"WordPress ([\d.]+)", "WordPress 6.4.2")
    assert resolve_version(r"\1", match) == "6.4.2"
    assert resolve_version(r"\1?modern:legacy", match) == "modern"
    assert resolve_version(r"\1", None) is None
    assert resolve_version("not a version!", match) is None


def test_two_signals_from_one_observation_do_not_count_twice():
    shopify = Signature(
        id="own:shopify",
        name="Shopify",
        patterns=[
            Pattern(kind=SignalKind.SCRIPT_SRC, value=r"cdn\.shopify\.com"),
            Pattern(kind=SignalKind.SCRIPT_HOST, value=r"^cdn\.shopify\.com$"),
        ],
    )
    same_tag = [
        signal(SignalKind.SCRIPT_SRC, "https://cdn.shopify.com/s/app.js", observation="home:script:3"),
        signal(SignalKind.SCRIPT_HOST, "cdn.shopify.com", observation="home:script:3"),
    ]
    detections = detect([shopify], same_tag)
    assert detections["shopify"].confidence == 0.85
    assert len(detections["shopify"].evidence) == 2


def test_independent_observations_raise_confidence():
    wordpress = Signature(
        id="own:wordpress",
        name="WordPress",
        patterns=[
            Pattern(kind=SignalKind.META, key="generator", value=r"^WordPress ([\d.]+)", version=r"\1"),
            Pattern(kind=SignalKind.ROBOTS_LINE, value=r"^Disallow: /wp-admin/$"),
        ],
    )
    detections = detect(
        [wordpress],
        [
            signal(SignalKind.META, "WordPress 6.4.2", key="generator", observation="home:meta:1"),
            signal(SignalKind.ROBOTS_LINE, "Disallow: /wp-admin/", observation="robots:line:2", document="robots"),
        ],
    )
    detection = detections["wordpress"]
    assert detection.confidence == noisy_or([0.9, 0.7])
    assert detection.version == "6.4.2"
    assert detection.documents == ["home", "robots"]
    assert {evidence.snippets[0] for evidence in detection.evidence} == {"generator: WordPress 6.4.2", "Disallow: /wp-admin/"}


def test_wildcard_cookie_keys_match():
    dealer = Signature(id="own:dealer", name="Dealer.com", patterns=[Pattern(kind=SignalKind.COOKIE, key="ddc_*")])
    detections = detect([dealer], [signal(SignalKind.COOKIE, "1", key="ddc_diag_akam_clientIP")])
    assert "dealer.com" in detections


def test_implies_requires_and_excludes():
    catalog = [
        Signature(id="external:WordPress", name="WordPress", source="external", implies=["PHP"],
                  patterns=[Pattern(kind=SignalKind.META, key="generator", value="^WordPress")]),
        Signature(id="external:PHP", name="PHP", source="external"),
        Signature(id="external:Yoast", name="Yoast SEO", source="external", requires=["WordPress"],
                  patterns=[Pattern(kind=SignalKind.ROBOTS_LINE, value="YOAST")]),
        Signature(id="external:Generic", name="WebsiteBuilder", source="external",
                  patterns=[Pattern(kind=SignalKind.META, key="generator", value="Website Builder$")]),
        Signature(id="own:wix", name="Wix", excludes=["WebsiteBuilder"],
                  patterns=[Pattern(kind=SignalKind.META, key="generator", value="^Wix")]),
    ]

    wordpress_site = detect(catalog, [
        signal(SignalKind.META, "WordPress 6.4", key="generator", observation="home:meta:1"),
        signal(SignalKind.ROBOTS_LINE, "# START YOAST BLOCK", observation="robots:line:1", document="robots"),
    ])
    assert wordpress_site["php"].inferred
    assert wordpress_site["php"].evidence[0].implied_by == "WordPress"
    assert "yoast seo" in wordpress_site

    orphan_plugin = detect(catalog, [signal(SignalKind.ROBOTS_LINE, "# START YOAST BLOCK", document="robots")])
    assert "yoast seo" not in orphan_plugin

    wix_site = detect(catalog, [signal(SignalKind.META, "Wix.com Website Builder", key="generator")])
    assert "wix" in wix_site
    assert "websitebuilder" not in wix_site


def test_dom_and_html_rules_run_against_document_text():
    signatures = [
        Signature(id="external:Yoast", name="Yoast SEO", source="external",
                  patterns=[Pattern(kind=SignalKind.HTML_TEXT, value=r"Yoast SEO plugin v([\d.]+)", version=r"\1")]),
        Signature(id="external:Swiper", name="Swiper", source="external",
                  patterns=[Pattern(kind=SignalKind.DOM, key="div.swiper-wrapper")]),
        Signature(id="external:FA", name="Font Awesome", source="external",
                  patterns=[Pattern(kind=SignalKind.DOM, key="link[href*='font-awesome']", attribute="href", value=r"font-awesome/([\d.]+)/", version=r"\1")]),
    ]
    html = (
        "<html><head><!-- This site is optimized with the Yoast SEO plugin v27.2 -->"
        "<link href='https://cdn.test/font-awesome/6.5.0/css/all.css'></head>"
        "<body><div class='swiper-wrapper'></div></body></html>"
    )
    detections = detect(signatures, [signal(SignalKind.HTML_TEXT, observation="home:html", content_ref="sha256:x")], text=html)
    assert detections["yoast seo"].version == "27.2"
    assert detections["swiper"].evidence[0].signal_kind is SignalKind.DOM
    assert detections["font awesome"].version == "6.5.0"
