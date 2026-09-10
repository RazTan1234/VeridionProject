import collections
import json
import statistics
import sys
import time

import httpx
import pyarrow.parquet as pq

INPUT_PARQUET = "../data/input/domains.snappy.parquet"
OUTPUT_JSONL = "explore_fetch_output.jsonl"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

REQUEST_HEADERS = {
    "User-Agent": BROWSER_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,*;q=0.5",
}

TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)

BODY_PREVIEW_BYTES = 3000
PARKED_BODY_LIMIT = 2500

TLS_ERROR_MARKERS = ("certificate", "ssl", "tls", "sslv3", "handshake")

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


def load_domains(path):
    table = pq.read_table(path)
    return table.column("root_domain").to_pylist()


def looks_like_tls_error(error):
    text = f"{type(error).__name__} {error}".lower()
    return any(marker in text for marker in TLS_ERROR_MARKERS)


def attempt(client, url):
    started = time.perf_counter()

    try:
        response = client.get(url, headers=REQUEST_HEADERS)
    except Exception as error:
        return {
            "url": url,
            "outcome": "error",
            "error_type": type(error).__name__,
            "error_message": str(error)[:200],
            "tls_related": looks_like_tls_error(error),
            "seconds": round(time.perf_counter() - started, 2),
        }

    body = response.content

    return {
        "url": url,
        "outcome": "response",
        "final_url": str(response.url),
        "status": response.status_code,
        "redirect_chain": [
            {"url": str(step.url), "status": step.status_code}
            for step in response.history
        ],
        "seconds": round(time.perf_counter() - started, 2),
        "header_names": sorted(response.headers.keys()),
        "headers": dict(response.headers),
        "set_cookie_names": [
            raw.split("=", 1)[0].strip()
            for raw in response.headers.get_list("set-cookie")
        ],
        "body_bytes": len(body),
        "body_preview": body[:BODY_PREVIEW_BYTES].decode(
            response.encoding or "utf-8", errors="replace"
        ),
    }


def classify(final):
    if final is None:
        return "error"

    body = final["body_preview"].lower()
    status = final["status"]

    if status in (403, 429, 503) and (
        "cf-mitigated" in final["headers"]
        or any(marker in body for marker in CHALLENGE_MARKERS)
    ):
        return "challenged"

    if status in (404, 410):
        return "not_found"

    if final["body_bytes"] < PARKED_BODY_LIMIT and any(
        marker in body for marker in PARKING_MARKERS
    ):
        return "parked"

    if status >= 500 or status in (409, 526):
        return "origin_error"

    if status >= 400:
        return "http_error"

    if final["body_bytes"] < 200:
        return "empty"

    return "content"


def probe_domain(client, domain):
    attempts = []

    https_verified = attempt(client, f"https://{domain}")
    attempts.append(https_verified)
    if https_verified["outcome"] == "response":
        return finish(domain, attempts, https_verified)

    if https_verified["tls_related"]:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT, verify=False) as unsafe_client:
            https_unverified = attempt(unsafe_client, f"https://{domain}")
        attempts.append(https_unverified)
        if https_unverified["outcome"] == "response":
            return finish(domain, attempts, https_unverified)

    plain_http = attempt(client, f"http://{domain}")
    attempts.append(plain_http)
    if plain_http["outcome"] == "response":
        return finish(domain, attempts, plain_http)

    return finish(domain, attempts, None)


def finish(domain, attempts, final):
    return {
        "domain": domain,
        "attempts": attempts,
        "final": final,
        "classification": classify(final),
    }


def summarize(results):
    print("\n" + "=" * 90)
    print("OUTCOME DISTRIBUTION")
    for label, count in collections.Counter(r["classification"] for r in results).most_common():
        print(f"  {label:<14} {count:>4}  ({count / len(results):.0%})")

    print("\nERROR TYPES (domains with no response at all)")
    failed = [r for r in results if r["final"] is None]
    for label, count in collections.Counter(
        r["attempts"][-1]["error_type"] for r in failed
    ).most_common():
        print(f"  {label:<32} {count:>4}")

    reached = [r for r in results if r["final"] is not None]

    print("\nHTTP STATUS CODES")
    for code, count in collections.Counter(r["final"]["status"] for r in reached).most_common():
        print(f"  {code:<14} {count:>4}")

    print("\nFALLBACKS USED")
    print(f"  needed >1 attempt      {sum(1 for r in reached if len(r['attempts']) > 1):>4}")
    print(f"  landed on http://      {sum(1 for r in reached if r['final']['url'].startswith('http://')):>4}")
    print(f"  had redirects          {sum(1 for r in reached if r['final']['redirect_chain']):>4}")

    print("\nTIMING (seconds, successful fetches)")
    times = sorted(r["final"]["seconds"] for r in reached)
    if times:
        print(f"  median {statistics.median(times):.2f}   p90 {times[int(len(times) * 0.9)]:.2f}   max {times[-1]:.2f}")

    print("\nBODY SIZE (bytes)")
    sizes = sorted(r["final"]["body_bytes"] for r in reached)
    if sizes:
        print(f"  min {sizes[0]}   median {statistics.median(sizes):.0f}   p90 {sizes[int(len(sizes) * 0.9)]}   max {sizes[-1]}")

    print("\nHEADER NAMES BY NUMBER OF DOMAINS (top 60)")
    header_counter = collections.Counter()
    for r in reached:
        header_counter.update(set(r["final"]["header_names"]))
    for name, count in header_counter.most_common(60):
        print(f"  {count:>4}  {name}")

    print("\nCOOKIE NAMES BY NUMBER OF DOMAINS (top 40)")
    cookie_counter = collections.Counter()
    for r in reached:
        cookie_counter.update(set(r["final"]["set_cookie_names"]))
    for name, count in cookie_counter.most_common(40):
        print(f"  {count:>4}  {name}")


def reclassify():
    rows = [json.loads(line) for line in open(OUTPUT_JSONL)]
    changed = 0
    for row in rows:
        previous = row["classification"]
        row["classification"] = classify(row["final"])
        if row["classification"] != previous:
            changed += 1
            print(f"  {row['domain']:<45} {previous} -> {row['classification']}")
    print(f"\nreclassified {changed} of {len(rows)} domains, 0 requests made")
    summarize(rows)


def main():
    domains = load_domains(INPUT_PARQUET)
    results = []

    with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as client:
        with open(OUTPUT_JSONL, "w") as handle:
            for index, domain in enumerate(domains, start=1):
                result = probe_domain(client, domain)
                results.append(result)
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")
                handle.flush()
                status = result["final"]["status"] if result["final"] else "-"
                print(
                    f"[{index:>3}/{len(domains)}] {domain:<45} "
                    f"{result['classification']:<12} {status}",
                    flush=True,
                )

    summarize(results)


if __name__ == "__main__":
    if "--reclassify" in sys.argv:
        reclassify()
    else:
        main()
    sys.exit(0)
