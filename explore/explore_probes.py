import collections
import json
import re
import sys
import time

import httpx

FETCH_JSONL = "explore_fetch_output.jsonl"
WPJSON_JSONL = "explore_wpjson_output.jsonl"
ROBOTS_JSONL = "explore_robots_output.jsonl"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
REQUEST_HEADERS = {"User-Agent": BROWSER_USER_AGENT, "Accept": "*/*"}
TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)


def load_fetch_results():
    return [json.loads(line) for line in open(FETCH_JSONL)]


def get_json(client, url):
    try:
        response = client.get(url, headers=REQUEST_HEADERS)
    except Exception as error:
        return {"url": url, "ok": False, "error": f"{type(error).__name__}: {error}"[:160]}

    if response.status_code != 200:
        return {"url": url, "ok": False, "status": response.status_code}

    try:
        return {"url": url, "ok": True, "status": 200, "json": response.json()}
    except Exception as error:
        return {
            "url": url,
            "ok": False,
            "status": 200,
            "error": f"not json: {type(error).__name__}",
            "body_head": response.text[:200],
        }


def get_text(client, url):
    try:
        response = client.get(url, headers=REQUEST_HEADERS)
    except Exception as error:
        return {"url": url, "ok": False, "error": f"{type(error).__name__}: {error}"[:160]}
    return {
        "url": url,
        "ok": response.status_code == 200,
        "status": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "text": response.text[:6000],
    }


def wordpress_targets(results):
    targets = []
    for row in results:
        final = row["final"]
        if not final:
            continue

        link_header = final["headers"].get("link", "")
        match = re.search(r'<([^>]+)>;\s*rel="https://api\.w\.org/"', link_header)
        if match:
            targets.append((row["domain"], match.group(1), "link_header"))
            continue

        body = final["body_preview"]
        if "wp-content" in body or "xmlrpc.php" in body:
            base = final["final_url"].rstrip("/")
            targets.append((row["domain"], f"{base}/wp-json/", "guessed"))
    return targets


def run_wpjson(client, results):
    targets = wordpress_targets(results)
    print(f"WordPress candidates: {len(targets)}")

    rows = []
    with open(WPJSON_JSONL, "w") as handle:
        for index, (domain, url, discovery) in enumerate(targets, start=1):
            probe = get_json(client, url)
            payload = probe.get("json") or {}
            record = {
                "domain": domain,
                "url": url,
                "discovery": discovery,
                "ok": probe["ok"],
                "status": probe.get("status"),
                "error": probe.get("error"),
                "namespaces": payload.get("namespaces", []) if isinstance(payload, dict) else [],
                "site_name": payload.get("name") if isinstance(payload, dict) else None,
                "route_count": len(payload.get("routes", {})) if isinstance(payload, dict) else 0,
            }
            rows.append(record)
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            print(
                f"[{index:>3}/{len(targets)}] {domain:<42} "
                f"{'OK ' if record['ok'] else 'no '} "
                f"ns={len(record['namespaces']):<3} routes={record['route_count']}",
                flush=True,
            )
    return rows


def report_wpjson(rows):
    ok = [r for r in rows if r["ok"]]
    print("\n" + "=" * 90)
    print(f"WP-JSON: {len(ok)}/{len(rows)} responded with usable JSON")

    print("\nFAILURE REASONS")
    for reason, count in collections.Counter(
        (r["error"] or f"status {r['status']}") for r in rows if not r["ok"]
    ).most_common():
        print(f"  {count:>3}  {reason[:70]}")

    namespace_counter = collections.Counter()
    for r in ok:
        namespace_counter.update(set(r["namespaces"]))

    print(f"\nDISTINCT NAMESPACES FOUND: {len(namespace_counter)}")
    for name, count in namespace_counter.most_common():
        print(f"  {count:>3}  {name}")

    per_site = [len(r["namespaces"]) for r in ok]
    if per_site:
        per_site.sort()
        print(f"\nNAMESPACES PER SITE: min {per_site[0]}  median {per_site[len(per_site)//2]}  max {per_site[-1]}")


def run_robots(client, results):
    reached = [r for r in results if r["final"]]
    print(f"\nrobots.txt targets: {len(reached)}")

    rows = []
    with open(ROBOTS_JSONL, "w") as handle:
        for index, row in enumerate(reached, start=1):
            base = row["final"]["final_url"].rstrip("/")
            probe = get_text(client, f"{base}/robots.txt")
            record = {
                "domain": row["domain"],
                "url": probe["url"],
                "ok": probe["ok"],
                "status": probe.get("status"),
                "content_type": probe.get("content_type", ""),
                "text": probe.get("text", ""),
            }
            rows.append(record)
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            if index % 20 == 0:
                print(f"  ...{index}/{len(reached)}", flush=True)
    return rows


def report_robots(rows):
    usable = [
        r for r in rows
        if r["ok"] and "html" not in r["content_type"].lower() and r["text"].strip()
    ]
    print("\n" + "=" * 90)
    print(f"ROBOTS: {len(usable)}/{len(rows)} returned a real robots.txt")

    print("\nDISALLOW PATHS BY NUMBER OF DOMAINS (top 40)")
    path_counter = collections.Counter()
    for r in usable:
        paths = set(re.findall(r"(?im)^\s*disallow:\s*(\S+)", r["text"]))
        path_counter.update(paths)
    for path, count in path_counter.most_common(40):
        print(f"  {count:>3}  {path[:70]}")

    print("\nSITEMAP URL SHAPES BY NUMBER OF DOMAINS (top 25)")
    sitemap_counter = collections.Counter()
    for r in usable:
        for match in set(re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r["text"])):
            shape = re.sub(r"^https?://[^/]+", "", match)
            sitemap_counter.update([shape])
    for shape, count in sitemap_counter.most_common(25):
        print(f"  {count:>3}  {shape[:70]}")

    print("\nCOMMENT LINES BY NUMBER OF DOMAINS (top 25)")
    comment_counter = collections.Counter()
    for r in usable:
        comments = set(
            line.strip().lower()
            for line in r["text"].splitlines()
            if line.strip().startswith("#") and len(line.strip()) > 3
        )
        comment_counter.update(comments)
    for comment, count in comment_counter.most_common(25):
        print(f"  {count:>3}  {comment[:80]}")


def main():
    results = load_fetch_results()
    started = time.perf_counter()
    with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as client:
        wpjson_rows = run_wpjson(client, results)
        robots_rows = run_robots(client, results)
    report_wpjson(wpjson_rows)
    report_robots(robots_rows)
    print(f"\ntotal wall time: {time.perf_counter() - started:.0f}s")


if __name__ == "__main__":
    main()
    sys.exit(0)
