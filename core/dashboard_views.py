"""
Dashboard API views — reads the pipeline's JSON output files
(scan_results.json, blast_radius_results.json, remediation_imds_results.json,
remediation_iam_results.json) and serves them as JSON responses, plus
serves the dashboard HTML page itself.

These files are produced by scanner.py, blast_radius.py, remediation_imds.py,
and remediation_iam.py, which should be run from the project root (same
directory manage.py lives in) so their output lands where this can find it.
"""

import json
import os
from django.http import JsonResponse, HttpResponse

# Project root — same directory as manage.py
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "dashboard.html")


def _read_json_file(filename):
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def api_scan_results(request):
    data = _read_json_file("scan_results.json")
    if data is None:
        return JsonResponse({"error": "scan_results.json not found. Run scanner.py first."}, status=404)
    return JsonResponse(data)


def api_blast_radius(request):
    data = _read_json_file("blast_radius_results.json")
    if data is None:
        return JsonResponse({"error": "blast_radius_results.json not found. Run blast_radius.py first."}, status=404)
    return JsonResponse(data)


def api_remediation_imds(request):
    data = _read_json_file("remediation_imds_results.json")
    if data is None:
        return JsonResponse({"error": "remediation_imds_results.json not found. Run remediation_imds.py first."}, status=404)
    return JsonResponse(data)


def api_remediation_iam(request):
    data = _read_json_file("remediation_iam_results.json")
    if data is None:
        return JsonResponse({"error": "remediation_iam_results.json not found or integration incomplete.", "status": "not_available"}, status=404)
    return JsonResponse(data)


def dashboard(request):
    # Served as a raw file, not through Django's template engine — this
    # page's React/JSX uses {{ }} for inline style objects, which Django's
    # template language also uses for variable interpolation, so running
    # this through render()/the template engine causes a parse error.
    with open(DASHBOARD_HTML_PATH, encoding="utf-8") as f:
        html = f.read()
    return HttpResponse(html)