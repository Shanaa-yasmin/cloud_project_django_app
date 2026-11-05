from django.http import HttpResponse, JsonResponse
import requests

def fetch_image(request):
    url = request.GET.get('url')
    if not url:
        return JsonResponse({'error': 'url parameter required'}, status=400)

    # Intentionally vulnerable: no validation, no allowlist,
    # no blocking of internal/link-local IP ranges
    try:
        resp = requests.get(url, timeout=5)
        return HttpResponse(resp.content, content_type=resp.headers.get('Content-Type', 'application/octet-stream'))
    except requests.RequestException as e:
        return JsonResponse({'error': str(e)}, status=500)

def validate_webhook(request):
    """A second intentionally vulnerable SSRF entry point — a webhook
    'validator' that pings a user-supplied callback URL to confirm it's
    reachable before 'registering' it. Classic real-world SSRF pattern,
    accepts input via JSON POST body rather than a GET query param."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    callback_url = body.get("callback_url")
    if not callback_url:
        return JsonResponse({"error": "callback_url required"}, status=400)

    # Intentionally vulnerable: no validation, no allowlist
    try:
        resp = requests.get(callback_url, timeout=5)
        return JsonResponse({
            "status": "reachable",
            "response_code": resp.status_code,
            "response_snippet": resp.text[:200],
        })
    except requests.RequestException as e:
        return JsonResponse({"status": "unreachable", "error": str(e)}, status=502)