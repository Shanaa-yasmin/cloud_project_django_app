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