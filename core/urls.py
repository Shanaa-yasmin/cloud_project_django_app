from django.urls import path
from . import views
from . import dashboard_views

urlpatterns = [
    path('fetch-image/', views.fetch_image, name='fetch_image'),

    path('', dashboard_views.dashboard, name='dashboard'),
    path('api/scan-results/', dashboard_views.api_scan_results, name='api_scan_results'),
    path('api/blast-radius/', dashboard_views.api_blast_radius, name='api_blast_radius'),
    path('api/remediation/imds/', dashboard_views.api_remediation_imds, name='api_remediation_imds'),
    path('api/remediation/iam/', dashboard_views.api_remediation_iam, name='api_remediation_iam'),
    path('validate-webhook/', views.validate_webhook, name='validate_webhook'),
]